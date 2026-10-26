package connections

// Connection sharing — the native-client equivalent of OpenSSH ControlMaster.
//
// A master process holds one authenticated upstream *ssh.Client and listens
// on a unix socket. Later wrapper calls connect to that socket with a local
// SSH handshake, and the master relays every channel (session, direct-tcpip)
// and channel request onto the shared upstream connection. The remote server
// sees one login for the master's lifetime instead of one per call, which is
// what keeps fail2ban / MaxStartups / per-IP rate limits from tripping.
//
// The local hop is authenticated twice over: the socket lives in a 0700
// directory, and the client must present a token derived from the vault's
// stored credentials, so a same-user process without vault access cannot
// ride an open master.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// muxStopRequest is the global request `--mux-stop` sends to a master.
const muxStopRequest = "stop@securewrapper"

// MuxEndpoint describes where the master for one connection lives.
type MuxEndpoint struct {
	SocketPath string
	Token      string
	// Start launches a master when none answers on SocketPath. A
	// *MuxUpstreamError means the master could not log in upstream; that is
	// returned to the caller as-is rather than retried directly, so one call
	// never costs the server two failed logins.
	Start func() error
}

// MuxUpstreamError reports that a master failed its upstream login.
type MuxUpstreamError struct{ Msg string }

func (e *MuxUpstreamError) Error() string { return "SSH connection failed: " + e.Msg }

var (
	muxMu        sync.Mutex
	muxEndpoints = map[string]*MuxEndpoint{}
)

func muxKey(user, addr string) string { return user + "@" + addr }

// RegisterMux routes later SSH dials for user@host:port through a master.
func RegisterMux(user, host string, port int, ep *MuxEndpoint) {
	muxMu.Lock()
	defer muxMu.Unlock()
	muxEndpoints[muxKey(user, fmt.Sprintf("%s:%d", host, port))] = ep
}

// dialSSH replaces ssh.Dial at every call site. Without a registered
// endpoint it dials directly, exactly as before.
func dialSSH(addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	muxMu.Lock()
	ep := muxEndpoints[muxKey(cfg.User, addr)]
	muxMu.Unlock()

	if ep != nil {
		if c, err := DialMux(ep.SocketPath, ep.Token); err == nil {
			return c, nil
		}
		if ep.Start != nil {
			err := ep.Start()
			var upErr *MuxUpstreamError
			if errors.As(err, &upErr) {
				return nil, err
			}
			if err == nil {
				if c, err := DialMux(ep.SocketPath, ep.Token); err == nil {
					return c, nil
				}
			}
		}
		// Master unavailable for a local reason — fall back to a direct dial.
	}
	return ssh.Dial("tcp", addr, cfg)
}

// DialMux connects to a running master. The master's host key is pinned
// from the .pub file it wrote next to the socket.
func DialMux(socketPath, token string) (*ssh.Client, error) {
	pubData, err := os.ReadFile(socketPath + ".pub")
	if err != nil {
		return nil, err
	}
	hostKey, err := ssh.ParsePublicKey(pubData)
	if err != nil {
		return nil, fmt.Errorf("mux host key: %w", err)
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            "mux",
		Auth:            []ssh.AuthMethod{ssh.Password(token)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         5 * time.Second,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, "mux", cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// StopMux asks a running master to exit. Returns an error if none answers.
func StopMux(socketPath, token string) error {
	c, err := DialMux(socketPath, token)
	if err != nil {
		return err
	}
	defer c.Close()
	_, _, err = c.SendRequest(muxStopRequest, true, nil)
	return err
}

// ListenMux generates a fresh host key for the local hop, publishes its
// public half at socketPath+".pub", and listens on socketPath.
func ListenMux(socketPath string) (net.Listener, ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}

	tmp := socketPath + ".pub.tmp"
	if err := os.WriteFile(tmp, signer.PublicKey().Marshal(), 0600); err != nil {
		return nil, nil, err
	}
	if err := os.Rename(tmp, socketPath+".pub"); err != nil {
		os.Remove(tmp)
		return nil, nil, err
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		os.Remove(socketPath + ".pub")
		return nil, nil, err
	}
	// Go would unlink socketPath on Close even if a newer master now owns
	// that path; MuxServer.release removes it only after checking ownership.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Chmod(socketPath, 0600); err != nil {
		ln.Close()
		os.Remove(socketPath)
		os.Remove(socketPath + ".pub")
		return nil, nil, err
	}
	return ln, signer, nil
}

// MuxServer relays local clients onto one upstream connection.
type MuxServer struct {
	Upstream *ssh.Client
	Token    string
	Signer   ssh.Signer
	// SocketPath is removed on exit, but only while this master still owns it.
	SocketPath string
	// Idle is how long the master outlives its last client (ControlPersist).
	Idle time.Duration

	mu        sync.Mutex
	ln        net.Listener
	active    int
	idleTimer *time.Timer
	conns     map[net.Conn]struct{}
	clients   sync.WaitGroup
	closeOnce sync.Once
}

// Serve accepts clients until the idle timeout, a stop request, or the
// upstream connection dies. A stop only closes the listener: calls already
// running (possibly another session's) finish on the shared connection, and
// new calls start a fresh master. It always closes the upstream before
// returning.
func (m *MuxServer) Serve(ln net.Listener) error {
	m.ln = ln
	m.conns = map[net.Conn]struct{}{}

	cfg := &ssh.ServerConfig{
		MaxAuthTries: 1,
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(pw, []byte(m.Token)) == 1 {
				return nil, nil
			}
			return nil, errors.New("access denied")
		},
	}
	cfg.AddHostKey(m.Signer)

	m.mu.Lock()
	m.armIdle()
	m.mu.Unlock()

	go func() {
		m.Upstream.Wait()
		m.shutdown()
	}()
	go m.keepalive()

	for {
		c, err := ln.Accept()
		if err != nil {
			m.release()
			m.clients.Wait()
			m.shutdown()
			return nil
		}
		m.clients.Add(1)
		m.mu.Lock()
		m.active++
		m.conns[c] = struct{}{}
		if m.idleTimer != nil {
			m.idleTimer.Stop()
			m.idleTimer = nil
		}
		m.mu.Unlock()

		go func() {
			m.handle(c, cfg)
			m.mu.Lock()
			m.active--
			delete(m.conns, c)
			if m.active == 0 {
				m.armIdle()
			}
			m.mu.Unlock()
			m.clients.Done()
		}()
	}
}

// armIdle starts the persist countdown. Caller holds m.mu.
func (m *MuxServer) armIdle() {
	if m.Idle > 0 {
		m.idleTimer = time.AfterFunc(m.Idle, m.shutdown)
	}
}

// release removes the socket and .pub, unless a newer master has replaced
// them (its .pub then carries a different host key).
func (m *MuxServer) release() {
	if m.SocketPath == "" {
		return
	}
	pub, err := os.ReadFile(m.SocketPath + ".pub")
	if err != nil || !bytes.Equal(pub, m.Signer.PublicKey().Marshal()) {
		return
	}
	os.Remove(m.SocketPath)
	os.Remove(m.SocketPath + ".pub")
}

func (m *MuxServer) shutdown() {
	m.closeOnce.Do(func() {
		m.ln.Close()
		m.Upstream.Close()
		m.mu.Lock()
		for c := range m.conns {
			c.Close()
		}
		m.mu.Unlock()
	})
}

// keepalive detects a dead upstream (NAT timeout, server restart) so the
// master exits instead of handing clients a connection that cannot work.
func (m *MuxServer) keepalive() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		done := make(chan error, 1)
		go func() {
			_, _, err := m.Upstream.SendRequest("keepalive@openssh.com", true, nil)
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				m.shutdown()
				return
			}
		case <-time.After(15 * time.Second):
			m.shutdown()
			return
		}
	}
}

func (m *MuxServer) handle(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	defer sc.Close()

	go func() {
		for r := range reqs {
			if r.Type == muxStopRequest {
				// Release before replying so the socket is gone once
				// --mux-stop returns.
				m.release()
				m.ln.Close()
				r.Reply(true, nil)
				continue
			}
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}()

	var wg sync.WaitGroup
	for nc := range chans {
		wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer wg.Done()
			m.relay(nc)
		}(nc)
	}
	wg.Wait()
}

// relay opens the same channel upstream and splices data and requests both
// ways. The local channel is closed last, after upstream output has drained
// and exit-status has been forwarded, so the client's Session.Wait sees the
// same sequence a direct connection would produce.
func (m *MuxServer) relay(nc ssh.NewChannel) {
	up, upReqs, err := m.Upstream.OpenChannel(nc.ChannelType(), nc.ExtraData())
	if err != nil {
		var oce *ssh.OpenChannelError
		if errors.As(err, &oce) {
			nc.Reject(oce.Reason, oce.Message)
		} else {
			nc.Reject(ssh.ConnectionFailed, err.Error())
		}
		return
	}
	local, localReqs, err := nc.Accept()
	if err != nil {
		up.Close()
		return
	}

	go func() {
		io.Copy(up, local)
		up.CloseWrite()
	}()
	// replyMu keeps the local channel open until an in-flight request has
	// been answered: a fast command can finish upstream before the reply to
	// its own `exec` reaches the client, which then sees EOF instead.
	var replyMu sync.Mutex
	go func() {
		for r := range localReqs {
			replyMu.Lock()
			ok, _ := up.SendRequest(r.Type, r.WantReply, r.Payload)
			if r.WantReply {
				r.Reply(ok, nil)
			}
			replyMu.Unlock()
		}
		// Client closed its side or vanished mid-command.
		up.Close()
	}()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		io.Copy(local, up)
		pumps.Done()
	}()
	go func() {
		io.Copy(local.Stderr(), up.Stderr())
		pumps.Done()
	}()

	for r := range upReqs {
		ok, _ := local.SendRequest(r.Type, r.WantReply, r.Payload)
		if r.WantReply {
			r.Reply(ok, nil)
		}
	}
	pumps.Wait()
	replyMu.Lock()
	local.CloseWrite()
	local.Close()
	replyMu.Unlock()
}
