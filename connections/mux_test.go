package connections

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeUpstream is a minimal SSH server: `exec` echoes the command to stdout,
// writes "err" to stderr, and exits 3. It counts logins.
type fakeUpstream struct {
	addr    string
	hostKey ssh.PublicKey
	logins  atomic.Int32
}

func startFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	f := &fakeUpstream{hostKey: signer.PublicKey()}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) != "secret" {
				return nil, errors.New("denied")
			}
			f.logins.Add(1)
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.addr = ln.Addr().String()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							r.Reply(true, nil)
							cmd := string(r.Payload[4:])
							ch.Write([]byte("out:" + cmd))
							ch.Stderr().Write([]byte("err"))
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{3}))
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	return f
}

func (f *fakeUpstream) dial(t *testing.T) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "u",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.FixedHostKey(f.hostKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func startMaster(t *testing.T, up *fakeUpstream, idle time.Duration) (string, chan struct{}) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "m.sock")
	ln, signer, err := ListenMux(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &MuxServer{Upstream: up.dial(t), Token: "tok", Signer: signer, SocketPath: sock, Idle: idle}
	done := make(chan struct{})
	go func() {
		srv.Serve(ln)
		close(done)
	}()
	t.Cleanup(func() { ln.Close() })
	return sock, done
}

func runVia(t *testing.T, c *ssh.Client, cmd string) (string, string, int) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	code := 0
	if err := s.Run(cmd); err != nil {
		var ee *ssh.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run: %v", err)
		}
		code = ee.ExitStatus()
	}
	return out.String(), errb.String(), code
}

func TestMuxSharesOneUpstreamLogin(t *testing.T) {
	up := startFakeUpstream(t)
	sock, _ := startMaster(t, up, time.Minute)

	for i, cmd := range []string{"uptime", "df -h", "whoami"} {
		c, err := DialMux(sock, "tok")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		out, errOut, code := runVia(t, c, cmd)
		c.Close()
		if out != "out:"+cmd || errOut != "err" || code != 3 {
			t.Fatalf("call %d: got out=%q err=%q code=%d", i, out, errOut, code)
		}
	}
	if n := up.logins.Load(); n != 1 {
		t.Fatalf("upstream logins = %d, want 1", n)
	}
}

func TestMuxRejectsWrongToken(t *testing.T) {
	up := startFakeUpstream(t)
	sock, _ := startMaster(t, up, time.Minute)
	if c, err := DialMux(sock, "wrong"); err == nil {
		c.Close()
		t.Fatal("wrong token accepted")
	}
}

func TestMuxIdleExit(t *testing.T) {
	up := startFakeUpstream(t)
	_, done := startMaster(t, up, 150*time.Millisecond)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("master did not exit after idle timeout")
	}
}

func TestMuxStop(t *testing.T) {
	up := startFakeUpstream(t)
	sock, done := startMaster(t, up, time.Minute)
	if err := StopMux(sock, "tok"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("master did not exit after stop")
	}
}

func TestDialSSHUsesRegisteredMux(t *testing.T) {
	up := startFakeUpstream(t)
	sock, _ := startMaster(t, up, time.Minute)

	// 192.0.2.1 is TEST-NET-1: a direct dial would fail, so success proves
	// the call went through the master.
	RegisterMux("u", "192.0.2.1", 22, &MuxEndpoint{SocketPath: sock, Token: "tok"})
	t.Cleanup(func() {
		muxMu.Lock()
		delete(muxEndpoints, muxKey("u", "192.0.2.1:22"))
		muxMu.Unlock()
	})

	c, err := dialSSH("192.0.2.1:22", &ssh.ClientConfig{User: "u", Timeout: time.Second})
	if err != nil {
		t.Fatalf("dialSSH: %v", err)
	}
	defer c.Close()
	if out, _, _ := runVia(t, c, "hostname"); !strings.HasPrefix(out, "out:hostname") {
		t.Fatalf("got %q", out)
	}
}

func TestDialSSHReturnsUpstreamErrorWithoutRetry(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "none.sock")
	RegisterMux("u", "192.0.2.1", 22, &MuxEndpoint{
		SocketPath: sock,
		Token:      "tok",
		Start:      func() error { return &MuxUpstreamError{Msg: "auth failed"} },
	})
	t.Cleanup(func() {
		muxMu.Lock()
		delete(muxEndpoints, muxKey("u", "192.0.2.1:22"))
		muxMu.Unlock()
	})

	start := time.Now()
	_, err := dialSSH("192.0.2.1:22", &ssh.ClientConfig{User: "u", Timeout: 5 * time.Second})
	var upErr *MuxUpstreamError
	if !errors.As(err, &upErr) {
		t.Fatalf("err = %v, want MuxUpstreamError", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("fell through to a direct dial after an upstream login failure")
	}
}

func TestMuxStopDrainsInFlightClients(t *testing.T) {
	up := startFakeUpstream(t)
	sock, done := startMaster(t, up, time.Minute)

	// Another session's client is connected when the stop arrives.
	other, err := DialMux(sock, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := StopMux(sock, "tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatal("socket still present after stop; new callers would not start a fresh master")
	}
	if out, _, _ := runVia(t, other, "still-works"); out != "out:still-works" {
		t.Fatalf("in-flight client broken by stop: %q", out)
	}
	select {
	case <-done:
		t.Fatal("master exited while a client was still connected")
	case <-time.After(100 * time.Millisecond):
	}
	other.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("master did not exit after the last client left")
	}
}

func TestMuxSurvivesKilledClient(t *testing.T) {
	up := startFakeUpstream(t)
	sock, _ := startMaster(t, up, time.Minute)

	// Simulate TaskStop / timeout: drop the raw socket mid-handshake and
	// mid-session without any orderly SSH close.
	raw, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	raw.Write([]byte("SSH-2.0-dying\r\n"))
	raw.Close()

	c, err := DialMux(sock, "tok")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	_ = s
	c.Conn.Close() // vanish with a session open

	c2, err := DialMux(sock, "tok")
	if err != nil {
		t.Fatalf("master unusable after a killed client: %v", err)
	}
	defer c2.Close()
	if out, _, _ := runVia(t, c2, "after"); out != "out:after" {
		t.Fatalf("got %q", out)
	}
	if n := up.logins.Load(); n != 1 {
		t.Fatalf("upstream logins = %d, want 1", n)
	}
}

func TestMuxDoesNotRemoveNewerMastersSocket(t *testing.T) {
	up := startFakeUpstream(t)
	sock, oldDone := startMaster(t, up, 300*time.Millisecond)

	// A credential change: the next caller removes the old master's files and
	// a new master takes over the same path.
	os.Remove(sock)
	os.Remove(sock + ".pub")
	ln, signer, err := ListenMux(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	newSrv := &MuxServer{Upstream: up.dial(t), Token: "tok2", Signer: signer, SocketPath: sock, Idle: time.Minute}
	go newSrv.Serve(ln)

	select {
	case <-oldDone:
	case <-time.After(3 * time.Second):
		t.Fatal("old master did not idle out")
	}
	c, err := DialMux(sock, "tok2")
	if err != nil {
		t.Fatalf("old master's exit removed the new master's socket: %v", err)
	}
	c.Close()
}
