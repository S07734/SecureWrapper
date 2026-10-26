//go:build linux || darwin

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"securewrapper/connections"

	"golang.org/x/crypto/ssh"
)

// startEchoSSHServer runs an SSH server whose `exec` prints "out:<cmd>" and
// exits 0. Returns host, port and a login counter.
func startEchoSSHServer(t *testing.T) (string, int, *atomic.Int32) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	var logins atomic.Int32
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) != "pw" {
				return nil, errors.New("denied")
			}
			logins.Add(1)
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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
							ch.Write([]byte("out:" + string(r.Payload[4:])))
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port, &logins
}

// TestMuxEndToEnd drives the real spawn path: enableMux, a detached
// --mux-master process, the flock, and --mux-stop.
func TestMuxEndToEnd(t *testing.T) {
	t.Setenv("WRAPPER_MUX", "")
	t.Setenv("WRAPPER_MUX_PERSIST", "1m")
	host, port, logins := startEchoSSHServer(t)
	conn := Connection{Name: "e2e", Type: ConnSSHPassword, Host: host, Port: port, Username: "u", Password: "pw"}
	sock, token := muxSocketPath(conn), muxToken(conn)
	t.Cleanup(func() { connections.StopMux(sock, token) })

	enableMux(conn)

	// Concurrent first calls must still produce exactly one master.
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := "call" + strconv.Itoa(i)
			r := ExecuteConnectionSSH(conn, nil, cmd)
			if r.Error != nil || r.Output != "out:"+cmd {
				errs <- errors.New(cmd + ": " + r.Output + " " + errString(r.Error))
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := logins.Load(); n != 1 {
		t.Fatalf("upstream logins = %d, want 1", n)
	}

	fi, err := os.Stat(muxDir())
	if err != nil || fi.Mode().Perm() != 0700 {
		t.Fatalf("mux dir perms = %v (%v), want 0700", fi.Mode().Perm(), err)
	}

	if err := connections.StopMux(sock, token); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatal("socket remains after stop")
	}

	// Next call starts a fresh master: exactly one more login.
	if r := ExecuteConnectionSSH(conn, nil, "again"); r.Output != "out:again" {
		t.Fatalf("after stop: %q %v", r.Output, r.Error)
	}
	if n := logins.Load(); n != 2 {
		t.Fatalf("upstream logins after restart = %d, want 2", n)
	}
}

func TestMuxEndToEndUpstreamFailureSingleAttempt(t *testing.T) {
	t.Setenv("WRAPPER_MUX", "")
	host, port, _ := startEchoSSHServer(t)
	conn := Connection{Name: "e2e-bad", Type: ConnSSHPassword, Host: host, Port: port, Username: "u", Password: "wrong"}
	enableMux(conn)

	r := ExecuteConnectionSSH(conn, nil, "x")
	var upErr *connections.MuxUpstreamError
	if !errors.As(r.Error, &upErr) {
		t.Fatalf("err = %v, want MuxUpstreamError", r.Error)
	}
	if _, err := os.Stat(muxSocketPath(conn)); !os.IsNotExist(err) {
		t.Fatal("failed master left a socket behind")
	}
}

func TestMuxDisabledByEnv(t *testing.T) {
	t.Setenv("WRAPPER_MUX", "off")
	host, port, logins := startEchoSSHServer(t)
	conn := Connection{Name: "e2e-off", Type: ConnSSHPassword, Host: host, Port: port, Username: "u", Password: "pw"}
	enableMux(conn)
	for i := 0; i < 3; i++ {
		ExecuteConnectionSSH(conn, nil, "x")
	}
	if n := logins.Load(); n != 3 {
		t.Fatalf("logins = %d, want 3 direct dials", n)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
