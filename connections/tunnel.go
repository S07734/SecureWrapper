package connections

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// DialSSH opens an SSH client connection using either password or key auth.
// Exactly one of password or keyPath must be non-empty (keyPass is optional
// when the key is unencrypted). Caller is responsible for Close() on the
// returned client.
//
// Host key verification uses the same TOFU known_hosts store as the other
// SSH code paths — a tunneled bastion gets the same trust-on-first-use and
// change-detection behavior as direct SSH connections.
func DialSSH(host string, port int, username, password, keyPath, keyPass string) (*ssh.Client, error) {
	hostKeyCallback, err := GetHostKeyCallback()
	if err != nil {
		return nil, fmt.Errorf("host key verification setup: %w", err)
	}

	var authMethods []ssh.AuthMethod
	switch {
	case keyPath != "":
		keyData, err := os.ReadFile(expandHome(keyPath))
		if err != nil {
			return nil, fmt.Errorf("cannot read key %s: %w", keyPath, err)
		}
		var signer ssh.Signer
		if keyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(keyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		authMethods = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	case password != "":
		authMethods = []ssh.AuthMethod{ssh.Password(password)}
	default:
		return nil, fmt.Errorf("SSH connection requires either password or key")
	}

	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	return ssh.Dial("tcp", addr, cfg)
}

// OpenTunnel binds a local TCP listener on 127.0.0.1 (OS-chosen port) and
// forwards every incoming connection to targetHost:targetPort through the
// provided SSH client. Returns the local address to connect to (e.g.
// "127.0.0.1:54321") and a cleanup function that stops the listener and
// closes the SSH client.
//
// The cleanup function is safe to call from defer. It blocks until the
// accept loop has stopped to avoid leaking goroutines past cleanup.
func OpenTunnel(sshClient *ssh.Client, targetHost string, targetPort int) (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("local listen: %w", err)
	}

	target := fmt.Sprintf("%s:%d", targetHost, targetPort)
	accepted := make(chan struct{})

	go func() {
		defer close(accepted)
		for {
			local, err := listener.Accept()
			if err != nil {
				// Listener closed — normal shutdown path.
				return
			}
			go func(local net.Conn) {
				remote, err := sshClient.Dial("tcp", target)
				if err != nil {
					local.Close()
					return
				}
				bidirectionalCopy(local, remote)
			}(local)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-accepted
		sshClient.Close()
	}

	return listener.Addr().String(), cleanup, nil
}

// bidirectionalCopy shuttles bytes both ways between two connections and
// returns once either direction reports EOF or an error. Both conns are
// closed before the function returns.
func bidirectionalCopy(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}
