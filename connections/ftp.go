package connections

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ExecuteSFTP runs SFTP commands using Go's native SSH client.
func ExecuteSFTP(host string, port int, username, password string, passthroughArgs []string, command string) Result {
	hostKeyCallback, err := GetHostKeyCallback()
	if err != nil {
		return Result{Error: fmt.Errorf("host key verification setup failed: %w", err)}
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return Result{Error: fmt.Errorf("SSH connection failed: %w", err)}
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return Result{Error: fmt.Errorf("SSH session failed: %w", err)}
	}
	defer session.Close()

	// Request sftp subsystem
	if err := session.RequestSubsystem("sftp"); err != nil {
		// Fall back to running sftp-server directly
		session.Close()
		return executeSFTPFallback(client, command)
	}

	// For batch commands, pipe them through
	if command != "" {
		var stdout, stderr bytes.Buffer
		session.Stdout = &stdout
		session.Stderr = &stderr
		session.Stdin = strings.NewReader(command + "\n")

		session.Wait()

		output := stdout.String()
		if errOut := stderr.String(); errOut != "" {
			output += "\n" + errOut
		}
		return Result{Output: strings.TrimSpace(output)}
	}

	// Interactive mode
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	session.Wait()
	return Result{ExitCode: 0}
}

func executeSFTPFallback(client *ssh.Client, command string) Result {
	// Use SSH exec to run sftp-like commands
	session, err := client.NewSession()
	if err != nil {
		return Result{Error: fmt.Errorf("SSH session failed: %w", err)}
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Convert sftp commands to shell equivalents
	if command != "" {
		shellCmd := convertSFTPCommand(command)
		if err := session.Run(shellCmd); err != nil {
			return Result{Output: stderr.String(), Error: err}
		}
		return Result{Output: strings.TrimSpace(stdout.String())}
	}

	return Result{Error: fmt.Errorf("interactive SFTP not available on this server")}
}

func convertSFTPCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "echo 'no command'"
	}

	switch parts[0] {
	case "ls":
		if len(parts) > 1 {
			return "ls -la " + shellEscape(parts[1])
		}
		return "ls -la"
	case "pwd":
		return "pwd"
	case "get":
		if len(parts) < 2 {
			return "echo 'get requires a path argument'"
		}
		// Can't do get through shell — need actual sftp
		return fmt.Sprintf("cat %s", shellEscape(parts[1]))
	default:
		return fmt.Sprintf("echo 'unsupported command: %s'", shellEscape(parts[0]))
	}
}

// TestFTP tests SFTP connectivity using Go's native SSH client.
func TestFTP(host string, port int, username, password string) error {
	hostKeyCallback, err := GetHostKeyCallback()
	if err != nil {
		return fmt.Errorf("host key verification setup failed: %w", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("session failed: %w", err)
	}
	defer session.Close()

	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := session.Run("echo connection_ok"); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	if !strings.Contains(stdout.String(), "connection_ok") {
		return fmt.Errorf("unexpected output")
	}

	return nil
}
