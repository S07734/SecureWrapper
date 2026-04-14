package connections

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ExecuteSSHPassword runs a command on a remote host using Go's native SSH client.
func ExecuteSSHPassword(host string, port int, username, password string, passthroughArgs []string, command string) Result {
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

	return executeSSH(host, port, config, passthroughArgs, command)
}

// ExecuteSSHKey runs a command using SSH key auth via Go's native SSH client.
func ExecuteSSHKey(host string, port int, username, keyPath, keyPassphrase string, passthroughArgs []string, command string) Result {
	hostKeyCallback, err := GetHostKeyCallback()
	if err != nil {
		return Result{Error: fmt.Errorf("host key verification setup failed: %w", err)}
	}

	keyData, err := os.ReadFile(expandHome(keyPath))
	if err != nil {
		return Result{Error: fmt.Errorf("cannot read key file %s: %w", keyPath, err)}
	}

	var signer ssh.Signer
	if keyPassphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(keyPassphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyData)
	}
	if err != nil {
		return Result{Error: fmt.Errorf("cannot parse key: %w", err)}
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	return executeSSH(host, port, config, passthroughArgs, command)
}

func executeSSH(host string, port int, config *ssh.ClientConfig, passthroughArgs []string, command string) Result {
	addr := fmt.Sprintf("%s:%d", host, port)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return Result{Error: fmt.Errorf("SSH connection failed: %w", err)}
	}
	defer client.Close()

	// If no command, open interactive session
	if command == "" {
		return interactiveSSH(client)
	}

	session, err := client.NewSession()
	if err != nil {
		return Result{Error: fmt.Errorf("SSH session failed: %w", err)}
	}
	defer session.Close()

	// Check for -t flag (request PTY)
	requestPTY := false
	var filteredArgs []string
	for _, arg := range passthroughArgs {
		if arg == "-t" {
			requestPTY = true
		} else {
			filteredArgs = append(filteredArgs, arg)
		}
	}

	if requestPTY {
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
			return Result{Error: fmt.Errorf("PTY request failed: %w", err)}
		}
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(command)
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			return Result{Output: stderr.String(), Error: err}
		}
	}

	output := stdout.String()
	if errOut := stderr.String(); errOut != "" {
		if output != "" {
			output += "\n" + errOut
		} else {
			output = errOut
		}
	}

	return Result{Output: strings.TrimSpace(output), ExitCode: exitCode}
}

func interactiveSSH(client *ssh.Client) Result {
	session, err := client.NewSession()
	if err != nil {
		return Result{Error: fmt.Errorf("SSH session failed: %w", err)}
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return Result{Error: fmt.Errorf("PTY request failed: %w", err)}
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return Result{Error: fmt.Errorf("shell failed: %w", err)}
	}

	session.Wait()
	return Result{ExitCode: 0}
}

// TestSSH tests connectivity to an SSH host.
func TestSSH(host string, port int, username, password, keyPath string) error {
	var result Result
	if keyPath != "" {
		result = ExecuteSSHKey(host, port, username, keyPath, "", nil, "echo connection_ok")
	} else {
		result = ExecuteSSHPassword(host, port, username, password, nil, "echo connection_ok")
	}

	if result.Error != nil {
		return result.Error
	}
	if !strings.Contains(result.Output, "connection_ok") {
		return fmt.Errorf("SSH connected but unexpected output: %s", result.Output)
	}
	return nil
}

// ExecuteSCPPassword copies files via SCP using Go SSH for auth + native scp for transfer.
// Uses the SSH connection to pipe data rather than shelling out to expect.
func ExecuteSCPPassword(host string, port int, username, password string, passthrough []string) Result {
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

	return executeSCP(host, port, config, username, passthrough)
}

// ExecuteSCPKey copies files via SCP with key auth.
func ExecuteSCPKey(host string, port int, username, keyPath, keyPassphrase string, passthrough []string) Result {
	hostKeyCallback, err := GetHostKeyCallback()
	if err != nil {
		return Result{Error: fmt.Errorf("host key verification setup failed: %w", err)}
	}

	keyData, err := os.ReadFile(expandHome(keyPath))
	if err != nil {
		return Result{Error: fmt.Errorf("cannot read key file: %w", err)}
	}

	var signer ssh.Signer
	if keyPassphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(keyPassphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyData)
	}
	if err != nil {
		return Result{Error: fmt.Errorf("cannot parse key: %w", err)}
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	return executeSCP(host, port, config, username, passthrough)
}

// expandHome expands ~ to the user's home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

// shellEscape wraps a string in single quotes, escaping any embedded single quotes.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func executeSCP(host string, port int, config *ssh.ClientConfig, username string, passthrough []string) Result {
	// Determine direction: upload or download
	// ":" prefix on an arg means remote path
	addr := fmt.Sprintf("%s:%d", host, port)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return Result{Error: fmt.Errorf("SSH connection failed: %w", err)}
	}
	defer client.Close()

	// Parse passthrough to find source/dest and flags
	var flags []string
	var paths []string
	for _, arg := range passthrough {
		if strings.HasPrefix(arg, "-") && len(paths) == 0 {
			flags = append(flags, arg)
		} else {
			paths = append(paths, arg)
		}
	}

	if len(paths) < 2 {
		return Result{Error: fmt.Errorf("SCP requires source and destination paths")}
	}

	source := paths[0]
	dest := paths[1]

	isUpload := strings.HasPrefix(dest, ":")
	isDownload := strings.HasPrefix(source, ":")

	if isUpload {
		remotePath := strings.TrimPrefix(dest, ":")
		return scpUpload(client, source, remotePath, flags)
	} else if isDownload {
		remotePath := strings.TrimPrefix(source, ":")
		return scpDownload(client, remotePath, dest, flags)
	}

	return Result{Error: fmt.Errorf("one of source or dest must be a remote path (prefixed with ':')")}
}

func scpUpload(client *ssh.Client, localPath, remotePath string, flags []string) Result {
	localFile, err := os.Open(localPath)
	if err != nil {
		return Result{Error: fmt.Errorf("cannot open local file: %w", err)}
	}
	defer localFile.Close()

	stat, err := localFile.Stat()
	if err != nil {
		return Result{Error: fmt.Errorf("cannot stat local file: %w", err)}
	}

	session, err := client.NewSession()
	if err != nil {
		return Result{Error: fmt.Errorf("SSH session failed: %w", err)}
	}
	defer session.Close()

	var stderr bytes.Buffer
	session.Stderr = &stderr

	w, err := session.StdinPipe()
	if err != nil {
		return Result{Error: err}
	}

	// Start remote scp sink
	go func() {
		defer w.Close()
		fmt.Fprintf(w, "C0644 %d %s\n", stat.Size(), stat.Name())
		io.Copy(w, localFile)
		fmt.Fprint(w, "\x00")
	}()

	recursive := ""
	for _, f := range flags {
		if f == "-r" {
			recursive = "-r"
		}
	}

	cmd := fmt.Sprintf("scp %s -t %s", recursive, shellEscape(remotePath))
	if err := session.Run(cmd); err != nil {
		return Result{Output: stderr.String(), Error: fmt.Errorf("SCP upload failed: %w", err)}
	}

	return Result{Output: fmt.Sprintf("Uploaded %s → %s (%d bytes)", localPath, remotePath, stat.Size())}
}

func scpDownload(client *ssh.Client, remotePath, localPath string, flags []string) Result {
	session, err := client.NewSession()
	if err != nil {
		return Result{Error: fmt.Errorf("SSH session failed: %w", err)}
	}
	defer session.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Use cat for simple file download — more reliable than scp protocol
	cmd := fmt.Sprintf("cat %s", shellEscape(remotePath))
	if err := session.Run(cmd); err != nil {
		return Result{Output: stderr.String(), Error: fmt.Errorf("download failed: %w", err)}
	}

	// Determine local destination
	destPath := localPath
	if info, err := os.Stat(localPath); err == nil && info.IsDir() {
		// Extract filename from remote path
		parts := strings.Split(remotePath, "/")
		destPath = localPath + "/" + parts[len(parts)-1]
	}

	if err := os.WriteFile(destPath, stdout.Bytes(), 0644); err != nil {
		return Result{Error: fmt.Errorf("cannot write local file: %w", err)}
	}

	return Result{Output: fmt.Sprintf("Downloaded %s → %s (%d bytes)", remotePath, destPath, stdout.Len())}
}

// SSHProxy acts as a stdio-based SSH transport for rsync.
// It authenticates using Go's native SSH client and bridges stdin/stdout
// to the remote session. The password/key never leaves Go's memory.
// Rsync calls this via its -e flag as a drop-in SSH replacement.
func SSHProxy(host string, port int, username, password, keyPath, keyPassphrase, command string) Result {
	hostKeyCallback, err := GetHostKeyCallback()
	if err != nil {
		return Result{Error: fmt.Errorf("host key verification setup failed: %w", err)}
	}

	var authMethods []ssh.AuthMethod
	if keyPath != "" {
		keyData, err := os.ReadFile(expandHome(keyPath))
		if err != nil {
			return Result{Error: fmt.Errorf("cannot read key file: %w", err)}
		}
		var signer ssh.Signer
		if keyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(keyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return Result{Error: fmt.Errorf("cannot parse key: %w", err)}
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
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

	// Bridge stdin/stdout directly — rsync communicates through these
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if command != "" {
		err = session.Run(command)
	} else {
		err = session.Shell()
		if err == nil {
			err = session.Wait()
		}
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			return Result{Error: err}
		}
	}

	return Result{ExitCode: exitCode}
}

// ExecuteRsyncPassword and ExecuteRsyncKey are removed.
// Rsync now uses the wrapper in --ssh-proxy mode as its SSH transport.
// This keeps passwords entirely within Go's memory — no sshpass, no env var leaks.
