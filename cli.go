package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"securewrapper/connections"

	"golang.org/x/term"
)

func readLine(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return ""
	}
	return string(pw)
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func pause() {
	fmt.Println()
	readLine(dimStyle.Render("  Press enter to continue..."))
}

func testConn(vault *Vault, conn Connection) error {
	switch conn.Type {
	case ConnSSHPassword:
		return connections.TestSSH(conn.Host, conn.Port, conn.Username, conn.Password, "")
	case ConnSSHKey:
		return connections.TestSSH(conn.Host, conn.Port, conn.Username, "", conn.KeyPath)
	case ConnAPI:
		return connections.TestAPI(conn.BaseURL, conn.AuthType, conn.AuthHeader, conn.AuthValue, conn.Insecure)
	case ConnFTP:
		return connections.TestFTP(conn.Host, conn.Port, conn.Username, conn.Password)
	case ConnDBPostgres, ConnDBMySQL, ConnDBMSSQL:
		r := ExecuteConnectionDB(vault, conn, "")
		if r.Error != nil {
			return r.Error
		}
		return nil
	case ConnWinRM:
		r := ExecuteConnectionWinRM(vault, conn, "")
		if r.Error != nil {
			return r.Error
		}
		return nil
	default:
		return fmt.Errorf("unknown connection type: %s", conn.Type)
	}
}

// dbDriverForType maps the vault's ConnectionType to the database/sql driver
// name registered by the import side-effects in connections/db.go.
func dbDriverForType(t ConnectionType) string {
	switch t {
	case ConnDBPostgres:
		return "postgres"
	case ConnDBMySQL:
		return "mysql"
	case ConnDBMSSQL:
		return "sqlserver"
	}
	return ""
}

// ExecuteConnectionDB runs a query against a database connection. Empty
// query = connectivity test (ping only). If conn.TunnelVia is set, an SSH
// port-forward is established first and the DB dials through localhost.
func ExecuteConnectionDB(vault *Vault, conn Connection, query string) connections.Result {
	driver := dbDriverForType(conn.Type)
	if driver == "" {
		return connections.Result{Error: fmt.Errorf("connection \"%s\" is type %s, not a database", conn.Name, conn.Type)}
	}
	host, port, cleanup, err := resolveTunnel(vault, conn)
	if err != nil {
		return connections.Result{Error: err, ExitCode: 1}
	}
	defer cleanup()
	return connections.ExecuteDB(connections.DBConfig{
		Driver:   driver,
		Host:     host,
		Port:     port,
		Username: conn.Username,
		Password: conn.Password,
		Database: conn.Database,
		SSLMode:  conn.SSLMode,
	}, query)
}

// ExecuteConnectionWinRM runs a PowerShell command against a WinRM endpoint.
// Empty command = connectivity test. If conn.TunnelVia is set, an SSH port-
// forward is established first and the WinRM client talks to localhost.
func ExecuteConnectionWinRM(vault *Vault, conn Connection, command string) connections.Result {
	if conn.Type != ConnWinRM {
		return connections.Result{Error: fmt.Errorf("connection \"%s\" is type %s, not WinRM", conn.Name, conn.Type)}
	}
	host, port, cleanup, err := resolveTunnel(vault, conn)
	if err != nil {
		return connections.Result{Error: err, ExitCode: 1}
	}
	defer cleanup()
	return connections.ExecuteWinRM(connections.WinRMConfig{
		Host:     host,
		Port:     port,
		Username: conn.Username,
		Password: conn.Password,
		UseHTTPS: conn.UseHTTPS,
		Insecure: conn.Insecure,
	}, command)
}

// resolveTunnel optionally wraps a connection in an SSH port-forward. If the
// connection has no TunnelVia field (or we have no vault reference) it
// returns the connection's own host/port and a no-op cleanup. Otherwise it
// dials SSH through the named tunnel profile, opens a local listener
// forwarding to the target, and returns "127.0.0.1:<ephemeral>" plus a
// cleanup that tears down the tunnel.
func resolveTunnel(vault *Vault, conn Connection) (string, int, func(), error) {
	noop := func() {}
	if conn.TunnelVia == "" || vault == nil {
		return conn.Host, conn.Port, noop, nil
	}

	tun := vault.GetConnection(conn.TunnelVia)
	if tun == nil {
		return "", 0, nil, fmt.Errorf("tunnel connection %q not found in vault", conn.TunnelVia)
	}
	if tun.Type != ConnSSHPassword && tun.Type != ConnSSHKey {
		return "", 0, nil, fmt.Errorf("tunnel connection %q must be SSH type, got %s", conn.TunnelVia, tun.Type)
	}

	var password, keyPath, keyPass string
	if tun.Type == ConnSSHPassword {
		password = tun.Password
	} else {
		keyPath = tun.KeyPath
		keyPass = tun.KeyPass
	}

	sshClient, err := connections.DialSSH(tun.Host, tun.Port, tun.Username, password, keyPath, keyPass)
	if err != nil {
		return "", 0, nil, fmt.Errorf("SSH tunnel dial (%s): %w", conn.TunnelVia, err)
	}

	localAddr, cleanup, err := connections.OpenTunnel(sshClient, conn.Host, conn.Port)
	if err != nil {
		sshClient.Close()
		return "", 0, nil, fmt.Errorf("open tunnel: %w", err)
	}

	host, portStr, splitErr := net.SplitHostPort(localAddr)
	if splitErr != nil {
		cleanup()
		return "", 0, nil, fmt.Errorf("parse tunnel addr: %w", splitErr)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port, cleanup, nil
}

// ExecuteConnectionSSH runs a command via SSH using the connection's credentials.
func ExecuteConnectionSSH(conn Connection, flags []string, command string) connections.Result {
	switch conn.Type {
	case ConnSSHPassword:
		return connections.ExecuteSSHPassword(conn.Host, conn.Port, conn.Username, conn.Password, flags, command)
	case ConnSSHKey:
		return connections.ExecuteSSHKey(conn.Host, conn.Port, conn.Username, conn.KeyPath, conn.KeyPass, flags, command)
	default:
		return connections.Result{Error: fmt.Errorf("connection \"%s\" is type %s, not SSH", conn.Name, conn.Type)}
	}
}

// ExecuteConnectionSCP copies files via SCP using the connection's credentials.
func ExecuteConnectionSCP(conn Connection, passthrough []string) connections.Result {
	switch conn.Type {
	case ConnSSHPassword:
		return connections.ExecuteSCPPassword(conn.Host, conn.Port, conn.Username, conn.Password, passthrough)
	case ConnSSHKey:
		return connections.ExecuteSCPKey(conn.Host, conn.Port, conn.Username, conn.KeyPath, conn.KeyPass, passthrough)
	default:
		return connections.Result{Error: fmt.Errorf("connection \"%s\" is type %s, not SSH", conn.Name, conn.Type)}
	}
}

// ExecuteConnectionSFTP opens an SFTP session using the connection's credentials.
func ExecuteConnectionSFTP(conn Connection, passthrough []string) connections.Result {
	switch conn.Type {
	case ConnSSHPassword:
		command := ""
		if len(passthrough) > 0 {
			command = strings.Join(passthrough, "\n")
		}
		return connections.ExecuteSFTP(conn.Host, conn.Port, conn.Username, conn.Password, nil, command)
	default:
		return connections.Result{Error: fmt.Errorf("connection \"%s\" is type %s, not SSH", conn.Name, conn.Type)}
	}
}

// ExecuteConnectionSSHProxy acts as an SSH stdio proxy for rsync.
// Authenticates via Go's native SSH, bridges stdin/stdout. Password never leaves Go.
func ExecuteConnectionSSHProxy(conn Connection, command string) connections.Result {
	switch conn.Type {
	case ConnSSHPassword:
		return connections.SSHProxy(conn.Host, conn.Port, conn.Username, conn.Password, "", "", command)
	case ConnSSHKey:
		return connections.SSHProxy(conn.Host, conn.Port, conn.Username, "", conn.KeyPath, conn.KeyPass, command)
	default:
		return connections.Result{Error: fmt.Errorf("connection \"%s\" is type %s, not SSH", conn.Name, conn.Type)}
	}
}

// ExecuteConnectionRsync runs rsync over SSH using the wrapper as the SSH transport.
func ExecuteConnectionRsync(conn Connection, passthrough []string) connections.Result {
	exePath, err := os.Executable()
	if err != nil {
		return connections.Result{Error: fmt.Errorf("cannot find executable: %w", err)}
	}

	sshCmd := fmt.Sprintf("%s --sys %s --ssh-proxy", exePath, conn.Name)

	args := []string{"-e", sshCmd}

	for _, arg := range passthrough {
		if strings.HasPrefix(arg, ":/") || strings.HasPrefix(arg, ":~") {
			args = append(args, fmt.Sprintf("%s@%s%s", conn.Username, conn.Host, arg))
		} else {
			args = append(args, arg)
		}
	}

	cmd := exec.Command("rsync", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = status.ExitStatus()
			}
		} else {
			return connections.Result{Error: runErr}
		}
	}

	return connections.Result{ExitCode: exitCode}
}

func printSuccess(msg string) {
	fmt.Println(successStyle.Render("  ✓ " + msg))
}

func printError(msg string) {
	fmt.Println(errorStyle.Render("  ✗ " + msg))
}

func printWarn(msg string) {
	fmt.Println(warnStyle.Render("  ⚠ " + msg))
}

func printPrompt(msg string) string {
	return readLine(promptStyle.Render("  "+msg) + " ")
}

func printPasswordPrompt(msg string) string {
	return readPassword(promptStyle.Render("  "+msg) + " ")
}
