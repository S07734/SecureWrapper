package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
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

func testConn(conn Connection) error {
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
		r := ExecuteConnectionDB(conn, "")
		if r.Error != nil {
			return r.Error
		}
		return nil
	case ConnWinRM:
		r := ExecuteConnectionWinRM(conn, "")
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
// query = connectivity test (ping only).
func ExecuteConnectionDB(conn Connection, query string) connections.Result {
	driver := dbDriverForType(conn.Type)
	if driver == "" {
		return connections.Result{Error: fmt.Errorf("connection \"%s\" is type %s, not a database", conn.Name, conn.Type)}
	}
	return connections.ExecuteDB(connections.DBConfig{
		Driver:   driver,
		Host:     conn.Host,
		Port:     conn.Port,
		Username: conn.Username,
		Password: conn.Password,
		Database: conn.Database,
		SSLMode:  conn.SSLMode,
	}, query)
}

// ExecuteConnectionWinRM runs a PowerShell command against a WinRM endpoint.
// Empty command = connectivity test.
func ExecuteConnectionWinRM(conn Connection, command string) connections.Result {
	if conn.Type != ConnWinRM {
		return connections.Result{Error: fmt.Errorf("connection \"%s\" is type %s, not WinRM", conn.Name, conn.Type)}
	}
	return connections.ExecuteWinRM(connections.WinRMConfig{
		Host:     conn.Host,
		Port:     conn.Port,
		Username: conn.Username,
		Password: conn.Password,
		UseHTTPS: conn.UseHTTPS,
		Insecure: conn.Insecure,
	}, command)
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
