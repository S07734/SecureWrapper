package connections

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

// WinRMConfig holds everything needed to open a WinRM/PowerShell session.
// Ports follow Microsoft defaults: 5985 for HTTP, 5986 for HTTPS. TLS
// verification follows the caller's Insecure preference — self-signed certs
// are common on internal endpoints.
type WinRMConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	UseHTTPS bool
	Insecure bool // skip TLS verification (self-signed certs)
}

const winrmExecTimeout = 5 * time.Minute

// ExecuteWinRM opens a WinRM session and runs the given PowerShell command.
// Output captures stdout; stderr is appended on error so callers see both.
// A blank command performs only the handshake — acts as a connectivity test.
func ExecuteWinRM(cfg WinRMConfig, command string) Result {
	if cfg.Host == "" {
		return Result{Error: fmt.Errorf("host required"), ExitCode: 1}
	}
	if cfg.Port == 0 {
		if cfg.UseHTTPS {
			cfg.Port = 5986
		} else {
			cfg.Port = 5985
		}
	}

	endpoint := winrm.NewEndpoint(cfg.Host, cfg.Port, cfg.UseHTTPS, cfg.Insecure, nil, nil, nil, 30*time.Second)

	client, err := winrm.NewClient(endpoint, cfg.Username, cfg.Password)
	if err != nil {
		return Result{Error: fmt.Errorf("winrm client: %w", err), ExitCode: 1}
	}

	// Empty command → connectivity test. Run a no-op that's universally safe.
	cmd := command
	if strings.TrimSpace(cmd) == "" {
		cmd = "$null"
	}

	ctx, cancel := context.WithTimeout(context.Background(), winrmExecTimeout)
	defer cancel()

	stdout, stderr, exitCode, err := client.RunPSWithContext(ctx, cmd)
	if err != nil {
		combined := strings.TrimSpace(stdout + stderr)
		return Result{
			Output:   combined,
			Error:    fmt.Errorf("winrm exec: %w", err),
			ExitCode: 1,
		}
	}

	out := stdout
	if errText := strings.TrimSpace(stderr); errText != "" {
		// Surface stderr when present — PowerShell writes non-fatal output there.
		out = out + "\n" + errText
	}
	return Result{Output: out, ExitCode: exitCode}
}
