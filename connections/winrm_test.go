package connections

import (
	"testing"
)

func TestExecuteWinRM_MissingHost(t *testing.T) {
	r := ExecuteWinRM(WinRMConfig{Username: "u", Password: "p"}, "whoami")
	if r.Error == nil {
		t.Fatal("expected error when host missing")
	}
	if r.ExitCode != 1 {
		t.Errorf("exit code = %d, want 1", r.ExitCode)
	}
}

// ExecuteWinRM against an unreachable host should fail cleanly rather than
// hang. We use a blackhole address on a random high port and rely on the
// endpoint timeout baked into the client.
func TestExecuteWinRM_UnreachableHost(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	// 203.0.113.0/24 is TEST-NET-3 — guaranteed not to route anywhere.
	r := ExecuteWinRM(WinRMConfig{
		Host: "203.0.113.1", Port: 65432, Username: "u", Password: "p",
	}, "whoami")
	if r.Error == nil {
		t.Fatal("expected error on unroutable host")
	}
}
