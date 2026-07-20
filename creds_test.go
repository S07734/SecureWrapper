package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildCredsJSON_DeniedByDefault(t *testing.T) {
	conn := Connection{Name: "svc", Type: ConnSSHPassword, Host: "h", Port: 22, Username: "u", Password: "s3cr3t-pw"}
	out, err := buildCredsJSON(conn)
	if err == nil {
		t.Fatal("expected --creds to be denied when AllowCreds is false")
	}
	if out != "" {
		t.Fatalf("expected empty output on denial, got %q", out)
	}
	if strings.Contains(err.Error(), "s3cr3t-pw") {
		t.Fatalf("error message must not leak the password: %v", err)
	}
}

func TestBuildCredsJSON_AllowedWhenEnabled(t *testing.T) {
	conn := Connection{Name: "svc", Type: ConnSSHPassword, Host: "h", Port: 22, Username: "u", Password: "s3cr3t-pw", AllowCreds: true}
	out, err := buildCredsJSON(conn)
	if err != nil {
		t.Fatalf("expected success when AllowCreds true: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if m["password"] != "s3cr3t-pw" {
		t.Fatalf("password missing from creds output: %v", m)
	}
	if m["name"] != "svc" || m["type"] != string(ConnSSHPassword) {
		t.Fatalf("metadata missing/wrong: %v", m)
	}
}

// Every connection type must be gated — no type is exempt from the default-off
// policy.
func TestBuildCredsJSON_AllTypesGatedByDefault(t *testing.T) {
	types := []ConnectionType{
		ConnSSHPassword, ConnSSHKey, ConnAPI, ConnFTP,
		ConnDBPostgres, ConnDBMySQL, ConnDBMSSQL, ConnWinRM,
	}
	for _, ct := range types {
		if _, err := buildCredsJSON(Connection{Name: "x", Type: ct}); err == nil {
			t.Fatalf("%s: --creds must be denied by default", ct)
		}
		if _, err := buildCredsJSON(Connection{Name: "x", Type: ct, AllowCreds: true}); err != nil {
			t.Fatalf("%s: --creds should succeed when enabled: %v", ct, err)
		}
	}
}

// Existing vaults have no allow_creds field; it must decode to false (secure
// default) and a false value must not be serialized back (omitempty).
func TestAllowCreds_OmitEmptyLegacyDefaultsDisabled(t *testing.T) {
	raw := `{"name":"legacy","type":"ssh-password","host":"h","port":22,"username":"u","password":"p"}`
	var conn Connection
	if err := json.Unmarshal([]byte(raw), &conn); err != nil {
		t.Fatal(err)
	}
	if conn.AllowCreds {
		t.Fatal("legacy connection without allow_creds must default to disabled")
	}
	out, _ := json.Marshal(conn)
	if strings.Contains(string(out), "allow_creds") {
		t.Fatalf("allow_creds=false should be omitted from JSON, got %s", out)
	}

	conn.AllowCreds = true
	out, _ = json.Marshal(conn)
	if !strings.Contains(string(out), `"allow_creds":true`) {
		t.Fatalf("allow_creds=true must serialize, got %s", out)
	}
}
