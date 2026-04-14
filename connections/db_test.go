package connections

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildDSN_Postgres(t *testing.T) {
	dsn, err := BuildDSN(DBConfig{
		Driver: "postgres", Host: "db.example.com", Port: 5432,
		Username: "admin", Password: "p@ss word", Database: "appdb",
		SSLMode: "require",
	})
	if err != nil {
		t.Fatalf("BuildDSN: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	if u.Scheme != "postgres" {
		t.Errorf("scheme = %q, want postgres", u.Scheme)
	}
	if u.Host != "db.example.com:5432" {
		t.Errorf("host = %q", u.Host)
	}
	if pass, _ := u.User.Password(); pass != "p@ss word" {
		t.Errorf("password lost in DSN: %q", pass)
	}
	if u.Path != "/appdb" {
		t.Errorf("database path = %q", u.Path)
	}
	if u.Query().Get("sslmode") != "require" {
		t.Errorf("sslmode = %q", u.Query().Get("sslmode"))
	}
}

func TestBuildDSN_PostgresDefaultSSL(t *testing.T) {
	dsn, err := BuildDSN(DBConfig{
		Driver: "postgres", Host: "db", Port: 5432, Username: "u", Password: "p",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(dsn)
	if u.Query().Get("sslmode") != "require" {
		t.Errorf("default sslmode should be require, got %q", u.Query().Get("sslmode"))
	}
}

func TestBuildDSN_MySQL(t *testing.T) {
	dsn, err := BuildDSN(DBConfig{
		Driver: "mysql", Host: "10.0.0.1", Port: 3306,
		Username: "root", Password: "secret", Database: "logs",
	})
	if err != nil {
		t.Fatalf("BuildDSN: %v", err)
	}
	if !strings.HasPrefix(dsn, "root:secret@tcp(10.0.0.1:3306)/logs?") {
		t.Errorf("mysql dsn shape unexpected: %s", dsn)
	}
	if !strings.Contains(dsn, "parseTime=true") {
		t.Error("parseTime missing")
	}
}

func TestBuildDSN_MSSQL(t *testing.T) {
	dsn, err := BuildDSN(DBConfig{
		Driver: "sqlserver", Host: "sql.example.com", Port: 1433,
		Username: "sa", Password: "hunter2", Database: "master",
		SSLMode: "true",
	})
	if err != nil {
		t.Fatalf("BuildDSN: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Scheme != "sqlserver" {
		t.Errorf("scheme: %q", u.Scheme)
	}
	if u.Query().Get("database") != "master" {
		t.Errorf("database: %q", u.Query().Get("database"))
	}
	if u.Query().Get("encrypt") != "true" {
		t.Errorf("encrypt: %q", u.Query().Get("encrypt"))
	}
}

func TestBuildDSN_DefaultPort(t *testing.T) {
	tests := []struct {
		driver   string
		wantPort string
	}{
		{"postgres", "5432"},
		{"mysql", "3306"},
		{"sqlserver", "1433"},
	}
	for _, tc := range tests {
		dsn, err := BuildDSN(DBConfig{Driver: tc.driver, Host: "h", Username: "u", Password: "p"})
		if err != nil {
			t.Errorf("%s: %v", tc.driver, err)
			continue
		}
		if !strings.Contains(dsn, ":"+tc.wantPort) {
			t.Errorf("%s DSN missing default port %s: %s", tc.driver, tc.wantPort, dsn)
		}
	}
}

func TestBuildDSN_UnknownDriver(t *testing.T) {
	if _, err := BuildDSN(DBConfig{Driver: "oracle", Host: "h"}); err == nil {
		t.Fatal("expected error for unknown driver")
	}
}

func TestBuildDSN_MissingHost(t *testing.T) {
	if _, err := BuildDSN(DBConfig{Driver: "postgres"}); err == nil {
		t.Fatal("expected error when host is empty")
	}
}

func TestSanitizeCell(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"hello", "hello"},
		{"line1\nline2", "line1 line2"},
		{"col\tA\tcol\tB", "col A col B"},
		{"carriage\rreturn", "carriage return"},
		{"mixed\r\n\tstuff", "mixed   stuff"},
	}
	for _, tc := range tests {
		got := sanitizeCell(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeCell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFormatValue(t *testing.T) {
	if got := formatValue(nil); got != "" {
		t.Errorf("nil: got %q, want empty", got)
	}
	if got := formatValue([]byte("hello")); got != "hello" {
		t.Errorf("[]byte: got %q", got)
	}
	if got := formatValue(42); got != "42" {
		t.Errorf("int: got %q", got)
	}
}
