package main

import "testing"

func TestDBDriverForType(t *testing.T) {
	cases := []struct {
		in   ConnectionType
		want string
	}{
		{ConnDBPostgres, "postgres"},
		{ConnDBMySQL, "mysql"},
		{ConnDBMSSQL, "sqlserver"},
		{ConnSSHPassword, ""},
		{ConnAPI, ""},
		{ConnWinRM, ""},
	}
	for _, tc := range cases {
		got := dbDriverForType(tc.in)
		if got != tc.want {
			t.Errorf("dbDriverForType(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDefaultPortForType(t *testing.T) {
	cases := []struct {
		ct       ConnectionType
		useHTTPS bool
		want     int
	}{
		{ConnSSHPassword, false, 22},
		{ConnSSHKey, false, 22},
		{ConnFTP, false, 22},
		{ConnDBPostgres, false, 5432},
		{ConnDBMySQL, false, 3306},
		{ConnDBMSSQL, false, 1433},
		{ConnWinRM, false, 5985},
		{ConnWinRM, true, 5986},
		{ConnAPI, false, 0},
	}
	for _, tc := range cases {
		got := defaultPortForType(tc.ct, tc.useHTTPS)
		if got != tc.want {
			t.Errorf("defaultPortForType(%s, https=%v) = %d, want %d", tc.ct, tc.useHTTPS, got, tc.want)
		}
	}
}

func TestDefaultSSLModeForType(t *testing.T) {
	if got := defaultSSLModeForType(ConnDBPostgres); got != "require" {
		t.Errorf("postgres default ssl mode = %q, want require", got)
	}
	if got := defaultSSLModeForType(ConnDBMySQL); got != "preferred" {
		t.Errorf("mysql default ssl mode = %q, want preferred", got)
	}
	if got := defaultSSLModeForType(ConnDBMSSQL); got != "true" {
		t.Errorf("mssql default ssl mode = %q, want true", got)
	}
	if got := defaultSSLModeForType(ConnSSHPassword); got != "" {
		t.Errorf("non-db type should return empty, got %q", got)
	}
}

func TestConnectionTypeLabel_New(t *testing.T) {
	cases := []struct {
		in   ConnectionType
		want string
	}{
		{ConnDBPostgres, "Database (PostgreSQL)"},
		{ConnDBMySQL, "Database (MySQL/MariaDB)"},
		{ConnDBMSSQL, "Database (SQL Server)"},
		{ConnWinRM, "WinRM / PowerShell"},
	}
	for _, tc := range cases {
		got := connectionTypeLabel(tc.in)
		if got != tc.want {
			t.Errorf("label(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
