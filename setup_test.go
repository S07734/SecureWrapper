package main

import (
	"fmt"
	"os"
	"testing"
)

func TestVaultCreateAndOpen(t *testing.T) {
	os.RemoveAll(vaultPath())

	passphrase := "test-passphrase-123"

	// Create vault
	vault, err := CreateVault(passphrase)
	if err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	// Add test connections
	vault.AddConnection(Connection{
		Name:     "test-ssh",
		Type:     ConnSSHPassword,
		Host:     "localhost",
		Port:     22,
		Username: "testuser",
		Password: "testpass",
	})

	vault.AddConnection(Connection{
		Name:     "test-api",
		Type:     ConnAPI,
		BaseURL:  "https://api.example.com",
		AuthType: "key",
		AuthHeader: "X-API-KEY",
		AuthValue: "secret-key-123",
		Insecure: true,
	})

	// Save before adding auth key (connections must be in vault)
	if err := vault.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Add an auth key (this encrypts current connections with the auth key)
	authKey, err := vault.AddAuthKey("test-key")
	if err != nil {
		t.Fatalf("AddAuthKey failed: %v", err)
	}
	fmt.Printf("Generated test auth key: %s\n", authKey)

	// Save again (writes auth key vault entry)
	if err := vault.Save(); err != nil {
		t.Fatalf("Save with auth key failed: %v", err)
	}

	// Test 1: Reopen with passphrase (full access)
	vault2, err := OpenVault(passphrase)
	if err != nil {
		t.Fatalf("OpenVault failed: %v", err)
	}

	conns := vault2.ListConnections()
	if len(conns) != 2 {
		t.Fatalf("Expected 2 connections, got %d", len(conns))
	}

	ssh := vault2.GetConnection("test-ssh")
	if ssh == nil || ssh.Password != "testpass" {
		t.Fatalf("SSH connection not recovered correctly")
	}

	// Test 2: Open with auth key (connection access only)
	vault3, err := OpenVaultWithAuthKey(authKey)
	if err != nil {
		t.Fatalf("OpenVaultWithAuthKey failed: %v", err)
	}

	conns3 := vault3.ListConnections()
	if len(conns3) != 2 {
		t.Fatalf("Auth key vault: expected 2 connections, got %d", len(conns3))
	}

	ssh3 := vault3.GetConnection("test-ssh")
	if ssh3 == nil || ssh3.Password != "testpass" {
		t.Fatalf("Auth key vault: SSH connection not recovered correctly")
	}

	api3 := vault3.GetConnection("test-api")
	if api3 == nil || api3.AuthValue != "secret-key-123" {
		t.Fatalf("Auth key vault: API connection not recovered correctly")
	}

	// Test 3: Wrong auth key fails
	_, err = OpenVaultWithAuthKey("swk_wrongkey")
	if err == nil {
		t.Fatalf("Should fail with wrong auth key")
	}

	// Test 4: Wrong passphrase fails
	_, err = OpenVault("wrong-passphrase")
	if err == nil {
		t.Fatalf("Should fail with wrong passphrase")
	}

	// Test 5: Revoke auth key
	vault2.RevokeAuthKey("test-key")
	if err := vault2.Save(); err != nil {
		t.Fatalf("Save after revoke failed: %v", err)
	}

	_, err = OpenVaultWithAuthKey(authKey)
	if err == nil {
		t.Fatalf("Revoked auth key should not open vault")
	}

	// Clean up
	os.RemoveAll(vaultPath())
	fmt.Println("All tests passed.")
}
