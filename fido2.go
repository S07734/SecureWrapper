package main

import "errors"

// FIDO2-protected backups derive their encryption key from BOTH a password
// and the hmac-secret output of a hardware security key (YubiKey or any
// CTAP2 authenticator with the hmac-secret extension). Decrypting requires
// the backup file + the password + a physical touch of the enrolled key —
// a true 2-of-2 factor split, following the systemd-cryptenroll /
// age-plugin-fido2-hmac pattern.
//
// The credential is non-resident (rk=false): the key material is wrapped
// inside the credential ID stored in the backup header, so nothing is
// consumed on the authenticator and any number of backups can be made.

const (
	fidoRPID   = "securewrapper.local"
	fidoRPName = "SecureWrapper"
)

// errFIDO2PINRequired signals that the authenticator demands its client PIN
// (PIN set + policy, or alwaysUV) and none was provided — the TUI prompts
// and retries.
var errFIDO2PINRequired = errors.New("security key requires its PIN")

// fido2Provider abstracts the platform FIDO2 stack. Implementations:
// fido2_ctap.go (Linux/macOS — raw CTAP2 over HID, pure Go) and
// fido2_windows.go (webauthn.dll — raw HID is admin-only on Windows).
// Tests substitute a deterministic fake that mirrors authenticator
// behavior (HMAC-SHA256 of a per-credential secret over the salt).
type fido2Provider interface {
	// Enroll creates a fresh non-resident credential with the hmac-secret
	// extension enabled and returns its credential ID. Requires a user
	// presence touch on the key.
	Enroll(pin string) ([]byte, error)

	// Secret performs a GetAssertion with the hmac-secret extension and
	// returns the authenticator's 32-byte HMAC output for salt, plus
	// whether user verification was performed. The authenticator keeps
	// separate CredRandom values for UV and non-UV assertions, so restore
	// must replicate the UV state recorded at backup time.
	Secret(credID, salt []byte, pin string) (out []byte, uv bool, err error)
}

// newFIDO2Provider returns the platform implementation. Var so tests can
// swap in a fake without hardware.
var newFIDO2Provider = newPlatformFIDO2Provider
