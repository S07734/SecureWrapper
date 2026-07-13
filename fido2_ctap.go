//go:build linux || darwin

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/discover"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/webauthn"
)

// ctapProvider talks CTAP2 directly over USB HID: hidraw on Linux,
// IOHIDManager (via purego, no cgo) on macOS. No elevated privileges
// needed on either platform for FIDO usage-page devices.
type ctapProvider struct{}

func newPlatformFIDO2Provider() fido2Provider { return ctapProvider{} }

// openFIDO2Device enumerates connected authenticators, opens one (touch
// selects when several are plugged in), and verifies hmac-secret support.
func openFIDO2Device() (*authenticator.Device, error) {
	devs, err := discover.EnumerateFIDODevices()
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate security keys: %w", err)
	}
	if len(devs) == 0 {
		return nil, fmt.Errorf("no FIDO2 security key found — plug one in and try again")
	}
	dev, err := discover.SelectDevice()
	if err != nil {
		return nil, fmt.Errorf("cannot open security key: %w", err)
	}
	if !slices.Contains(dev.GetInfo().Extensions, extension.ExtensionIdentifierHMACSecret) {
		dev.Close()
		return nil, fmt.Errorf("this security key does not support the hmac-secret extension (FIDO2/CTAP2 required, U2F-only keys won't work)")
	}
	return dev, nil
}

// fidoClientData builds a minimal WebAuthn-shaped clientDataJSON. Only its
// SHA-256 reaches the authenticator and nothing ever verifies it — but a
// fresh random challenge keeps every signature unique.
func fidoClientData(typ string) ([]byte, error) {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":"https://%s"}`,
		typ, base64.RawURLEncoding.EncodeToString(challenge), fidoRPID)), nil
}

// mapPINError converts the library's PIN-demand errors into the sentinel
// the TUI understands.
func mapPINError(err error, pin string) error {
	if pin != "" {
		return err
	}
	if errors.Is(err, authenticator.ErrPinUvAuthTokenRequired) ||
		strings.Contains(strings.ToLower(err.Error()), "pin") {
		return errFIDO2PINRequired
	}
	return err
}

func (ctapProvider) Enroll(pin string) ([]byte, error) {
	dev, err := openFIDO2Device()
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	var token []byte
	if pin != "" {
		token, err = dev.GetPinUvAuthTokenUsingPIN(pin, protocol.PermissionMakeCredential, fidoRPID)
		if err != nil {
			return nil, fmt.Errorf("security key PIN rejected: %w", err)
		}
	}

	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		return nil, err
	}
	clientData, err := fidoClientData("webauthn.create")
	if err != nil {
		return nil, err
	}

	resp, err := dev.MakeCredential(
		token,
		clientData,
		credential.PublicKeyCredentialRpEntity{ID: fidoRPID, Name: fidoRPName},
		credential.PublicKeyCredentialUserEntity{ID: userID, Name: "vault-backup", DisplayName: "SecureWrapper vault backup"},
		[]credential.PublicKeyCredentialParameters{
			{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: -7},   // ES256
			{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: -8},   // EdDSA
			{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: -257}, // RS256
		},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretInputs: &webauthn.CreateHMACSecretInputs{HMACCreateSecret: true},
		},
		nil, 0, nil,
	)
	if err != nil {
		return nil, mapPINError(err, pin)
	}
	if resp.AuthData == nil || resp.AuthData.AttestedCredentialData == nil {
		return nil, fmt.Errorf("authenticator returned no credential data")
	}
	return resp.AuthData.AttestedCredentialData.CredentialID, nil
}

func (ctapProvider) Secret(credID, salt []byte, pin string) ([]byte, bool, error) {
	dev, err := openFIDO2Device()
	if err != nil {
		return nil, false, err
	}
	defer dev.Close()

	var token []byte
	if pin != "" {
		token, err = dev.GetPinUvAuthTokenUsingPIN(pin, protocol.PermissionGetAssertion, fidoRPID)
		if err != nil {
			return nil, false, fmt.Errorf("security key PIN rejected: %w", err)
		}
	}

	clientData, err := fidoClientData("webauthn.get")
	if err != nil {
		return nil, false, err
	}

	for resp, err := range dev.GetAssertion(
		token,
		fidoRPID,
		clientData,
		[]credential.PublicKeyCredentialDescriptor{
			{Type: credential.PublicKeyCredentialTypePublicKey, ID: credID},
		},
		&webauthn.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: salt},
			},
		},
		nil,
	) {
		if err != nil {
			return nil, false, mapPINError(err, pin)
		}
		if resp.ExtensionOutputs == nil || resp.ExtensionOutputs.GetHMACSecretOutputs == nil {
			return nil, false, fmt.Errorf("authenticator did not return an hmac-secret output")
		}
		uv := resp.AuthData != nil && resp.AuthData.Flags&protocol.AuthDataFlag(0x04) != 0
		return resp.ExtensionOutputs.GetHMACSecretOutputs.HMACGetSecret.Output1, uv, nil
	}
	return nil, false, fmt.Errorf("security key returned no assertion (credential not found on this key?)")
}
