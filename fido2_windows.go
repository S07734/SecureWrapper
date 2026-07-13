//go:build windows

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/winhello"
	"github.com/go-ctap/winhello/hiddenwindow"
)

// winHelloProvider goes through webauthn.dll — Windows blocks raw HID
// access to FIDO devices for non-elevated processes, so the system
// WebAuthn API (with its own touch/PIN UI) is the only sane path.
// hmac-secret salt evaluation requires webauthn.dll API version 4+
// (Windows 11 22H2 or newer).
type winHelloProvider struct{}

func newPlatformFIDO2Provider() fido2Provider { return winHelloProvider{} }

func checkWinHelloVersion() error {
	if winhello.APIVersionNumber() < 4 {
		return fmt.Errorf("FIDO2 backup needs webauthn.dll API v4+ (Windows 11 22H2 or newer); this system reports v%d", winhello.APIVersionNumber())
	}
	return nil
}

func winClientData(typ string) ([]byte, error) {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":"https://%s"}`,
		typ, base64.RawURLEncoding.EncodeToString(challenge), fidoRPID)), nil
}

// hiddenHWND creates the invisible window webauthn.dll needs to anchor its
// system UI when running from a console app.
func hiddenHWND() (*hiddenwindow.HiddenWindow, error) {
	return hiddenwindow.New(slog.New(slog.DiscardHandler), fidoRPName)
}

func (winHelloProvider) Enroll(pin string) ([]byte, error) {
	if err := checkWinHelloVersion(); err != nil {
		return nil, err
	}
	win, err := hiddenHWND()
	if err != nil {
		return nil, fmt.Errorf("cannot create window for WebAuthn UI: %w", err)
	}
	defer win.Close()

	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		return nil, err
	}
	clientData, err := winClientData("webauthn.create")
	if err != nil {
		return nil, err
	}

	// PIN entry is handled by the Windows system UI — the pin argument is
	// unused here; UV requirement is left to the platform.
	resp, err := winhello.MakeCredential(
		win.WindowHandle(),
		clientData,
		webauthntypes.PublicKeyCredentialRpEntity{ID: fidoRPID, Name: fidoRPName},
		webauthntypes.PublicKeyCredentialUserEntity{ID: userID, Name: "vault-backup", DisplayName: "SecureWrapper vault backup"},
		[]webauthntypes.PublicKeyCredentialParameters{
			{Type: webauthntypes.PublicKeyCredentialTypePublicKey, Algorithm: -7},
			{Type: webauthntypes.PublicKeyCredentialTypePublicKey, Algorithm: -257},
		},
		nil,
		&webauthntypes.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretInputs: &webauthntypes.CreateHMACSecretInputs{HMACCreateSecret: true},
		},
		&winhello.AuthenticatorMakeCredentialOptions{
			AuthenticatorAttachment: winhello.WinHelloAuthenticatorAttachmentCrossPlatform,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("credential creation failed: %w", err)
	}
	return resp.CredentialID, nil
}

func (winHelloProvider) Secret(credID, salt []byte, pin string) ([]byte, bool, error) {
	if err := checkWinHelloVersion(); err != nil {
		return nil, false, err
	}
	win, err := hiddenHWND()
	if err != nil {
		return nil, false, fmt.Errorf("cannot create window for WebAuthn UI: %w", err)
	}
	defer win.Close()

	clientData, err := winClientData("webauthn.get")
	if err != nil {
		return nil, false, err
	}

	resp, err := winhello.GetAssertion(
		win.WindowHandle(),
		fidoRPID,
		clientData,
		[]webauthntypes.PublicKeyCredentialDescriptor{
			{Type: webauthntypes.PublicKeyCredentialTypePublicKey, ID: credID},
		},
		&webauthntypes.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthntypes.GetHMACSecretInputs{
				HMACGetSecret: webauthntypes.HMACGetSecretInput{Salt1: salt},
			},
		},
		nil,
	)
	if err != nil {
		return nil, false, fmt.Errorf("assertion failed: %w", err)
	}
	if resp.ExtensionOutputs == nil || resp.ExtensionOutputs.GetHMACSecretOutputs == nil {
		return nil, false, fmt.Errorf("authenticator did not return an hmac-secret output")
	}
	uv := resp.AuthData != nil && byte(resp.AuthData.Flags)&0x04 != 0
	return resp.ExtensionOutputs.GetHMACSecretOutputs.HMACGetSecret.Output1, uv, nil
}
