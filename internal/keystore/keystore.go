// Package keystore defines what a signing back end (the Windows certificate
// store, a PKCS#11 token driver) must provide, and the errors the HTTP layer
// maps to responses.
package keystore

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
)

// Certificate is a signing certificate whose private key lives on a token or
// in the OS key store. The key itself never leaves that place.
type Certificate struct {
	// ID is the SHA-1 thumbprint of DER, lowercase hex. Stable across runs.
	ID string
	// DER is the X.509 certificate.
	DER []byte
	// Label is a human-readable name for where the key lives (token label,
	// "Windows certificate store").
	Label string
	// Source is "windows" or "pkcs11".
	Source string
}

// Consent is what the user is shown before a signature is made.
type Consent struct {
	// Origin is the web page asking for the signature, e.g.
	// "https://prashantsinha.com". Empty means a local program.
	Origin string
	// Document is the file name the page says it is signing.
	Document string
	// Signer is the certificate holder's name.
	Signer string
	// Token is where the key lives (token label).
	Token string
}

// Prompter shows native dialogs. Implementations live in internal/prompt.
type Prompter interface {
	// Confirm asks the user to allow one signature. Used where the key
	// store asks for the PIN itself (Windows token drivers, PIN pads).
	Confirm(c Consent) (bool, error)
	// ConfirmWithPIN asks the user to allow one signature by entering the
	// token PIN. ok is false when the user cancelled.
	ConfirmWithPIN(c Consent) (pin string, ok bool, err error)
}

// Store is a signing back end.
type Store interface {
	// List returns the signing certificates currently available. It must not
	// trigger PIN prompts.
	List() ([]Certificate, error)
	// Sign produces an RSA PKCS#1 v1.5 signature over a SHA-256 digest with
	// the key of the certificate id, after the user agreed to consent.
	Sign(id string, sha256Digest []byte, consent Consent) ([]byte, error)
	Close() error
}

var (
	ErrDeclined        = errors.New("the user declined the signature")
	ErrNotFound        = errors.New("certificate not found; is the token plugged in?")
	ErrPINIncorrect    = errors.New("incorrect PIN")
	ErrPINLocked       = errors.New("the token PIN is locked")
	ErrUnsupportedKey  = errors.New("only RSA keys are supported")
	ErrNoDialogProgram = errors.New("no dialog program found to ask for consent (install zenity or kdialog)")
)

// ID returns the thumbprint used as a certificate's ID.
func ID(der []byte) string {
	sum := sha1.Sum(der)
	return hex.EncodeToString(sum[:])
}

// SHA256DigestInfo is the DER DigestInfo prefix for a SHA-256 hash, for keys
// that sign raw PKCS#1 v1.5 blocks (CKM_RSA_PKCS).
var SHA256DigestInfo = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
