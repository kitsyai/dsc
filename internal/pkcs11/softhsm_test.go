//go:build !windows

package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kitsyai/dsc/internal/keystore"
)

const softhsmLib = "/usr/lib/softhsm/libsofthsm2.so"

type fakePrompt struct {
	pin     string
	allow   bool
	consent keystore.Consent
	calls   int
}

func (f *fakePrompt) Confirm(c keystore.Consent) (bool, error) {
	f.calls++
	f.consent = c
	return f.allow, nil
}

func (f *fakePrompt) ConfirmWithPIN(c keystore.Consent) (string, bool, error) {
	f.calls++
	f.consent = c
	return f.pin, f.allow, nil
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// softToken creates a SoftHSM token holding an RSA key and its certificate.
func softToken(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	if _, err := os.Stat(softhsmLib); err != nil {
		t.Skip("SoftHSM2 not installed")
	}
	for _, tool := range []string{"softhsm2-util", "pkcs11-tool"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	dir := t.TempDir()
	tokens := filepath.Join(dir, "tokens")
	os.Mkdir(tokens, 0o700)
	conf := filepath.Join(dir, "softhsm2.conf")
	os.WriteFile(conf, []byte("directories.tokendir = "+tokens+"\nobjectstore.backend = file\n"), 0o600)
	t.Setenv("SOFTHSM2_CONF", conf)

	run(t, "softhsm2-util", "--init-token", "--free", "--label", "TestToken", "--pin", "1234", "--so-pin", "5678")

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Asha Verma", Organization: []string{"Kitsy Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	os.WriteFile(filepath.Join(dir, "cert.der"), der, 0o600)
	os.WriteFile(filepath.Join(dir, "key.der"), keyDER, 0o600)

	base := []string{"--module", softhsmLib, "--token-label", "TestToken", "--login", "--pin", "1234"}
	run(t, "pkcs11-tool", append(base, "--write-object", filepath.Join(dir, "key.der"), "--type", "privkey", "--id", "a1b2", "--label", "signing key")...)
	run(t, "pkcs11-tool", append(base, "--write-object", filepath.Join(dir, "cert.der"), "--type", "cert", "--id", "a1b2", "--label", "signing cert")...)
	return cert, key
}

func TestSoftHSMListAndSign(t *testing.T) {
	cert, key := softToken(t)
	prompt := &fakePrompt{pin: "1234", allow: true}
	store := New([]string{softhsmLib}, nil, prompt)
	defer store.Close()

	certs, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].ID != keystore.ID(cert.Raw) || certs[0].Label != "TestToken" || certs[0].Source != "pkcs11" {
		t.Fatalf("unexpected list %+v", certs)
	}
	if prompt.calls != 0 {
		t.Fatal("listing must not prompt")
	}

	digest := sha256.Sum256([]byte("signed attributes"))
	sig, err := store.Sign(certs[0].ID, digest[:], keystore.Consent{Origin: "https://prashantsinha.com", Document: "contract.pdf"})
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if prompt.calls != 1 || prompt.consent.Signer != "Asha Verma" || prompt.consent.Token != "TestToken" || prompt.consent.Document != "contract.pdf" {
		t.Fatalf("consent dialog got %+v", prompt.consent)
	}
}

func TestSoftHSMDeclineAndWrongPIN(t *testing.T) {
	cert, _ := softToken(t)
	digest := sha256.Sum256([]byte("x"))

	declined := New([]string{softhsmLib}, nil, &fakePrompt{pin: "1234", allow: false})
	defer declined.Close()
	if _, err := declined.Sign(keystore.ID(cert.Raw), digest[:], keystore.Consent{}); !errors.Is(err, keystore.ErrDeclined) {
		t.Fatalf("decline: %v", err)
	}

	wrong := New([]string{softhsmLib}, nil, &fakePrompt{pin: "0000", allow: true})
	defer wrong.Close()
	if _, err := wrong.Sign(keystore.ID(cert.Raw), digest[:], keystore.Consent{}); !errors.Is(err, keystore.ErrPINIncorrect) {
		t.Fatalf("wrong PIN: %v", err)
	}
	if _, err := wrong.Sign("deadbeef", digest[:], keystore.Consent{}); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestMissingExplicitModule(t *testing.T) {
	s := New([]string{"/nonexistent/driver.so"}, nil, &fakePrompt{})
	if _, err := s.List(); err == nil {
		t.Fatal("an explicit missing driver must be an error")
	}
	quiet := New(nil, []string{"/nonexistent/driver.so"}, &fakePrompt{})
	if certs, err := quiet.List(); err != nil || len(certs) != 0 {
		t.Fatalf("missing default drivers are skipped: %v %v", certs, err)
	}
}
