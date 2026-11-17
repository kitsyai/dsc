//go:build !windows

package pkcs11

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kitsyai/dsc/internal/keystore"
)

// Diagnose prints which drivers load, what each token supports and holds,
// then makes one test signature per mechanism (one PIN prompt) and verifies
// each. Nothing is saved. It is what `dsc diagnose` runs.
func (s *Store) Diagnose(w io.Writer) error {
	fmt.Fprintln(w, "Drivers:")
	for _, p := range s.paths {
		state := "not present"
		if _, err := os.Stat(p); err == nil {
			state = "present"
		}
		fmt.Fprintf(w, "  %-60s %s\n", p, state)
	}
	certs, err := s.List()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "\nTokens:")
	s.onThread(func() {
		for path, l := range s.libs {
			slots, err := l.slots()
			if err != nil {
				fmt.Fprintf(w, "  %s: %v\n", path, err)
				continue
			}
			fmt.Fprintf(w, "  %s: %d token(s)\n", path, len(slots))
			for _, slot := range slots {
				info, _ := l.tokenInfo(slot)
				mechs, merr := l.mechanisms(slot)
				var names []string
				others := 0
				for _, m := range mechs {
					if _, known := mechNames[m]; known {
						names = append(names, mechName(m))
					} else {
						others++
					}
				}
				if others > 0 {
					names = append(names, fmt.Sprintf("(+%d others)", others))
				}
				fmt.Fprintf(w, "    slot %d: %q serial %q flags 0x%X (PIN pad: %v)\n", slot, info.label, info.serial, info.flags, info.flags&ckfProtectedAuthPath != 0)
				if merr != nil {
					fmt.Fprintf(w, "      mechanisms: %v\n", merr)
				} else {
					fmt.Fprintf(w, "      mechanisms: %s\n", strings.Join(names, ", "))
				}
			}
		}
	})
	if len(certs) == 0 {
		fmt.Fprintln(w, "\nNo signing certificate found. Is the token plugged in, and its driver listed above as present?")
		return nil
	}
	fmt.Fprintln(w, "\nCertificates:")
	for _, c := range certs {
		ref := s.refs[c.ID]
		fmt.Fprintf(w, "  %s  %s (issued by %s)\n", c.ID[:12], ref.cert.Subject.CommonName, ref.cert.Issuer.CommonName)
	}

	ref := s.refs[certs[0].ID]
	pub, ok := ref.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return keystore.ErrUnsupportedKey
	}
	fmt.Fprintf(w, "\nTest signature with %s (one PIN prompt; nothing is saved):\n", ref.cert.Subject.CommonName)
	consent := keystore.Consent{
		Origin:   "dsc diagnose (a test you started in a terminal)",
		Document: "a test message; nothing is saved",
		Signer:   ref.cert.Subject.CommonName,
		Token:    ref.token.label,
	}
	pinPad := ref.token.flags&ckfProtectedAuthPath != 0
	var pin string
	if pinPad {
		ok, err := s.prompt.Confirm(consent)
		if err != nil || !ok {
			fmt.Fprintln(w, "  skipped (cancelled)")
			return err
		}
	} else {
		p, ok, err := s.prompt.ConfirmWithPIN(consent)
		if err != nil || !ok {
			fmt.Fprintln(w, "  skipped (cancelled)")
			return err
		}
		pin = p
	}
	data := []byte("dsc diagnose test message")
	sum := sha256.Sum256(data)
	pinBytes := []byte(pin)
	defer func() {
		for i := range pinBytes {
			pinBytes[i] = 0
		}
	}()
	for _, a := range signAttempts(nil, data) {
		var sig []byte
		var err error
		s.onThread(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			sig, err = s.signOnce(ref, pinPad, pinBytes, a)
		})
		switch {
		case err != nil:
			fmt.Fprintf(w, "  %-22s failed: %v\n", mechName(a.mech), err)
			if !retryable(err) {
				return nil // PIN errors: stop, don't risk locking the token
			}
		case rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil:
			fmt.Fprintf(w, "  %-22s signed, but the signature does not verify\n", mechName(a.mech))
		default:
			fmt.Fprintf(w, "  %-22s OK (signature verified)\n", mechName(a.mech))
		}
	}
	return nil
}
