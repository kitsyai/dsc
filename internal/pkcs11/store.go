//go:build !windows

package pkcs11

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/kitsyai/dsc/internal/keystore"
)

// DefaultModules lists where common token drivers install their PKCS#11
// library. Missing paths are skipped; add others with --pkcs11 or
// DSC_PKCS11_MODULES. Vendor paths vary by driver version, so this list is a
// convenience, not a guarantee.
func DefaultModules() []string {
	if runtime.GOOS == "darwin" {
		return []string{
			"/usr/local/lib/libcastle.1.0.0.dylib",                                  // ePass2003 (Longmai/Castle)
			"/usr/local/lib/libcastle.dylib",                                        // ePass2003
			"/usr/local/lib/WatchData/ProxKey/libwdpkcs_SignatureP11.dylib",         // ProxKey (WatchData)
			"/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib", // SafeNet eToken
			"/usr/local/lib/libeTPkcs11.dylib",                                      // SafeNet
			"/Library/OpenSC/lib/opensc-pkcs11.so",                                  // OpenSC
		}
	}
	return []string{
		"/usr/lib/libcastle.so.1.0.0",                              // ePass2003
		"/usr/lib/WatchData/ProxKey/lib/libwdpkcs_SignatureP11.so", // ProxKey (WatchData)
		"/usr/lib/libwdpkcs_SignatureP11.so",                       // ProxKey
		"/usr/lib/libeToken.so",                                    // SafeNet eToken
		"/usr/lib/libeTPkcs11.so",                                  // SafeNet
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",               // OpenSC (Debian/Ubuntu)
		"/usr/lib64/opensc-pkcs11.so",                              // OpenSC (Fedora)
		"/usr/lib/opensc-pkcs11.so",                                // OpenSC
	}
}

// ModulesFromEnv splits DSC_PKCS11_MODULES (OS path-list separated).
func ModulesFromEnv() []string {
	var out []string
	for _, p := range filepath.SplitList(os.Getenv("DSC_PKCS11_MODULES")) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type certRef struct {
	lib   *lib
	slot  ckULong
	ckaID []byte
	token tokenInfo
	cert  *x509.Certificate
}

// Store signs with keys found through PKCS#11 driver libraries.
type Store struct {
	mu       sync.Mutex
	paths    []string
	explicit map[string]bool
	libs     map[string]*lib
	refs     map[string]certRef
	prompt   keystore.Prompter
}

// New returns a store over the given driver paths. Paths in explicit must
// load; the others (defaults) are skipped when absent.
func New(explicit, defaults []string, prompt keystore.Prompter) *Store {
	s := &Store{explicit: map[string]bool{}, libs: map[string]*lib{}, refs: map[string]certRef{}, prompt: prompt}
	seen := map[string]bool{}
	for _, p := range append(append([]string{}, explicit...), defaults...) {
		if !seen[p] {
			seen[p] = true
			s.paths = append(s.paths, p)
		}
	}
	for _, p := range explicit {
		s.explicit[p] = true
	}
	return s
}

func (s *Store) loadAll() ([]*lib, error) {
	var out []*lib
	for _, p := range s.paths {
		if l, ok := s.libs[p]; ok {
			out = append(out, l)
			continue
		}
		if _, err := os.Stat(p); err != nil {
			if s.explicit[p] {
				return nil, fmt.Errorf("PKCS#11 library %s: %w", p, err)
			}
			continue
		}
		l, err := load(p)
		if err != nil {
			if s.explicit[p] {
				return nil, err
			}
			continue
		}
		s.libs[p] = l
		out = append(out, l)
	}
	return out, nil
}

// List reads certificates from every present token. Certificates are public
// objects, so no PIN is needed.
func (s *Store) List() ([]keystore.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	libs, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	refs := map[string]certRef{}
	var out []keystore.Certificate
	for _, l := range libs {
		slots, err := l.slots()
		if err != nil {
			continue
		}
		for _, slot := range slots {
			info, err := l.tokenInfo(slot)
			if err != nil {
				continue
			}
			session, err := l.open(slot)
			if err != nil {
				continue
			}
			class := ckULong(ckoCertificate)
			objs, _ := l.find(session, classTemplate(&class, nil))
			for _, obj := range objs {
				der, _ := l.attr(session, obj, ckaValue)
				id, _ := l.attr(session, obj, ckaID)
				if len(der) == 0 || len(id) == 0 {
					continue
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil || cert.IsCA {
					continue
				}
				key := keystore.ID(der)
				if _, dup := refs[key]; dup {
					continue
				}
				refs[key] = certRef{lib: l, slot: slot, ckaID: id, token: info, cert: cert}
				label := info.label
				if label == "" {
					label = "Token"
				}
				out = append(out, keystore.Certificate{ID: key, DER: der, Label: label, Source: "pkcs11"})
			}
			l.closeSession(session)
		}
	}
	s.refs = refs
	return out, nil
}

func pinError(err error) error {
	var e *Error
	if errors.As(err, &e) {
		switch e.RV {
		case ckrPINIncorrect, ckrPINInvalid, ckrPINLenRange:
			return keystore.ErrPINIncorrect
		case ckrPINLocked, ckrPINExpired:
			return keystore.ErrPINLocked
		case ckrTokenNotPresent, ckrDeviceRemoved:
			return keystore.ErrNotFound
		}
	}
	return err
}

// Sign asks for consent and the PIN in one native dialog (or consent only
// for PIN-pad readers), logs in, signs, and logs out again.
func (s *Store) Sign(id string, digest []byte, consent keystore.Consent) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("expected a SHA-256 digest")
	}
	s.mu.Lock()
	ref, ok := s.refs[id]
	s.mu.Unlock()
	if !ok {
		if _, err := s.List(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		ref, ok = s.refs[id]
		s.mu.Unlock()
		if !ok {
			return nil, keystore.ErrNotFound
		}
	}
	if _, isRSA := ref.cert.PublicKey.(*rsa.PublicKey); !isRSA {
		return nil, keystore.ErrUnsupportedKey
	}
	if consent.Signer == "" {
		consent.Signer = ref.cert.Subject.CommonName
	}
	consent.Token = ref.token.label

	pinPad := ref.token.flags&ckfProtectedAuthPath != 0
	var pin string
	if pinPad {
		ok, err := s.prompt.Confirm(consent)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, keystore.ErrDeclined
		}
	} else {
		p, ok, err := s.prompt.ConfirmWithPIN(consent)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, keystore.ErrDeclined
		}
		pin = p
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	l := ref.lib
	session, err := l.open(ref.slot)
	if err != nil {
		return nil, pinError(err)
	}
	defer l.closeSession(session)

	var rv ckULong
	if pinPad {
		rv = l.login(session, ckuUser, nil, 0)
	} else {
		pinBytes := []byte(pin)
		if len(pinBytes) == 0 {
			return nil, keystore.ErrPINIncorrect
		}
		rv = l.login(session, ckuUser, &pinBytes[0], ckULong(len(pinBytes)))
		for i := range pinBytes {
			pinBytes[i] = 0
		}
	}
	if rv != ckrOK && rv != ckrUserAlreadyLoggedIn {
		return nil, pinError(check("C_Login", rv))
	}
	defer l.logout(session)

	class := ckULong(ckoPrivateKey)
	keys, err := l.find(session, classTemplate(&class, ref.ckaID))
	if err != nil {
		return nil, pinError(err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no private key on the token matches this certificate")
	}
	data := append(append([]byte{}, keystore.SHA256DigestInfo...), digest...)
	sig, err := l.signRaw(session, keys[0], data)
	if err != nil {
		return nil, pinError(err)
	}
	return sig, nil
}

// Close finalizes every loaded driver.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.libs {
		l.finalize(nil)
	}
	s.libs = map[string]*lib{}
	return nil
}
