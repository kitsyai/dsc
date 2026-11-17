//go:build !windows

package pkcs11

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/kitsyai/dsc/internal/keystore"
)

// DefaultModules lists where common token drivers install their PKCS#11
// library. Entries may be glob patterns (driver file names carry versions,
// e.g. libcastle_v2.1.0.0.dylib). Missing paths are skipped; add others with
// --pkcs11 or DSC_PKCS11_MODULES. Vendor paths vary by driver version, so this
// list is a convenience, not a guarantee.
func DefaultModules() []string {
	if runtime.GOOS == "darwin" {
		return []string{
			"/usr/local/lib/libcastle_v*.dylib",                                     // ePass2003, newer drivers (e.g. libcastle_v2.1.0.0.dylib)
			"/usr/local/lib/libcastle.1.0.0.dylib",                                  // ePass2003 (Longmai/Castle)
			"/usr/local/lib/libcastle.dylib",                                        // ePass2003
			"/usr/local/lib/WatchData/ProxKey/libwdpkcs_SignatureP11.dylib",         // ProxKey (WatchData)
			"/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib", // SafeNet eToken
			"/usr/local/lib/libeTPkcs11.dylib",                                      // SafeNet
			"/Library/OpenSC/lib/opensc-pkcs11.so",                                  // OpenSC
		}
	}
	return []string{
		"/usr/lib/libcastle_v*.so*",                                // ePass2003, newer drivers
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

	// calls runs every PKCS#11 call on one locked OS thread. Smart-card
	// drivers (e.g. ePass2003 on macOS) can tie a session or login to the
	// thread that made it; Go would otherwise move work between threads.
	calls chan func()
}

// worker runs PKCS#11 calls on a single OS thread for the store's lifetime.
func (s *Store) worker() {
	runtime.LockOSThread()
	for f := range s.calls {
		f()
	}
}

// onThread runs f on the PKCS#11 thread and waits for it.
func (s *Store) onThread(f func()) {
	done := make(chan struct{})
	s.calls <- func() {
		defer close(done)
		f()
	}
	<-done
}

// New returns a store over the given driver paths. Paths in explicit must
// load; the others (defaults) are skipped when absent.
func New(explicit, defaults []string, prompt keystore.Prompter) *Store {
	s := &Store{explicit: map[string]bool{}, libs: map[string]*lib{}, refs: map[string]certRef{}, prompt: prompt, calls: make(chan func())}
	go s.worker()
	seen := map[string]bool{}
	for _, p := range append(append([]string{}, explicit...), expandDefaults(defaults)...) {
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

// expandDefaults expands glob patterns among the default driver paths, newest
// file name first, so a versioned driver (libcastle_v2.1.0.0.dylib) is found
// without configuration.
func expandDefaults(defaults []string) []string {
	var out []string
	for _, p := range defaults {
		if !strings.ContainsAny(p, "*?[") {
			out = append(out, p)
			continue
		}
		matches, _ := filepath.Glob(p)
		sort.Sort(sort.Reverse(sort.StringSlice(matches)))
		out = append(out, matches...)
	}
	return out
}

// List reads certificates from every present token. Certificates are public
// objects, so no PIN is needed.
func (s *Store) List() (certs []keystore.Certificate, err error) {
	s.onThread(func() { certs, err = s.list() })
	return certs, err
}

func (s *Store) list() ([]keystore.Certificate, error) {
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
func (s *Store) Sign(id string, data []byte, consent keystore.Consent) ([]byte, error) {
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

	var sig []byte
	var err error
	s.onThread(func() { sig, err = s.signOnToken(ref, pinPad, pin, data) })
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsc: signing with %s (%s) failed: %v\n", ref.cert.Subject.CommonName, ref.lib.path, err)
		return nil, pinError(err)
	}
	return sig, nil
}

// signAttempt is one way to have the token make the signature.
type signAttempt struct {
	mech  ckULong
	input []byte
	chunk int // > 0: C_SignUpdate in parts of this size, then C_SignFinal
}

// partChunk is the C_SignUpdate piece size: well under one smart-card packet.
const partChunk = 64

func (a signAttempt) name() string {
	if a.chunk > 0 {
		return mechName(a.mech) + " (in parts)"
	}
	return mechName(a.mech)
}

// signAttempts orders the mechanisms to try. CKM_SHA256_RSA_PKCS (the token
// hashes) comes first: some cards, such as the ePass2003, refuse raw
// CKM_RSA_PKCS with CKR_DEVICE_ERROR. Both produce the same RSA PKCS#1 v1.5
// SHA-256 signature. The token-hashing method is tried in one C_Sign, then
// fed in parts, since some drivers fail single-part hashing on longer data.
// If the driver doesn't list its mechanisms, every method is tried.
func signAttempts(mechs []ckULong, data []byte) []signAttempt {
	sum := sha256.Sum256(data)
	hashed := signAttempt{mech: ckmSHA256RSAPKCS, input: data}
	raw := signAttempt{mech: ckmRSAPKCS, input: append(append([]byte{}, keystore.SHA256DigestInfo...), sum[:]...)}
	has := map[ckULong]bool{}
	for _, m := range mechs {
		has[m] = true
	}
	hashedParts := signAttempt{mech: ckmSHA256RSAPKCS, input: data, chunk: partChunk}
	switch {
	case has[ckmSHA256RSAPKCS] && !has[ckmRSAPKCS]:
		return []signAttempt{hashed, hashedParts}
	case has[ckmRSAPKCS] && !has[ckmSHA256RSAPKCS]:
		return []signAttempt{raw}
	default:
		return []signAttempt{hashed, hashedParts, raw}
	}
}

// retryable reports errors where another mechanism may still work. PIN
// errors are never retried, so a wrong PIN can't lock the token.
func retryable(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return errors.Is(err, errBadSignature)
	}
	switch e.RV {
	case 0x005, 0x006, 0x007, 0x021, 0x030, 0x054, 0x063, 0x068, 0x070, 0x071:
		return true
	}
	return false
}

var errBadSignature = errors.New("the token returned a signature that does not verify")

// signOnToken tries each signing mechanism the token supports until one
// produces a signature that verifies with the certificate. It runs on the
// PKCS#11 thread.
func (s *Store) signOnToken(ref certRef, pinPad bool, pin string, data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pinBytes := []byte(pin)
	defer func() {
		for i := range pinBytes {
			pinBytes[i] = 0
		}
	}()
	pub, _ := ref.cert.PublicKey.(*rsa.PublicKey)
	sum := sha256.Sum256(data)
	mechs, _ := ref.lib.mechanisms(ref.slot)
	var last error
	for i, a := range signAttempts(mechs, data) {
		sig, err := s.signOnce(ref, pinPad, pinBytes, a)
		if err == nil && pub != nil && rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
			err = errBadSignature
		}
		if err == nil {
			if i > 0 {
				fmt.Fprintf(os.Stderr, "dsc: signed with %s (%d bytes)\n", a.name(), len(data))
			}
			return sig, nil
		}
		fmt.Fprintf(os.Stderr, "dsc: %s with %s failed on %d bytes: %v\n", a.name(), ref.lib.path, len(data), err)
		last = err
		if !retryable(err) {
			break
		}
	}
	return nil, last
}

// signOnce opens a session, logs in, finds the key and signs with one
// mechanism.
func (s *Store) signOnce(ref certRef, pinPad bool, pinBytes []byte, a signAttempt) ([]byte, error) {
	l := ref.lib
	session, err := l.open(ref.slot)
	if err != nil {
		return nil, err
	}
	defer l.closeSession(session)
	login := func(userType ckULong) ckULong {
		if pinPad {
			return l.login(session, userType, nil, 0)
		}
		if len(pinBytes) == 0 {
			return ckrPINIncorrect
		}
		return l.login(session, userType, &pinBytes[0], ckULong(len(pinBytes)))
	}
	if rv := login(ckuUser); rv != ckrOK && rv != ckrUserAlreadyLoggedIn {
		return nil, check("C_Login", rv)
	}
	defer l.logout(session)

	class := ckULong(ckoPrivateKey)
	keys, err := l.find(session, classTemplate(&class, ref.ckaID))
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no private key on the token matches this certificate")
	}
	var reauth func() error
	if v, _ := l.attr(session, keys[0], ckaAlwaysAuthenticate); len(v) == 1 && v[0] != 0 {
		reauth = func() error { return check("C_Login(context-specific)", login(ckuContextSpecific)) }
	}
	sigLen := 0
	if pub, ok := ref.cert.PublicKey.(*rsa.PublicKey); ok {
		sigLen = pub.Size()
	}
	return l.signWith(session, keys[0], a.mech, a.input, sigLen, reauth, a.chunk)
}

// Close finalizes every loaded driver.
func (s *Store) Close() error {
	s.onThread(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, l := range s.libs {
			l.finalize(nil)
		}
		s.libs = map[string]*lib{}
	})
	return nil
}
