//go:build windows

// Package winstore signs with keys in the Windows "Personal" certificate
// store. USB token drivers (ePass2003, ProxKey, Watchdata, mToken, SafeNet)
// publish their certificates there, and their own driver dialog asks for
// the PIN when a key is used. Only the standard library is used: crypt32,
// ncrypt and advapi32 are called through syscall, no cgo.
package winstore

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/kitsyai/dsc/internal/keystore"
)

var (
	crypt32                            = syscall.NewLazyDLL("crypt32.dll")
	procCertGetCertificateContextProp  = crypt32.NewProc("CertGetCertificateContextProperty")
	procCryptAcquireCertificatePrivKey = crypt32.NewProc("CryptAcquireCertificatePrivateKey")

	ncrypt             = syscall.NewLazyDLL("ncrypt.dll")
	procNCryptSignHash = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObj  = ncrypt.NewProc("NCryptFreeObject")

	advapi32              = syscall.NewLazyDLL("advapi32.dll")
	procCryptCreateHash   = advapi32.NewProc("CryptCreateHash")
	procCryptSetHashParam = advapi32.NewProc("CryptSetHashParam")
	procCryptSignHashW    = advapi32.NewProc("CryptSignHashW")
	procCryptDestroyHash  = advapi32.NewProc("CryptDestroyHash")
	procCryptReleaseCtx   = advapi32.NewProc("CryptReleaseContext")
)

const (
	certKeyProvInfoPropID           = 2
	cryptAcquireCacheFlag           = 0x1
	cryptAcquireCompareKeyFlag      = 0x4
	cryptAcquirePreferNCryptKeyFlag = 0x20000
	certNCryptKeySpec               = 0xFFFFFFFF
	bcryptPadPKCS1                  = 0x2
	calgSHA256                      = 0x800c
	hpHashVal                       = 0x2

	ntePINIncorrect = 0x8010006B // SCARD_W_WRONG_CHV
	ntePINLocked    = 0x8010006C // SCARD_W_CHV_BLOCKED
	nteCancelled    = 0x8010006E // SCARD_W_CANCELLED_BY_USER
	nteUserCancel   = 0x80090036 // NTE_USER_CANCELLED
	errCancelled    = 0x800704C7 // HRESULT_FROM_WIN32(ERROR_CANCELLED)
)

type bcryptPKCS1PaddingInfo struct {
	algID *uint16
}

// Store is the current user's Personal certificate store.
type Store struct {
	mu     sync.Mutex
	prompt keystore.Prompter
}

func New(prompt keystore.Prompter) *Store { return &Store{prompt: prompt} }

func hasPrivateKey(ctx *syscall.CertContext) bool {
	var size uint32
	r, _, _ := procCertGetCertificateContextProp.Call(uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&size)))
	return r != 0
}

func certBytes(ctx *syscall.CertContext) []byte {
	b := unsafe.Slice(ctx.EncodedCert, ctx.Length)
	return append([]byte(nil), b...)
}

// usable keeps signing certificates: not a CA, and allowed to sign if the
// certificate restricts key usage. Expired ones are kept; the page warns.
func usable(der []byte) (*x509.Certificate, bool) {
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.IsCA {
		return nil, false
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return nil, false
	}
	return cert, true
}

// walk calls fn for each certificate with a private key. If fn returns
// true, walk returns that context; the caller must free it.
func walk(fn func(ctx *syscall.CertContext, der []byte) bool) (*syscall.CertContext, error) {
	name, _ := syscall.UTF16PtrFromString("MY")
	store, err := syscall.CertOpenSystemStore(0, name)
	if err != nil {
		return nil, fmt.Errorf("open the Personal certificate store: %w", err)
	}
	defer syscall.CertCloseStore(store, 0)
	var ctx *syscall.CertContext
	for {
		ctx, err = syscall.CertEnumCertificatesInStore(store, ctx)
		if ctx == nil {
			return nil, nil
		}
		if !hasPrivateKey(ctx) {
			continue
		}
		if fn(ctx, certBytes(ctx)) {
			// Stopping the enumeration keeps ctx alive (and the store with
			// it, despite CertCloseStore) until the caller frees it.
			return ctx, nil
		}
	}
}

func (s *Store) List() ([]keystore.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []keystore.Certificate
	seen := map[string]bool{}
	_, err := walk(func(ctx *syscall.CertContext, der []byte) bool {
		if _, ok := usable(der); !ok {
			return false
		}
		id := keystore.ID(der)
		if !seen[id] {
			seen[id] = true
			out = append(out, keystore.Certificate{ID: id, DER: der, Label: "Windows certificate store", Source: "windows"})
		}
		return false
	})
	return out, err
}

func mapErr(r uintptr, err error) error {
	var errno syscall.Errno
	code := uint32(r)
	if errors.As(err, &errno) && code == 0 {
		code = uint32(errno)
	}
	switch code {
	case ntePINIncorrect:
		return keystore.ErrPINIncorrect
	case ntePINLocked:
		return keystore.ErrPINLocked
	case nteCancelled, nteUserCancel, errCancelled:
		return keystore.ErrDeclined
	}
	if code != 0 {
		return fmt.Errorf("signing failed (0x%08X)", code)
	}
	return fmt.Errorf("signing failed: %v", err)
}

// Sign shows the consent dialog, then signs. The token driver shows its own
// PIN dialog when the key is used.
func (s *Store) Sign(id string, digest []byte, consent keystore.Consent) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("expected a SHA-256 digest")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var cert *x509.Certificate
	ctx, err := walk(func(_ *syscall.CertContext, der []byte) bool {
		if keystore.ID(der) != id {
			return false
		}
		cert, _ = x509.ParseCertificate(der)
		return cert != nil
	})
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, keystore.ErrNotFound
	}
	defer syscall.CertFreeCertificateContext(ctx)
	if _, isRSA := cert.PublicKey.(*rsa.PublicKey); !isRSA {
		return nil, keystore.ErrUnsupportedKey
	}
	if consent.Signer == "" {
		consent.Signer = cert.Subject.CommonName
	}
	ok, err := s.prompt.Confirm(consent)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, keystore.ErrDeclined
	}

	var key uintptr
	var keySpec uint32
	var callerFree int32
	r, _, callErr := procCryptAcquireCertificatePrivKey.Call(uintptr(unsafe.Pointer(ctx)),
		cryptAcquireCompareKeyFlag|cryptAcquirePreferNCryptKeyFlag, 0,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&keySpec)), uintptr(unsafe.Pointer(&callerFree)))
	if r == 0 {
		return nil, mapErr(0, callErr)
	}
	if keySpec == certNCryptKeySpec {
		if callerFree != 0 {
			defer procNCryptFreeObj.Call(key)
		}
		return signNCrypt(key, digest)
	}
	if callerFree != 0 {
		defer procCryptReleaseCtx.Call(key, 0)
	}
	return signCAPI(key, keySpec, digest)
}

func signNCrypt(key uintptr, digest []byte) ([]byte, error) {
	alg, _ := syscall.UTF16PtrFromString("SHA256")
	pad := &bcryptPKCS1PaddingInfo{algID: alg}
	var size uint32
	r, _, err := procNCryptSignHash.Call(key, uintptr(unsafe.Pointer(pad)), uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&size)), bcryptPadPKCS1)
	if r != 0 {
		return nil, mapErr(r, err)
	}
	sig := make([]byte, size)
	r, _, err = procNCryptSignHash.Call(key, uintptr(unsafe.Pointer(pad)), uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), bcryptPadPKCS1)
	if r != 0 {
		return nil, mapErr(r, err)
	}
	return sig[:size], nil
}

// signCAPI handles keys only reachable through a legacy CryptoAPI CSP.
// CryptoAPI returns signatures little-endian, so the bytes are reversed.
func signCAPI(prov uintptr, keySpec uint32, digest []byte) ([]byte, error) {
	var hash uintptr
	r, _, err := procCryptCreateHash.Call(prov, calgSHA256, 0, 0, uintptr(unsafe.Pointer(&hash)))
	if r == 0 {
		return nil, fmt.Errorf("this token's driver does not support SHA-256 signing: %v", err)
	}
	defer procCryptDestroyHash.Call(hash)
	if r, _, err = procCryptSetHashParam.Call(hash, hpHashVal, uintptr(unsafe.Pointer(&digest[0])), 0); r == 0 {
		return nil, mapErr(0, err)
	}
	var size uint32
	if r, _, err = procCryptSignHashW.Call(hash, uintptr(keySpec), 0, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil, mapErr(0, err)
	}
	sig := make([]byte, size)
	if r, _, err = procCryptSignHashW.Call(hash, uintptr(keySpec), 0, 0, uintptr(unsafe.Pointer(&sig[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil, mapErr(0, err)
	}
	sig = sig[:size]
	for i, j := 0, len(sig)-1; i < j; i, j = i+1, j-1 {
		sig[i], sig[j] = sig[j], sig[i]
	}
	return sig, nil
}

func (s *Store) Close() error { return nil }
