//go:build !windows

// Package pkcs11 signs with keys on USB tokens and smart cards through the
// vendor's PKCS#11 driver library, loaded at run time with purego (no cgo).
//
// Types follow the PKCS#11 v2.40 C headers on 64-bit Unix: CK_ULONG is 64
// bits and structures use natural alignment.
package pkcs11

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

type ckULong = uint64

const (
	ckrOK                      = 0x000
	ckrUserAlreadyLoggedIn     = 0x100
	ckrUserNotLoggedIn         = 0x101
	ckrPINIncorrect            = 0x0A0
	ckrPINInvalid              = 0x0A1
	ckrPINLenRange             = 0x0A2
	ckrPINExpired              = 0x0A3
	ckrPINLocked               = 0x0A4
	ckrCryptokiAlreadyInitized = 0x191
	ckrBufferTooSmall          = 0x150
	ckrTokenNotPresent         = 0x0E0
	ckrDeviceRemoved           = 0x032

	ckfSerialSession      = 0x4
	ckfOSLockingOK        = 0x2
	ckfProtectedAuthPath  = 0x100
	ckuUser               = 1
	ckuContextSpecific    = 2
	ckaAlwaysAuthenticate = 0x202
	ckoCertificate        = 1
	ckoPrivateKey         = 3
	ckaClass              = 0x000
	ckaLabel              = 0x003
	ckaValue              = 0x011
	ckaID                 = 0x102
	ckmRSAPKCS            = 0x001
	unavailableInfo       = ^ckULong(0)
)

type attribute struct {
	typ   ckULong
	value unsafe.Pointer
	len   ckULong
}

type mechanism struct {
	mech  ckULong
	param unsafe.Pointer
	len   ckULong
}

type initArgs struct {
	createMutex, destroyMutex, lockMutex, unlockMutex uintptr
	flags                                             ckULong
	reserved                                          uintptr
}

// Error is a PKCS#11 return value other than CKR_OK.
type Error struct {
	Func string
	RV   ckULong
}

var rvNames = map[ckULong]string{
	0x005: "CKR_GENERAL_ERROR", 0x006: "CKR_FUNCTION_FAILED", 0x007: "CKR_ARGUMENTS_BAD",
	0x030: "CKR_DEVICE_ERROR", 0x031: "CKR_DEVICE_MEMORY", 0x032: "CKR_DEVICE_REMOVED",
	0x021: "CKR_DATA_LEN_RANGE", 0x063: "CKR_KEY_TYPE_INCONSISTENT", 0x068: "CKR_KEY_FUNCTION_NOT_PERMITTED",
	0x070: "CKR_MECHANISM_INVALID", 0x071: "CKR_MECHANISM_PARAM_INVALID", 0x090: "CKR_OPERATION_ACTIVE",
	0x091: "CKR_OPERATION_NOT_INITIALIZED", 0x0A0: "CKR_PIN_INCORRECT", 0x0A4: "CKR_PIN_LOCKED",
	0x0B3: "CKR_SESSION_HANDLE_INVALID", 0x0E0: "CKR_TOKEN_NOT_PRESENT", 0x101: "CKR_USER_NOT_LOGGED_IN",
	0x150: "CKR_BUFFER_TOO_SMALL",
}

func (e *Error) Error() string {
	if name, ok := rvNames[e.RV]; ok {
		return fmt.Sprintf("%s failed: %s (0x%X)", e.Func, name, e.RV)
	}
	return fmt.Sprintf("%s failed: CKR 0x%X", e.Func, e.RV)
}

func check(name string, rv ckULong) error {
	if rv == ckrOK {
		return nil
	}
	return &Error{Func: name, RV: rv}
}

// lib is one loaded PKCS#11 driver.
type lib struct {
	path string

	initialize        func(args unsafe.Pointer) ckULong
	finalize          func(reserved unsafe.Pointer) ckULong
	getSlotList       func(present uint8, slots *ckULong, count *ckULong) ckULong
	getTokenInfo      func(slot ckULong, info *byte) ckULong
	openSession       func(slot, flags ckULong, app, notify unsafe.Pointer, session *ckULong) ckULong
	closeSession      func(session ckULong) ckULong
	login             func(session, userType ckULong, pin *byte, pinLen ckULong) ckULong
	logout            func(session ckULong) ckULong
	findObjectsInit   func(session ckULong, template *attribute, count ckULong) ckULong
	findObjects       func(session ckULong, objects *ckULong, max ckULong, count *ckULong) ckULong
	findObjectsFinal  func(session ckULong) ckULong
	getAttributeValue func(session, object ckULong, template *attribute, count ckULong) ckULong
	signInit          func(session ckULong, mech *mechanism, key ckULong) ckULong
	sign              func(session ckULong, data *byte, dataLen ckULong, sig *byte, sigLen *ckULong) ckULong
}

func load(path string) (l *lib, err error) {
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	defer func() {
		// purego.RegisterLibFunc panics on a missing symbol.
		if r := recover(); r != nil {
			purego.Dlclose(handle)
			l, err = nil, fmt.Errorf("load %s: not a PKCS#11 library (%v)", path, r)
		}
	}()
	l = &lib{path: path}
	reg := func(fptr any, name string) { purego.RegisterLibFunc(fptr, handle, name) }
	reg(&l.initialize, "C_Initialize")
	reg(&l.finalize, "C_Finalize")
	reg(&l.getSlotList, "C_GetSlotList")
	reg(&l.getTokenInfo, "C_GetTokenInfo")
	reg(&l.openSession, "C_OpenSession")
	reg(&l.closeSession, "C_CloseSession")
	reg(&l.login, "C_Login")
	reg(&l.logout, "C_Logout")
	reg(&l.findObjectsInit, "C_FindObjectsInit")
	reg(&l.findObjects, "C_FindObjects")
	reg(&l.findObjectsFinal, "C_FindObjectsFinal")
	reg(&l.getAttributeValue, "C_GetAttributeValue")
	reg(&l.signInit, "C_SignInit")
	reg(&l.sign, "C_Sign")

	args := &initArgs{flags: ckfOSLockingOK}
	rv := l.initialize(unsafe.Pointer(args))
	runtime.KeepAlive(args)
	if rv != ckrOK && rv != ckrCryptokiAlreadyInitized {
		purego.Dlclose(handle)
		return nil, check("C_Initialize", rv)
	}
	return l, nil
}

func (l *lib) slots() ([]ckULong, error) {
	var n ckULong
	if err := check("C_GetSlotList", l.getSlotList(1, nil, &n)); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	slots := make([]ckULong, n)
	if err := check("C_GetSlotList", l.getSlotList(1, &slots[0], &n)); err != nil {
		return nil, err
	}
	return slots[:n], nil
}

type tokenInfo struct {
	label, serial string
	flags         ckULong
}

func trimPadded(b []byte) string {
	end := len(b)
	for end > 0 && (b[end-1] == ' ' || b[end-1] == 0) {
		end--
	}
	return string(b[:end])
}

func (l *lib) tokenInfo(slot ckULong) (tokenInfo, error) {
	// CK_TOKEN_INFO: label[32] manufacturerID[32] model[16] serialNumber[16]
	// flags(CK_ULONG at offset 96) ... well under 512 bytes.
	buf := make([]byte, 512)
	if err := check("C_GetTokenInfo", l.getTokenInfo(slot, &buf[0])); err != nil {
		return tokenInfo{}, err
	}
	return tokenInfo{
		label:  trimPadded(buf[0:32]),
		serial: trimPadded(buf[80:96]),
		flags:  *(*ckULong)(unsafe.Pointer(&buf[96])),
	}, nil
}

func (l *lib) find(session ckULong, template []attribute) ([]ckULong, error) {
	if err := check("C_FindObjectsInit", l.findObjectsInit(session, &template[0], ckULong(len(template)))); err != nil {
		return nil, err
	}
	runtime.KeepAlive(template)
	defer l.findObjectsFinal(session)
	var out []ckULong
	batch := make([]ckULong, 32)
	for {
		var n ckULong
		if err := check("C_FindObjects", l.findObjects(session, &batch[0], ckULong(len(batch)), &n)); err != nil {
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
		out = append(out, batch[:n]...)
	}
}

// attr reads one attribute's bytes (nil if the token can't provide it).
func (l *lib) attr(session, object ckULong, typ ckULong) ([]byte, error) {
	t := []attribute{{typ: typ}}
	rv := l.getAttributeValue(session, object, &t[0], 1)
	if rv != ckrOK || t[0].len == unavailableInfo {
		return nil, nil
	}
	if t[0].len == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, t[0].len)
	t[0].value = unsafe.Pointer(&buf[0])
	err := check("C_GetAttributeValue", l.getAttributeValue(session, object, &t[0], 1))
	runtime.KeepAlive(buf)
	if err != nil {
		return nil, err
	}
	return buf[:t[0].len], nil
}

func classTemplate(class *ckULong, id []byte) []attribute {
	t := []attribute{{typ: ckaClass, value: unsafe.Pointer(class), len: 8}}
	if len(id) > 0 {
		t = append(t, attribute{typ: ckaID, value: unsafe.Pointer(&id[0]), len: ckULong(len(id))})
	}
	return t
}

func (l *lib) open(slot ckULong) (ckULong, error) {
	var session ckULong
	err := check("C_OpenSession", l.openSession(slot, ckfSerialSession, nil, nil, &session))
	return session, err
}

// signRaw signs data (a DigestInfo) with CKM_RSA_PKCS. sigLen is the
// expected signature size (the RSA modulus length): the signature is
// requested in one call with a buffer of that size, because some vendor
// drivers mishandle the separate length query. reauth, if set, is called
// between C_SignInit and C_Sign for keys marked CKA_ALWAYS_AUTHENTICATE.
func (l *lib) signRaw(session, key ckULong, data []byte, sigLen int, reauth func() error) ([]byte, error) {
	m := &mechanism{mech: ckmRSAPKCS}
	if err := check("C_SignInit", l.signInit(session, m, key)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(m)
	if reauth != nil {
		if err := reauth(); err != nil {
			return nil, err
		}
	}
	if sigLen < 64 {
		sigLen = 1024
	}
	sig := make([]byte, sigLen)
	n := ckULong(len(sig))
	rv := l.sign(session, &data[0], ckULong(len(data)), &sig[0], &n)
	if rv == ckrBufferTooSmall && n > ckULong(len(sig)) {
		sig = make([]byte, n)
		rv = l.sign(session, &data[0], ckULong(len(data)), &sig[0], &n)
	}
	runtime.KeepAlive(data)
	if err := check("C_Sign", rv); err != nil {
		return nil, err
	}
	return sig[:n], nil
}
