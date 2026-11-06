//go:build windows

package prompt

import (
	"syscall"
	"unsafe"

	"github.com/kitsyai/dsc/internal/keystore"
)

var (
	user32      = syscall.NewLazyDLL("user32.dll")
	messageBoxW = user32.NewProc("MessageBoxW")
)

const (
	mbYesNo         = 0x00000004
	mbIconWarning   = 0x00000030
	mbDefButton2    = 0x00000100
	mbSystemModal   = 0x00001000
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
	idYes           = 6
)

// Native shows Windows message boxes. The token driver asks for the PIN
// itself, so ConfirmWithPIN is not used on Windows.
type Native struct{}

func (Native) Confirm(c keystore.Consent) (bool, error) {
	text, err := syscall.UTF16PtrFromString(Message(c, false) + "\n\nSign it?")
	if err != nil {
		return false, err
	}
	title, _ := syscall.UTF16PtrFromString(Title)
	r, _, callErr := messageBoxW.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)),
		mbYesNo|mbIconWarning|mbDefButton2|mbSystemModal|mbSetForeground|mbTopmost)
	if r == 0 {
		return false, callErr
	}
	return r == idYes, nil
}

func (Native) ConfirmWithPIN(c keystore.Consent) (string, bool, error) {
	return "", false, keystore.ErrNoDialogProgram
}
