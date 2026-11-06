//go:build windows

package main

import (
	"github.com/kitsyai/dsc/internal/keystore"
	"github.com/kitsyai/dsc/internal/prompt"
	"github.com/kitsyai/dsc/internal/winstore"
)

func openStore(pkcs11Modules []string) (keystore.Store, error) {
	// Token drivers on Windows publish their certificates to the Personal
	// store, so --pkcs11 is not needed here.
	return winstore.New(prompt.Native{}), nil
}
