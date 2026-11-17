//go:build !windows

package main

import (
	"os"

	"github.com/kitsyai/dsc/internal/keystore"
	"github.com/kitsyai/dsc/internal/pkcs11"
	"github.com/kitsyai/dsc/internal/prompt"
)

func openStore(pkcs11Modules []string) (keystore.Store, error) {
	return newPKCS11Store(pkcs11Modules), nil
}

func newPKCS11Store(pkcs11Modules []string) *pkcs11.Store {
	explicit := append(append([]string{}, pkcs11Modules...), pkcs11.ModulesFromEnv()...)
	return pkcs11.New(explicit, pkcs11.DefaultModules(), prompt.Native{})
}

func diagnose(pkcs11Modules []string) error {
	store := newPKCS11Store(pkcs11Modules)
	defer store.Close()
	return store.Diagnose(os.Stdout)
}
