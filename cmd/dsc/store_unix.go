//go:build !windows

package main

import (
	"github.com/kitsyai/dsc/internal/keystore"
	"github.com/kitsyai/dsc/internal/pkcs11"
	"github.com/kitsyai/dsc/internal/prompt"
)

func openStore(pkcs11Modules []string) (keystore.Store, error) {
	explicit := append(append([]string{}, pkcs11Modules...), pkcs11.ModulesFromEnv()...)
	return pkcs11.New(explicit, pkcs11.DefaultModules(), prompt.Native{}), nil
}
