//go:build !linux

package vaultsecret

import (
	"errors"
	"os"
)

func openMemoryDirectory(string) (*os.Root, error) {
	return nil, errors.New("Vault file delivery requires Linux tmpfs")
}

func RequireMemoryFilesystem(string) error {
	return errors.New("Vault runtime files require Linux tmpfs")
}
