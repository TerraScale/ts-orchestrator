//go:build !sandboxvm

package vmqual

import (
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
)

func newSandboxVMProvider(Config) (*sandboxvm.Provider, error) {
	return nil, errors.New("vmqual: real Firecracker runtime requires -tags sandboxvm")
}
