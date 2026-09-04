//go:build !sandboxvm

package vmqual

import (
	"context"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
)

func newSandboxVMProvider(Config) (*sandboxvm.Provider, error) {
	return nil, errors.New("vmqual: real Firecracker runtime requires -tags sandboxvm")
}

func (f *firecrackerFactory) prepareGuest(context.Context, Guest, *sandboxvm.Config) (string, error) {
	return "", errors.New("vmqual: real Firecracker runtime requires -tags sandboxvm")
}

func newGuestExecutor(sandboxvm.Config) sandboxvm.CommandRunner { return nil }
