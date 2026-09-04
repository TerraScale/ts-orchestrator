//go:build !sandboxvm

package vmqual

import (
	"context"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

func newSandboxVMProvider(Config) (*sandboxvm.Provider, error) {
	return nil, errors.New("vmqual: real Firecracker runtime requires -tags sandboxvm")
}

func (f *firecrackerFactory) prepareGuest(context.Context, Guest, *sandboxvm.Config) (string, error) {
	return "", errors.New("vmqual: real Firecracker runtime requires -tags sandboxvm")
}

func newGuestExecutor(sandboxvm.Config) sandboxvm.CommandRunner { return nil }

// zeroBytes is kept available to the portable network checks even though the
// real guest transport is compiled only for the sandboxvm build.
func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func releaseGuestTransport(string) error { return nil }

func newQualificationServices(Config, vmnet.NetworkPlan, vmimage.Architecture) (qualificationServices, error) {
	return nil, errors.New("vmqual: real Firecracker runtime requires -tags sandboxvm")
}
