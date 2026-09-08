//go:build !sandboxvm

package vmqualruntime

import (
	"context"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func (factory *firecrackerFactory) prepareGuest(context.Context, vmqual.Guest) error {
	return nil
}

func (factory *firecrackerFactory) activateGuest(context.Context, string) error {
	return errors.New("vmqual: initial guest activation requires the sandboxvm build")
}

func (factory *firecrackerFactory) guestReady(context.Context, string) error {
	return errors.New("vmqual: guest runtime binding requires the sandboxvm build")
}
