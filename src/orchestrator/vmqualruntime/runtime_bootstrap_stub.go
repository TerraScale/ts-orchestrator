//go:build !sandboxvm

package vmqualruntime

import (
	"context"
	"errors"
)

func (factory *firecrackerFactory) activateGuest(context.Context, string) error {
	return errors.New("vmqual: initial guest activation requires the sandboxvm build")
}

func (factory *firecrackerFactory) guestReady(context.Context, string) error {
	return errors.New("vmqual: guest runtime binding requires the sandboxvm build")
}
