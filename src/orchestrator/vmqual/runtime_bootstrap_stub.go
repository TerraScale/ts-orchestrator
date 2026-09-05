//go:build !sandboxvm

package vmqual

import (
	"context"
	"errors"
)

func (factory *firecrackerFactory) activateGuest(context.Context, string) error {
	return errors.New("vmqual: initial guest activation requires the sandboxvm build")
}
