package ociclient

import (
	"context"
	"errors"
)

// CheckRequestGuard repeats only the guard already carried by the original
// request context. It grants no authority and accepts no replacement callback.
func CheckRequestGuard(ctx context.Context) error {
	if ctx == nil {
		return errors.New("OCI request context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	guard, ok := ctx.Value(requestGuardKey{}).(func(context.Context) error)
	if !ok {
		return nil
	}
	if guard == nil {
		return errors.New("OCI request session is unavailable")
	}
	// Match SDK dispatch: a guard's own OCI reads must not recursively invoke it.
	err := guard(context.WithValue(ctx, requestGuardKey{}, struct{}{}))
	return errors.Join(err, ctx.Err())
}
