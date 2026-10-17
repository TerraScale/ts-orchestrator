package bootstrapmaterial

import (
	"context"
	"slices"
	"time"
)

type publicationGuardKey struct{}
type publicationGuards []func(context.Context) error

// WithPublicationGuard retains the caller's live authority through local
// publication waits. Nested source guards narrow, rather than replace, it.
func WithPublicationGuard(ctx context.Context, guard func(context.Context) error) context.Context {
	previous, _ := ctx.Value(publicationGuardKey{}).(publicationGuards)
	return context.WithValue(ctx, publicationGuardKey{}, append(slices.Clone(previous), guard))
}

// GuardPublication runs immediately before a durable local rename/checkpoint.
func GuardPublication(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	guards, _ := ctx.Value(publicationGuardKey{}).(publicationGuards)
	verification := context.WithValue(ctx, publicationGuardKey{}, struct{}{})
	// Check the outer root caller last, after any source verification reads.
	for i := len(guards) - 1; i >= 0; i-- {
		guard := guards[i]
		if guard == nil {
			return ErrProvision
		}
		// Source verification may check this hook too; each guard runs once.
		if err := guard(verification); err != nil {
			return err
		}
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return ctx.Err()
}
