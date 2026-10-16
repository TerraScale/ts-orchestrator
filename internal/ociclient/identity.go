package ociclient

import "context"

type authorityKey struct{}

// WithAuthority rechecks a durable operation's write authority for every SDK
// mutation attempt, including retries after a lost response or provider error.
// The caller cancels ctx when the claim is lost; reads remain available.
func WithAuthority(ctx context.Context, guard func(context.Context) error) context.Context {
	if guard == nil {
		return ctx
	}
	return context.WithValue(ctx, authorityKey{}, guard)
}
