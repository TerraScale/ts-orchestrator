package ociclient

import "context"

type authorityKey struct{}
type admissionKey struct{}

// WithAuthority rechecks a durable operation's write authority for every SDK
// mutation attempt, including retries after a lost response or provider error.
// The caller cancels ctx when the claim is lost; reads remain available.
func WithAuthority(ctx context.Context, guard func(context.Context) error) context.Context {
	if guard == nil {
		return ctx
	}
	return context.WithValue(ctx, authorityKey{}, guard)
}

// WithAdmission acquires current write authority for each HTTP mutation attempt
// and holds it until that attempt returns. SDK retries acquire it again.
// Clients must use ConfigureRequestCancellation, as Factory clients do.
func WithAdmission(ctx context.Context, acquire func(context.Context) (func(), error)) context.Context {
	return context.WithValue(ctx, admissionKey{}, acquire)
}
