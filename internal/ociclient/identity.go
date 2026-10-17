package ociclient

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type authorityKey struct{}
type admissionKey struct{}
type wireAttemptKey struct{}
type admissionDeadlineKey struct{}
type requestGuardKey struct{}

// WithRequestGuard rechecks a root IPC session immediately before every wire
// attempt, including read retries. It does not confer cloud mutation authority.
func WithRequestGuard(ctx context.Context, guard func(context.Context) error) context.Context {
	return context.WithValue(ctx, requestGuardKey{}, guard)
}

type admissionDeadline struct{ until time.Time }

// LimitAdmission carries the earliest authenticated expiry through any remaining
// admission waits. The dispatcher checks it again immediately before sending.
func LimitAdmission(ctx context.Context, deadline time.Time) error {
	if deadline.IsZero() || !time.Now().Before(deadline) {
		return errors.New("OCI current admission facts expired")
	}
	if state, ok := ctx.Value(admissionDeadlineKey{}).(*admissionDeadline); ok {
		if state.until.IsZero() || deadline.Before(state.until) {
			state.until = deadline
		}
	}
	return nil
}

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

// WithWireAttempt records each dispatch before the final authority admission.
// A missing finish record remains unknown, including after process failure.
func WithWireAttempt(ctx context.Context, begin func(*http.Request) (func(*http.Response, error, bool) error, error)) context.Context {
	return context.WithValue(ctx, wireAttemptKey{}, begin)
}
