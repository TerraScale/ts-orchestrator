package delivery

import (
	"context"
	"errors"
	"time"
)

// RegionalCommandAuthority is the live regional lease and signed desired
// generation that a node command must bind into its signed envelope.
type RegionalCommandAuthority struct {
	AuthorityID       string
	Epoch             int64
	CandidateID       string
	LeaseID           string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	DesiredGeneration int64
}

type regionalAuthorityContextKey struct{}
type regionalAuthorityResolver func(context.Context) (RegionalCommandAuthority, error)

// WithRegionalCommandAuthority installs a live resolver, not a cached lease.
func WithRegionalCommandAuthority(ctx context.Context, resolve func(context.Context) (RegionalCommandAuthority, error)) (context.Context, error) {
	if ctx == nil || resolve == nil {
		return nil, errors.New("delivery: regional command authority resolver is required")
	}
	return context.WithValue(ctx, regionalAuthorityContextKey{}, regionalAuthorityResolver(resolve)), nil
}

// RegionalCommandAuthorityFromContext rechecks the operation fence and reads
// the current regional lease immediately before the transport signs a command.
func RegionalCommandAuthorityFromContext(ctx context.Context) (RegionalCommandAuthority, error) {
	if err := CheckExecutionFence(ctx); err != nil {
		return RegionalCommandAuthority{}, err
	}
	resolve, ok := ctx.Value(regionalAuthorityContextKey{}).(regionalAuthorityResolver)
	if !ok || resolve == nil {
		return RegionalCommandAuthority{}, errors.New("delivery: live regional command authority is missing")
	}
	value, err := resolve(ctx)
	if err != nil {
		return RegionalCommandAuthority{}, err
	}
	if value.AuthorityID == "" || value.Epoch <= 0 || value.CandidateID == "" || value.LeaseID == "" || value.DesiredGeneration <= 0 || value.IssuedAt.IsZero() || !value.ExpiresAt.After(value.IssuedAt) || !time.Now().Before(value.ExpiresAt) {
		return RegionalCommandAuthority{}, errors.New("delivery: regional command authority is invalid or expired")
	}
	return value, nil
}
