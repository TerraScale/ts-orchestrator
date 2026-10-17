package region

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// VerifiedNetBirdJournalUnderlay is read-only evidence of the original private
// route. It conveys no OCI, listener, NATS, signing or journal-write authority.
type VerifiedNetBirdJournalUnderlay struct {
	purpose  VerifiedNetBirdJournalPurpose
	journal  NetBirdUnderlayRecord
	factory  *ociclient.Factory
	resolver FoundationResolver
	original context.Context
	expires  time.Time
}

func (v VerifiedNetBirdJournalUnderlay) IsVerified() bool {
	return v.original != nil && v.journal.PurposeSHA256 != ""
}
func (v VerifiedNetBirdJournalUnderlay) Purpose() bootstrap.NetBirdJournalPurpose {
	return v.purpose.Purpose()
}
func (v VerifiedNetBirdJournalUnderlay) PurposeDigest() string { return v.journal.PurposeSHA256 }
func (v VerifiedNetBirdJournalUnderlay) GrantDigest() string   { return v.journal.GrantSHA256 }
func (v VerifiedNetBirdJournalUnderlay) ManagerInstanceID() string {
	return v.journal.Manager.InstanceID
}
func (v VerifiedNetBirdJournalUnderlay) ManagerVNICID() string    { return v.journal.Manager.VNICID }
func (v VerifiedNetBirdJournalUnderlay) WriterInstanceID() string { return v.journal.Writer.InstanceID }
func (v VerifiedNetBirdJournalUnderlay) WriterVNICID() string     { return v.journal.Writer.VNICID }
func (v VerifiedNetBirdJournalUnderlay) WriterPrivateIP() string {
	return v.journal.Recipe.WriterPrivateIP
}
func (v VerifiedNetBirdJournalUnderlay) ExpiresAt() time.Time { return v.expires }

func (v VerifiedNetBirdJournalUnderlay) Revalidate(ctx context.Context) error {
	_, err := v.CurrentDeadline(ctx)
	return err
}

func (v VerifiedNetBirdJournalUnderlay) CurrentDeadline(ctx context.Context) (time.Time, error) {
	if !v.IsVerified() || ctx == nil || v.original.Err() != nil || !time.Now().Before(v.expires) {
		return time.Time{}, errors.New("NetBird private underlay proof is absent, canceled or expired")
	}
	ctx, cancel := context.WithDeadline(ctx, v.expires)
	stop := context.AfterFunc(v.original, cancel)
	defer func() { stop(); cancel() }()
	current, deadline, err := verifyNetBirdUnderlaySnapshot(ctx, v.original, v.factory, v.resolver, v.purpose)
	if err != nil {
		return time.Time{}, err
	}
	if !netBirdUnderlayEqual(current, v.journal) {
		return time.Time{}, errors.New("NetBird private underlay original native route or cap changed")
	}
	if v.expires.Before(deadline) {
		deadline = v.expires
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return deadline, ociclient.LimitAdmission(ctx, deadline)
}

func (v VerifiedNetBirdJournalUnderlay) BootstrapPurpose(ctx context.Context) (bootstrap.VerifiedNetBirdJournalPurpose, error) {
	deadline, err := v.CurrentDeadline(ctx)
	if err != nil {
		return bootstrap.VerifiedNetBirdJournalPurpose{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(v.original, cancel)
	defer func() { stop(); cancel() }()
	lower, err := v.purpose.BootstrapPurpose(ctx)
	if err != nil {
		return bootstrap.VerifiedNetBirdJournalPurpose{}, err
	}
	return lower.LimitForOperation(ctx, v.original, deadline)
}

// VerifyNetBirdJournalUnderlayForOperation separates the initial read deadline
// from the original caller lifetime retained by subsequent revalidation.
func VerifyNetBirdJournalUnderlayForOperation(ctx, originalCtx context.Context, factory *ociclient.Factory, resolver FoundationResolver, purpose VerifiedNetBirdJournalPurpose) (VerifiedNetBirdJournalUnderlay, error) {
	if ctx == nil || originalCtx == nil || ctx.Err() != nil || originalCtx.Err() != nil {
		return VerifiedNetBirdJournalUnderlay{}, errors.New("NetBird private underlay requires live operation and original caller contexts")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(originalCtx, cancel)
	defer func() { stop(); cancel() }()
	if deadline, ok := originalCtx.Deadline(); ok {
		var release context.CancelFunc
		ctx, release = context.WithDeadline(ctx, deadline)
		defer release()
	}
	journal, expires, err := verifyNetBirdUnderlaySnapshot(ctx, originalCtx, factory, resolver, purpose)
	if err != nil {
		return VerifiedNetBirdJournalUnderlay{}, err
	}
	if deadline, ok := originalCtx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	return VerifiedNetBirdJournalUnderlay{purpose: purpose, journal: journal, factory: factory, resolver: resolver, original: originalCtx, expires: expires}, nil
}

func verifyNetBirdUnderlaySnapshot(ctx, originalCtx context.Context, factory *ociclient.Factory, resolver FoundationResolver, purpose VerifiedNetBirdJournalPurpose) (NetBirdUnderlayRecord, time.Time, error) {
	var zero NetBirdUnderlayRecord
	if ctx == nil || resolver.Store == nil {
		return zero, time.Time{}, errors.New("NetBird private underlay verification requires the protected original foundation store")
	}
	if err := validateNetBirdUnderlayStore(resolver, purpose); err != nil {
		return zero, time.Time{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, purpose.ExpiresAt())
	defer cancel()
	record, _, err := resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return zero, time.Time{}, err
	}
	if record.NetBirdUnderlay == nil {
		return zero, time.Time{}, ErrNetBirdUnderlayPending
	}
	journal := *record.NetBirdUnderlay
	ctx, retainedCancel := context.WithDeadline(ctx, journal.ExpiresAt)
	defer retainedCancel()
	if err := journal.Validate(); err != nil {
		return zero, time.Time{}, err
	}
	expected, err := netBirdUnderlayBirth(ctx, originalCtx, factory, resolver, purpose)
	if err != nil || !sameNetBirdUnderlayBirth(journal, expected) {
		return zero, time.Time{}, errors.Join(ErrFoundationFenced, err)
	}
	ctx, capCancel := context.WithDeadline(ctx, expected.ExpiresAt)
	defer capCancel()
	client, err := factory.Network()
	if err != nil {
		return zero, time.Time{}, err
	}
	for _, key := range netBirdUnderlaySteps {
		if journal.Requests[key].VerifiedAt.IsZero() {
			return zero, time.Time{}, ErrNetBirdUnderlayPending
		}
		if err := observeNetBirdUnderlayRequest(ctx, client, journal, key); err != nil {
			return zero, time.Time{}, err
		}
	}
	if err := purpose.Revalidate(ctx); err != nil {
		return zero, time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return zero, time.Time{}, err
	}
	expires := journal.ExpiresAt
	if expected.ExpiresAt.Before(expires) {
		expires = expected.ExpiresAt
	}
	return journal, expires, nil
}
