package region

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// OriginalNetBirdOCIRSession retains the original authenticated user. A manager
// instance proof cannot construct this producer or acquire its home IAM lease.
type OriginalNetBirdOCIRSession struct {
	authority *HomeIAMAuthority
	reader    *SignedFootprint
	scopes    [3]VerifiedOCIRIssuer
	original  FoundationRecord
	deadline  time.Time
}

func NewOriginalNetBirdOCIRSession(ctx context.Context, factory *ociclient.Factory, roots trust.Keyring, bundle RetainedFoundation) (*OriginalNetBirdOCIRSession, error) {
	if ctx == nil || factory == nil || len(roots) == 0 {
		return nil, ErrOriginalSourceProducerHold
	}
	authority, resolver, err := newOperatorHomeIAMAuthority(ctx, factory, roots, bundle)
	if err != nil {
		return nil, err
	}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || authority.operator == nil {
		return nil, ErrOriginalSourceProducerHold
	}
	session := &OriginalNetBirdOCIRSession{authority: authority, reader: reader, deadline: authority.operator.deadline}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(session.deadline) {
		session.deadline = deadline
	}
	state, err := session.current(ctx)
	if err != nil {
		return nil, err
	}
	session.scopes, err = originalNetBirdOCIRIssuers(state)
	if err != nil {
		return nil, err
	}
	session.original = state.record
	for _, scope := range session.scopes {
		if scope.ExpiresAt().Before(session.deadline) {
			session.deadline = scope.ExpiresAt()
		}
	}
	if err := session.Guard(ctx, session.scopes[0]); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *OriginalNetBirdOCIRSession) Scopes() [3]VerifiedOCIRIssuer {
	if s == nil {
		return [3]VerifiedOCIRIssuer{}
	}
	return s.scopes
}

func (s *OriginalNetBirdOCIRSession) current(ctx context.Context) (originalNetBirdState, error) {
	if s == nil || s.authority == nil || s.authority.operator == nil || s.reader == nil || ctx == nil ||
		ctx.Err() != nil || !time.Now().Before(s.deadline) {
		return originalNetBirdState{}, ErrOriginalSourceProducerHold
	}
	ctx = ociclient.CheckpointContext(ctx)
	if err := s.authority.Guard(ctx, 0); err != nil {
		return originalNetBirdState{}, err
	}
	state, err := s.reader.originalNetBirdStateFromBundle(ctx, s.authority.resolver, s.authority.operator.bundle)
	if err != nil {
		return originalNetBirdState{}, err
	}
	a, intent, err := s.authority.netBirdMaterialScope(state.grant)
	if err != nil {
		return originalNetBirdState{}, err
	}
	if err := s.authority.checkNetBirdMaterialBirth(state.record, state.grant, a, intent); err != nil {
		return originalNetBirdState{}, err
	}
	if err := s.authority.checkOriginalSourceProducerBirth(ctx); err != nil {
		return originalNetBirdState{}, err
	}
	if err := s.authority.checkNetBirdMaterialOrigins(ctx, state.grant); err != nil {
		return originalNetBirdState{}, err
	}
	if err := s.authority.Guard(ctx, 0); err != nil {
		return originalNetBirdState{}, err
	}
	if !time.Now().Before(s.deadline) {
		return originalNetBirdState{}, ErrOriginalSourceProducerHold
	}
	return state, nil
}

func (s *OriginalNetBirdOCIRSession) Guard(ctx context.Context, scope VerifiedOCIRIssuer) error {
	_, _, err := s.read(ctx, scope)
	return err
}

func (s *OriginalNetBirdOCIRSession) read(ctx context.Context, scope VerifiedOCIRIssuer) (FoundationRecord, string, error) {
	state, err := s.current(ctx)
	if err != nil {
		return FoundationRecord{}, "", err
	}
	scopes, err := originalNetBirdOCIRIssuers(state)
	if err != nil {
		return FoundationRecord{}, "", err
	}
	matched := false
	for index, expected := range scopes {
		if !sameOriginalNetBirdIssuer(expected, s.scopes[index]) {
			return FoundationRecord{}, "", ErrOriginalSourceProducerHold
		}
		matched = matched || sameOriginalNetBirdIssuer(expected, scope)
	}
	r := state.record
	if !matched || r.Cell != "GRU" || r.OCIRegion != foundationHomeRegion || r.Stage != "original-foundation" || !r.netBirdMaterialOnly() ||
		r.TenancyID != s.original.TenancyID || r.Generation != s.original.Generation || r.Epoch != s.original.Epoch ||
		r.OperationID != s.original.OperationID || r.GrantSHA256 != s.original.GrantSHA256 || r.IntentDigest != s.original.IntentDigest ||
		r.OriginalFoundationCompartments == nil || s.original.OriginalFoundationCompartments == nil ||
		r.OriginalFoundationCompartments.BundleSHA256 != s.original.OriginalFoundationCompartments.BundleSHA256 {
		return FoundationRecord{}, "", ErrOriginalSourceProducerHold
	}
	return r, state.etag, nil
}

func sameOriginalNetBirdIssuer(a, b VerifiedOCIRIssuer) bool {
	return a.IsVerified() && b.IsVerified() && a.Intent() == b.Intent() && a.TenancyID() == b.TenancyID() &&
		a.InstallationID() == b.InstallationID() && a.Generation() == b.Generation() && a.GrantDigest() == b.GrantDigest() && a.ExpiresAt().Equal(b.ExpiresAt())
}

func (s *OriginalNetBirdOCIRSession) Journal(ctx context.Context, scope VerifiedOCIRIssuer) (*OriginalNetBirdIssuerJournal, error) {
	if err := s.Guard(ctx, scope); err != nil {
		return nil, err
	}
	return &OriginalNetBirdIssuerJournal{session: s, scope: scope}, nil
}

func (s *OriginalNetBirdOCIRSession) HomeWrite(ctx context.Context) (context.Context, func(), error) {
	if s == nil {
		return ctx, nil, ErrOriginalSourceProducerHold
	}
	if err := s.Guard(ctx, s.scopes[0]); err != nil {
		return ctx, nil, err
	}
	limited, cancel := context.WithDeadline(ctx, s.deadline)
	leased, release, err := s.authority.HomeWrite(limited, s.original.Epoch)
	if err != nil {
		cancel()
		return ctx, nil, err
	}
	return leased, func() { release(); cancel() }, nil
}
