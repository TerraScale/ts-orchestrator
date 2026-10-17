package rootsecret

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// NetBirdJournalSource retains the same original public source and native route.
// It grants no credential, listener, reservation or account effect authority.
type NetBirdJournalSource struct {
	public    NetBirdBrokerSource
	readonly  NetBirdBrokerSource
	recipient region.VerifiedNetBirdManagerRecipient
	purpose   bootstrap.VerifiedNetBirdJournalPurpose
	underlay  region.VerifiedNetBirdJournalUnderlay
	custody   *NetBirdStartupCustody
	manager   *region.VerifiedNetBirdManager
	original  context.Context
	expires   time.Time
}

func (s NetBirdJournalSource) Source() NetBirdBrokerSource                       { return s.public }
func (s NetBirdJournalSource) Recipient() region.VerifiedNetBirdManagerRecipient { return s.recipient }
func (s NetBirdJournalSource) Purpose() bootstrap.VerifiedNetBirdJournalPurpose  { return s.purpose }
func (s NetBirdJournalSource) Underlay() region.VerifiedNetBirdJournalUnderlay   { return s.underlay }
func (s NetBirdJournalSource) Context() context.Context                          { return s.original }
func (s NetBirdJournalSource) ExpiresAt() time.Time                              { return s.expires }

// BrokerSource is the authenticated original readonly slot, without locators.
func (s NetBirdJournalSource) BrokerSource() NetBirdBrokerSource { return s.readonly }

// ForBrokerMaterial authenticates the retained readonly slot under the writer's
// frozen source. It never resolves overlay routes or adopts a successor CURRENT.
func (s NetBirdJournalSource) ForBrokerMaterial(ctx context.Context, material NetBirdBrokerMaterial) (NetBirdJournalSource, error) {
	if (material.Schema != 1 && material.Schema != 2) || (material.Schema == 2 && len(material.Endpoints) != 0) || s.Guard(ctx) != nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	readonly := s.readonly
	if readonly.startup.IsVerified() {
		if readonly.startup.Manifest().Slot != material.StartupSlot {
			return NetBirdJournalSource{}, ErrDelivery
		}
	} else {
		var err error
		readonly, err = s.public.forPublicStartupSlot(ctx, material.StartupSlot)
		if err != nil {
			return NetBirdJournalSource{}, ErrDelivery
		}
	}
	material.Schema, material.Endpoints = 1, nil
	if _, _, err := CheckNetBirdBrokerMaterial(material, readonly, s.recipient, time.Now().UTC()); err != nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	s.readonly = readonly
	s.expires = minDeadline(s.expires, minDeadline(readonly.ExpiresAt(), material.ExpiresAt))
	if s.Guard(ctx) != nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	return s, nil
}

// LoadNetBirdJournalSourceForOperation is the original writer's early source.
// Its lifetime comes exclusively from actual admitted root process custody.
func LoadNetBirdJournalSourceForOperation(ctx context.Context, custody *NetBirdStartupCustody, factory *ociclient.Factory) (NetBirdJournalSource, error) {
	if custody == nil || custody.Context() == nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	deadline, err := custody.CurrentDeadline(ctx)
	if err != nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	ctx, cancel := netBirdReadContext(ctx, custody.Context(), deadline)
	defer cancel()
	s, err := loadNetBirdJournalPublicSource(ctx, custody.Context(), factory, custody.underlay)
	if err != nil {
		return NetBirdJournalSource{}, err
	}
	s.custody = custody
	s.expires = minDeadline(s.expires, deadline)
	startup, accepted := s.public.startup, custody.accepted
	selected, err := custody.reader.ReadCurrent(ctx, time.Now().UTC())
	if err != nil || startup.Digest() != netBirdDigest(selected.ManifestWires[accepted.Slot]) || startup.AnchorDigest() != selected.Anchor.Digest() ||
		startup.Manifest().DeploymentID != accepted.DeploymentID || startup.Manifest().ClusterID != accepted.ClusterID ||
		startup.Manifest().Environment != accepted.Environment || s.underlay.WriterInstanceID() != accepted.InstanceOCID ||
		s.underlay.WriterVNICID() != accepted.PrimaryVNICOCID || s.underlay.WriterPrivateIP() != accepted.PrimaryPrivateIP || s.Guard(ctx) != nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	return s, nil
}

// LoadNetBirdJournalManagerSourceForOperation authenticates the dedicated local
// manager before overlay startup. NET separately retains actual process custody.
func LoadNetBirdJournalManagerSourceForOperation(ctx, original context.Context, factory *ociclient.Factory, local region.VerifiedNetBirdManager, underlay region.VerifiedNetBirdJournalUnderlay) (NetBirdJournalSource, error) {
	if ctx == nil || original == nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	ctx, cancel := netBirdReadContext(ctx, original, local.ExpiresAt())
	defer cancel()
	if local.Check(ctx) != nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	s, err := loadNetBirdJournalPublicSource(ctx, original, factory, underlay)
	if err != nil {
		return NetBirdJournalSource{}, err
	}
	s.manager = &local
	s.expires = minDeadline(s.expires, local.ExpiresAt())
	if s.Guard(ctx) != nil {
		return NetBirdJournalSource{}, ErrDelivery
	}
	return s, nil
}

func loadNetBirdJournalPublicSource(ctx, original context.Context, factory *ociclient.Factory, underlay region.VerifiedNetBirdJournalUnderlay) (NetBirdJournalSource, error) {
	var s NetBirdJournalSource
	if ctx == nil || original == nil || original.Err() != nil || factory == nil || factory.Region() != "sa-saopaulo-1" || !underlay.IsVerified() {
		return s, ErrDelivery
	}
	deadline, err := underlay.CurrentDeadline(ctx)
	if err != nil {
		return s, ErrDelivery
	}
	ctx, cancel := netBirdReadContext(ctx, original, deadline)
	defer cancel()
	purpose, err := underlay.BootstrapPurpose(ctx)
	if err != nil {
		return s, ErrDelivery
	}
	deadline = minDeadline(deadline, purpose.ExpiresAt())
	ctx, cancelPurpose := context.WithDeadline(ctx, deadline)
	defer cancelPurpose()
	public, err := loadNetBirdPublicSourceForOperation(ctx, original, factory, "GRU", "controller-a")
	if err != nil || purpose.MatchesStartup(ctx, public.startup) != nil {
		return s, ErrDelivery
	}
	deadline = minDeadline(deadline, public.ExpiresAt())
	ctx, cancelSource := context.WithDeadline(ctx, deadline)
	defer cancelSource()
	recipient, err := region.VerifyNetBirdManagerRecipientForOperation(ctx, original, factory, public.resolver, public.source)
	if err != nil || recipient.InstanceID() != underlay.ManagerInstanceID() || recipient.PrivateIP() != purpose.Purpose().Underlay.ManagerPrivateIP ||
		recipient.GrantDigest() != purpose.GrantDigest() || public.startup.TemplateDigest() != purpose.TemplateDigest() ||
		public.startup.Manifest().Cell != "GRU" || public.startup.Manifest().Slot != "controller-a" ||
		public.startup.Manifest().SeedSlot != "controller-a" || public.source.StorageDomain() != purpose.Purpose().Storage {
		return s, ErrDelivery
	}
	deadline = minDeadline(deadline, recipient.ExpiresAt())
	if until, ok := original.Deadline(); ok {
		deadline = minDeadline(deadline, until)
	}
	if ctx.Err() != nil || original.Err() != nil || !time.Now().Before(deadline) {
		return s, ErrDelivery
	}
	return NetBirdJournalSource{public: public, recipient: recipient, purpose: purpose, underlay: underlay, original: original, expires: deadline}, nil
}

func (s NetBirdJournalSource) Guard(ctx context.Context) error {
	_, err := s.CurrentDeadline(ctx)
	return err
}

// CurrentDeadline communicates every newly shorter genuine cap to signing and
// waits without retaining the caller's temporary operation deadline.
func (s NetBirdJournalSource) CurrentDeadline(ctx context.Context) (time.Time, error) {
	if ctx == nil || s.original == nil || s.original.Err() != nil || s.expires.IsZero() || !time.Now().Before(s.expires) ||
		(s.custody == nil) == (s.manager == nil) {
		return time.Time{}, ErrDelivery
	}
	ctx, cancel := netBirdReadContext(ctx, s.original, s.expires)
	defer cancel()
	deadline, err := s.underlay.CurrentDeadline(ctx)
	if err != nil {
		return time.Time{}, ErrDelivery
	}
	deadline = minDeadline(s.expires, minDeadline(deadline, minDeadline(s.public.ExpiresAt(), s.recipient.ExpiresAt())))
	ctx, cancelRoute := context.WithDeadline(ctx, deadline)
	defer cancelRoute()
	if s.public.guardPublicSource(ctx) != nil || s.recipient.Check(ctx) != nil || s.purpose.MatchesStartup(ctx, s.public.startup) != nil {
		return time.Time{}, ErrDelivery
	}
	if s.readonly.startup.IsVerified() {
		deadline = minDeadline(deadline, s.readonly.ExpiresAt())
		var cancelReadonly context.CancelFunc
		ctx, cancelReadonly = context.WithDeadline(ctx, deadline)
		defer cancelReadonly()
		if s.readonly.guardPublicSource(ctx) != nil {
			return time.Time{}, ErrDelivery
		}
	}
	if s.custody != nil {
		current, err := s.custody.CurrentDeadline(ctx)
		if err != nil {
			return time.Time{}, ErrDelivery
		}
		deadline = minDeadline(deadline, current)
	} else {
		deadline = minDeadline(deadline, s.manager.ExpiresAt())
		ctx, cancelManager := context.WithDeadline(ctx, deadline)
		defer cancelManager()
		if s.manager.Check(ctx) != nil || s.manager.StoreGeneration() != s.recipient.StoreGeneration() || s.manager.VaultTarget() != s.recipient.VaultTarget() {
			return time.Time{}, ErrDelivery
		}
		instance, err := bootstrapstart.NewIMDSClient().FetchInstanceID(ctx)
		if err != nil || instance != s.recipient.InstanceID() || instance != s.underlay.ManagerInstanceID() {
			return time.Time{}, ErrDelivery
		}
	}
	if ctx.Err() != nil || s.checkOriginal() != nil || !time.Now().Before(deadline) {
		return time.Time{}, ErrDelivery
	}
	return deadline, nil
}

// checkOriginal seals retained cancellation after the final blocking check. It
// supplies no currentness authority and never replaces CurrentDeadline.
func (s NetBirdJournalSource) checkOriginal() error {
	if s.original == nil || s.original.Err() != nil || s.expires.IsZero() || !time.Now().Before(s.expires) ||
		s.underlay.CheckOriginal() != nil || s.recipient.CheckOriginal() != nil || s.public.snapshot == nil ||
		s.public.snapshot.Context() == nil || s.public.snapshot.Context().Err() != nil {
		return ErrDelivery
	}
	if s.readonly.startup.IsVerified() && (s.readonly.snapshot == nil || s.readonly.snapshot.Context() == nil || s.readonly.snapshot.Context().Err() != nil || !time.Now().Before(s.readonly.ExpiresAt())) {
		return ErrDelivery
	}
	if (s.custody == nil) == (s.manager == nil) {
		return ErrDelivery
	}
	if s.custody != nil {
		if s.custody.original == nil || s.custody.original.Err() != nil || s.custody.Context() == nil || s.custody.Context().Err() != nil || !time.Now().Before(s.custody.ExpiresAt()) {
			return ErrDelivery
		}
	} else if s.manager.CheckOriginal() != nil {
		return ErrDelivery
	}
	return nil
}
