package rootsecret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

// NetBirdStartupCustody retains the actual original writer's root process and
// accepted source. It grants no NATS, account effect or credential authority.
type NetBirdStartupCustody struct {
	original context.Context
	lifetime context.Context
	cancel   context.CancelFunc
	reader   *bootstrapstart.CurrentFounderAuthorityReader
	accepted bootstrapstart.AcceptedIdentity
	marker   []byte
	process  *rootoci.ProcessWitness
	binding  string
	binary   bootstrapstart.RunningBinary
	trust    [sha256.Size]byte
	source   [sha256.Size]byte
	home     *region.HomeIAMAuthority
	underlay region.VerifiedNetBirdJournalUnderlay
	expires  time.Time
}

// NewNetBirdStartupCustody accepts only the retained root process that passed
// installed restart admission; paths and release layout are fixed internally.
func NewNetBirdStartupCustody(ctx, original context.Context, process *rootoci.ProcessWitness, reader *bootstrapstart.CurrentFounderAuthorityReader,
	accepted bootstrapstart.AcceptedIdentity, home *region.HomeIAMAuthority, underlay region.VerifiedNetBirdJournalUnderlay,
) (*NetBirdStartupCustody, error) {
	if ctx == nil || original == nil || ctx.Err() != nil || original.Err() != nil || original.Done() == nil || reader == nil || home == nil ||
		accepted.Validate() != nil || accepted.Cell != "GRU" || accepted.Slot != "controller-a" || accepted.SeedSlot != accepted.Slot || !underlay.IsVerified() {
		return nil, ErrDelivery
	}
	expires := minDeadline(underlay.ExpiresAt(), underlay.Purpose().ExpiresAt)
	if deadline, ok := original.Deadline(); ok {
		expires = minDeadline(expires, deadline)
	}
	ctx, cancel := netBirdStartupReadContext(ctx, original, expires)
	defer cancel()
	if err := checkNetBirdStartupProcess(process, ""); err != nil {
		return nil, err
	}
	marker, err := bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil || checkNetBirdStartupMarker(marker) != nil {
		return nil, ErrDelivery
	}
	underlayDeadline, err := underlay.CurrentDeadline(ctx)
	if err != nil {
		return nil, err
	}
	expires = minDeadline(expires, underlayDeadline)
	ctx, cancelUnderlay := context.WithDeadline(ctx, expires)
	defer cancelUnderlay()
	purpose := underlay.Purpose()
	if purpose.Validate() != nil || purpose.DeploymentID != accepted.DeploymentID || purpose.ClusterID != accepted.ClusterID || purpose.Environment != accepted.Environment ||
		underlay.WriterInstanceID() != accepted.InstanceOCID || underlay.WriterVNICID() != accepted.PrimaryVNICOCID ||
		underlay.WriterPrivateIP() != accepted.PrimaryPrivateIP || home.StorageDomain() != purpose.Storage {
		return nil, ErrDelivery
	}
	homeDeadline, err := home.FoundationWriterDeadlineForOperation(ctx, original)
	if err != nil {
		return nil, err
	}
	expires = minDeadline(expires, homeDeadline)
	ctx, cancelHome := context.WithDeadline(ctx, expires)
	defer cancelHome()
	principal, err := home.InstancePrincipal(ctx)
	if err != nil || principal != accepted.InstanceOCID {
		return nil, ErrDelivery
	}
	source, sourceDeadline, err := observeNetBirdStartupSource(ctx, reader, accepted, underlay)
	if err != nil {
		return nil, err
	}
	expires = minDeadline(expires, sourceDeadline)
	ctx, cancelSource := context.WithDeadline(ctx, expires)
	defer cancelSource()
	inputs, err := bootstrapstart.LoadTrustInputs(accepted)
	if err != nil {
		return nil, err
	}
	trust, err := netBirdStartupDigest([]any{inputs.ChainIdentity, inputs.Genesis, inputs.Chain})
	if err != nil {
		return nil, err
	}
	measured, err := bootstrapstart.ReadVerifiedRestartProcessBinary(ctx, process.Peer().PID, accepted, selfupdate.NewLayout(selfupdate.DefaultRoot), inputs.Roots.Historical)
	if err != nil || checkNetBirdStartupProcess(process, process.Binding()) != nil || checkNetBirdStartupMarker(marker) != nil {
		return nil, ErrDelivery
	}
	if original.Err() != nil || ctx.Err() != nil || !time.Now().Before(expires) {
		return nil, ErrDelivery
	}
	lifetime, stop := context.WithDeadline(original, expires)
	custody := &NetBirdStartupCustody{original: original, lifetime: lifetime, cancel: stop, reader: reader, accepted: accepted.Clone(), marker: bytes.Clone(marker),
		process: process, binding: process.Binding(), binary: measured, trust: trust, source: source, home: home, underlay: underlay, expires: expires}
	if err := custody.Guard(ctx); err != nil {
		custody.Close()
		return nil, err
	}
	return custody, nil
}

func (custody *NetBirdStartupCustody) Context() context.Context {
	if custody == nil {
		return nil
	}
	return custody.lifetime
}

func (custody *NetBirdStartupCustody) ExpiresAt() time.Time {
	if custody == nil {
		return time.Time{}
	}
	return custody.expires
}

func (custody *NetBirdStartupCustody) Close() error {
	if custody != nil && custody.cancel != nil {
		custody.cancel()
	}
	return nil
}

// Guard rechecks the same source and measured process without adopting replacements.
func (custody *NetBirdStartupCustody) Guard(ctx context.Context) error {
	_, err := custody.CurrentDeadline(ctx)
	return err
}

// CurrentDeadline returns the current minimum without changing the first expiry
// or retaining a temporary operation deadline.
func (custody *NetBirdStartupCustody) CurrentDeadline(ctx context.Context) (time.Time, error) {
	if custody == nil || ctx == nil || custody.original == nil || custody.original.Err() != nil || custody.lifetime == nil || custody.lifetime.Err() != nil || custody.reader == nil || custody.home == nil ||
		!time.Now().Before(custody.expires) || checkNetBirdStartupProcess(custody.process, custody.binding) != nil {
		return time.Time{}, ErrDelivery
	}
	ctx, cancel := netBirdStartupReadContext(ctx, custody.lifetime, custody.expires)
	defer cancel()
	if checkNetBirdStartupMarker(custody.marker) != nil {
		return time.Time{}, ErrDelivery
	}
	homeDeadline, err := custody.home.FoundationWriterDeadlineForOperation(ctx, custody.lifetime)
	if err != nil {
		return time.Time{}, err
	}
	expires := minDeadline(custody.expires, homeDeadline)
	ctx, cancelHome := context.WithDeadline(ctx, expires)
	defer cancelHome()
	underlayDeadline, err := custody.underlay.CurrentDeadline(ctx)
	if err != nil {
		return time.Time{}, err
	}
	expires = minDeadline(expires, underlayDeadline)
	ctx, cancelUnderlay := context.WithDeadline(ctx, expires)
	defer cancelUnderlay()
	source, sourceDeadline, err := observeNetBirdStartupSource(ctx, custody.reader, custody.accepted, custody.underlay)
	if err != nil || source != custody.source {
		return time.Time{}, ErrDelivery
	}
	expires = minDeadline(expires, sourceDeadline)
	ctx, cancelSource := context.WithDeadline(ctx, expires)
	defer cancelSource()
	inputs, err := bootstrapstart.LoadTrustInputs(custody.accepted)
	if err != nil {
		return time.Time{}, err
	}
	trust, err := netBirdStartupDigest([]any{inputs.ChainIdentity, inputs.Genesis, inputs.Chain})
	if err != nil || trust != custody.trust {
		return time.Time{}, ErrDelivery
	}
	measured, err := bootstrapstart.ReadVerifiedRestartProcessBinary(ctx, custody.process.Peer().PID, custody.accepted,
		selfupdate.NewLayout(selfupdate.DefaultRoot), inputs.Roots.Historical)
	if err != nil || measured != custody.binary || checkNetBirdStartupProcess(custody.process, custody.binding) != nil || checkNetBirdStartupMarker(custody.marker) != nil {
		return time.Time{}, ErrDelivery
	}
	if custody.original.Err() != nil || custody.lifetime.Err() != nil || ctx.Err() != nil || !time.Now().Before(expires) {
		return time.Time{}, ErrDelivery
	}
	return expires, nil
}

func checkNetBirdStartupProcess(process *rootoci.ProcessWitness, binding string) error {
	if os.Geteuid() != 0 || process == nil || process.Verify() != nil || process.Peer().PID != os.Getpid() ||
		process.Peer().UID != 0 || process.Peer().GID != 0 || process.Cgroup() == "" || process.Binding() == "" || binding != "" && process.Binding() != binding {
		return ErrDelivery
	}
	return nil
}

func checkNetBirdStartupMarker(expected []byte) error {
	current, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return err
	}
	wire, err := bootstrapstart.EncodeAcceptedIdentity(current)
	if err != nil || !bytes.Equal(wire, expected) {
		return ErrDelivery
	}
	return nil
}

func observeNetBirdStartupSource(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity,
	underlay region.VerifiedNetBirdJournalUnderlay,
) ([sha256.Size]byte, time.Time, error) {
	selected, err := reader.ReadCurrent(ctx, time.Now().UTC())
	if err != nil || selected.Plan == nil || !selected.Plan.IsVerified() || !selected.Anchor.IsVerified() {
		return [sha256.Size]byte{}, time.Time{}, ErrDelivery
	}
	expires := minDeadline(selected.SelectionExpiresAt, selected.Anchor.ExpiresAt())
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	runtime, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil || runtime.Anchor().Digest() != selected.Anchor.Digest() || runtime.Identity().InstanceID != underlay.WriterInstanceID() ||
		runtime.Identity().PrivateIP != underlay.WriterPrivateIP() || runtime.Identity().Slot != "controller-a" || runtime.Identity().SeedSlot != "controller-a" || runtime.Identity().OCIRegion != "sa-saopaulo-1" {
		return [sha256.Size]byte{}, time.Time{}, ErrDelivery
	}
	confirmed, err := reader.ReadCurrent(ctx, time.Now().UTC())
	if err != nil || confirmed.Plan == nil || confirmed.SelectionGeneration != selected.SelectionGeneration ||
		confirmed.SelectionSHA256 != selected.SelectionSHA256 || confirmed.Plan.Digest() != selected.Plan.Digest() || confirmed.Anchor.Digest() != selected.Anchor.Digest() {
		return [sha256.Size]byte{}, time.Time{}, ErrDelivery
	}
	scope, err := runtime.Anchor().FoundationScope()
	if err != nil || scope.GrantSHA256 != underlay.GrantDigest() || scope.InstallationID != underlay.Purpose().InstallationID || scope.StorageDomain != underlay.Purpose().Storage {
		return [sha256.Size]byte{}, time.Time{}, ErrDelivery
	}
	snapshot, err := netBirdStartupDigest(struct {
		Generation                     uint64
		Selection, Plan, Anchor        string
		PlanWire, AnchorWire           []byte
		Manifests                      map[string][]byte
		Runtime                        bootstrapstart.RuntimeIdentity
		SelectionExpiry, RuntimeExpiry time.Time
	}{selected.SelectionGeneration, selected.SelectionSHA256, selected.Plan.Digest(), selected.Anchor.Digest(),
		selected.PlanWire, selected.AnchorWire, selected.ManifestWires, runtime.Identity(), selected.SelectionExpiresAt, runtime.ExpiresAt()})
	if err != nil || ctx.Err() != nil {
		return [sha256.Size]byte{}, time.Time{}, ErrDelivery
	}
	return snapshot, minDeadline(expires, runtime.ExpiresAt()), nil
}

func netBirdStartupDigest(value any) ([sha256.Size]byte, error) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return [sha256.Size]byte{}, ErrDelivery
	}
	return sha256.Sum256(wire), nil
}

func netBirdStartupReadContext(ctx, original context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	if until, ok := original.Deadline(); ok {
		deadline = minDeadline(deadline, until)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(original, cancel)
	if original.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}
