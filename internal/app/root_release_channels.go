package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// rootReleaseChannels is constructed only by the privileged runtime supervisor.
// Its concrete dependencies never come from the ordinary runtime or socket.
type rootReleaseChannels struct {
	*rootrelease.Backend
	cfg         Config
	factory     *ociclient.Factory
	sources     rootrelease.Sources
	js          jetstream.JetStream
	board       jetstream.KeyValue
	proofs      *rolloutexec.Collector
	controllers []rollout.Unit
	ctx         context.Context
	mu          sync.Mutex
	bound       bool
	keys        rolloutexec.KeyResolver
	proofWires  map[string][]byte
}

var _ rootoci.Releases = (*rootReleaseChannels)(nil)

func newRootReleaseChannels(ctx context.Context, cfg Config, factory *ociclient.Factory, containers *rootrelease.Backend, founder *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (*rootReleaseChannels, error) {
	if os.Geteuid() != 0 || ctx == nil || factory == nil || containers == nil || founder == nil || accepted.Validate() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	if _, _, _, err := loadSignedManagedControllerConfig(cfg); err != nil {
		return nil, err
	}
	wire, err := cfg.signedWire()
	if err != nil {
		return nil, err
	}
	cfg, err = decodeConfig(bytes.Clone(wire))
	if err != nil {
		return nil, err
	}
	return &rootReleaseChannels{Backend: containers, cfg: cfg, factory: factory, ctx: ctx, sources: rootrelease.Sources{Authority: founder, Accepted: accepted.Clone()}}, nil
}

func (b *rootReleaseChannels) Bind(ctx context.Context, conn *nats.Conn, sources rootrelease.Sources) error {
	if b == nil {
		return rootoci.ErrUnauthorized
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if os.Geteuid() != 0 || b.bound || conn == nil || sources.Authority != b.sources.Authority || sources.Accepted.Validate() != nil || sources.Hosts == nil || sources.Leases == nil || sources.Intents == nil || sources.Node == nil || sources.Roots == nil || sources.Specs == nil {
		return rootoci.ErrUnauthorized
	}
	if sources.Specs.Bucket() != cellSpecBucket || sources.Roots.Bucket() != rootChainBucket {
		return rootoci.ErrInvalid
	}
	want, err := bootstrapstart.EncodeAcceptedIdentity(b.sources.Accepted)
	if err != nil {
		return err
	}
	actual, err := bootstrapstart.EncodeAcceptedIdentity(sources.Accepted)
	if err != nil || !bytes.Equal(want, actual) {
		return rootoci.ErrUnauthorized
	}
	sources.Accepted = sources.Accepted.Clone()
	cfg, factory := b.cfg, b.factory
	source, err := sources.Authority.ReadRuntimeAuthority(ctx, sources.Accepted, time.Now().UTC())
	if err != nil {
		return err
	}
	identity := source.Identity()
	if identity.OCIRegion != factory.Region() || cfg.NATS.Cell != strings.ToLower(identity.Cell) || cfg.NATS.Instance != identity.Slot {
		return rootoci.ErrUnauthorized
	}
	slots := slices.Clone(source.Anchor().Anchor().ControllerSlots)
	if len(slots) != 3 || !slices.Equal(slots, sources.Accepted.ControllerSlots) {
		return rootoci.ErrUnauthorized
	}
	controllers, err := rolloutexec.ControllerUnits(slots, identity.SeedSlot)
	if err != nil {
		return err
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(sources.Accepted)
	if err != nil {
		return err
	}
	bundle, err := hostenroll.ParsePublicBundle(launch.HostEnrollment)
	if err != nil {
		return err
	}
	public, err := bundle.ResponsePublicKey()
	if err != nil {
		return err
	}
	keys, err := trust.ParseKeyring(ed25519.PublicKey(public))
	if err != nil {
		return err
	}
	js, err := jetstream.New(conn)
	if err != nil {
		return err
	}
	board, err := js.KeyValue(ctx, rollout.Bucket)
	if err != nil {
		return err
	}
	b.sources, b.js, b.board, b.controllers = sources, js, board, controllers
	b.sources.Accepted = sources.Accepted.Clone()
	b.proofWires = map[string][]byte{}
	b.keys = func(unit string) (trust.Keyring, error) {
		if slices.Contains(slots, unit) {
			return keys, nil
		}
		readCtx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		defer cancel()
		if _, err := sources.Authority.ReadRuntimeAuthority(readCtx, sources.Accepted, time.Now().UTC()); err != nil {
			return nil, err
		}
		hosts, err := sources.Hosts.ListHosts(readCtx)
		if err != nil {
			return nil, err
		}
		for _, status := range hosts {
			r := status.Registration
			if r.Node != unit || r.Cell != cfg.NATS.Cell || r.Environment != identity.Environment || status.Retired || !status.Verified || !time.Now().Before(status.SessionExpiresAt) {
				continue
			}
			entry, err := (rootReleaseKV{KeyValue: board, js: js}).Get(readCtx, rollout.HostMembershipKey(unit))
			if err != nil {
				return nil, err
			}
			var membership rollout.HostMembership
			if protocol.DecodeTolerant(entry.Value(), &membership, maxHostReply) != nil || membership.Node != unit || membership.PublicKey != r.PublicKey {
				return nil, rootoci.ErrUnauthorized
			}
			public, err := decodePublicKey(r.PublicKey)
			if err != nil {
				return nil, err
			}
			return trust.ParseKeyring(public)
		}
		return nil, rootoci.ErrUnauthorized
	}
	b.proofs = rolloutexec.NewCollector(cfg.NATS.Cell, b.keys, nil)
	subscription, err := conn.Subscribe(protocol.RolloutProofSubject(cfg.NATS.Cell, ""), func(msg *nats.Msg) {
		if b.proofs.Observe(msg.Subject, msg.Data) != nil {
			return
		}
		envelope, err := trust.DecodeEnvelope(msg.Data)
		if err != nil {
			return
		}
		var proof rolloutexec.HealthProof
		if protocol.DecodeStrict(envelope.Payload, &proof, trust.MaxPayloadBytes) != nil {
			return
		}
		latest, ok := b.proofs.Latest(proof.Unit)
		if !ok || latest.ProcessID != proof.ProcessID || latest.StartNonce != proof.StartNonce || !latest.ObservedAt.Equal(proof.ObservedAt) || latest.BinarySHA256 != proof.BinarySHA256 {
			return
		}
		b.mu.Lock()
		if len(b.proofWires) >= 4*rollout.MaxUnits {
			for unit := range b.proofWires {
				held, ok := b.proofs.Latest(unit)
				if !ok || time.Since(held.ReceivedAt) > rolloutexec.HealthLifetime+time.Minute {
					delete(b.proofWires, unit)
				}
			}
			if _, exists := b.proofWires[proof.Unit]; !exists && len(b.proofWires) >= 4*rollout.MaxUnits {
				b.mu.Unlock()
				return
			}
		}
		b.proofWires[proof.Unit] = bytes.Clone(msg.Data)
		b.mu.Unlock()
	})
	if err != nil {
		return err
	}
	flushCtx, flushCancel := context.WithTimeout(ctx, 5*time.Second)
	defer flushCancel()
	if err := conn.FlushWithContext(flushCtx); err != nil {
		_ = subscription.Unsubscribe()
		return err
	}
	context.AfterFunc(b.ctx, func() { _ = subscription.Unsubscribe() })
	if _, err := sources.Authority.ReadRuntimeAuthority(ctx, sources.Accepted, time.Now().UTC()); err != nil {
		_ = subscription.Unsubscribe()
		return err
	}
	b.bound = true
	return nil
}

type rootReleaseObservation struct {
	b                          *rootReleaseChannels
	call                       rootoci.Call
	source                     bootstrapstart.RuntimeAuthority
	lease                      *authority.LeaseAdmission
	registry                   *specRegistry
	rollouts                   *rollout.Reader
	channelKV                  rootReleaseKV
	rootWire, specWire         []byte
	rootRevision, specRevision uint64
	deadline                   time.Time
	scopeCtx                   context.Context
	cancel                     context.CancelFunc
	deadlineTimer              *time.Timer
	witnesses                  rootReleaseWitnesses
}

func (b *rootReleaseChannels) beginChannel(ctx context.Context, call rootoci.Call, operation rootoci.Operation) (context.Context, context.CancelFunc, *rootReleaseObservation, error) {
	if b == nil || os.Geteuid() != 0 || call.Operation() != operation || call.Deadline().IsZero() || b.ctx.Err() != nil {
		return ctx, func() {}, nil, rootoci.ErrUnauthorized
	}
	b.mu.Lock()
	bound := b.bound
	b.mu.Unlock()
	if !bound {
		return ctx, func() {}, nil, rootrelease.ErrPending
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	fail := func(err error) (context.Context, context.CancelFunc, *rootReleaseObservation, error) {
		return ctx, cancel, nil, errors.Join(rootrelease.ErrPending, err)
	}
	if err := call.Guard(ctx); err != nil {
		return fail(err)
	}
	if _, _, _, err := loadSignedManagedControllerConfig(b.cfg); err != nil {
		return fail(err)
	}
	source, err := b.sources.Authority.ReadRuntimeAuthority(ctx, b.sources.Accepted, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	ctx, stopSource := context.WithDeadline(ctx, source.ExpiresAt())
	stopCall := cancel
	cancel = func() {
		stopSource()
		stopCall()
	}
	identity := source.Identity()
	candidate := call.RuntimeID()
	if candidate == "" || identity.OCIRegion != b.factory.Region() || call.Expected().Cell != "" && !strings.EqualFold(call.Expected().Cell, identity.Cell) {
		return fail(rootoci.ErrUnauthorized)
	}
	lease, err := b.sources.Leases.AdmitRuntimeLease(ctx, identity.DeploymentID, candidate)
	if err != nil {
		return fail(err)
	}
	ctx, stopLease := context.WithDeadline(ctx, lease.Deadline())
	stopSources := cancel
	cancel = func() {
		stopLease()
		stopSources()
	}
	if expected := call.Expected().Epoch; expected != 0 && expected != lease.Epoch() {
		return fail(rootoci.ErrUnauthorized)
	}
	registry, err := newSpecRegistry(b.cfg, "")
	if err != nil {
		return fail(err)
	}
	registry.roots.path = ""
	observation := &rootReleaseObservation{b: b, call: call, source: source, lease: lease, registry: registry, scopeCtx: ctx, cancel: cancel, deadline: call.Deadline()}
	observation.capDeadline(source.ExpiresAt(), lease.Deadline())
	operationCancel := cancel
	cancel = func() {
		operationCancel()
		if observation.deadlineTimer != nil {
			observation.deadlineTimer.Stop()
		}
	}
	roots, err := (rootReleaseKV{KeyValue: b.sources.Roots, js: b.js}).Get(ctx, rootChainKey)
	if err != nil {
		return fail(err)
	}
	chain, err := trust.DecodeRootChain(roots.Value())
	if err != nil {
		return fail(err)
	}
	if err := registry.roots.adopt(chain); err != nil {
		return fail(err)
	}
	observation.rootRevision, observation.rootWire = roots.Revision(), bytes.Clone(roots.Value())
	registry.kv = rootReleaseKV{KeyValue: b.sources.Specs, js: b.js}
	entry, err := registry.kv.Get(ctx, cellSpecKey)
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return fail(err)
	}
	if err == nil {
		verified, err := registry.verify(entry.Value(), nil)
		if err != nil {
			return fail(err)
		}
		registry.current = verified.Spec
		observation.specRevision, observation.specWire = entry.Revision(), bytes.Clone(entry.Value())
	}
	board := observation.pinnedKV(b.board)
	observation.rollouts, err = rollout.BindReader(board, b.cfg.NATS.Cell)
	if err != nil {
		return fail(err)
	}
	channelKV, err := b.js.KeyValue(ctx, releasechannel.Bucket)
	if err != nil {
		return fail(err)
	}
	observation.channelKV = observation.pinnedKV(channelKV)
	ctx = ociclient.WithRequestGuard(ctx, observation.guard)
	return ctx, cancel, observation, observation.guard(ctx)
}

func earlierRootRelease(values ...time.Time) time.Time {
	var earliest time.Time
	for _, value := range values {
		if earliest.IsZero() || value.Before(earliest) {
			earliest = value
		}
	}
	return earliest
}

func (o *rootReleaseObservation) guard(ctx context.Context) error {
	if o == nil || ctx.Err() != nil || o.scopeCtx.Err() != nil || !time.Now().Before(o.deadline) || o.b.ctx.Err() != nil || o.witnesses.err != nil {
		return rootrelease.ErrPending
	}
	if err := o.call.Guard(ctx); err != nil {
		return err
	}
	if err := o.lease.Guard(ctx); err != nil {
		return err
	}
	if _, _, _, err := loadSignedManagedControllerConfig(o.b.cfg); err != nil {
		return err
	}
	if _, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(o.b.sources.Accepted); err != nil {
		return err
	}
	checkCtx, cancel := context.WithDeadline(o.scopeCtx, o.deadline)
	stop := context.AfterFunc(ctx, cancel)
	defer cancel()
	defer stop()
	current, err := o.b.sources.Authority.ReadRuntimeAuthority(checkCtx, o.b.sources.Accepted, time.Now().UTC())
	if err != nil || current.Identity() != o.source.Identity() || !time.Now().Before(current.ExpiresAt()) {
		return errors.Join(rootrelease.ErrPending, err)
	}
	for _, record := range []struct {
		kv       jetstream.KeyValue
		key      string
		revision uint64
		wire     []byte
	}{
		{o.b.sources.Roots, rootChainKey, o.rootRevision, o.rootWire}, {o.b.sources.Specs, cellSpecKey, o.specRevision, o.specWire},
	} {
		entry, err := (rootReleaseKV{KeyValue: record.kv, js: o.b.js}).Get(checkCtx, record.key)
		if errors.Is(err, jetstream.ErrKeyNotFound) && record.revision == 0 {
			continue
		}
		if err != nil || entry.Revision() != record.revision || !bytes.Equal(entry.Value(), record.wire) {
			return errors.Join(rootrelease.ErrPending, err)
		}
	}
	if err := o.call.Guard(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || o.scopeCtx.Err() != nil || !time.Now().Before(o.deadline) {
		return rootrelease.ErrPending
	}
	return nil
}

func (o *rootReleaseObservation) location(ctx context.Context) (releasechannel.Location, error) {
	if err := o.guard(ctx); err != nil {
		return releasechannel.Location{}, err
	}
	client, err := o.b.factory.ObjectStorage()
	if err != nil {
		return releasechannel.Location{}, err
	}
	response, err := client.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
	if err != nil || response.Value == nil || *response.Value == "" {
		return releasechannel.Location{}, errors.Join(rootrelease.ErrPending, err)
	}
	bucket, err := releasechannel.BucketName(o.source.Identity().Cell)
	return releasechannel.Location{Client: client, Namespace: *response.Value, Bucket: bucket}, err
}

func (b *rootReleaseChannels) ReconcileOrchestratorStatus(ctx context.Context, call rootoci.Call, request rootoci.OrchestratorStatusRequest) (rootoci.OrchestratorStatusReceipt, error) {
	ctx, cancel, o, err := b.beginChannel(ctx, call, rootoci.OperationReconcileOrchestratorStatus)
	defer cancel()
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	location, err := o.location(ctx)
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	channel, found, err := releasechannel.ReadChannel(ctx, location)
	if err != nil || !found {
		return rootoci.OrchestratorStatusReceipt{}, errors.Join(rootrelease.ErrPending, err)
	}
	wire, err := json.Marshal(channel, json.Deterministic(true))
	if err != nil || controllerSHA256(wire) != request.ExpectedChannelSHA256 {
		return rootoci.OrchestratorStatusReceipt{}, rootoci.ErrUnauthorized
	}
	verified, err := channel.Verify(o.registry.roots.current(), o.source.Identity().Cell, o.source.Identity().Environment, time.Now().UTC())
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	for _, binary := range verified {
		o.capDeadline(binary.ExpiresAt())
	}
	status := releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: o.source.Identity().Cell, Environment: o.source.Identity().Environment, Architectures: []string{goruntime.GOARCH}, SourceRevision: channel.SourceRevision, RunNumber: channel.RunNumber, ReleaseSequence: channel.ReleaseSequence, UpdatedAt: time.Now().UTC(), State: releasechannel.StateRolling, Reason: "waiting for the release's retained generation"}
	_, managed, _, err := loadSignedManagedControllerConfig(b.cfg)
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	architecture, err := managedImageArchitecture(ctx, managed)
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	if !slices.Contains(status.Architectures, architecture) {
		status.Architectures = append(status.Architectures, architecture)
		slices.Sort(status.Architectures)
	}
	history, err := o.rollouts.Retained(ctx)
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	desired, revision, err := o.rollouts.Desired(ctx)
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	var generation rollout.Release
	for _, retained := range history {
		if err := o.verifyRetained(retained); err != nil {
			return rootoci.OrchestratorStatusReceipt{}, err
		}
		if binary, ok := verified[goruntime.GOARCH]; ok && retained.Digest == binary.Receipt().SHA256 && retained.RunNumber == channel.RunNumber && retained.ReleaseSequence == channel.ReleaseSequence && retained.Generation <= desired.Generation() && retained.Generation > generation.Generation {
			generation = retained
		}
	}
	if generation.Generation != 0 {
		control := rolloutControl{cell: b.cfg.NATS.Cell}
		colocated := colocatedNodes(b.cfg.NATS.Cell, b.controllers, func(slot string) string { return o.registry.controllerNode(b.cfg.NATS.Cell, slot) })
		control.program = rolloutexec.ReleaseProgram{Proofs: rootChannelProofs{b: b, ctx: ctx, observation: o}, Controllers: b.controllers, Hosts: hostUnits(o.ListHosts, o.pinnedKV(b.board), colocated)}
		status.State, status.Reason, err = control.generationState(ctx, o.rollouts, generation)
		if err != nil {
			return rootoci.OrchestratorStatusReceipt{}, err
		}
		if status.State == releasechannel.StateComplete {
			units, err := control.program.Hosts(ctx)
			if err != nil {
				return rootoci.OrchestratorStatusReceipt{}, err
			}
			for _, unit := range append(slices.Clone(b.controllers), units...) {
				proof, ok := (rootChannelProofs{b: b, ctx: ctx, observation: o}).Latest(unit.ID)
				if !ok {
					return rootoci.OrchestratorStatusReceipt{}, rootrelease.ErrPending
				}
				o.capDeadline(proof.ReceivedAt.Add(rolloutexec.DefaultProofFreshness))
				b.mu.Lock()
				wire := bytes.Clone(b.proofWires[unit.ID])
				b.mu.Unlock()
				envelope, err := trust.DecodeEnvelope(wire)
				if err != nil {
					return rootoci.OrchestratorStatusReceipt{}, err
				}
				o.capDeadline(envelope.ExpiresAt)
			}
			hosts, err := o.ListHosts(ctx)
			if err != nil {
				return rootoci.OrchestratorStatusReceipt{}, err
			}
			for _, status := range hosts {
				if slices.ContainsFunc(units, func(unit rollout.Unit) bool { return unit.ID == status.Registration.Node }) {
					if !status.Verified || status.Retired {
						return rootoci.OrchestratorStatusReceipt{}, rootrelease.ErrPending
					}
					o.capDeadline(status.SessionExpiresAt)
				}
			}
		}
	}
	rollback, bad, err := o.rollouts.ReleasePins(ctx)
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	status.Pins = &releasechannel.ReleasePins{Rollback: rollback, KnownBad: bad}
	cell, _, err := o.rollouts.Cell(ctx)
	if err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	if cell.ActiveRolloutID != "" {
		if _, _, err := o.rollouts.Load(ctx, cell.ActiveRolloutID); err != nil {
			return rootoci.OrchestratorStatusReceipt{}, errors.Join(rootrelease.ErrPending, err)
		}
	}
	if err := o.verifyRollbackPins(rollback, history); err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	status.Reason = releasechannel.Clip(status.Reason)
	_, after, err := o.rollouts.Desired(ctx)
	if err != nil || revision != after {
		return rootoci.OrchestratorStatusReceipt{}, errors.Join(rootrelease.ErrPending, err)
	}
	if err := o.publishStatus(ctx, location, releasechannel.StatusObject, status, func(ctx context.Context) error {
		current, found, err := releasechannel.ReadChannel(ctx, location)
		if err != nil || !found {
			return errors.Join(rootrelease.ErrPending, err)
		}
		wire, err := json.Marshal(current, json.Deterministic(true))
		if err != nil || controllerSHA256(wire) != request.ExpectedChannelSHA256 {
			return errors.Join(rootrelease.ErrPending, err)
		}
		_, currentRevision, err := o.rollouts.Desired(ctx)
		if err != nil || currentRevision != revision {
			return errors.Join(rootrelease.ErrPending, err)
		}
		rollback, bad, err := o.rollouts.ReleasePins(ctx)
		if err != nil || !status.Pins.Equal(&releasechannel.ReleasePins{Rollback: rollback, KnownBad: bad}) {
			return errors.Join(rootrelease.ErrPending, err)
		}
		return o.validateWitnesses(ctx)
	}); err != nil {
		return rootoci.OrchestratorStatusReceipt{}, err
	}
	return rootoci.OrchestratorStatusReceipt{Status: status, ExpiresAt: o.deadline}, nil
}

func (o *rootReleaseObservation) retainedBinary(retained rollout.Release) (release.BinaryReceipt, error) {
	envelope, err := trust.DecodeEnvelope(retained.Receipt)
	if err != nil {
		return release.BinaryReceipt{}, errors.Join(rootrelease.ErrPending, err)
	}
	architecture, ok := strings.CutPrefix(envelope.Scope.Slot, "linux-")
	if !ok {
		return release.BinaryReceipt{}, rootoci.ErrUnauthorized
	}
	binary, err := release.VerifyBinaryUpdateHistorical(retained.Receipt, retained.Delegation, o.registry.roots.historical(), release.UpdateExpectation{Environment: o.source.Identity().Environment, Cell: o.source.Identity().Cell, Architecture: architecture})
	if err != nil || binary.Receipt().SHA256 != retained.Digest || binary.Receipt().SourceRevision != retained.SourceRevision {
		return release.BinaryReceipt{}, errors.Join(rootrelease.ErrPending, err)
	}
	var update release.BinaryUpdateReceipt
	if err := protocol.DecodeStrict(envelope.Payload, &update, trust.MaxPayloadBytes); err != nil {
		return release.BinaryReceipt{}, err
	}
	if update.ReleaseSequence != retained.ReleaseSequence || update.SequenceMigrationSHA256 != retained.SequenceMigrationSHA256 || update.Lineage.QualificationRunNum != retained.RunNumber {
		return release.BinaryReceipt{}, rootoci.ErrUnauthorized
	}
	return binary.Receipt(), nil
}

func (o *rootReleaseObservation) verifyRetained(retained rollout.Release) error {
	_, err := o.retainedBinary(retained)
	return err
}

func (o *rootReleaseObservation) verifyRollbackPins(pins []string, history []rollout.Release) error {
	for _, digest := range pins {
		if slices.ContainsFunc(history, func(retained rollout.Release) bool { return retained.Digest == digest }) {
			continue
		}
		receipt, delegation, err := bootstrapstart.LoadAcceptedManagedImageMaterial(o.b.sources.Accepted)
		if err != nil {
			return errors.Join(rootrelease.ErrPending, err)
		}
		image, err := release.VerifyImageHistorical(receipt, delegation, o.registry.roots.historical(), release.ImageExpectation{Environment: o.source.Identity().Environment, LogicalRegion: o.source.Identity().Cell, OCIImageOCID: o.b.sources.Accepted.ImageOCID})
		if err != nil || image.Receipt().BinarySHA256 != digest {
			return errors.Join(rootrelease.ErrPending, err)
		}
	}
	return nil
}

// rootReleaseKV reads the leader's retained record without enabling direct reads.
type rootReleaseKV struct {
	jetstream.KeyValue
	js    jetstream.JetStream
	guard func(context.Context) error
	pin   func(string, jetstream.KeyValueEntry, error) error
}

func (kv rootReleaseKV) Get(ctx context.Context, key string) (entry jetstream.KeyValueEntry, readErr error) {
	defer func() {
		if kv.pin != nil {
			if err := kv.pin(key, entry, readErr); err != nil {
				entry, readErr = nil, err
			}
		}
	}()
	if kv.guard != nil {
		if err := kv.guard(ctx); err != nil {
			return nil, err
		}
	}
	msg, err := nativeLeaderGet(ctx, kv.js, kv.Bucket(), key)
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, jetstream.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if msg.Subject != "$KV."+kv.Bucket()+"."+key || msg.Sequence == 0 || msg.Time.IsZero() {
		return nil, rootoci.ErrUnauthorized
	}
	if msg.Header.Get("KV-Operation") != "" || msg.Header.Get(jetstream.MarkerReasonHeader) != "" {
		return nil, jetstream.ErrKeyDeleted
	}
	return rootReleaseEntry{bucket: kv.Bucket(), key: key, msg: msg}, nil
}

type rootReleaseEntry struct {
	bucket, key string
	msg         *nats.RawStreamMsg
}

func (e rootReleaseEntry) Bucket() string                  { return e.bucket }
func (e rootReleaseEntry) Key() string                     { return e.key }
func (e rootReleaseEntry) Value() []byte                   { return e.msg.Data }
func (e rootReleaseEntry) Revision() uint64                { return e.msg.Sequence }
func (e rootReleaseEntry) Created() time.Time              { return e.msg.Time }
func (e rootReleaseEntry) Delta() uint64                   { return 0 }
func (e rootReleaseEntry) Operation() jetstream.KeyValueOp { return jetstream.KeyValuePut }

func (o *rootReleaseObservation) publishStatus(ctx context.Context, location releasechannel.Location, name string, status any, guard func(context.Context) error) error {
	ctx = ociclient.WithRequestGuard(ctx, func(attempt context.Context) error {
		if attempt.Err() != nil {
			return attempt.Err()
		}
		if err := guard(o.scopeCtx); err != nil {
			return err
		}
		return o.guard(attempt)
	})
	wire, err := json.Marshal(status, json.Deterministic(true))
	if err != nil || len(wire) > releasechannel.MaxValueBytes {
		return errors.Join(rootrelease.ErrPending, err)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	current, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{NamespaceName: new(location.Namespace), BucketName: new(location.Bucket), ObjectName: new(name)})
	var etag string
	if err == nil {
		if current.Content == nil || current.ETag == nil || *current.ETag == "" {
			if current.Content != nil {
				_ = current.Content.Close()
			}
			return rootrelease.ErrPending
		}
		data, readErr := io.ReadAll(io.LimitReader(current.Content, releasechannel.MaxValueBytes+1))
		_ = current.Content.Close()
		if readErr != nil || len(data) > releasechannel.MaxValueBytes {
			return errors.Join(rootrelease.ErrPending, readErr)
		}
		var before, after struct {
			UpdatedAt       time.Time `json:"updated_at"`
			ReleaseSequence uint64    `json:"release_sequence"`
			RunNumber       int64     `json:"run_number"`
			IssuedAt        time.Time `json:"issued_at"`
		}
		if json.Unmarshal(data, &before) != nil || json.Unmarshal(wire, &after) != nil {
			return rootrelease.ErrPending
		}
		if before.UpdatedAt.After(after.UpdatedAt) || before.ReleaseSequence > after.ReleaseSequence || before.RunNumber > after.RunNumber || before.IssuedAt.After(after.IssuedAt) {
			return rootrelease.ErrPending
		}
		etag = *current.ETag
	} else if !rootReleaseNotFound(err) {
		return err
	}
	if err := guard(ctx); err != nil {
		return err
	}
	request := objectstorage.PutObjectRequest{NamespaceName: new(location.Namespace), BucketName: new(location.Bucket), ObjectName: new(name), ContentLength: new(int64(len(wire))), PutObjectBody: bytesReaderCloser(wire), ContentType: new("application/json")}
	if etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(etag)
	}
	_, writeErr := location.Client.PutObject(ctx, request)
	if err := guard(ctx); err != nil {
		return errors.Join(rootrelease.ErrPending, writeErr, err)
	}
	if err := o.readStatusBack(ctx, location, name, wire); err != nil {
		return errors.Join(rootrelease.ErrPending, writeErr, err)
	}
	return guard(ctx)
}

type rootChannelProofs struct {
	b           *rootReleaseChannels
	ctx         context.Context
	observation *rootReleaseObservation
}

func (p rootChannelProofs) Latest(unit string) (rolloutexec.HealthProof, bool) {
	latest, ok := p.b.proofs.Latest(unit)
	if !ok || p.ctx.Err() != nil {
		return rolloutexec.HealthProof{}, false
	}
	p.b.mu.Lock()
	wire := bytes.Clone(p.b.proofWires[unit])
	p.b.mu.Unlock()
	keys, err := p.b.keys(unit)
	if err != nil {
		return rolloutexec.HealthProof{}, false
	}
	verified, err := rolloutexec.VerifyHealthProof(wire, p.b.cfg.NATS.Cell, unit, keys, time.Now().UTC())
	if err != nil || latest.ProcessID != verified.ProcessID || latest.StartNonce != verified.StartNonce || !latest.ObservedAt.Equal(verified.ObservedAt) || latest.BinarySHA256 != verified.BinarySHA256 {
		return rolloutexec.HealthProof{}, false
	}
	if p.ctx.Err() != nil {
		return rolloutexec.HealthProof{}, false
	}
	if p.observation != nil {
		if err := p.observation.pinProof(p.ctx, unit, latest, wire); err != nil {
			return rolloutexec.HealthProof{}, false
		}
	}
	return latest, true
}
