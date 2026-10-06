package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/artifact"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// Operator rollout requests travel on the host registration subject, like
// cell spec requests, so every issued operator credential can already send them.
const (
	rolloutStatusKind   = "rollout.status"
	rolloutPublishKind  = "rollout.publish"
	rolloutPauseKind    = "rollout.pause"
	rolloutResumeKind   = "rollout.resume"
	rolloutRollbackKind = "rollout.rollback"
	rolloutHistory      = 10
)

// rolloutSeedSlot names the cell's founding controller, which every
// controller rollout replaces last. A lab cell has none; tests replace it.
var rolloutSeedSlot = func(cfg Config) (string, error) {
	if cfg.NATS.Lab {
		return "", nil
	}
	accepted, err := bootstrapstart.NewMarkerStore().Read()
	return accepted.SeedSlot, err
}

// rolloutControl answers the operator's rollout requests and, with
// controller.rollouts.executor, runs the cell's orchestrator self-update:
// every controller publishes signed health proofs, collects its peers' and
// relays its own steps to the node's root step agent, and the authority
// leader's executor moves the controllers to the desired release, one per
// wave and the seed last. With controller.rollouts.channel the leader also
// follows the region's release channel (TS-557).
type rolloutControl struct {
	cell  string
	store atomic.Pointer[rollout.Store]
	// status is the newest status this controller's executor derived; only
	// the leader's is current, and only the leader answers requests.
	status atomic.Pointer[rolloutexec.Status]
	conn   *nats.Conn
	// verify admits a currently valid release receipt for this cell and
	// returns the release it names; nil refuses every publish.
	verify func(receipt, delegation []byte, now time.Time) (rollout.Release, error)
	// ready reports a controller that finished starting; it publishes
	// health proofs only then.
	ready atomic.Bool
	// interval overrides the executor's and the step relay's tick in tests.
	interval time.Duration

	// roots and environment verify a release channel for this cell.
	roots       *rootRegistry
	environment string
	// follow runs the release channel consumer (controller.rollouts.channel).
	follow bool
	// ticks wakes the consumer after every executor tick.
	ticks chan struct{}
	// channel is the region's head bucket, the CI edge; nil bridges none.
	channel *channelSource
	// channelInterval overrides how often the CI edge reads it, in tests.
	channelInterval time.Duration
	// reported is the status this leader last wrote to the channel.
	reported atomic.Pointer[releasechannel.Status]
	// program derives the executor's rollouts; the channel reads its proofs.
	program rolloutexec.ReleaseProgram
	// spool and layout are the step relay's directory and the node's
	// release root; tests point them elsewhere.
	spool  string
	layout selfupdate.Layout
}

// newRolloutControl takes the effective settings (rolloutSettings) and the
// controller's OCI region, which locates the release channel.
func newRolloutControl(cfg Config, services *specRegistry, region string) (*rolloutControl, error) {
	c := &rolloutControl{cell: cfg.NATS.Cell, spool: rolloutexec.DefaultSpoolDir,
		layout: selfupdate.NewLayout(selfupdate.DefaultRoot), ticks: make(chan struct{}, 1)}
	settings := cfg.Controller.Rollouts
	if settings != nil && settings.Executor && !settings.Enabled {
		return nil, errors.New("controller.rollouts.executor needs controller.rollouts.enabled")
	}
	if settings != nil && settings.Channel && !settings.Executor {
		return nil, errors.New("controller.rollouts.channel needs controller.rollouts.executor")
	}
	c.follow = settings != nil && settings.Channel
	if c.follow && region != "" {
		c.channel = instancePrincipalChannel(region, strings.ToUpper(cfg.NATS.Cell))
	}
	if settings != nil && settings.Policy != nil {
		if err := settings.Policy.Validate(); err != nil {
			return nil, fmt.Errorf("controller.rollouts.policy: %w", err)
		}
	}
	if services != nil && services.roots != nil {
		c.roots, c.environment = services.roots, services.identity.Environment
		// The leader refuses a receipt that no node would stage; every node
		// still verifies it against its own roots before it keeps a byte.
		// The current roots are read per receipt, so a root rotation applies.
		c.verify = func(receipt, delegation []byte, now time.Time) (rollout.Release, error) {
			policy := selfupdate.ReceiptPolicy{Roots: services.roots.current(), Environment: services.identity.Environment,
				Cell: strings.ToUpper(cfg.NATS.Cell), Architecture: goruntime.GOARCH,
				AllowScopedAutoSign: settings != nil && settings.AllowScopedAutoSign}
			verified, err := policy.Verify(receipt, delegation, now)
			if err != nil {
				return rollout.Release{}, err
			}
			admitted := rollout.Release{Digest: verified.Receipt().SHA256,
				SourceRevision: verified.Receipt().SourceRevision, Receipt: receipt, Delegation: delegation}
			// An update receipt's authentic payload names the CI run.
			if envelope, err := trust.DecodeEnvelope(receipt); err == nil && envelope.Scope.Domain == release.UpdateReceiptDomain {
				var update release.BinaryUpdateReceipt
				if err := protocol.DecodeStrict(envelope.Payload, &update, trust.MaxPayloadBytes); err != nil {
					return rollout.Release{}, err
				}
				admitted.RunNumber = update.Lineage.QualificationRunNum
			}
			return admitted, nil
		}
	}
	return c, nil
}

// PublishStatus keeps the executor's status for requests, publishes it and
// wakes the release channel consumer.
func (c *rolloutControl) PublishStatus(status rolloutexec.Status) {
	c.status.Store(&status)
	rolloutexec.NATSStatus{Conn: c.conn, Cell: c.cell}.PublishStatus(status)
	select {
	case c.ticks <- struct{}{}:
	default:
	}
}

// rolloutControllers returns the cell's controller units: the configured
// brokers, or this controller alone in a single-broker lab.
func rolloutControllers(cfg Config) ([]rollout.Unit, error) {
	controllers := cfg.NATS.Embedded.BrokerIDs
	if len(controllers) == 0 {
		controllers = []string{cfg.NATS.Instance}
	}
	seed, err := rolloutSeedSlot(cfg)
	if err != nil {
		return nil, fmt.Errorf("read the cell's seed controller: %w", err)
	}
	return rolloutexec.ControllerUnits(controllers, seed)
}

// start returns the runner of the proof collector and the executor, which
// acts only while this controller holds the authority lease. Proofs are
// verified with the regional controller response key.
func (c *rolloutControl) start(ctx context.Context, cfg Config, runtime *natscell.Runtime, fencer authority.Fencer,
	responseKey ed25519.PrivateKey,
) (func(context.Context) error, error) {
	store := c.store.Load()
	if store == nil {
		return nil, errors.New("the rollout executor needs the rollout store")
	}
	controllers, err := rolloutControllers(cfg)
	if err != nil {
		return nil, err
	}
	keys, err := trust.ParseKeyring(responseKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, unit := range controllers {
		known[unit.ID] = true
	}
	collector := rolloutexec.NewCollector(cfg.NATS.Cell, func(unit string) (trust.Keyring, error) {
		if !known[unit] {
			return nil, fmt.Errorf("unit %q is not a controller of this cell", unit)
		}
		return keys, nil
	}, nil)
	subscription, err := collector.Subscribe(runtime.Conn())
	if err != nil {
		return nil, fmt.Errorf("subscribe to rollout health proofs: %w", err)
	}
	policy := rollout.AllAtOncePolicy()
	if cfg.Controller.Rollouts.Policy != nil {
		policy = *cfg.Controller.Rollouts.Policy
	}
	board, err := runtime.JetStream().KeyValue(ctx, rollout.Bucket)
	if err != nil {
		return nil, fmt.Errorf("open the rollout step board: %w", err)
	}
	c.conn = runtime.Conn()
	c.program = rolloutexec.ReleaseProgram{Store: store, Proofs: collector, Controllers: controllers, Policy: policy}
	executor := &rolloutexec.Executor{Cell: cfg.NATS.Cell, Store: store, Fencer: fencer, Proofs: collector, Status: c,
		Driver: rolloutexec.KVDriver{KV: board, Cell: cfg.NATS.Cell, Key: responseKey, Releases: store},
		Gate: rolloutexec.ClusterGate{Cluster: runtime, ServerOf: func(unit string) (string, bool) {
			return natscell.ServerName(cfg.NATS.Cell, unit), known[unit]
		}},
		Program:  c.program.Program,
		Interval: c.interval}
	relay := &rolloutexec.Relay{KV: board, Cell: cfg.NATS.Cell, Unit: cfg.NATS.Instance, Leaders: keys, Dir: c.spool,
		Layout: c.layout, Sources: c.binarySources(runtime.JetStream()), Interval: c.interval}
	return func(ctx context.Context) error {
		defer subscription.Unsubscribe()
		var workers sync.WaitGroup
		defer workers.Wait()
		workers.Go(func() {
			if err := relay.Run(ctx); ctx.Err() == nil {
				slog.Error("rollout step relay stopped", observability.ComponentKey, "rollout", "error", err)
			}
		})
		if c.follow {
			workers.Go(func() { c.followChannel(ctx, store, fencer, runtime.JetStream(), cfg.NATS.Replicas) })
		}
		if c.follow && c.channel != nil {
			workers.Go(func() { c.bridgeChannel(ctx, fencer, runtime.JetStream(), cfg.NATS.Replicas) })
		}
		return executor.Run(ctx)
	}, nil
}

// binarySources are where the step relay fetches a release the node has
// not staged: the delivery artifact store (ts-orch operator artifact-push,
// for ts-orch rollout publish), then the region's release channel.
func (c *rolloutControl) binarySources(js jetstream.JetStream) []rolloutexec.BinarySource {
	sources := []rolloutexec.BinarySource{func(ctx context.Context, digest string, dst io.Writer) error {
		store, err := js.ObjectStore(ctx, delivery.ArtifactBucket)
		if err != nil {
			return err
		}
		info, err := store.GetInfo(ctx, "sha256-"+digest)
		if err != nil {
			return err
		}
		return artifact.ReadVerified(ctx, js, store, delivery.ArtifactBucket, "sha256-"+digest, digest,
			int64(info.Size), selfupdate.MaxBinaryBytes, dst)
	}}
	if c.channel != nil {
		sources = append(sources, func(ctx context.Context, digest string, dst io.Writer) error {
			location, err := c.channel.get(ctx)
			if err != nil {
				return err
			}
			return releasechannel.ReadBinary(ctx, location, digest, dst)
		})
	}
	return sources
}

// publishProofs signs this controller's rollout health proof with the
// regional response key while it is ready, until ctx ends. A controller
// that cannot prove itself only holds rollouts; it keeps running.
func (c *rolloutControl) publishProofs(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	responseKey ed25519.PrivateKey,
) {
	publisher := rolloutexec.Publisher{Conn: runtime.Conn(), Cell: cfg.NATS.Cell, Unit: cfg.NATS.Instance,
		Key: responseKey, Healthy: func() bool { return c.ready.Load() && runtime.Ready() }}
	if err := publisher.Run(ctx); ctx.Err() == nil {
		slog.Error("rollout health proofs stopped", observability.ComponentKey, "rollout", "error", err)
	}
}

type rolloutPublishRequest struct {
	Receipt    []byte `json:"receipt"`
	Delegation []byte `json:"delegation,omitempty"`
}

type rolloutRollbackRequest struct {
	To uint64 `json:"to"`
}

// rolloutReply is the leader's answer: what changed, the desired release
// (receipts left out), recent generations and the executor's status.
type rolloutReply struct {
	Status          string              `json:"status,omitempty"`
	Cell            string              `json:"cell,omitempty"`
	Paused          bool                `json:"paused,omitzero"`
	Desired         *rollout.Release    `json:"desired,omitempty"`
	DesiredKnownBad bool                `json:"desired_known_bad,omitzero"`
	History         []rollout.Release   `json:"history,omitempty"`
	Rollout         *rolloutexec.Status `json:"rollout,omitempty"`
	// Channel is the leader's newest report to the region's release channel.
	Channel *releasechannel.Status `json:"channel,omitempty"`
	Stopped string                 `json:"stopped,omitempty"`
	Resumed string                 `json:"resumed,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// serve answers one signed operator rollout request. Any trusted signer of
// the signed controller config may read the status; every other request
// needs its can_roll_out_orchestrator grant, since pausing, rolling back or
// aborting a release changes what the controllers run.
func (c *rolloutControl) serve(ctx context.Context, wire []byte, policy signerPolicy, fencer authority.Fencer,
) (rolloutReply, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxRegistrationWireBytes); err != nil {
		return rolloutReply{}, err
	}
	trusted, ok := policy.codec.Trusted[envelope.KeyID]
	if !ok || trusted.Actor != envelope.Actor {
		return rolloutReply{}, errors.New("rollout request signer is untrusted")
	}
	now := time.Now().UTC()
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: c.cell, Kind: envelope.Kind,
		Actor: trusted.Actor, OperationID: envelope.OperationID, Generation: envelope.Generation, Epoch: envelope.Epoch,
	}, trusted.PublicKey, now, protocol.VerifyPolicy{MaxLifetime: time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return rolloutReply{}, err
	}
	epoch := envelope.Epoch
	if epoch == 0 || fencer.Current().Epoch != epoch {
		return rolloutReply{}, authority.ErrFenced
	}
	if envelope.Kind != rolloutStatusKind && !policy.grants[trusted.Actor].CanRollOutOrchestrator {
		return rolloutReply{}, fmt.Errorf("trusted signer %s may not roll out the orchestrator (can_roll_out_orchestrator)", trusted.Actor)
	}
	store := c.store.Load()
	if store == nil {
		return rolloutReply{}, errors.New("rollouts are not enabled in this cell (controller.rollouts.enabled)")
	}
	reply := rolloutReply{}
	var err error
	switch envelope.Kind {
	case rolloutStatusKind:
	case rolloutPublishKind:
		var request rolloutPublishRequest
		if err := protocol.DecodeStrict(envelope.Payload, &request, maxRegistrationBytes); err != nil {
			return rolloutReply{}, err
		}
		if c.verify == nil {
			return rolloutReply{}, errors.New("this controller has no release trust roots to admit a receipt")
		}
		admitted, verifyErr := c.verify(request.Receipt, request.Delegation, now)
		if verifyErr != nil {
			return rolloutReply{}, fmt.Errorf("release receipt: %w", verifyErr)
		}
		admitted.Actor, admitted.CreatedAt = trusted.Actor, now
		_, err = store.PublishRelease(ctx, epoch, admitted)
		reply.Status = "published"
	case rolloutRollbackKind:
		var request rolloutRollbackRequest
		if err := protocol.DecodeStrict(envelope.Payload, &request, maxRegistrationBytes); err != nil {
			return rolloutReply{}, err
		}
		target, targetErr := store.ReleaseGeneration(ctx, request.To)
		if targetErr != nil {
			return rolloutReply{}, targetErr
		}
		// Nodes restage a pruned release from its receipt: one that no
		// longer verifies would freeze the rollback's rollout.
		if c.verify == nil {
			return rolloutReply{}, errors.New("this controller has no release trust roots to admit a receipt")
		}
		if _, verifyErr := c.verify(target.Receipt, target.Delegation, now); verifyErr != nil {
			return rolloutReply{}, fmt.Errorf("generation %d's release receipt no longer verifies; publish it again: %w",
				request.To, verifyErr)
		}
		var release rollout.Release
		release, err = store.RollbackRelease(ctx, epoch, request.To, trusted.Actor, now)
		if err == nil || errors.Is(err, rollout.ErrReleaseUnchanged) {
			// The rollout in flight moved towards the release the operator
			// just rejected: stop it, returning its units first. A retried
			// request whose generation already exists stops it too.
			stopped, abortErr := rolloutexec.Abort(ctx, store, epoch, release.Digest,
				fmt.Sprintf("%s rolled the cell back to generation %d", trusted.Actor, request.To), now)
			if reply.Stopped = stopped; abortErr != nil {
				err = abortErr
			}
		}
		reply.Status = "rolled-back"
	case rolloutPauseKind:
		_, err = store.PauseReleases(ctx, epoch, true)
		reply.Status = "paused"
	case rolloutResumeKind:
		if _, err = store.PauseReleases(ctx, epoch, false); err == nil {
			reply.Resumed, err = rolloutexec.Resume(ctx, store, epoch, now)
		}
		reply.Status = "resumed"
	default:
		return rolloutReply{}, fmt.Errorf("unknown rollout request %q", envelope.Kind)
	}
	if errors.Is(err, rollout.ErrReleaseUnchanged) {
		reply.Status, err = "unchanged", nil
	}
	if err != nil {
		return rolloutReply{}, err
	}
	if envelope.Kind != rolloutStatusKind {
		slog.Info("rollout request", observability.ComponentKey, "rollout", "actor", trusted.Actor,
			"kind", envelope.Kind, "status", reply.Status)
	}
	return c.view(ctx, store, reply)
}

// view fills the reply with the desired release, recent generations and
// the executor's newest status.
func (c *rolloutControl) view(ctx context.Context, store *rollout.Store, reply rolloutReply) (rolloutReply, error) {
	desired, _, err := store.Desired(ctx)
	if err != nil {
		return rolloutReply{}, err
	}
	history, err := store.Releases(ctx, rolloutHistory)
	if err != nil {
		return rolloutReply{}, err
	}
	for index := range history {
		history[index].Receipt, history[index].Delegation = nil, nil
	}
	reply.Cell, reply.Paused, reply.History = c.cell, desired.Paused, history
	if len(history) > 0 && history[0].Generation == desired.Generation() {
		reply.Desired = &history[0]
		if reply.DesiredKnownBad, err = store.IsKnownBad(ctx, history[0].Digest); err != nil {
			return rolloutReply{}, err
		}
	}
	reply.Rollout, reply.Channel = c.status.Load(), c.reported.Load()
	return reply, nil
}
