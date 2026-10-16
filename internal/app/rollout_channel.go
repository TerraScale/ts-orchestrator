package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	// channelActor publishes the generations the release channel brings.
	channelActor = "release-channel"
	// defaultChannelInterval is how often the CI edge reads Object Storage.
	defaultChannelInterval = releasechannel.PinRefreshInterval
)

// channelSource opens the region's head bucket once, from the controller's
// instance principal; a failure (the metadata service, the namespace call)
// is retried on the next use.
type channelSource struct {
	mu       sync.Mutex
	location *releasechannel.Location
	open     func(context.Context) (releasechannel.Location, error)
}

func (s *channelSource) get(ctx context.Context) (releasechannel.Location, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.location != nil {
		return *s.location, nil
	}
	location, err := s.open(ctx)
	if err != nil {
		return releasechannel.Location{}, err
	}
	s.location = &location
	return location, nil
}

func instancePrincipalChannel(region, cell string) *channelSource {
	return &channelSource{open: func(ctx context.Context) (releasechannel.Location, error) {
		bucket, err := releasechannel.BucketName(cell)
		if err != nil {
			return releasechannel.Location{}, err
		}
		factory, err := ociclient.InstancePrincipal(region)
		if err != nil {
			return releasechannel.Location{}, err
		}
		client, err := factory.ObjectStorage()
		if err != nil {
			return releasechannel.Location{}, err
		}
		namespace, err := client.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
		if err != nil || namespace.Value == nil {
			return releasechannel.Location{}, fmt.Errorf("read the Object Storage namespace: %w", err)
		}
		return releasechannel.Location{Client: client, Namespace: *namespace.Value, Bucket: bucket}, nil
	}}
}

// admitChannel verifies the whole channel for this cell and admits its
// receipt for this controller's architecture exactly as a manual publish
// would.
func (c *rolloutControl) admitChannel(channel releasechannel.Channel, now time.Time) (rollout.Release, error) {
	if c.verify == nil || len(c.roots.current()) == 0 {
		return rollout.Release{}, errors.New("this controller has no release trust roots")
	}
	if _, err := channel.Verify(c.roots.current(), strings.ToUpper(c.cell), c.environment, now); err != nil {
		return rollout.Release{}, err
	}
	for _, wire := range channel.Receipts {
		if envelope, err := trust.DecodeEnvelope(wire); err == nil && envelope.Scope.Slot == "linux-"+goruntime.GOARCH {
			admitted, err := c.verify(wire, channel.Delegation, now)
			if err != nil {
				return rollout.Release{}, err
			}
			admitted.CreatedAt = envelope.IssuedAt
			admitted.ReleaseSequence = channel.ReleaseSequence
			if channel.ReleaseSequence > 0 {
				migration, err := trust.DecodeEnvelope(channel.SequenceMigration)
				if err != nil {
					return rollout.Release{}, err
				}
				admitted.SequenceMigration = slices.Clone(channel.SequenceMigration)
				admitted.SequenceMigrationSHA256, err = trust.Fingerprint(migration)
				if err != nil {
					return rollout.Release{}, err
				}
			}
			return admitted, nil
		}
	}
	return rollout.Release{}, fmt.Errorf("the channel has no receipt for %s", goruntime.GOARCH)
}

// openChannelBucket binds the cell's release channel bucket, creating it
// when it does not exist yet (TS-562 may provide it replicated), and
// retries until ctx ends.
func openChannelBucket(ctx context.Context, js jetstream.JetStream, replicas int) (jetstream.KeyValue, error) {
	for {
		ctx := observability.StartTrace(ctx)
		kv, err := js.KeyValue(ctx, releasechannel.Bucket)
		if errors.Is(err, jetstream.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: releasechannel.Bucket,
				Storage: jetstream.FileStorage, Replicas: replicas, History: 4, MaxValueSize: releasechannel.MaxValueBytes})
		}
		if err == nil {
			return kv, nil
		}
		slog.WarnContext(ctx, "open the release channel bucket", observability.ComponentKey, "rollout", "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// followChannel is the channel's consumer. It watches the cell's channel
// key and, on the authority leader, follows the newest document when it
// changes and after every executor tick, which also moves the report on as
// the rollout progresses. A periodic refresh keeps its pin inventory current.
func (c *rolloutControl) followChannel(ctx context.Context, store *rollout.Store, fencer authority.Fencer,
	js jetstream.JetStream, replicas int,
) {
	kv, err := openChannelBucket(ctx, js, replicas)
	if err != nil {
		return
	}
	for ctx.Err() == nil {
		watcher, err := kv.Watch(ctx, releasechannel.ChannelKey(strings.ToUpper(c.cell)))
		if err != nil {
			slog.WarnContext(ctx, "watch the release channel", observability.ComponentKey, "rollout", "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			continue
		}
		c.consumeUpdates(ctx, store, fencer, kv, watcher)
		_ = watcher.Stop()
	}
}

func (c *rolloutControl) consumeUpdates(ctx context.Context, store *rollout.Store, fencer authority.Fencer,
	kv jetstream.KeyValue, watcher jetstream.KeyWatcher,
) {
	var latest []byte
	initialized := false
	interval := c.interval
	if interval <= 0 {
		interval = releasechannel.PinRefreshInterval
	}
	refresh := time.NewTicker(interval)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-watcher.Updates():
			if !ok {
				return
			}
			initialized = true
			if entry != nil {
				latest = nil
				if entry.Operation() == jetstream.KeyValuePut {
					latest = entry.Value()
				}
			}
		case <-c.ticks:
		case <-refresh.C:
		}
		ctx := observability.StartTrace(ctx)
		if !initialized {
			continue
		}
		snapshot := fencer.Current()
		if !snapshot.CanMutate() {
			c.reported.Store(nil)
			continue
		}
		if err := c.consumeChannel(ctx, store, kv, snapshot.Epoch, latest, time.Now().UTC()); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "release channel", observability.ComponentKey, "rollout", "error", err)
		}
	}
}

// consumeChannel makes the channel's release the cell's next generation
// when it names a newer run than any the cell published, and reports that
// generation's progress. A channel that does not verify, names a run older
// than the cell's newest, or a release known bad here is reported failed.
// Errors reading or writing state report nothing; the next tick retries.
func (c *rolloutControl) consumeChannel(ctx context.Context, store *rollout.Store, kv jetstream.KeyValue, epoch uint64,
	wire []byte, now time.Time,
) error {
	architectures := slices.Clone(c.architectures)
	if c.managedArchitecture != nil {
		architecture, err := c.managedArchitecture(ctx)
		if err != nil {
			return fmt.Errorf("observe managed host architecture for release channel: %w", err)
		}
		if !slices.Contains(architectures, architecture) {
			architectures = append(architectures, architecture)
			slices.Sort(architectures)
		}
	}
	status := releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: strings.ToUpper(c.cell), UpdatedAt: now,
		Environment: c.environment, Architectures: architectures}
	var channel releasechannel.Channel
	if len(wire) == 0 {
		status.State, status.Reason = releasechannel.StateRolling, "the cell has no release channel"
	} else if err := json.Unmarshal(wire, &channel); err != nil {
		status.State, status.Reason = releasechannel.StateFailed, "the channel does not decode: "+err.Error()
	} else {
		status.RunNumber, status.ReleaseSequence = channel.RunNumber, channel.ReleaseSequence
		if release.ValidSourceRevision(channel.SourceRevision) {
			status.SourceRevision = channel.SourceRevision
		}
		if status.State, status.Reason, err = c.channelState(ctx, store, epoch, channel, now); err != nil {
			return err
		}
	}
	rollback, knownBad, err := store.ReleasePins(ctx)
	if err != nil {
		return err
	}
	status.Pins = &releasechannel.ReleasePins{Rollback: rollback, KnownBad: knownBad}
	status.Reason = releasechannel.Clip(status.Reason)
	return c.report(ctx, kv, status)
}

// report stores the leader's report in the bucket and publishes it for
// fan-in when it differs from the stored one. The stored report, not this
// leader's memory, decides, so a report a deposed leader left is replaced.
func (c *rolloutControl) report(ctx context.Context, kv jetstream.KeyValue, status releasechannel.Status) error {
	key := releasechannel.StatusKey(status.Cell)
	entry, err := kv.Get(ctx, key)
	if err == nil {
		var stored releasechannel.Status
		if json.Unmarshal(entry.Value(), &stored) == nil && sameReport(stored, status) &&
			!releasechannel.PinRefreshDue(stored.UpdatedAt, status.UpdatedAt) {
			c.reported.Store(&stored)
			return nil
		}
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return err
	}
	wire, err := json.Marshal(status, json.Deterministic(true))
	if err != nil {
		return err
	}
	if _, err := kv.Put(ctx, key, wire); err != nil {
		return err
	}
	if c.conn != nil {
		if err := c.conn.Publish(protocol.ReleaseStatusSubject(c.cell), wire); err != nil {
			slog.WarnContext(ctx, "publish the release channel status", observability.ComponentKey, "rollout", "error", err)
		}
	}
	// A repeat of the logged run, state and reason is steady state: DEBUG.
	level := slog.LevelDebug
	if logged := c.logged; logged == nil || logged.RunNumber != status.RunNumber || logged.State != status.State ||
		logged.Reason != status.Reason {
		level = slog.LevelInfo
		c.logged = &status
	}
	slog.Log(ctx, level, "release channel status", observability.ComponentKey, "rollout", "run", status.RunNumber,
		"state", status.State, "reason", status.Reason)
	c.reported.Store(&status)
	return nil
}

func sameReport(a, b releasechannel.Status) bool {
	return a.Cell == b.Cell && a.RunNumber == b.RunNumber && a.ReleaseSequence == b.ReleaseSequence && a.SourceRevision == b.SourceRevision &&
		a.State == b.State && a.Reason == b.Reason && a.Pins.Equal(b.Pins) &&
		a.Environment == b.Environment && slices.Equal(a.Architectures, b.Architectures)
}

// bridgeChannel is the CI edge until TS-562 announces releases over NATS.
// CI cannot reach the cell's NATS, so the authority leader copies CI's
// channel.json into the bucket and the bucket's report back out to
// status.json, which CI waits on. Only this edge reads Object Storage.
func (c *rolloutControl) bridgeChannel(ctx context.Context, fencer authority.Fencer, js jetstream.JetStream, replicas int) {
	kv, err := openChannelBucket(ctx, js, replicas)
	if err != nil {
		return
	}
	interval := c.channelInterval
	if interval <= 0 {
		interval = defaultChannelInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ctx := observability.StartTrace(ctx)
		if fencer.Current().CanMutate() {
			if err := c.bridgePass(ctx, kv); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "release channel bridge", observability.ComponentKey, "rollout", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *rolloutControl) bridgePass(ctx context.Context, kv jetstream.KeyValue) error {
	location, err := c.channel.get(ctx)
	if err != nil {
		return err
	}
	cell := strings.ToUpper(c.cell)
	channel, found, err := releasechannel.ReadChannel(ctx, location)
	if err != nil {
		return err
	}
	if found {
		wire, err := json.Marshal(channel, json.Deterministic(true))
		if err != nil {
			return err
		}
		if len(wire) > releasechannel.MaxValueBytes {
			return fmt.Errorf("%w: the channel exceeds %d bytes", releasechannel.ErrInvalid, releasechannel.MaxValueBytes)
		}
		entry, err := kv.Get(ctx, releasechannel.ChannelKey(cell))
		if errors.Is(err, jetstream.ErrKeyNotFound) || err == nil && !bytes.Equal(entry.Value(), wire) {
			if _, err := kv.Put(ctx, releasechannel.ChannelKey(cell), wire); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	entry, err := kv.Get(ctx, releasechannel.StatusKey(cell))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var report releasechannel.Status
	if err := json.Unmarshal(entry.Value(), &report); err != nil {
		return fmt.Errorf("decode the release channel report: %w", err)
	}
	// Preserve the inventory's collection time: copying an old report cannot renew it.
	if stored, found, err := releasechannel.ReadStatus(ctx, location); err == nil && found && sameReport(stored, report) &&
		stored.UpdatedAt.Equal(report.UpdatedAt) {
		return nil
	}
	return releasechannel.WriteStatus(ctx, location, report)
}

func (c *rolloutControl) channelState(ctx context.Context, store *rollout.Store, epoch uint64,
	channel releasechannel.Channel, now time.Time,
) (releasechannel.State, string, error) {
	admitted, err := c.admitChannel(channel, now)
	if err != nil {
		return releasechannel.StateFailed, "the release does not verify in this cell: " + err.Error(), nil
	}
	if admitted.CreatedAt.After(now) {
		return releasechannel.StateRolling, fmt.Sprintf("the release is issued at %s; waiting for the cell clock", admitted.CreatedAt), nil
	}
	generation, refusal, err := channelGeneration(ctx, store, epoch, admitted, c.roots.current(), c.cell, c.environment)
	if err != nil || refusal != "" {
		return releasechannel.StateFailed, refusal, err
	}
	return c.generationState(ctx, store, generation)
}

// channelGeneration returns the newest generation of the admitted release,
// publishing it first when its run is newer than every run the cell
// published. Generations are newest first, so an operator's rollback, a
// generation that repeats an older run, never makes the channel publish
// the release it rolled back from again.
func channelGeneration(ctx context.Context, store *rollout.Store, epoch uint64, admitted rollout.Release,
	roots trust.Keyring, cell, environment string,
) (rollout.Release, string, error) {
	if admitted.ReleaseSequence > 0 {
		admitted.Actor = channelActor
		published, err := store.PublishSequencedRelease(ctx, epoch, admitted, roots, cell, environment)
		switch {
		case errors.Is(err, rollout.ErrKnownBad):
			return rollout.Release{}, "the release is known bad in this cell", nil
		case errors.Is(err, rollout.ErrReleaseUnchanged):
			return published, "", nil
		case errors.Is(err, rollout.ErrInvalid):
			return rollout.Release{}, "the release violates the retained signed ordering floor", nil
		case err != nil:
			return rollout.Release{}, "", err
		default:
			return published, "", nil
		}
	}
	desired, _, err := store.Desired(ctx)
	if err != nil {
		return rollout.Release{}, "", err
	}
	if desired.OrderingFloor.ReleaseSequence > 0 {
		return rollout.Release{}, "a legacy release cannot replace the retained signed ordering floor", nil
	}
	history, err := store.Releases(ctx, rollout.ReleaseHistory)
	if err != nil {
		return rollout.Release{}, "", err
	}
	var newest int64
	for _, published := range history {
		if published.Digest == admitted.Digest && published.RunNumber == admitted.RunNumber {
			return published, "", nil
		}
		newest = max(newest, published.RunNumber)
	}
	if admitted.RunNumber <= newest {
		return rollout.Release{}, fmt.Sprintf("the cell already published run %d", newest), nil
	}
	admitted.Actor = channelActor
	published, err := store.PublishRelease(ctx, epoch, admitted)
	switch {
	case errors.Is(err, rollout.ErrKnownBad):
		return rollout.Release{}, "the release is known bad in this cell", nil
	case errors.Is(err, rollout.ErrReleaseUnchanged):
		// An operator already published the same binary.
		return published, "", nil
	case err != nil:
		return rollout.Release{}, "", err
	}
	slog.InfoContext(ctx, "release channel published a generation", observability.ComponentKey, "rollout",
		"generation", published.Generation, "run", published.RunNumber, "digest", published.Digest)
	return published, "", nil
}

// generationState is the progress of one generation's rollouts: the
// controllers', then the hosts'. Completion requires every current unit to
// freshly prove the target, even after its recorded rollout completed.
func (c *rolloutControl) generationState(ctx context.Context, store *rollout.Store, generation rollout.Release,
) (releasechannel.State, string, error) {
	parts := []struct {
		domain string
		units  func(context.Context) ([]rollout.Unit, error)
	}{
		{rollout.ControllerReleaseDomain, func(context.Context) ([]rollout.Unit, error) { return c.program.Controllers, nil }},
		{rollout.HostReleaseDomain, c.program.Hosts},
	}
	for _, part := range parts {
		if part.units == nil {
			continue
		}
		record, _, err := store.Load(ctx, entityid.Derive(part.domain, rollout.ReleaseRolloutID(generation.Generation)))
		if errors.Is(err, rollout.ErrAbandonedRollout) {
			return releasechannel.StateFailed, "the rollout was abandoned before any update; run release again", nil
		}
		if err == nil {
			switch record.Phase {
			case rollout.PhaseComplete:
			case rollout.PhaseRolledBack, rollout.PhaseAborted, rollout.PhaseFrozen:
				return releasechannel.StateFailed, fmt.Sprintf("%s %s: %s", record.RolloutID, record.Phase, record.Reason), nil
			default:
				return releasechannel.StateRolling, fmt.Sprintf("%s %s", record.RolloutID, record.Phase), nil
			}
		}
		if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
			return "", "", err
		}
		// No rollout of this part started (yet) for this generation.
		desired, _, err := store.Desired(ctx)
		if err != nil {
			return "", "", err
		}
		// A follower read can lag the generation just published by CAS.
		// Only a newer generation proves this release was superseded.
		if desired.Generation() < generation.Generation {
			return releasechannel.StateRolling, fmt.Sprintf("waiting for generation %d to become visible", generation.Generation), nil
		}
		if desired.Generation() != generation.Generation {
			return releasechannel.StateFailed, fmt.Sprintf("generation %d was replaced by generation %d before it rolled out",
				generation.Generation, desired.Generation()), nil
		}
		if bad, err := store.IsKnownBad(ctx, generation.Digest); err != nil || bad {
			return releasechannel.StateFailed, "the release is known bad in this cell", err
		}
		if desired.Paused {
			return releasechannel.StateRolling, "the cell's rollouts are paused", nil
		}
		units, err := part.units(ctx)
		if err != nil {
			return releasechannel.StateRolling, "the cell's hosts are unreadable: " + err.Error(), nil
		}
		behind, _, err := c.program.Behind(units, generation.Digest)
		if err == nil && len(behind) == 0 {
			continue
		}
		if err != nil {
			return releasechannel.StateRolling, "waiting for health proofs: " + err.Error(), nil
		}
		reason := "waiting for the rollout to start"
		if status := c.status.Load(); status != nil && status.Waiting != "" {
			reason = status.Waiting
		}
		return releasechannel.StateRolling, reason, nil
	}
	return releasechannel.StateComplete, "", nil
}
