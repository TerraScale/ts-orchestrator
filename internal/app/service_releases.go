package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oklog/ulid/v2"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/seatrollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
)

// errFencePrepare reports a release whose fence mark could not be written:
// it was not submitted, and an earlier submission of it may still be
// rolling, so it is retried rather than failed.
var errFencePrepare = errors.New("the release fence mark was not written")

// serviceReleaseMaxAge bounds the age of a CI release claim the leader has
// not started yet: CI signs it right before it publishes, so an older one
// is a replay or a release the cell missed, which CI runs again.
const serviceReleaseMaxAge = time.Hour

// serviceReleaseRoles are the native roles CI releases through the service
// release channel, in the order the leader checks them.
var serviceReleaseRoles = []string{terrabase.Role, tsauth.Role}

// serviceReleaseReplicas is the replica count role's readiness gate waits
// for, as the operator's release command for the role counts it.
func serviceReleaseReplicas(cell, role string, profile WorkloadProfile) (int, error) {
	switch role {
	case terrabase.Role:
		members, err := terrabase.ParseProfile(profile.Env)
		return len(members.Peers), err
	case tsauth.Role:
		return tsauth.Replicas, tsauth.ValidateProfile(cell, profile.Args, profile.Env, profile.Secrets)
	}
	return 0, fmt.Errorf("role %s has no release rule", role)
}

// serviceReleases follows the service release channels in the region's
// head bucket (TS-610). CI publishes one artifact claim per role, signed by
// a trusted signer the cell lets release that role; the authority leader
// admits the claimed binary and rolls the role out through the same
// readiness gate and rollback as the operator's release commands, one role
// at a time, and reports in the role's status.json.
type serviceReleases struct {
	cell       string // the NATS cell, e.g. gru
	channel    *channelSource
	deliveries *delivery.Service
	hosts      seatrollout.Hosts
	profiles   func() map[string]WorkloadProfile
	fencer     authority.Fencer
	// fences restarts each release one node at a time when the cell spec
	// has a release fence; nil restarts every replica at once.
	fences *releaseFence
	// canary gates a fenced release on its first node when the fence has
	// a canary (TS-623).
	canary canaryGate
	// interval is how often the channels are read; zero means
	// defaultChannelInterval.
	interval time.Duration
	// wait overrides the readiness gate's wait in tests.
	wait time.Duration
}

// serviceReleaseState is the leader's record of a role's newest release,
// under releasechannel.ServiceStatusKey in the release channel bucket, so a
// new leader resumes the release instead of starting it again.
type serviceReleaseState struct {
	SourceRevision string    `json:"source_revision,omitempty"`
	Claim          string    `json:"claim"` // SHA-256 of release.json
	IssuedAt       time.Time `json:"issued_at"`
	Digest         string    `json:"digest,omitempty"`
	Actor          string    `json:"actor,omitempty"`
	Previous       string    `json:"previous,omitempty"`
	// Retained protects the last release while a newer claim is refused
	// before the leader resolves its actual serving rollback target.
	Retained []string         `json:"retained,omitempty"`
	Intent   *delivery.Intent `json:"intent,omitempty"` // persisted before submission
	// Rollback is set once the release failed its gate and the rollback
	// to Previous is submitted; a new leader finishes it.
	Rollback *delivery.Intent `json:"rollback,omitempty"`

	// claim and location are the channel's claim while it is admitted;
	// they are never stored.
	claim    []byte
	location releasechannel.Location
	State    releasechannel.State `json:"state"`
	Reason   string               `json:"reason,omitempty"`
}

func (r *serviceReleases) run(ctx context.Context, js jetstream.JetStream, replicas int) {
	kv, err := openChannelBucket(ctx, js, replicas)
	if err != nil {
		return
	}
	interval := r.interval
	if interval <= 0 {
		interval = defaultChannelInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if r.fencer.Current().CanMutate() {
			if err := r.fences.reconcile(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("release fence", observability.ComponentKey, "rollout", "error", err)
			}
		}
		for _, role := range serviceReleaseRoles {
			if !r.fencer.Current().CanMutate() {
				break
			}
			if err := r.pass(ctx, kv, role); err != nil && ctx.Err() == nil {
				slog.Warn("service release channel", observability.ComponentKey, "rollout", "role", role, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pass reads role's channel and starts, resumes or reports its release. An
// error leaves the state as it was; the next pass retries.
func (r *serviceReleases) pass(ctx context.Context, kv jetstream.KeyValue, role string) error {
	key := releasechannel.ServiceStatusKey(strings.ToUpper(r.cell), role)
	state, revision, err := loadServiceRelease(ctx, kv, key)
	if err != nil {
		return err
	}
	// A submitted release finishes, or rolls back, from its recorded intent
	// before the channel is read: its delivery may be partly committed, and
	// neither a newer claim nor an unreadable channel may hold it.
	if state.State != releasechannel.StateRolling || state.Intent == nil {
		location, err := r.channel.get(ctx)
		if err != nil {
			return err
		}
		claim, found, err := releasechannel.ReadServiceClaim(ctx, location, role)
		if err != nil {
			return err
		}
		if !found {
			if revision == 0 {
				state.State, state.Reason = releasechannel.StateRolling, "the service release channel has no claim"
			}
			return r.report(ctx, kv, role, state)
		}
		sum := sha256.Sum256(claim)
		if state.Claim == hex.EncodeToString(sum[:]) && state.State != releasechannel.StateRolling {
			return r.report(ctx, kv, role, state)
		}
		if state.Claim != hex.EncodeToString(sum[:]) {
			// Only an authentic claim moves the cell's issuance watermark;
			// any other is reported failed and leaves the state as it was.
			next := serviceReleaseState{Claim: hex.EncodeToString(sum[:]), Previous: state.Previous, State: releasechannel.StateRolling,
				Reason: "admitting the release"}
			next.Retained = slices.Clone(state.Retained)
			// Only a persisted intent means this digest could have reached hosts.
			if state.Intent != nil && state.Digest != "" {
				next.Retained = append(next.Retained, state.Digest)
			}
			slices.Sort(next.Retained)
			next.Retained = slices.Compact(next.Retained)
			record, actor, issued, err := r.verify(ctx, role, claim)
			next.IssuedAt, next.Digest, next.Actor = issued, record.Digest, actor
			switch {
			case err != nil && !errors.Is(err, delivery.ErrInvalid) && !errors.Is(err, delivery.ErrUnauthorized):
				return err
			case err != nil:
				next.State, next.Reason = releasechannel.StateFailed, "the claim does not verify in this cell: "+err.Error()
				return r.report(ctx, kv, role, next)
			case issued.After(time.Now().Add(releasechannel.ClaimClockSkew)):
				next.State, next.Reason = releasechannel.StateFailed, fmt.Sprintf("the claim is issued in the future, at %s", issued)
				return r.report(ctx, kv, role, next)
			case !issued.After(state.IssuedAt):
				return fmt.Errorf("release.json holds a claim issued at %s, not after the cell's last %s release", issued, role)
			}
			next.SourceRevision = record.Source.Commit
			if bad, found, err := knownBad(ctx, kv, role, record.Digest); err != nil {
				return err
			} else if found {
				next.State, next.Reason = releasechannel.StateFailed,
					fmt.Sprintf("%s %s is known bad in this cell since %s (%s); release a new build", role, record.Digest,
						bad.At.Format(time.RFC3339), bad.Reason)
			}
			if age := time.Since(issued); next.State == releasechannel.StateRolling && age > serviceReleaseMaxAge {
				next.State, next.Reason = releasechannel.StateFailed,
					fmt.Sprintf("the claim was issued %s ago, more than %s; run the release again", age.Round(time.Second), serviceReleaseMaxAge)
			}
			state = next
			if revision, err = saveServiceRelease(ctx, kv, key, state, revision); err != nil {
				return err
			}
			r.reportQuietly(ctx, kv, role, state)
			if state.State == releasechannel.StateFailed {
				return nil
			}
		}
		state.claim, state.location = claim, location
	}
	finished, err := r.release(ctx, kv, role, state, func(next serviceReleaseState) error {
		state = next
		if revision, err = saveServiceRelease(ctx, kv, key, state, revision); err != nil {
			return err
		}
		r.reportQuietly(ctx, kv, role, state)
		return nil
	})
	if err != nil {
		return err
	}
	// A leader deposed during the gate leaves the outcome to the next one.
	if !r.fencer.Current().CanMutate() {
		return errors.New("lost the authority lease during the release")
	}
	if _, err := saveServiceRelease(ctx, kv, key, finished, revision); err != nil {
		return err
	}
	r.reportQuietly(ctx, kv, role, finished)
	return nil
}

// verify authenticates role's claim for this cell and returns its record,
// signer and issuance instant.
func (r *serviceReleases) verify(ctx context.Context, role string, claim []byte) (delivery.ArtifactRecord, string, time.Time, error) {
	issued, err := releasechannel.ClaimIssuedAt(claim)
	if err != nil {
		return delivery.ArtifactRecord{}, "", time.Time{}, fmt.Errorf("%w: %w", delivery.ErrInvalid, err)
	}
	record, actor, err := r.deliveries.VerifyClaim(ctx, claim)
	if err == nil && record.Role != role {
		err = fmt.Errorf("%w: the claim is for role %s", delivery.ErrInvalid, record.Role)
	}
	return record, actor, issued, err
}

// release admits the channel's claim unless state already holds its intent,
// rolls the role out and returns the final state: complete once every
// replica serves the release, failed once it was refused before anything
// changed or rolled back. save records progress; an error from release or
// save means the release may be retried, and a release whose rollback has
// not finished stays rolling.
func (r *serviceReleases) release(ctx context.Context, kv jetstream.KeyValue, role string, state serviceReleaseState,
	save func(serviceReleaseState) error,
) (serviceReleaseState, error) {
	failed := func(err error) (serviceReleaseState, error) {
		state.State, state.Reason = releasechannel.StateFailed, err.Error()
		return state, nil
	}
	var rollback delivery.ArtifactRecord
	if state.Intent == nil {
		// The profile decides a new release only; a recorded one resumes
		// with its own replica count whatever the cell spec says now.
		profile, ok := r.profiles()[role]
		if !ok {
			return failed(fmt.Errorf("this cell has no %s profile", role))
		}
		replicas, err := serviceReleaseReplicas(r.cell, role, profile)
		if err != nil {
			return failed(err)
		}
		record, actor, err := r.admit(ctx, state.location, role, state.claim)
		if errors.Is(err, delivery.ErrInvalid) || errors.Is(err, delivery.ErrUnauthorized) {
			return failed(err)
		}
		if err != nil {
			return state, err
		}
		deployer := r.deployer(actor, nil)
		previous, generation, err := deployer.current(ctx, role, record.Environment)
		if errors.Is(err, errReplicasDisagree) {
			return failed(err)
		}
		if err != nil {
			return state, err
		}
		// Resolve the rollback target before anything changes.
		if rollback, err = deployer.rollbackTarget(ctx, previous, record.Digest, role, record.Environment); permanentLookup(err) {
			return failed(err)
		} else if err != nil {
			return state, err
		}
		intent := nativeIntent(record, nativeRelease{Role: role, Replicas: replicas, Profile: profile}, generation)
		intent.SchemaVersion, intent.OperationID = delivery.SchemaVersion, ulid.MustNew(ulid.Now(), rand.Reader).String()
		intent.AuthorityEpoch = r.fencer.Current().Epoch
		state.Digest, state.Actor, state.Previous, state.Intent = record.Digest, actor, previous, &intent
		state.Retained = nil
		state.Reason = fmt.Sprintf("rolling %d replicas from %s", replicas, previous)
		if err := save(state); err != nil {
			return state, err
		}
	} else if state.Rollback == nil {
		var err error
		rollback, err = r.deployer(state.Actor, nil).rollbackTarget(ctx, state.Previous, state.Digest, role, state.Intent.Environment)
		if permanentLookup(err) {
			// The release is submitted: gate it even without a target.
			slog.Warn("service release has no rollback target", observability.ComponentKey, "rollout", "role", role,
				"previous", state.Previous, "error", err)
			rollback = delivery.ArtifactRecord{}
		} else if err != nil {
			return state, err
		}
	}
	wait := r.wait
	if wait == 0 {
		// A fenced release restarts its nodes one at a time.
		wait = defaultReleaseWait(role, state.Intent.DesiredReplicas) + r.fences.allowance(state.Intent.DesiredReplicas)
	}
	progress := &stickyWriter{writer: serviceReleaseLog{role: role}}
	unfinished := func(err error) (serviceReleaseState, error) {
		state.Reason = fmt.Sprintf("the rollback to %s has not finished; retrying: %v", state.Previous, err)
		return state, errors.Join(err, save(state))
	}
	if state.Rollback != nil {
		// An earlier pass or leader started the rollback: finish it.
		intent, changed, err := r.fresh(ctx, role, *state.Rollback)
		if err != nil {
			return state, err
		}
		if changed {
			state.Rollback = &intent
			if err := save(state); err != nil {
				return state, err
			}
		}
		deployer := r.deployer(state.Actor, nil)
		deployer.canary = nil
		if _, err := deployer.rollOut(ctx, intent, wait, progress); err != nil {
			return unfinished(err)
		}
		return failed(fmt.Errorf("%s release %s failed its readiness gate and was rolled back to %s", role, state.Digest, state.Previous))
	}
	intent, changed, err := r.fresh(ctx, role, *state.Intent)
	if err != nil {
		return state, err
	}
	if changed {
		state.Intent = &intent
		if err := save(state); err != nil {
			return state, err
		}
	}
	deployer := r.deployer(state.Actor, func(ctx context.Context, rollback delivery.Intent, cause error) (delivery.Intent, error) {
		// Recorded before the rollback: the cell never releases it again.
		if errors.Is(cause, errBadRelease) {
			if err := markKnownBad(ctx, kv, role, state.Digest, cause); err != nil {
				return rollback, err
			}
		}
		rollback.SchemaVersion, rollback.OperationID = delivery.SchemaVersion, ulid.MustNew(ulid.Now(), rand.Reader).String()
		rollback.AuthorityEpoch = r.fencer.Current().Epoch
		state.Rollback, state.Reason = &rollback, "rolling back to "+state.Previous
		return rollback, save(state)
	})
	switch err := deployer.roll(ctx, intent, rollback, wait, progress); {
	case errors.Is(err, errRecoveryNotStarted), errors.Is(err, errFencePrepare):
		// Nothing proves the release, or its rollback, reached the hosts or
		// failed there: a later pass resumes it.
		return state, err
	case errors.Is(err, errRollbackUnfinished):
		return unfinished(err)
	case err != nil:
		return failed(err)
	}
	state.State, state.Reason = releasechannel.StateComplete, ""
	return state, nil
}

// permanentLookup reports an artifact lookup that a retry cannot change.
func permanentLookup(err error) bool {
	return errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, delivery.ErrInvalid) ||
		errors.Is(err, delivery.ErrUnauthorized)
}

// admit copies the claimed binary out of the head bucket and admits it.
func (r *serviceReleases) admit(ctx context.Context, location releasechannel.Location, role string, claim []byte,
) (delivery.ArtifactRecord, string, error) {
	claimed, _, _, err := r.verify(ctx, role, claim)
	if err != nil {
		return delivery.ArtifactRecord{}, "", err
	}
	file, err := os.CreateTemp("", "ts-orchestrator-service-release-")
	if err != nil {
		return delivery.ArtifactRecord{}, "", err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := releasechannel.ReadServiceBinary(ctx, location, role, claimed.Digest, file); err != nil {
		return delivery.ArtifactRecord{}, "", err
	}
	return r.deliveries.AdmitClaim(ctx, file, claim)
}

// fresh returns intent, or, when an earlier leader submitted it under its
// epoch and the delivery worker has not accepted it, which fences it, the
// same intent issued again under this leader's epoch, above every
// generation committed since; changed reports the latter.
func (r *serviceReleases) fresh(ctx context.Context, role string, intent delivery.Intent) (delivery.Intent, bool, error) {
	epoch := r.fencer.Current().Epoch
	if intent.AuthorityEpoch == epoch {
		return intent, false, nil
	}
	receipt, err := r.deliveries.StatusFor(ctx, intent)
	if err != nil && !errors.Is(err, delivery.ErrPending) {
		return intent, false, err
	}
	if err == nil && receipt.Status == "accepted" {
		return intent, false, nil
	}
	desired, err := r.hosts.ListDesired(ctx, role)
	if err != nil {
		return intent, false, err
	}
	intent.OperationID, intent.AuthorityEpoch = ulid.MustNew(ulid.Now(), rand.Reader).String(), epoch
	intent.Generation = max(intent.Generation, nextReleaseGeneration(desired))
	return intent, true, nil
}

// deployer submits intents for actor, the signer of the release's claim,
// under the leader's current authority epoch; recovering records a
// rollback before it is submitted.
func (r *serviceReleases) deployer(actor string, recovering func(context.Context, delivery.Intent, error) (delivery.Intent, error)) nativeDeployer {
	deployer := nativeDeployer{service: r.deliveries, hosts: r.hosts, recovering: recovering,
		submit: func(ctx context.Context, intent delivery.Intent) (delivery.Intent, string, error) {
			if !r.fencer.Current().CanMutate() {
				return intent, "", errors.New("this controller no longer holds the authority lease")
			}
			if intent.OperationID == "" {
				intent.OperationID = ulid.MustNew(ulid.Now(), rand.Reader).String()
			}
			if intent.AuthorityEpoch == 0 {
				intent.AuthorityEpoch = r.fencer.Current().Epoch
			}
			fingerprint, err := intent.Fingerprint()
			if err != nil {
				return intent, "", err
			}
			// Sequence the release before any host can see it. Nothing is
			// published yet; the release stays rolling and is retried.
			if err := r.fences.prepare(ctx, intent); err != nil {
				return intent, "", fmt.Errorf("%w: %w", errFencePrepare, err)
			}
			return intent, fingerprint, r.deliveries.SubmitVerified(ctx, intent, actor)
		}}
	if r.fences != nil {
		deployer.sequence, deployer.canary = r.fences.sequence, r.canary
	}
	return deployer
}

// reportQuietly reports state and only logs a failure: status.json is
// telemetry, and the next pass writes it again.
func (r *serviceReleases) reportQuietly(ctx context.Context, kv jetstream.KeyValue, role string, state serviceReleaseState) {
	if err := r.report(ctx, kv, role, state); err != nil && ctx.Err() == nil {
		slog.Warn("service release status", observability.ComponentKey, "rollout", "role", role, "error", err)
	}
}

// report writes the role's status.json when it changes or its inventory heartbeat is due.
func (r *serviceReleases) report(ctx context.Context, kv jetstream.KeyValue, role string, state serviceReleaseState) error {
	if !r.fencer.Current().CanMutate() {
		return errors.New("this controller no longer holds the authority lease")
	}
	// A historical completion cannot prove a currently serving source revision.
	if state.State == releasechannel.StateComplete && state.SourceRevision != "" {
		ready := false
		if state.Intent != nil && state.Intent.DesiredReplicas > 0 {
			statuses, err := r.hosts.ListHosts(ctx)
			if err != nil {
				return err
			}
			ready, _ = terraBaseReady(statuses, *state.Intent, time.Now())
		}
		if !ready {
			state.State, state.Reason = releasechannel.StateRolling, "waiting for fresh target proofs from every service replica"
		}
	}
	// A stalled inventory must not look newer than when collection began.
	updatedAt := time.Now().UTC()
	pins := &releasechannel.ReleasePins{Rollback: []string{}, KnownBad: []string{}}
	rollback := slices.Clone(state.Retained)
	if state.Previous != "" {
		rollback = append(rollback, state.Previous)
	}
	for _, digest := range rollback {
		if len(digest) != sha256.Size*2 || !lowerHexString(digest) {
			return fmt.Errorf("invalid %s rollback digest %q", role, digest)
		}
		pins.Rollback = append(pins.Rollback, digest)
	}
	slices.Sort(pins.Rollback)
	pins.Rollback = slices.Compact(pins.Rollback)
	prefix := knownBadKey(role, "")
	keys, err := releasechannel.PinKeys(ctx, kv, prefix+">")
	if err != nil {
		return fmt.Errorf("list %s release pins: %w", role, err)
	}
	for _, key := range keys {
		if digest, found := strings.CutPrefix(key, prefix); found {
			if len(digest) != sha256.Size*2 || !lowerHexString(digest) {
				return fmt.Errorf("invalid known-bad digest key %q", key)
			}
			pins.KnownBad = append(pins.KnownBad, digest)
		}
	}
	slices.Sort(pins.KnownBad)
	pins.KnownBad = slices.Compact(pins.KnownBad)
	location, err := r.channel.get(ctx)
	if err != nil {
		return err
	}
	status := releasechannel.ServiceStatus{Schema: releasechannel.ServiceStatusSchema, Cell: strings.ToUpper(r.cell),
		SourceRevision: state.SourceRevision,
		Role:           role, Digest: state.Digest, IssuedAt: state.IssuedAt, State: state.State, Reason: releasechannel.Clip(state.Reason),
		UpdatedAt: updatedAt, Pins: pins}
	stored, found, err := releasechannel.ReadServiceStatus(ctx, location, role)
	if err != nil && !errors.Is(err, releasechannel.ErrInvalid) {
		return err
	}
	if err == nil && found && stored.Cell == status.Cell && stored.Digest == status.Digest &&
		stored.SourceRevision == status.SourceRevision &&
		stored.IssuedAt.Equal(status.IssuedAt) && stored.State == status.State && stored.Reason == status.Reason &&
		stored.Pins.Equal(status.Pins) && !releasechannel.PinRefreshDue(stored.UpdatedAt, updatedAt) {
		return nil
	}
	slog.Info("service release status", observability.ComponentKey, "rollout", "role", role, "digest", status.Digest,
		"state", status.State, "reason", status.Reason)
	if !r.fencer.Current().CanMutate() {
		return errors.New("this controller no longer holds the authority lease")
	}
	return releasechannel.WriteServiceStatus(ctx, location, status)
}

// knownBadRecord withdraws a release digest from a cell: one rolled back
// on evidence against it (errBadRelease), not on a timeout (TS-623).
// Remove the knownBadKey entry only after review.
type knownBadRecord struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

func knownBadKey(role, digest string) string { return "knownbad." + role + "." + digest }

func knownBad(ctx context.Context, kv jetstream.KeyValue, role, digest string) (knownBadRecord, bool, error) {
	entry, err := kv.Get(ctx, knownBadKey(role, digest))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return knownBadRecord{}, false, nil
	}
	if err != nil {
		return knownBadRecord{}, false, err
	}
	var record knownBadRecord
	if err := json.Unmarshal(entry.Value(), &record); err != nil {
		return knownBadRecord{}, false, fmt.Errorf("decode %s: %w", entry.Key(), err)
	}
	return record, true, nil
}

func markKnownBad(ctx context.Context, kv jetstream.KeyValue, role, digest string, cause error) error {
	wire, err := json.Marshal(knownBadRecord{At: time.Now().UTC(), Reason: releasechannel.Clip(cause.Error())})
	if err != nil {
		return err
	}
	_, err = kv.Put(ctx, knownBadKey(role, digest), wire)
	return err
}

func loadServiceRelease(ctx context.Context, kv jetstream.KeyValue, key string) (serviceReleaseState, uint64, error) {
	entry, err := kv.Get(ctx, key)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return serviceReleaseState{}, 0, nil
	}
	if err != nil {
		return serviceReleaseState{}, 0, err
	}
	var state serviceReleaseState
	if err := json.Unmarshal(entry.Value(), &state); err != nil {
		return serviceReleaseState{}, 0, fmt.Errorf("decode %s: %w", key, err)
	}
	return state, entry.Revision(), nil
}

// saveServiceRelease writes state at revision (zero creates it) and returns
// the new revision; a concurrent writer fails it.
func saveServiceRelease(ctx context.Context, kv jetstream.KeyValue, key string, state serviceReleaseState, revision uint64) (uint64, error) {
	wire, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		return 0, err
	}
	if revision == 0 {
		return kv.Create(ctx, key, wire)
	}
	return kv.Update(ctx, key, wire, revision)
}

// serviceReleaseLog logs the release gate's progress lines.
type serviceReleaseLog struct{ role string }

func (l serviceReleaseLog) Write(data []byte) (int, error) {
	slog.Info("service release", observability.ComponentKey, "rollout", "role", l.role,
		"step", strings.TrimSpace(string(data)))
	return len(data), nil
}
