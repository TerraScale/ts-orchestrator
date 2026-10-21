package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
)

// errFencePrepare reports a release whose fence mark could not be written:
// it was not submitted, and an earlier submission of it may still be
// rolling, so it is retried rather than failed.
var errFencePrepare = errors.New("the release fence mark was not written")

// serviceReleaseRoles are the first-party roles followed by the regional
// release controller, in the order the leader checks them.
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

// serviceReleases follows first-party release channels in the region's head
// bucket. TSAuth uses signed OCI intents; TerraBase retains its native
// readiness and rollback path while qualified stateful admission is pending.
type serviceReleases struct {
	js         jetstream.JetStream
	cell       string // the NATS cell, e.g. gru
	channel    *channelSource
	deliveries *delivery.Service
	hosts      seatrollout.Hosts
	profiles   func() map[string]WorkloadProfile
	fencer     authority.Fencer
	history    *nativeHistory
	// fences restarts each release one node at a time when the cell spec
	// has a release fence; nil restarts every replica at once.
	fences *releaseFence
	// interval is how often the channels are read; zero means
	// defaultChannelInterval.
	interval time.Duration
	// wait overrides the readiness gate's wait in tests.
	wait time.Duration
	// policy holds the root-delegated release key the channel carries.
	policy signerPolicy
	// roots and environment verify that delegation for this cell.
	roots       func() trust.Keyring
	environment string
	// logged is the status last logged at INFO per role, and warned the error
	// text last logged at WARN per role. Only the pass loop reads or writes them.
	logged map[string]serviceLog
	warned map[string]string
}

// serviceLog is the part of a role's status that an INFO record shows.
type serviceLog struct {
	digest, reason string
	state          releasechannel.State
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
	// Preparation is persisted before native CAS; its exact request survives
	// either side of the native/channel handoff, including epoch refreshes.
	Preparation *nativePrepareRequest `json:"preparation,omitempty"`
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
		ctx := observability.StartTrace(ctx)
		if r.fencer.Current().CanMutate() {
			if err := r.fences.reconcile(ctx); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "release fence", observability.ComponentKey, "rollout", "error", err)
			}
		}
		for _, role := range serviceReleaseRoles {
			if !r.fencer.Current().CanMutate() {
				break
			}
			if err := r.pass(ctx, kv, role); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "service release channel", observability.ComponentKey, "rollout", "role", role, "error", err)
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
	if role == tsauth.Role {
		return r.containerPass(ctx, kv, role)
	}
	return r.nativePass(ctx, kv, role)
}

func (r *serviceReleases) nativePass(ctx context.Context, kv jetstream.KeyValue, role string) error {
	epoch := r.fencer.Current().Epoch
	if !r.fencer.Current().CanMutate() {
		return errors.New("lost the authority lease before the release")
	}
	if err := r.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	key := releasechannel.ServiceStatusKey(strings.ToUpper(r.cell), role)
	state, revision, err := r.load(ctx, key)
	if err != nil {
		return err
	}
	// A submitted release finishes, or rolls back, from its recorded intent
	// before the channel is read: its delivery may be partly committed, and
	// neither a newer claim nor an unreadable channel may hold it.
	if state.State != releasechannel.StateRolling || state.Intent == nil && state.Preparation == nil {
		claim, found, err := r.channel.readNativeClaim(ctx, role)
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
			record, actor, issued, err := r.verify(ctx, kv, role, claim)
			next.IssuedAt, next.Digest, next.Actor = issued, record.Digest, actor
			now := time.Now()
			switch {
			case err != nil && !errors.Is(err, delivery.ErrInvalid) && !errors.Is(err, delivery.ErrUnauthorized):
				return err
			case err != nil:
				next.State, next.Reason = releasechannel.StateFailed, "the claim does not verify in this cell: "+err.Error()
				return r.report(ctx, kv, role, next)
			case issued.After(now.Add(releasechannel.ClaimClockSkew)):
				next.State, next.Reason = releasechannel.StateFailed, fmt.Sprintf("the claim is issued in the future, at %s", issued)
				return r.report(ctx, kv, role, next)
			case !issued.After(state.IssuedAt):
				return fmt.Errorf("release.json holds a claim issued at %s, not after the cell's last %s release", issued, role)
			case issued.After(now):
				// Tolerated skew waits without changing the signed observation start.
				return fmt.Errorf("the claim is issued at %s; waiting for the cell clock", issued)
			}
			next.SourceRevision = record.Source.Commit
			if bad, found, err := knownBad(ctx, kv, role, record.Digest); err != nil {
				return err
			} else if found {
				next.State, next.Reason = releasechannel.StateFailed,
					fmt.Sprintf("%s %s is known bad in this cell since %s (%s); release a new build", role, record.Digest,
						bad.At.Format(time.RFC3339), bad.Reason)
			}
			if age := time.Since(issued); next.State == releasechannel.StateRolling && age >= rollout.ObservationBudget {
				next.State, next.Reason = releasechannel.StateFailed,
					fmt.Sprintf("the claim was issued %s ago, past its %s observation window; run the release again", age.Round(time.Second), rollout.ObservationBudget)
			}
			state = next
			if revision, err = r.save(ctx, kv, key, state, revision, epoch); err != nil {
				return err
			}
			r.reportQuietly(ctx, kv, role, state)
			if state.State == releasechannel.StateFailed {
				return nil
			}
		}
		state.claim = claim
		if r.channel.client == nil {
			state.location, err = r.channel.get(ctx)
			if err != nil {
				return err
			}
		}
	}
	finished, err := r.release(ctx, kv, role, state, epoch, func(next serviceReleaseState) error {
		state = next
		if revision, err = r.save(ctx, kv, key, state, revision, epoch); err != nil {
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
	if _, err := r.save(ctx, kv, key, finished, revision, epoch); err != nil {
		return err
	}
	r.reportQuietly(ctx, kv, role, finished)
	return nil
}

// verify authenticates role's claim for this cell and returns its record,
// signer and issuance instant.
func (r *serviceReleases) verify(ctx context.Context, kv jetstream.KeyValue, role string, claim []byte) (delivery.ArtifactRecord, string, time.Time, error) {
	issued, err := releasechannel.ClaimIssuedAt(claim)
	if err != nil {
		return delivery.ArtifactRecord{}, "", time.Time{}, fmt.Errorf("%w: %w", delivery.ErrInvalid, err)
	}
	if err := r.trustReleaseDelegation(ctx, kv); err != nil {
		return delivery.ArtifactRecord{}, "", time.Time{}, err
	}
	record, actor, err := r.deliveries.VerifyClaim(ctx, claim)
	if err == nil && record.Role != role {
		err = fmt.Errorf("%w: the claim is for role %s", delivery.ErrInvalid, record.Role)
	}
	return record, actor, issued, err
}

// trustReleaseDelegation makes the cell's root-delegated release key the
// current release signer. An absent or unverifiable delegation clears it, so
// the claim verifies through the cell signers alone; a failed read is returned
// so the pass retries instead of failing the claim.
func (r *serviceReleases) trustReleaseDelegation(ctx context.Context, kv jetstream.KeyValue) error {
	if r.policy.release == nil {
		return nil
	}
	entry, err := kv.Get(ctx, releasechannel.ChannelKey(strings.ToUpper(r.cell)))
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return fmt.Errorf("read the release delegation: %w", err)
	}
	if err == nil {
		var channel releasechannel.Channel
		if err = protocol.DecodeStrict(entry.Value(), &channel, releasechannel.MaxValueBytes); err == nil {
			var delegation release.BinaryUpdateDelegation
			var key ed25519.PublicKey
			var expires time.Time
			delegation, key, expires, err = release.VerifyReleaseDelegationCurrent(channel.Delegation, r.roots(), r.environment, time.Now())
			if err == nil {
				err = r.policy.setReleaseDelegation(delegation, key, expires)
			}
		}
	}
	if err != nil {
		slog.Warn("release delegation refused; claims verify through cell signers only", observability.ComponentKey, "rollout",
			"cell", r.cell, "error", err)
		r.policy.release.Store(nil)
	}
	return nil
}

// release admits the channel's claim unless state already holds its intent,
// rolls the role out and returns the final state: complete once every
// replica serves the release, failed once it was refused before anything
// changed or rolled back. save records progress; an error from release or
// save means the release may be retried, and a release whose rollback has
// not finished stays rolling.
func (r *serviceReleases) release(ctx context.Context, kv jetstream.KeyValue, role string, state serviceReleaseState, operationEpoch uint64,
	save func(serviceReleaseState) error,
) (serviceReleaseState, error) {
	if err := r.fencer.Guard(ctx, operationEpoch); err != nil {
		return state, err
	}
	failed := func(err error) (serviceReleaseState, error) {
		state.State, state.Reason = releasechannel.StateFailed, err.Error()
		return state, nil
	}
	if state.Preparation != nil {
		if err := r.finishPreparation(ctx, &state, operationEpoch, save); err != nil {
			return state, err
		}
		if state.State == releasechannel.StateFailed {
			return state, nil
		}
	}
	var target *nativeGoodRelease
	deadline := state.IssuedAt.Add(rollout.ObservationBudget)
	if state.Intent == nil {
		if !time.Now().Before(deadline) {
			return failed(fmt.Errorf("the claim is past its %s observation window; run the release again", rollout.ObservationBudget))
		}
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
		record, actor, err := r.admit(ctx, kv, state.location, role, state.claim)
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
		intent := nativeIntent(record, nativeRelease{Role: role, Replicas: replicas, Profile: profile}, generation)
		intent.SchemaVersion = delivery.SchemaVersion
		intent.AuthorityEpoch = operationEpoch
		intent.OperationID = entityid.Derive("native-channel-release", r.cell, role, state.Claim, strconv.FormatUint(intent.AuthorityEpoch, 10))
		// Admission and predecessor lookup may have spent the remaining window without touching hosts.
		if !time.Now().Before(deadline) {
			return failed(fmt.Errorf("the claim is past its %s observation window; run the release again", rollout.ObservationBudget))
		}
		if r.history == nil {
			return failed(errors.New("native signed profile history is unavailable"))
		}
		state.Digest, state.Actor, state.Previous = record.Digest, actor, previous
		state.Preparation = &nativePrepareRequest{Intent: intent, Deadline: deadline}
		state.Reason = "selecting the signed native release and predecessor"
		if err := save(state); err != nil {
			return state, err
		}
		if err := r.finishPreparation(ctx, &state, operationEpoch, save); err != nil {
			return state, err
		}
		if state.State == releasechannel.StateFailed {
			return state, nil
		}
	}
	{
		if r.history == nil {
			return state, errors.New("native signed profile history is unavailable")
		}
		history, _, err := r.history.load(ctx, role)
		if err != nil {
			return state, err
		}
		target = history.Previous
		if history.Pending == nil || history.Pending.Intent.OperationID != state.Intent.OperationID {
			return state, delivery.ErrConflict
		}
		if history.Recovery != nil && state.Rollback == nil {
			state.Rollback = &history.Recovery.Intent
			if err := save(state); err != nil {
				return state, err
			}
		}
		if state.Rollback == nil && target == nil && !time.Now().Before(deadline) {
			if err := r.deliveries.RefuseIntent(ctx, *state.Intent, state.Actor, operationEpoch,
				"native observation expired before first-install delivery"); err == nil {
				return failed(context.DeadlineExceeded)
			} else if !errors.Is(err, delivery.ErrConflict) {
				return state, err
			}
		}
	}
	wait := r.wait
	if wait == 0 {
		wait = rollout.ObservationBudget
	}
	progress := &stickyWriter{writer: serviceReleaseLog{role: role}}
	unfinished := func(err error) (serviceReleaseState, error) {
		state.Reason = fmt.Sprintf("the rollback to %s has not finished; retrying: %v", state.Previous, err)
		return state, errors.Join(err, save(state))
	}
	if state.Rollback != nil {
		// An earlier pass or leader started the rollback: finish it.
		intent, changed, err := r.fresh(ctx, role, *state.Rollback, operationEpoch)
		if err != nil {
			return state, err
		}
		if changed {
			state.Preparation = &nativePrepareRequest{Intent: intent, RecoveryOf: state.Intent.OperationID, ResumeOf: state.Rollback.OperationID}
			if err := save(state); err != nil {
				return state, err
			}
			if err := r.finishPreparation(ctx, &state, operationEpoch, save); err != nil {
				return state, err
			}
			intent = *state.Rollback
		}
		deployer := r.deployer(state.Actor, nil)
		deployer.canary = nil
		if _, err := deployer.rollOut(ctx, intent, wait, progress); err != nil {
			return unfinished(err)
		}
		return failed(fmt.Errorf("%s release %s failed its readiness gate and was rolled back to %s", role, state.Digest, state.Previous))
	}
	intent, changed := *state.Intent, false
	if time.Now().Before(deadline) {
		var err error
		intent, changed, err = r.fresh(ctx, role, intent, operationEpoch)
		if err != nil {
			return state, err
		}
	}
	if changed {
		state.Preparation = &nativePrepareRequest{Intent: intent, ResumeOf: state.Intent.OperationID, Deadline: deadline}
		if err := save(state); err != nil {
			return state, err
		}
		if err := r.finishPreparation(ctx, &state, operationEpoch, save); err != nil {
			return state, err
		}
		intent = *state.Intent
	}
	deployer := r.deployer(state.Actor, func(ctx context.Context, rollback delivery.Intent, cause error) (delivery.Intent, error) {
		rollback.SchemaVersion, rollback.OperationID = delivery.SchemaVersion, entityid.New()
		rollback.AuthorityEpoch = operationEpoch
		state.Preparation = &nativePrepareRequest{Intent: rollback, RecoveryOf: intent.OperationID}
		state.Reason = "selecting the recorded native predecessor for recovery"
		if err := save(state); err != nil {
			return rollback, err
		}
		if err := r.finishPreparation(ctx, &state, operationEpoch, save); err != nil {
			return rollback, err
		}
		rollback = *state.Rollback
		if err := r.history.reject(ctx, intent, cause, operationEpoch); err != nil {
			return rollback, err
		}
		// Recorded before the rollback: the cell never releases it again.
		if errors.Is(cause, errBadRelease) && (target == nil || target.Binding.Artifact.Digest != state.Digest) {
			if err := r.fencer.Guard(ctx, operationEpoch); err != nil {
				return rollback, err
			}
			if err := markKnownBad(ctx, kv, role, state.Digest, cause); err != nil {
				return rollback, err
			}
		}
		state.Rollback, state.Reason = &rollback, "rolling back to "+state.Previous
		return rollback, save(state)
	})
	deployer.target, deployer.bound = nativeTarget(target), true
	// Refresh and persistence are read/metadata work, never additional observation.
	forward, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	wait = min(wait, time.Until(deadline))
	switch err := deployer.roll(forward, intent, wait, progress); {
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

// Reconcile an exact durably recorded handoff before reading another claim.
// A native CAS with a lost reply is completed by read-back, never reselection.
func (r *serviceReleases) finishPreparation(ctx context.Context, state *serviceReleaseState, epoch uint64, save func(serviceReleaseState) error) error {
	if r.history == nil {
		return errors.New("native signed profile history is unavailable")
	}
	request := *state.Preparation
	history, _, err := r.history.load(ctx, request.Intent.Role)
	if err != nil {
		return err
	}
	selected := history.Pending
	if request.RecoveryOf != "" {
		selected = history.Recovery
	}
	fingerprint, err := request.Intent.Fingerprint()
	if err != nil {
		return err
	}
	if selected == nil || selected.Fingerprint != fingerprint {
		if request.RecoveryOf == "" && !time.Now().Before(request.Deadline) {
			state.Preparation = nil
			if state.Intent == nil {
				state.State, state.Reason = releasechannel.StateFailed, "the claim is past its observation window before native selection"
			}
			return save(*state)
		}
		fresh, changed, err := r.fresh(ctx, request.Intent.Role, request.Intent, epoch)
		if err != nil {
			return err
		}
		if changed {
			request.Intent = fresh
			fingerprint, err = request.Intent.Fingerprint()
			if err != nil {
				return err
			}
			state.Preparation = &request
			if err := save(*state); err != nil {
				return err
			}
		}
		if _, err := r.history.prepare(ctx, request); err != nil {
			// Includes ambiguous CAS and a fence mark failure after selection.
			// Keep the request so a later leader can read back that exact binding.
			return err
		}
		history, _, err = r.history.load(ctx, request.Intent.Role)
		if err != nil {
			return err
		}
		selected = history.Pending
		if request.RecoveryOf != "" {
			selected = history.Recovery
		}
	}
	if selected == nil || selected.Fingerprint != fingerprint {
		return delivery.ErrConflict
	}
	if request.RecoveryOf != "" {
		if history.Pending == nil || history.Pending.Intent.OperationID != request.RecoveryOf {
			return delivery.ErrConflict
		}
		state.Rollback, state.Reason = new(selected.Intent), "rolling back to "+state.Previous
	} else {
		state.Intent = new(selected.Intent)
		if history.Previous != nil {
			state.Previous = history.Previous.Binding.Artifact.Digest
		}
		state.Retained = nil
		state.Reason = fmt.Sprintf("rolling %d replicas from %s", selected.Intent.DesiredReplicas, state.Previous)
	}
	state.Preparation = nil
	return save(*state)
}

// admit copies the claimed binary out of the head bucket and admits it.
func (r *serviceReleases) admit(ctx context.Context, kv jetstream.KeyValue, location releasechannel.Location, role string, claim []byte,
) (delivery.ArtifactRecord, string, error) {
	claimed, _, _, err := r.verify(ctx, kv, role, claim)
	if err != nil {
		return delivery.ArtifactRecord{}, "", err
	}
	file, err := os.CreateTemp("", "ts-orchestrator-service-release-")
	if err != nil {
		return delivery.ArtifactRecord{}, "", err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	var readErr error
	if r.channel != nil && r.channel.client != nil {
		readErr = r.channel.readNativeBinary(ctx, role, claimed.Digest, claim, file)
	} else {
		readErr = releasechannel.ReadServiceBinary(ctx, location, role, claimed.Digest, file)
	}
	if readErr != nil {
		return delivery.ArtifactRecord{}, "", readErr
	}
	return r.deliveries.AdmitClaim(ctx, file, claim)
}

// fresh returns intent, or, when an earlier leader submitted it under its
// epoch and the delivery worker has not accepted it, which fences it, the
// same intent issued again under this leader's epoch, above every
// generation committed since; changed reports the latter.
func (r *serviceReleases) fresh(ctx context.Context, role string, intent delivery.Intent, epoch uint64) (delivery.Intent, bool, error) {
	if err := r.fencer.Guard(ctx, epoch); err != nil {
		return intent, false, err
	}
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
	intent.OperationID, intent.AuthorityEpoch = entityid.New(), epoch
	intent.Generation = max(intent.Generation, nextReleaseGeneration(desired))
	return intent, true, nil
}

// deployer submits intents for actor, the signer of the release's claim,
// under the leader's current authority epoch; recovering records a
// rollback before it is submitted.
func (r *serviceReleases) deployer(actor string, recovering func(context.Context, delivery.Intent, error) (delivery.Intent, error)) nativeDeployer {
	deployer := nativeDeployer{service: r.deliveries, hosts: r.hosts, recovering: recovering,
		prepare: func(ctx context.Context, intent delivery.Intent, recoveryOf, resumeOf string) (delivery.Intent, *nativeRollbackTarget, error) {
			if r.history == nil {
				return intent, nil, errors.New("native signed profile history is unavailable")
			}
			reply, err := r.history.prepare(ctx, nativePrepareRequest{Intent: intent, RecoveryOf: recoveryOf, ResumeOf: resumeOf})
			return reply.Intent, reply.Previous, err
		},
		observe: func(ctx context.Context, intent delivery.Intent) (bool, error) {
			if r.history == nil {
				return false, errors.New("native signed profile history is unavailable")
			}
			return r.history.observe(ctx, intent)
		},
		submit: func(ctx context.Context, intent delivery.Intent) (delivery.Intent, string, error) {
			if !r.fencer.Current().CanMutate() {
				return intent, "", errors.New("this controller no longer holds the authority lease")
			}
			if intent.OperationID == "" {
				intent.OperationID = entityid.New()
			}
			epoch := intent.AuthorityEpoch
			if r.history == nil {
				return intent, "", errors.New("native signed profile history is unavailable")
			}
			if _, err := r.history.profile(ctx, intent); err != nil {
				return intent, "", err
			}
			fingerprint, err := intent.Fingerprint()
			if err != nil {
				return intent, "", err
			}
			if intent.AuthorityEpoch != r.fencer.Current().Epoch {
				receipt, err := r.deliveries.StatusFor(ctx, intent)
				if err != nil || receipt.Status != "accepted" {
					return intent, "", authority.ErrFenced
				}
				return intent, fingerprint, nil
			}
			if err := r.fencer.Guard(ctx, epoch); err != nil {
				return intent, "", err
			}
			// Sequence the release before any host can see it. Nothing is
			// published yet; the release stays rolling and is retried.
			history, _, err := r.history.load(ctx, intent.Role)
			if err != nil {
				return intent, "", err
			}
			if err := r.history.prepareGate(ctx, intent, history); err != nil {
				return intent, "", fmt.Errorf("%w: %w", errFencePrepare, err)
			}
			if _, err := r.history.profile(ctx, intent); err != nil {
				return intent, "", err
			}
			return intent, fingerprint, r.deliveries.SubmitVerified(ctx, intent, actor)
		}}
	return deployer
}

// reportQuietly reports state and only logs a failure: status.json is
// telemetry, and the next pass writes it again.
func (r *serviceReleases) reportQuietly(ctx context.Context, kv jetstream.KeyValue, role string, state serviceReleaseState) {
	err := r.report(ctx, kv, role, state)
	if err == nil {
		delete(r.warned, role)
		return
	}
	if ctx.Err() != nil {
		return
	}
	// A failure that repeats its text on every pass is steady state: DEBUG.
	level := slog.LevelDebug
	if r.warned[role] != err.Error() {
		level = slog.LevelWarn
		if r.warned == nil {
			r.warned = map[string]string{}
		}
		r.warned[role] = err.Error()
	}
	slog.Log(ctx, level, "service release status", observability.ComponentKey, "rollout", "role", role, "error", err)
}

// report writes the role's status.json when it changes or its inventory heartbeat is due.
func (r *serviceReleases) report(ctx context.Context, kv jetstream.KeyValue, role string, state serviceReleaseState) error {
	if !r.fencer.Current().CanMutate() {
		return errors.New("this controller no longer holds the authority lease")
	}
	if r.channel != nil && r.channel.client != nil {
		receipt, err := r.channel.client.ReconcileNativeServiceStatus(ctx, rootoci.NativeServiceStatusRequest{Role: role, ExpectedClaimSHA256: state.Claim})
		if err != nil {
			return err
		}
		if !time.Now().Before(receipt.ExpiresAt) || receipt.Status.Role != role || receipt.Status.Cell != strings.ToUpper(r.cell) {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	// A historical completion cannot prove a currently serving source revision.
	if state.State == releasechannel.StateComplete && state.SourceRevision != "" {
		ready := false
		if state.Intent != nil && state.Intent.DesiredReplicas > 0 && r.history != nil {
			nodes, err := r.history.ready(ctx, *state.Intent)
			if err != nil && !errors.Is(err, errBadRelease) {
				return err
			}
			ready = len(nodes) != 0
		}
		if !ready {
			state.State, state.Reason = releasechannel.StateRolling, "waiting for fresh target proofs from every service replica"
		}
	}
	// A stalled inventory must not look newer than when collection began.
	updatedAt := time.Now().UTC()
	pins := &releasechannel.ReleasePins{Rollback: []string{}, KnownBad: []string{}}
	rollback := slices.Clone(state.Retained)
	if r.history != nil {
		uses, err := r.history.artifactsInUse(ctx)
		if err != nil {
			return err
		}
		for _, use := range uses {
			if use.Role == role {
				rollback = append(rollback, use.Digest)
			}
		}
	}
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
	// A repeat of the logged digest, state and reason is steady state: DEBUG.
	shown := serviceLog{digest: status.Digest, state: status.State, reason: status.Reason}
	level := slog.LevelDebug
	if logged, seen := r.logged[role]; !seen || logged != shown {
		level = slog.LevelInfo
		if r.logged == nil {
			r.logged = map[string]serviceLog{}
		}
		r.logged[role] = shown
	}
	slog.Log(ctx, level, "service release status", observability.ComponentKey, "rollout", "role", role, "digest", status.Digest,
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

func (r *serviceReleases) load(ctx context.Context, key string) (serviceReleaseState, uint64, error) {
	if r.js == nil {
		return serviceReleaseState{}, 0, errors.New("native release channel leader reader is unavailable")
	}
	legacy, err := r.js.Conn().JetStream()
	if err != nil {
		return serviceReleaseState{}, 0, err
	}
	subject := "$KV." + releasechannel.Bucket + "." + key
	msg, err := legacy.GetLastMsg("KV_"+releasechannel.Bucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return serviceReleaseState{}, 0, nil
	}
	if err != nil {
		return serviceReleaseState{}, 0, err
	}
	if msg.Subject != subject || msg.Sequence == 0 || msg.Header.Get("KV-Operation") != "" {
		return serviceReleaseState{}, 0, errors.New("invalid native release channel state marker")
	}
	var state serviceReleaseState
	if err := json.Unmarshal(msg.Data, &state, json.RejectUnknownMembers(true)); err != nil {
		return state, 0, err
	}
	return state, msg.Sequence, nil
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

func (r *serviceReleases) save(ctx context.Context, kv jetstream.KeyValue, key string, state serviceReleaseState, revision, epoch uint64) (uint64, error) {
	if err := r.fencer.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	return saveServiceRelease(ctx, kv, key, state, revision)
}

// serviceReleaseLog logs the release gate's progress lines.
type serviceReleaseLog struct{ role string }

func (l serviceReleaseLog) Write(data []byte) (int, error) {
	slog.Info("service release", observability.ComponentKey, "rollout", "role", l.role,
		"step", strings.TrimSpace(string(data)))
	return len(data), nil
}
