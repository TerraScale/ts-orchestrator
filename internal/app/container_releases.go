package app

import (
	"bytes"
	"context"
	"errors"
	"math"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go/jetstream"
)

// containerPass retains an exact intent in the existing channel record before
// submission. The delivery consumer remains the sole owner of runtime apply.
func (r *serviceReleases) containerPass(ctx context.Context, kv jetstream.KeyValue, role string) error {
	registry := r.policy.services
	if registry == nil || registry.kv == nil || registry.roots == nil || r.channel == nil || r.deliveries == nil {
		return containermaterial.ErrPending
	}
	epoch := r.fencer.Current().Epoch
	if err := r.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	entry, err := registry.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return err
	}
	registry.mu.Lock()
	adopted := registry.revision
	registry.mu.Unlock()
	if adopted != entry.Revision() {
		return containermaterial.ErrPending
	}
	rootHead, roots := registry.roots.reply("").Head, registry.roots.current()
	historicalRoots := registry.roots.historical()
	spec, err := cellspec.VerifyHistorical(entry.Value(), roots, registry.identity)
	if err != nil || !spec.RootSigned {
		return errors.Join(containermaterial.ErrPending, err)
	}
	var selected *cellspec.Service
	for i := range spec.Services {
		if spec.Services[i].Role == role {
			selected = &spec.Services[i]
			break
		}
	}
	if selected == nil || selected.Spec == nil || selected.Spec.Kind != workload.KindStateless || selected.Spec.Environment != r.environment || selected.Spec.Validate() != nil {
		return containermaterial.ErrPending
	}
	observation, err := r.channel.readContainerRelease(ctx, role, runtime.GOARCH)
	if err != nil {
		return err
	}
	if !observation.Found {
		return containermaterial.ErrPending
	}
	// The original root observation bounds every later broker read and write.
	ctx, cancel := context.WithDeadline(ctx, observation.ExpiresAt)
	defer cancel()
	target := release.ContainerTarget{Cell: strings.ToUpper(r.cell), Environment: r.environment, Role: role, Architecture: runtime.GOARCH}
	verified, err := release.VerifyContainerHistorical(observation.Bundle, roots, target)
	if err != nil {
		return err
	}
	envelope, err := trust.DecodeEnvelope(observation.Bundle.Claim)
	if err != nil {
		return err
	}
	signer, ok := r.policy.trusted(envelope.KeyID)
	if !ok || signer.Actor == "" {
		return delivery.ErrUnauthorized
	}
	if _, err := trust.VerifyCurrent(envelope, release.ContainerScope(target), trust.Keyring{envelope.KeyID: signer.PublicKey}, time.Now().UTC(), trust.Policy{MaxLifetime: release.MaxUpdateReceiptLifetime}); err != nil {
		return err
	}
	key := releasechannel.ServiceStatusKey(target.Cell, role)
	state, revision, err := r.load(ctx, key)
	if err != nil {
		return err
	}
	previousFingerprint := ""
	if state.Intent != nil {
		previousFingerprint, _ = state.Intent.Fingerprint()
	}
	previousActor := state.Actor
	var originalProfile containermaterial.Profile
	var originalRelease release.HistoricalContainer
	var originalGuard func(context.Context) error
	if observation.Floor.Found {
		// A floor locates archival provenance; its original actor grants no current rights.
		if r.history == nil {
			return containermaterial.ErrPending
		}
		original, reference, err := r.deliveries.ContainerProvenance(ctx, observation.Floor.OperationID)
		if err != nil || original.Container == nil {
			return errors.Join(containermaterial.ErrPending, err)
		}
		originalWire, err := r.history.ReadContainerProfile(ctx, reference)
		if err != nil {
			return err
		}
		prior, err := release.VerifyContainerHistorical(*original.Container, historicalRoots, target)
		if err != nil {
			return err
		}
		floor := observation.Floor
		if original.Cell != r.cell || original.Role != role || original.Environment != r.environment || original.Generation != floor.Generation || prior.Claim().ReleaseSequence != floor.ReleaseSequence || prior.ReleaseIdentity() != floor.ReleaseIdentity {
			return containermaterial.ErrPending
		}
		profile, err := containermaterial.VerifyProfile(originalWire, historicalRoots, registry.identity, original)
		if err != nil {
			return err
		}
		workload, err := containermaterial.ServiceIntent(profile, target.Architecture)
		if err != nil {
			return err
		}
		originalSHA256, err := swarmruntime.HistoricalServiceIntentSHA256(workload, prior)
		if err != nil || originalSHA256 != floor.IntentSHA256 {
			return errors.Join(containermaterial.ErrPending, err)
		}
		originalProfile, originalRelease = profile, prior
		originalFingerprint, err := original.Fingerprint()
		if err != nil {
			return err
		}
		originalGuard = func(ctx context.Context) error {
			retained, currentReference, err := r.deliveries.ContainerProvenance(ctx, original.OperationID)
			if err != nil || currentReference != reference {
				return errors.Join(containermaterial.ErrPending, err)
			}
			fingerprint, err := retained.Fingerprint()
			if err != nil || fingerprint != originalFingerprint {
				return errors.Join(containermaterial.ErrPending, err)
			}
			currentWire, err := r.history.ReadContainerProfile(ctx, reference)
			if err != nil || !bytes.Equal(originalWire, currentWire) {
				return errors.Join(containermaterial.ErrPending, err)
			}
			retained, currentReference, err = r.deliveries.ContainerProvenance(ctx, original.OperationID)
			if err != nil || currentReference != reference {
				return errors.Join(containermaterial.ErrPending, err)
			}
			fingerprint, err = retained.Fingerprint()
			if err != nil || fingerprint != originalFingerprint {
				return errors.Join(containermaterial.ErrPending, err)
			}
			return ctx.Err()
		}
		if state.Intent == nil || state.Intent.Container == nil || state.Intent.Generation < floor.Generation {
			state.Intent = new(original)
		} else {
			retained, err := release.VerifyContainerHistorical(*state.Intent.Container, historicalRoots, target)
			if err != nil {
				return err
			}
			if state.Intent.Generation == floor.Generation && (retained.ReleaseIdentity() != floor.ReleaseIdentity || state.Intent.ConfigDigest != original.ConfigDigest) {
				return containermaterial.ErrPending
			}
			if state.Intent.Generation > floor.Generation && retained.Claim().ReleaseSequence <= floor.ReleaseSequence {
				return containermaterial.ErrPending
			}
		}
	}
	intent, err := containerChannelIntent(state, observation, verified, *selected, r.cell, epoch, historicalRoots)
	if errors.Is(err, containermaterial.ErrPending) && observation.Floor.Found {
		intent, err = containerChannelRenewal(state, observation, originalProfile, originalRelease, verified, entry.Value(), roots, epoch)
	}
	if err != nil {
		return err
	}
	if _, err := containermaterial.VerifyProfile(entry.Value(), roots, registry.identity, intent); err != nil {
		return err
	}
	selectorGuard := func() error {
		// Leader revisions pin the exact immutable record bytes, including our own CAS.
		_, currentRevision, err := r.load(ctx, key)
		if err != nil || currentRevision != revision {
			return errors.Join(containermaterial.ErrPending, err)
		}
		return ctx.Err()
	}
	observationGuard := func() error {
		current, err := r.channel.readContainerRelease(ctx, role, target.Architecture)
		if err != nil || !current.Found || current.BundleSHA256 != observation.BundleSHA256 || current.Fingerprint != observation.Fingerprint || current.Floor == nil || *current.Floor != *observation.Floor {
			return errors.Join(containermaterial.ErrPending, err)
		}
		return ctx.Err()
	}
	guard := func() error {
		if err := selectorGuard(); err != nil {
			return err
		}
		if originalGuard != nil {
			if err := originalGuard(ctx); err != nil {
				return err
			}
		}
		if err := observationGuard(); err != nil {
			return err
		}
		if err := selectorGuard(); err != nil {
			return err
		}
		latest, err := registry.kv.Get(ctx, cellSpecKey)
		if err != nil {
			return err
		}
		registry.mu.Lock()
		current := registry.revision
		registry.mu.Unlock()
		if current != adopted || latest.Revision() != adopted || !bytes.Equal(latest.Value(), entry.Value()) || registry.roots.reply("").Head != rootHead || !time.Now().Before(observation.ExpiresAt) {
			return containermaterial.ErrPending
		}
		currentSigner, ok := r.policy.trusted(envelope.KeyID)
		if !ok || currentSigner.Actor != signer.Actor || !currentSigner.PublicKey.Equal(signer.PublicKey) {
			return delivery.ErrUnauthorized
		}
		if err := r.policy.authorizeIntent(ctx, signer.Actor, intent); err != nil {
			return err
		}
		if err := r.fencer.Guard(ctx, epoch); err != nil {
			return err
		}
		if err := selectorGuard(); err != nil {
			return err
		}
		if err := observationGuard(); err != nil {
			return err
		}
		if err := selectorGuard(); err != nil {
			return err
		}
		registry.mu.Lock()
		current = registry.revision
		registry.mu.Unlock()
		if current != adopted || registry.roots.reply("").Head != rootHead || !time.Now().Before(observation.ExpiresAt) {
			return containermaterial.ErrPending
		}
		return ctx.Err()
	}
	if err := guard(); err != nil {
		return err
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	if previousFingerprint != fingerprint || previousActor != signer.Actor {
		state.Intent, state.Actor = new(intent.Clone()), signer.Actor
		state.Claim, state.SourceRevision = observation.BundleSHA256, intent.Source.Commit
		state.State, state.Reason = releasechannel.StateRolling, "waiting for signed container application readiness"
		if revision, err = r.save(ctx, kv, key, state, revision, epoch); err != nil {
			return err
		}
	}
	if err := guard(); err != nil {
		return err
	}
	receipt, err := r.deliveries.StatusFor(ctx, intent)
	if errors.Is(err, delivery.ErrPending) {
		if err := guard(); err != nil {
			return err
		}
		return r.deliveries.SubmitVerified(ctx, intent, signer.Actor)
	}
	if err != nil {
		return err
	}
	if receipt.Status != "accepted" {
		return containermaterial.ErrPending
	}
	if err := guard(); err != nil {
		return err
	}
	status, err := r.channel.client.ReconcileContainerStatus(ctx, rootoci.ContainerStatusRequest{OperationID: intent.OperationID, ExpectedFingerprint: observation.Fingerprint})
	if err != nil {
		return err
	}
	claim := verified.Claim()
	if status.OperationID != intent.OperationID || !time.Now().Before(status.ExpiresAt) || status.ExpiresAt.After(observation.ExpiresAt) ||
		status.Status.Role != role || status.Status.Cell != target.Cell || status.Status.Environment != target.Environment || status.Status.Architecture != target.Architecture ||
		status.Status.Image != claim.Image || status.Status.ReleaseSequence != claim.ReleaseSequence || status.Status.Fingerprint != observation.Fingerprint || status.Status.State != releasechannel.StateComplete {
		return containermaterial.ErrPending
	}
	if err := guard(); err != nil {
		return err
	}
	if state.State == releasechannel.StateComplete {
		return nil
	}
	state.State, state.Reason = releasechannel.StateComplete, "signed container service is application-ready"
	_, err = r.save(ctx, kv, key, state, revision, epoch)
	return err
}

// containerChannelRenewal proposes proof renewal; current execution is reauthorized by the broker and root consumers.
func containerChannelRenewal(state serviceReleaseState, observation rootoci.ContainerReleaseObservation, original containermaterial.Profile, historical, renewed release.HistoricalContainer, currentSpec []byte, roots trust.Keyring, epoch uint64) (delivery.Intent, error) {
	previous, floor := state.Intent, observation.Floor
	originalIntent := original.Intent()
	if previous == nil || previous.Container == nil || previous.Validate() != nil || floor == nil || !floor.Found ||
		state.Preparation != nil || state.Rollback != nil || state.State != releasechannel.StateRolling && state.State != releasechannel.StateComplete ||
		previous.Generation != floor.Generation || originalIntent.OperationID != floor.OperationID || originalIntent.Generation != floor.Generation ||
		historical.ReleaseIdentity() != floor.ReleaseIdentity || historical.Claim().ReleaseSequence != floor.ReleaseSequence {
		return delivery.Intent{}, containermaterial.ErrPending
	}
	previousBundle, err := release.ContainerBundleSHA256(*previous.Container)
	if err != nil || renewed.BundleSHA256() != observation.BundleSHA256 || renewed.Fingerprint() != observation.Fingerprint ||
		previousBundle == observation.BundleSHA256 && previous.AuthorityEpoch == epoch {
		return delivery.Intent{}, errors.Join(containermaterial.ErrPending, err)
	}
	intent := previous.Clone()
	intent.AuthorityEpoch = epoch
	intent.Container = new(observation.Bundle)
	intent.OperationID = entityid.Derive("container-channel-renewal", floor.OperationID, intent.Cell, intent.Role,
		observation.BundleSHA256, intent.ConfigDigest, strconv.FormatUint(epoch, 10), strconv.FormatUint(intent.Generation, 10))
	current, err := containermaterial.VerifyProfile(currentSpec, roots, original.Identity(), intent)
	if err != nil {
		return delivery.Intent{}, err
	}
	if err := containermaterial.VerifyHistoricalContinuity(original, historical, current, renewed); err != nil {
		return delivery.Intent{}, err
	}
	return intent, nil
}

func containerChannelIntent(state serviceReleaseState, observation rootoci.ContainerReleaseObservation, verified release.HistoricalContainer, service cellspec.Service, cell string, epoch uint64, roots trust.Keyring) (delivery.Intent, error) {
	if observation.Floor == nil || service.Spec == nil || state.Intent == nil && observation.Floor.Found || state.Intent != nil && state.Intent.Validate() != nil {
		// Missing original state cannot recover a failed floor from a rollback's older service.
		return delivery.Intent{}, containermaterial.ErrPending
	}
	previous := state.Intent
	claim := verified.Claim()
	if previous != nil && (previous.Cell != cell || previous.Role != claim.Role || previous.Environment != claim.Environment) {
		return delivery.Intent{}, containermaterial.ErrPending
	}
	config := delivery.ConfigDigestOf(service.Profile.Args, service.Profile.Env, service.Profile.Secrets)
	var generation uint64
	if previous != nil {
		generation = previous.Generation
	}
	replicas := service.Spec.Replicas.Min
	if previous == nil {
		if observation.Floor.Found {
			return delivery.Intent{}, containermaterial.ErrPending
		}
	} else if previous.Container == nil {
		if state.State != releasechannel.StateComplete || state.Preparation != nil || state.Rollback != nil {
			return delivery.Intent{}, containermaterial.ErrPending
		}
	} else {
		prior, err := release.VerifyContainerHistorical(*previous.Container, roots, release.ContainerTarget{Cell: claim.Cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture})
		if err != nil {
			return delivery.Intent{}, err
		}
		if prior.ReleaseIdentity() == verified.ReleaseIdentity() {
			// A retry must preserve the failed floor and its original rollback baseline.
			digest, err := release.ContainerBundleSHA256(*previous.Container)
			if err != nil || digest != observation.BundleSHA256 || previous.ConfigDigest != config || previous.AuthorityEpoch != epoch {
				return delivery.Intent{}, containermaterial.ErrPending
			}
			return previous.Clone(), nil
		} else if claim.ReleaseSequence <= prior.Claim().ReleaseSequence {
			return delivery.Intent{}, containermaterial.ErrPending
		}
	}
	if generation == math.MaxUint64 {
		return delivery.Intent{}, containermaterial.ErrPending
	}
	generation++
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.Derive("container-channel-release", cell, claim.Role, observation.BundleSHA256, config, strconv.FormatUint(epoch, 10), strconv.FormatUint(generation, 10)),
		Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256},
		Cell:   cell, Role: claim.Role, Environment: claim.Environment, Generation: generation, DesiredReplicas: replicas,
		ConfigDigest: config, AuthorityEpoch: epoch, Container: new(observation.Bundle)}
	return intent, intent.Validate()
}
