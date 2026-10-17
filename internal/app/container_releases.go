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
	if observation.Floor.Found {
		original, err := r.deliveries.ContainerIntent(ctx, observation.Floor.OperationID)
		if err != nil {
			return err
		}
		prior, err := release.VerifyContainerHistorical(*original.Container, roots, target)
		if err != nil {
			return err
		}
		floor := observation.Floor
		if original.Cell != r.cell || original.Role != role || original.Environment != r.environment || original.Generation != floor.Generation || prior.Claim().ReleaseSequence != floor.ReleaseSequence || prior.ReleaseIdentity() != floor.ReleaseIdentity {
			return containermaterial.ErrPending
		}
		if _, err := containermaterial.VerifyProfile(entry.Value(), roots, registry.identity, original); err != nil {
			return err
		}
		if state.Intent == nil || state.Intent.Container == nil || state.Intent.Generation < floor.Generation {
			state.Intent = new(original)
		} else {
			retained, err := release.VerifyContainerHistorical(*state.Intent.Container, roots, target)
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
	intent, err := containerChannelIntent(state, observation, verified, *selected, r.cell, epoch, roots)
	if err != nil {
		return err
	}
	if _, err := containermaterial.VerifyProfile(entry.Value(), roots, registry.identity, intent); err != nil {
		return err
	}
	guard := func() error {
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
		return r.fencer.Guard(ctx, epoch)
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
	if state.State == releasechannel.StateComplete {
		return nil
	}
	if err := guard(); err != nil {
		return err
	}
	state.State, state.Reason = releasechannel.StateComplete, "signed container service is application-ready"
	_, err = r.save(ctx, kv, key, state, revision, epoch)
	return err
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
	advance := true
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
			if previous.ConfigDigest != config {
				return delivery.Intent{}, containermaterial.ErrPending
			}
			advance, replicas = false, previous.DesiredReplicas
		} else if claim.ReleaseSequence <= prior.Claim().ReleaseSequence {
			return delivery.Intent{}, containermaterial.ErrPending
		}
	}
	if advance {
		if generation == math.MaxUint64 {
			return delivery.Intent{}, containermaterial.ErrPending
		}
		generation++
	}
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.Derive("container-channel-release", cell, claim.Role, observation.BundleSHA256, config, strconv.FormatUint(epoch, 10), strconv.FormatUint(generation, 10)),
		Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256},
		Cell:   cell, Role: claim.Role, Environment: claim.Environment, Generation: generation, DesiredReplicas: replicas,
		ConfigDigest: config, AuthorityEpoch: epoch, Container: new(observation.Bundle)}
	return intent, intent.Validate()
}
