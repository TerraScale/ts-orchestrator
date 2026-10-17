package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
)

func (o *rootReleaseObservation) nativeRelease(ctx context.Context, role string) (rootoci.NativeReleaseObservation, delivery.ArtifactRecord, error) {
	if !slices.Contains(serviceReleaseRoles, role) {
		return rootoci.NativeReleaseObservation{}, delivery.ArtifactRecord{}, rootoci.ErrUnauthorized
	}
	if _, ok := o.registry.profiles()[role]; !ok {
		return rootoci.NativeReleaseObservation{}, delivery.ArtifactRecord{}, rootoci.ErrUnauthorized
	}
	location, err := o.location(ctx)
	if err != nil {
		return rootoci.NativeReleaseObservation{}, delivery.ArtifactRecord{}, err
	}
	claim, found, err := releasechannel.ReadServiceClaim(ctx, location, role)
	if err != nil {
		return rootoci.NativeReleaseObservation{}, delivery.ArtifactRecord{}, err
	}
	result := rootoci.NativeReleaseObservation{Found: found, ExpiresAt: o.deadline}
	if !found {
		return result, delivery.ArtifactRecord{}, o.guard(ctx)
	}
	policy, err := buildSignerPolicy(o.b.cfg)
	if err != nil {
		return result, delivery.ArtifactRecord{}, err
	}
	policy.services = o.registry
	if err := policy.replaceSigners(o.registry.effectiveSigners(o.registry.current)); err != nil {
		return result, delivery.ArtifactRecord{}, err
	}
	channel, present, err := releasechannel.ReadChannel(ctx, location)
	if err != nil {
		return result, delivery.ArtifactRecord{}, err
	}
	if present {
		delegation, key, expires, verifyErr := release.VerifyReleaseDelegationCurrent(channel.Delegation, o.registry.roots.current(), o.source.Identity().Environment, time.Now().UTC())
		if verifyErr == nil {
			if err := policy.setReleaseDelegation(delegation, key, expires); err != nil {
				return result, delivery.ArtifactRecord{}, err
			}
			o.capDeadline(expires)
		}
	}
	record, actor, err := policy.codec.VerifyArchivedArtifact(ctx, claim)
	if err != nil {
		return result, delivery.ArtifactRecord{}, err
	}
	if err := policy.authorizeArtifact(ctx, actor, record); err != nil {
		return result, delivery.ArtifactRecord{}, err
	}
	if record.Role != role || record.Environment != o.source.Identity().Environment || record.Cell != o.b.cfg.NATS.Cell {
		return result, delivery.ArtifactRecord{}, rootoci.ErrUnauthorized
	}
	issued, err := releasechannel.ClaimIssuedAt(claim)
	if err != nil || issued.After(time.Now().Add(releasechannel.ClaimClockSkew)) {
		return result, delivery.ArtifactRecord{}, errors.Join(rootrelease.ErrPending, err)
	}
	result.Claim, result.ClaimSHA256, result.ExpiresAt = bytes.Clone(claim), controllerSHA256(claim), o.deadline
	return result, record, o.guard(ctx)
}

func (b *rootReleaseChannels) NativeRelease(ctx context.Context, call rootoci.Call, request rootoci.NativeReleaseRequest) (rootoci.NativeReleaseObservation, error) {
	ctx, cancel, o, err := b.beginChannel(ctx, call, rootoci.OperationNativeRelease)
	defer cancel()
	if err != nil {
		return rootoci.NativeReleaseObservation{}, err
	}
	result, _, err := o.nativeRelease(ctx, request.Role)
	return result, err
}

func (b *rootReleaseChannels) NativeReleaseBinaryChunk(ctx context.Context, call rootoci.Call, request rootoci.NativeReleaseBinaryChunkRequest) (rootoci.ReleaseBinaryChunk, error) {
	ctx, cancel, o, err := b.beginChannel(ctx, call, rootoci.OperationNativeReleaseBinaryChunk)
	defer cancel()
	if err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	observation, record, err := o.nativeRelease(ctx, request.Role)
	if err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	if !observation.Found || observation.ClaimSHA256 != request.ExpectedClaimSHA256 {
		return rootoci.ReleaseBinaryChunk{}, rootoci.ErrUnauthorized
	}
	location, err := o.location(ctx)
	if err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	result, err := o.binaryChunk(ctx, location, releasechannel.ServiceBinaryObject(record.Role, record.Digest), record.Digest, record.Size, request.Offset)
	if err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	current, _, err := o.nativeRelease(ctx, request.Role)
	if err != nil || current.ClaimSHA256 != request.ExpectedClaimSHA256 {
		return rootoci.ReleaseBinaryChunk{}, errors.Join(rootrelease.ErrPending, err)
	}
	return result, nil
}

func (b *rootReleaseChannels) ReconcileNativeServiceStatus(ctx context.Context, call rootoci.Call, request rootoci.NativeServiceStatusRequest) (rootoci.NativeServiceStatusReceipt, error) {
	ctx, cancel, o, err := b.beginChannel(ctx, call, rootoci.OperationReconcileNativeServiceStatus)
	defer cancel()
	if err != nil {
		return rootoci.NativeServiceStatusReceipt{}, err
	}
	observation, record, err := o.nativeRelease(ctx, request.Role)
	if err != nil {
		return rootoci.NativeServiceStatusReceipt{}, err
	}
	if !observation.Found || observation.ClaimSHA256 != request.ExpectedClaimSHA256 {
		return rootoci.NativeServiceStatusReceipt{}, rootoci.ErrUnauthorized
	}
	key := releasechannel.ServiceStatusKey(o.source.Identity().Cell, request.Role)
	entry, err := o.channelKV.Get(ctx, key)
	if err != nil {
		return rootoci.NativeServiceStatusReceipt{}, err
	}
	var state serviceReleaseState
	if err := json.Unmarshal(entry.Value(), &state, json.RejectUnknownMembers(true)); err != nil {
		return rootoci.NativeServiceStatusReceipt{}, err
	}
	issued, err := releasechannel.ClaimIssuedAt(observation.Claim)
	if err != nil {
		return rootoci.NativeServiceStatusReceipt{}, err
	}
	if state.Claim != observation.ClaimSHA256 || state.Digest != record.Digest || state.SourceRevision != record.Source.Commit || !state.IssuedAt.Equal(issued) {
		return rootoci.NativeServiceStatusReceipt{}, rootrelease.ErrPending
	}
	history := &nativeHistory{js: b.js, services: o.registry, deliveries: b.sources.Intents}
	retained, revision, err := history.load(ctx, request.Role)
	if err != nil || revision == 0 {
		return rootoci.NativeServiceStatusReceipt{}, errors.Join(rootrelease.ErrPending, err)
	}
	bindings := nativeBindings(&retained)
	if len(bindings) == 0 {
		return rootoci.NativeServiceStatusReceipt{}, rootrelease.ErrPending
	}
	status := releasechannel.ServiceStatus{Schema: releasechannel.ServiceStatusSchema, Cell: o.source.Identity().Cell, Role: request.Role, Digest: record.Digest, SourceRevision: record.Source.Commit, ReleaseSequence: record.ReleaseSequence, IssuedAt: issued, State: releasechannel.StateRolling, Reason: "waiting for fresh target proofs from every service replica", UpdatedAt: time.Now().UTC(), Pins: &releasechannel.ReleasePins{Rollback: []string{}, KnownBad: []string{}}}
	var selected *nativeReleaseBinding
	for _, binding := range bindings {
		if err := o.guard(ctx); err != nil {
			return rootoci.NativeServiceStatusReceipt{}, err
		}
		if err := history.verifyProfile(request.Role, binding.Profile, binding.Provenance); err != nil {
			return rootoci.NativeServiceStatusReceipt{}, err
		}
		admitted, err := b.sources.Intents.ResolveAdmittedArtifact(ctx, binding.Artifact.Digest, request.Role, binding.Intent.Environment)
		if err != nil || !sameRootArtifact(admitted, binding.Artifact) {
			return rootoci.NativeServiceStatusReceipt{}, errors.Join(rootrelease.ErrPending, err)
		}
		receipt, err := b.sources.Intents.StatusFor(ctx, binding.Intent)
		if err != nil || receipt.Status != "accepted" {
			return rootoci.NativeServiceStatusReceipt{}, errors.Join(rootrelease.ErrPending, err)
		}
		if err := o.pinValue("intent/"+binding.Fingerprint, receipt); err != nil {
			return rootoci.NativeServiceStatusReceipt{}, err
		}
		status.Pins.Rollback = append(status.Pins.Rollback, binding.Artifact.Digest)
		if state.Intent != nil {
			fp, err := state.Intent.Fingerprint()
			if err != nil {
				return rootoci.NativeServiceStatusReceipt{}, err
			}
			if fp == binding.Fingerprint && binding.Artifact.Digest == record.Digest && sameRootArtifact(binding.Artifact, record) {
				selected = binding
			}
		}
	}
	for _, digest := range append(slices.Clone(state.Retained), state.Previous) {
		if digest == "" {
			continue
		}
		if !slices.Contains(status.Pins.Rollback, digest) {
			return rootoci.NativeServiceStatusReceipt{}, rootrelease.ErrPending
		}
	}
	if selected == nil {
		return rootoci.NativeServiceStatusReceipt{}, rootrelease.ErrPending
	}
	proofs, proofErr := o.nativeProofs(ctx, selected.Intent)
	if proofErr != nil && !errors.Is(proofErr, errBadRelease) {
		return rootoci.NativeServiceStatusReceipt{}, proofErr
	}
	good := false
	for _, retainedGood := range retained.Good {
		if retainedGood.Binding.Fingerprint == selected.Fingerprint && slices.Equal(retainedGood.Nodes, slices.Sorted(maps.Keys(proofs))) {
			good = true
		}
	}
	switch {
	case errors.Is(proofErr, errBadRelease):
		status.State, status.Reason = releasechannel.StateFailed, proofErr.Error()
	case retained.Rejected == selected.Fingerprint || retained.Recovery != nil:
		if retained.Recovery == nil || state.Rollback == nil {
			return rootoci.NativeServiceStatusReceipt{}, rootrelease.ErrPending
		}
		fp, err := state.Rollback.Fingerprint()
		if err != nil || fp != retained.Recovery.Fingerprint {
			return rootoci.NativeServiceStatusReceipt{}, errors.Join(rootrelease.ErrPending, err)
		}
		rollback, err := o.nativeProofs(ctx, retained.Recovery.Intent)
		if err != nil {
			return rootoci.NativeServiceStatusReceipt{}, err
		}
		if len(rollback) > 0 {
			status.State, status.Reason = releasechannel.StateFailed, "the release rolled back to "+retained.Recovery.Artifact.Digest
			proofs = rollback
		}
	case len(proofs) > 0 && good:
		status.State, status.Reason = releasechannel.StateComplete, ""
	}
	if len(proofs) > 0 {
		hosts, err := o.ListHosts(ctx)
		if err != nil {
			return rootoci.NativeServiceStatusReceipt{}, err
		}
		for _, report := range proofs {
			o.capDeadline(report.ObservedAt.Add(host.ReportMaxAge))
		}
		for _, host := range hosts {
			if _, ok := proofs[host.Registration.Node]; ok {
				o.capDeadline(host.SessionExpiresAt)
			}
		}
	}
	prefix := knownBadKey(request.Role, "")
	keys, err := releasechannel.PinKeys(ctx, o.channelKV, prefix+">")
	if err != nil {
		return rootoci.NativeServiceStatusReceipt{}, err
	}
	slices.Sort(keys)
	for _, key := range keys {
		digest, ok := strings.CutPrefix(key, prefix)
		if !ok || len(digest) != 64 || !lowerHexString(digest) {
			return rootoci.NativeServiceStatusReceipt{}, rootoci.ErrInvalid
		}
		if _, err := o.channelKV.Get(ctx, key); err != nil {
			return rootoci.NativeServiceStatusReceipt{}, err
		}
		status.Pins.KnownBad = append(status.Pins.KnownBad, digest)
	}
	slices.Sort(status.Pins.Rollback)
	status.Pins.Rollback = slices.Compact(status.Pins.Rollback)
	slices.Sort(status.Pins.KnownBad)
	status.Pins.KnownBad = slices.Compact(status.Pins.KnownBad)
	status.Reason = releasechannel.Clip(status.Reason)
	location, err := o.location(ctx)
	if err != nil {
		return rootoci.NativeServiceStatusReceipt{}, err
	}
	guard := func(ctx context.Context) error {
		current, _, err := o.nativeRelease(ctx, request.Role)
		if err != nil || current.ClaimSHA256 != request.ExpectedClaimSHA256 {
			return errors.Join(rootrelease.ErrPending, err)
		}
		currentState, err := o.channelKV.Get(ctx, key)
		if err != nil || currentState.Revision() != entry.Revision() || !bytes.Equal(currentState.Value(), entry.Value()) {
			return errors.Join(rootrelease.ErrPending, err)
		}
		_, currentRevision, err := history.load(ctx, request.Role)
		if err != nil || currentRevision != revision {
			return errors.Join(rootrelease.ErrPending, err)
		}
		for _, binding := range bindings {
			admitted, err := b.sources.Intents.ResolveAdmittedArtifact(ctx, binding.Artifact.Digest, request.Role, binding.Intent.Environment)
			if err != nil || !sameRootArtifact(admitted, binding.Artifact) {
				return errors.Join(rootrelease.ErrPending, err)
			}
			receipt, err := b.sources.Intents.StatusFor(ctx, binding.Intent)
			if err != nil || receipt.Status != "accepted" {
				return errors.Join(rootrelease.ErrPending, err)
			}
			if err := o.pinValue("intent/"+binding.Fingerprint, receipt); err != nil {
				return err
			}
		}
		currentKeys, err := releasechannel.PinKeys(ctx, o.channelKV, prefix+">")
		slices.Sort(currentKeys)
		if err != nil || !slices.Equal(keys, currentKeys) {
			return errors.Join(rootrelease.ErrPending, err)
		}
		return o.validateWitnesses(ctx)
	}
	if err := o.publishStatus(ctx, location, releasechannel.ServiceStatusObject(request.Role), status, guard); err != nil {
		return rootoci.NativeServiceStatusReceipt{}, err
	}
	return rootoci.NativeServiceStatusReceipt{Status: status, ExpiresAt: o.deadline}, nil
}

func sameRootArtifact(a, b delivery.ArtifactRecord) bool {
	left, err := json.Marshal(a, json.Deterministic(true))
	if err != nil {
		return false
	}
	right, err := json.Marshal(b, json.Deterministic(true))
	return err == nil && bytes.Equal(left, right)
}

// A failed observation returns no proof map, but its original report still expires.
func (o *rootReleaseObservation) nativeProofs(ctx context.Context, intent delivery.Intent) (map[string]host.Report, error) {
	proofs, proofErr := observeNativeProofs(ctx, o.b.sources.Intents, o, intent)
	if !errors.Is(proofErr, errBadRelease) {
		return proofs, proofErr
	}
	desired, err := o.ListDesired(ctx, intent.Role)
	if err != nil {
		return nil, err
	}
	hosts, err := o.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	for _, status := range hosts {
		if !slices.ContainsFunc(desired, func(d host.Desired) bool { return d.Node == status.Registration.Node && !d.Withdrawn }) {
			continue
		}
		for _, report := range status.Reports {
			if report.Role == intent.Role && report.State == "failed" && report.Digest == intent.ArtifactDigest {
				o.capDeadline(status.SessionExpiresAt, report.ObservedAt.Add(host.ReportMaxAge))
			}
		}
	}
	return nil, proofErr
}
