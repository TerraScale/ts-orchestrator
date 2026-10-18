package executionleader

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// nativeRetainedData uses the original possible writer, never the latest
// placement artifact or a transactional MemberState revision.
func nativeRetainedData(owner host.ManagedRuntimeOwner) (executionwire.RetainedData, error) {
	d, r := owner.Native.Desired, owner.Native.Registration
	if d.ManagedMember == nil || d.ManagedMember.Runtime == nil || r.ManagedPlacement == nil ||
		d.ManagedMember.VolumeID != owner.VolumeID || d.Cell != owner.Cell {
		return executionwire.RetainedData{}, execution.ErrUnsafe
	}
	launch := d.ManagedMember
	return executionwire.RetainedData{DatabaseID: r.ManagedPlacement.DatabaseID, PartitionID: r.ManagedPlacement.PartitionID,
		VolumeID: owner.VolumeID, FileSystemUUID: launch.Runtime.FileSystemUUID, FileSystemType: launch.Runtime.FileSystemType,
		SourceArtifactSHA256: d.Digest, SourceTreeSHA256: launch.SourceDigest}, nil
}

// prepareManagedHandoff authenticates the replacement before the irreversible
// native fence. Existing drain production owns its root ETag; attachment ETags
// and a local stop can never substitute for remote publication settlement.
func (p *Producer) prepareManagedHandoff(ctx context.Context, intent delivery.Intent, state placement.MemberState) error {
	if p.hosts == nil || state.Validate() != nil || intent.Container == nil || intent.Cell != p.cell ||
		intent.Environment != p.environment || intent.Role != "terrabase" {
		return execution.ErrUnsafe
	}
	owner, _, err := host.ReadManagedRuntimeOwner(ctx, p.authority, p.cell, state.VolumeID)
	if err != nil {
		return err
	}
	retained, err := nativeRetainedData(owner)
	if err != nil {
		return err
	}
	if owner.Native.Desired.Node != state.HostNode || retained.DatabaseID != state.DatabaseID || retained.PartitionID != state.PartitionID {
		return execution.ErrUnsafe
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	originalState, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		return err
	}
	verify := func(check context.Context) error {
		if err := p.authority.Guard(check, intent.AuthorityEpoch); err != nil {
			return err
		}
		currentIntent, err := p.releases.ContainerIntent(check, intent.OperationID)
		if err != nil {
			return err
		}
		currentFingerprint, err := currentIntent.Fingerprint()
		if err != nil || currentFingerprint != fingerprint {
			return errors.Join(execution.ErrUnsafe, err)
		}
		currentMember, err := p.members.ReadMember(check, state.DatabaseID, state.PartitionID, state.MemberID)
		if err != nil {
			return err
		}
		currentState, err := json.Marshal(currentMember.State, json.Deterministic(true))
		if err != nil || currentMember.Revision == 0 || !bytes.Equal(currentState, originalState) {
			return errors.Join(execution.ErrUnsafe, err)
		}
		placementEntry, err := p.authority.ReadPlacementIntent(check, state.DatabaseID, state.PartitionID)
		if err != nil {
			return err
		}
		placementIntent, err := placement.DecodeCommittedIntent(placementEntry.Payload)
		if err != nil || placementIntent.Generation != state.IntentGeneration || placementIntent.PayloadDigest() != state.IntentPayloadDigest {
			return errors.Join(execution.ErrUnsafe, err)
		}
		if _, err := p.authority.ReadTerminalIntent(check, state.DatabaseID, state.PartitionID); !errors.Is(err, authority.ErrNotFound) {
			return errors.Join(execution.ErrUnsafe, err)
		}
		desiredEntry, err := p.authority.ReadHostMutation(check, authority.MutationDesired, p.cell+"."+state.HostNode+".terrabase")
		if err != nil {
			return err
		}
		registrationEntry, err := p.authority.ReadHostMutation(check, authority.MutationRegistration, p.cell+"."+state.HostNode)
		if err != nil {
			return err
		}
		var desired host.Desired
		var registration host.Registration
		if err := protocol.DecodeStrict(desiredEntry.Payload, &desired, 64<<10); err != nil {
			return err
		}
		if err := protocol.DecodeStrict(registrationEntry.Payload, &registration, 64<<10); err != nil {
			return err
		}
		desiredWire, err := json.Marshal(desired, json.Deterministic(true))
		if err != nil {
			return err
		}
		retainedDesired, err := json.Marshal(owner.Native.Desired, json.Deterministic(true))
		if err != nil {
			return err
		}
		registrationWire, err := json.Marshal(registration, json.Deterministic(true))
		if err != nil {
			return err
		}
		retainedRegistration, err := json.Marshal(owner.Native.Registration, json.Deterministic(true))
		if err != nil {
			return err
		}
		if desiredEntry.Sequence != owner.Native.DesiredSequence || registrationEntry.Sequence != owner.Native.RegistrationSequence ||
			!bytes.Equal(desiredWire, retainedDesired) || !bytes.Equal(registrationWire, retainedRegistration) ||
			host.ValidateContainerDesired(desired, registration) != nil {
			return execution.ErrUnsafe
		}
		target := release.ContainerTarget{Cell: strings.ToUpper(p.cell), Environment: p.environment, Role: "terrabase"}
		// The signed claim selects the architecture; the native ELF evidence
		// independently binds that architecture to the retained source artifact.
		envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
		if err != nil {
			return err
		}
		var claim release.ContainerClaim
		if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
			return err
		}
		target.Architecture = claim.Architecture
		allocations, err := p.allocations(check, intent.OperationID, *intent.Container, p.roots, target)
		if err != nil {
			return err
		}
		_, err = execution.VerifyNativeRetainedProvenance(check, *intent.Container, p.roots, target, retained,
			time.Now().UTC(), time.Now().UTC().Add(15*time.Second), p.open(intent.OperationID), allocations)
		return err
	}
	if err := verify(ctx); err != nil {
		return err
	}
	return p.hosts.FenceManagedNative(ctx, state.HostNode, intent.OperationID, fingerprint, verify)
}
