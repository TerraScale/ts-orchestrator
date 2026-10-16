// Package executionleader derives worker material from current manager records.
package executionleader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

type Producer struct {
	control           api.ControlClient
	authority         *authority.Runtime
	members           placement.Store
	releases          *delivery.Service
	volumes           *oci.VolumeMountObserver
	roots             trust.Keyring
	evidence          releasechannel.Location
	cell, environment string
}

func NewProducer(control api.ControlClient, fence *authority.Runtime, members placement.Store, releases *delivery.Service, volumes *oci.VolumeMountObserver, roots trust.Keyring, evidence releasechannel.Location, cell, environment string) (*Producer, error) {
	if control == nil || fence == nil || members == nil || releases == nil || volumes == nil || len(roots) == 0 || evidence.Client == nil || evidence.Namespace == "" || evidence.Bucket == "" || !release.ValidRegion(strings.ToUpper(cell)) || cell != strings.ToLower(cell) || environment == "" {
		return nil, execution.ErrUnsafe
	}
	keys := make(trust.Keyring, len(roots))
	for id, key := range roots {
		keys[id] = slices.Clone(key)
	}
	return &Producer{control: control, authority: fence, members: members, releases: releases, volumes: volumes, roots: keys, evidence: evidence, cell: cell, environment: environment}, nil
}

func (p *Producer) open(ctx context.Context, digest string) (io.ReadCloser, error) {
	return releasechannel.ReadContainerEvidence(ctx, p.evidence, "terrabase", digest)
}

// Resolve uses labels only to locate records; every value is checked against
// durable authority and the manager-owned service, node and assignment.
func (p *Producer) Resolve(ctx context.Context, requested *api.Task, caller host.RuntimeEffectCaller) (executionwire.WorkerGrantMaterial, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || requested == nil || !execution.Stateful(requested) || !time.Now().Before(caller.ExpiresAt()) || caller.SessionID() == "" {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	if err := p.authority.Guard(ctx, caller.Epoch()); err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	r := caller.Registration()
	if r.Cell != p.cell || r.Environment != p.environment || r.ManagedPlacement == nil || r.ManagedMember == nil || r.ManagedOCI == nil {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	// Do not accept a stale registration returned by a previously valid session.
	entry, err := p.authority.ReadHostMutation(ctx, authority.MutationRegistration, p.cell+"."+r.Node)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	registered, err := json.Marshal(r, json.Deterministic(true))
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	var actualRegistration host.Registration
	if err := protocol.DecodeStrict(entry.Payload, &actualRegistration, 64<<10); err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	actualWire, err := json.Marshal(actualRegistration, json.Deterministic(true))
	if err != nil || !bytes.Equal(actualWire, registered) {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	if _, err := p.authority.ReadHostMutation(ctx, authority.MutationRetirement, p.cell+"."+r.Node); !errors.Is(err, authority.ErrNotFound) {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	taskReply, err := p.control.GetTask(ctx, &api.GetTaskRequest{TaskID: requested.ID})
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if taskReply == nil || taskReply.Task == nil {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	task := taskReply.Task
	requestedHash, err := executionwire.TaskSHA256(requested)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	actualHash, err := executionwire.TaskSHA256(task)
	if err != nil || actualHash != requestedHash || task.NodeID == "" {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	nodeReply, err := p.control.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if nodeReply == nil || nodeReply.Node == nil || nodeReply.Node.Description == nil || nodeReply.Node.Description.Resources == nil {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	node := nodeReply.Node
	region, err := oci.Region(strings.ToUpper(p.cell)).OCIRegion()
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if node == nil || node.Spec.Membership != api.NodeMembershipAccepted || node.Spec.Availability != api.NodeAvailabilityActive || node.Spec.Annotations.Name != r.ID || node.Spec.Annotations.Labels["terrascale.region"] != region || node.Spec.Annotations.Labels["terrascale.instance-id"] != r.ManagedOCI.InstanceID || node.Spec.Annotations.Labels["terrascale.host-role"] != "container" || node.Spec.Annotations.Labels["terrascale.execution-scope"] != "platform" {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	serviceReply, err := p.control.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if serviceReply == nil || serviceReply.Service == nil {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	service := serviceReply.Service
	if service == nil || service.Spec.GetReplicated() == nil || service.Spec.GetReplicated().Replicas != 1 || !proto.Equal(&task.Spec, &service.Spec.Task) || !proto.Equal(&task.ServiceAnnotations, &service.Spec.Annotations) {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	pin := r.ManagedPlacement
	scope := authority.WorkloadScope{DatabaseID: pin.DatabaseID, PartitionID: pin.PartitionID}
	if _, err := p.authority.ReadTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID); !errors.Is(err, authority.ErrNotFound) {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	admitted, err := p.authority.ReadPlacementIntent(ctx, scope.DatabaseID, scope.PartitionID)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	intent, err := placement.DecodeCommittedIntent(admitted.Payload)
	if err != nil || intent.Generation != pin.IntentGeneration || intent.PayloadDigest() != pin.IntentPayloadDigest {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	versioned, err := p.members.ReadMember(ctx, scope.DatabaseID, scope.PartitionID, pin.SeatID)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	state := versioned.State
	if state.Validate() != nil || versioned.Revision == 0 || state.Region != oci.Region(strings.ToUpper(p.cell)) || state.HostNode != r.Node || state.InstanceID != r.ManagedOCI.InstanceID || state.CreateKey != r.ManagedOCI.CreateKey || state.HostGeneration != r.Generation || state.HostAttempt != r.ManagedMember.HostAttempt || state.IntentGeneration != intent.Generation || state.IntentPayloadDigest != intent.PayloadDigest() || state.CanonicalRosterDigest != pin.CanonicalRosterDigest || state.ManagedHostProfileDigest != pin.ManagedHostProfileDigest || state.CanonicalRosterRow.MemberID != r.ManagedMember.Scope.MemberID || state.CanonicalRosterRow.Incarnation != r.ManagedMember.Scope.Incarnation || state.Stage != placement.StageServing && state.Stage != placement.StageAwaitingHealthy && state.Stage != placement.StageDraining && state.Stage != placement.StageDrained {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	desiredEntry, err := p.authority.ReadHostMutation(ctx, authority.MutationDesired, p.cell+"."+r.Node+".terrabase")
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	var desired host.Desired
	if err := protocol.DecodeStrict(desiredEntry.Payload, &desired, 64<<10); err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if err := host.ValidateContainerDesired(desired, r); err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	launch := desired.ManagedMember
	manifest := state.EffectiveRuntimeManifest()
	if desired.Generation != state.DesiredGeneration || desired.AuthorityEpoch != desiredEntry.Epoch || launch.SourceDigest != manifest.SourceDigest || desired.Digest != manifest.ArtifactDigest || launch.VolumeID != state.VolumeID || launch.AttachmentID != state.AttachmentID || launch.AttachmentETag != state.AttachmentETag || launch.Runtime.DevicePath != state.AttachmentDevice || launch.Runtime.FileSystemUUID != manifest.FileSystemUUID || launch.Runtime.FileSystemType != manifest.FileSystemType || launch.Runtime.MountPath == "" {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	operationID := service.Spec.Annotations.Labels["terrascale.operation-id"]
	deployment, err := p.releases.ContainerIntent(ctx, operationID)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if deployment.Container == nil || deployment.Cell != p.cell || deployment.Environment != p.environment || deployment.Role != "terrabase" || deployment.AuthorityEpoch != caller.Epoch() {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	envelope, err := trust.DecodeEnvelope(deployment.Container.Claim)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	target := release.ContainerTarget{Cell: strings.ToUpper(p.cell), Environment: p.environment, Role: "terrabase", Architecture: claim.Architecture}
	verified, err := release.VerifyContainerCurrent(ctx, *deployment.Container, p.roots, target, time.Now().UTC(), caller.ExpiresAt(), p.open)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	uid, gid, err := qualifiedUser(ctx, *deployment.Container, p.roots, target, p.open)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	expectedSpec, err := memberServiceSpec(deployment, state, task.NodeID, verified.Claim(), uid, gid, r, node.Description.Resources)
	if err != nil || !proto.Equal(&service.Spec, expectedSpec) {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	volume := oci.VolumeInitializationPins{DatabaseID: scope.DatabaseID, PartitionID: scope.PartitionID, InstanceID: state.InstanceID, HostCreateKey: state.CreateKey, VolumeID: state.VolumeID, AttachmentID: state.AttachmentID, AttachmentETag: state.AttachmentETag, Device: state.AttachmentDevice, FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType}
	observed, err := p.volumes.InspectVolumeMount(ctx, volume, state.PreviousInstanceID)
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if !observed.IsVerified() || observed.Pins() != volume {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	retained := executionwire.RetainedData{DatabaseID: scope.DatabaseID, PartitionID: scope.PartitionID, VolumeID: state.VolumeID, FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType, SourceArtifactSHA256: manifest.ArtifactDigest, SourceTreeSHA256: manifest.SourceDigest}
	previous, retained, err := p.previousWriter(ctx, scope, retained, task.ID, *deployment.Container, target, caller.ExpiresAt())
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if retained.DatabaseID != volume.DatabaseID || retained.PartitionID != volume.PartitionID || retained.VolumeID != volume.VolumeID || retained.FileSystemUUID != volume.FileSystemUUID || retained.FileSystemType != volume.FileSystemType {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	declared, err := execution.VerifyStatefulDeclared(ctx, *deployment.Container, p.roots, target, time.Now().UTC(), caller.ExpiresAt(), p.open)
	if err != nil || declared.Data() != retained {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	survivor := memberstatus.Survivor{}
	for _, row := range intent.CanonicalRoster.Rows {
		if row.MemberID == manifest.ReplicationPeerMemberID {
			survivor = memberstatus.Survivor{MemberID: row.MemberID, Incarnation: row.Incarnation}
		}
	}
	if survivor.MemberID == "" {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	memberBytes, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	desiredBytes, err := json.Marshal(desired, json.Deterministic(true))
	if err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	material := executionwire.WorkerGrantMaterial{Desired: desiredBytes, Registration: registered, RuntimeRoot: manifest.ManagedRuntimeRoot, BootDescriptorSHA256: observed.BootDescriptorSHA256(), Scope: memberstatus.Scope(launch.Member.Scope), MemberAuthority: memberstatus.Authority(launch.Authority), Volume: volume, Mount: hostvolume.MountPins{DevicePath: volume.Device, MountPath: launch.Runtime.MountPath, FileSystemUUID: volume.FileSystemUUID, FileSystemType: volume.FileSystemType, UID: uid, GID: gid}, Container: *deployment.Container, RetainedContainer: previous, Retained: retained, DesiredGeneration: desired.Generation, PlacementGeneration: intent.Generation, MemberRevision: versioned.Revision, HostAttempt: state.HostAttempt, PlacementSHA256: intent.PayloadDigest(), RosterSHA256: state.CanonicalRosterDigest, MemberSHA256: fmt.Sprintf("%x", sha256.Sum256(memberBytes)), OperationID: operationID, Survivor: survivor}
	// Every remote read above can overlap placement or registration changes.
	// Re-read the pinned records before the leader may durably retain this grant.
	freshMember, err := p.members.ReadMember(ctx, scope.DatabaseID, scope.PartitionID, pin.SeatID)
	if err != nil || freshMember.Revision != versioned.Revision {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	freshBytes, err := json.Marshal(freshMember.State, json.Deterministic(true))
	if err != nil || !bytes.Equal(freshBytes, memberBytes) {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	for _, record := range []struct {
		kind     authority.HostMutationKind
		key      string
		sequence uint64
	}{{authority.MutationDesired, p.cell + "." + r.Node + ".terrabase", desiredEntry.Sequence}, {authority.MutationRegistration, p.cell + "." + r.Node, entry.Sequence}, {authority.MutationPlacementIntent, scope.DatabaseID + "." + scope.PartitionID, admitted.Sequence}} {
		current, err := p.authority.ReadHostMutation(ctx, record.kind, record.key)
		if err != nil || current.Sequence != record.sequence {
			return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
		}
	}
	if _, err := p.authority.ReadTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID); !errors.Is(err, authority.ErrNotFound) {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	if _, err := p.authority.ReadHostMutation(ctx, authority.MutationRetirement, p.cell+"."+r.Node); !errors.Is(err, authority.ErrNotFound) {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	freshTask, err := p.control.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
	if err != nil || freshTask == nil || freshTask.Task == nil {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	freshHash, err := executionwire.TaskSHA256(freshTask.Task)
	if err != nil || freshHash != actualHash {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	freshService, err := p.control.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
	if err != nil || freshService == nil || freshService.Service == nil || !proto.Equal(&freshService.Service.Spec, &service.Spec) {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	freshNode, err := p.control.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil || freshNode == nil || freshNode.Node == nil || freshNode.Node.Description == nil || !proto.Equal(&freshNode.Node.Spec, &node.Spec) || !proto.Equal(freshNode.Node.Description.Resources, node.Description.Resources) {
		return executionwire.WorkerGrantMaterial{}, errors.Join(execution.ErrUnsafe, err)
	}
	if err := p.authority.Guard(ctx, caller.Epoch()); err != nil {
		return executionwire.WorkerGrantMaterial{}, err
	}
	if !time.Now().Before(caller.ExpiresAt()) {
		return executionwire.WorkerGrantMaterial{}, execution.ErrUnsafe
	}
	return material, nil
}

func (p *Producer) VerifyCurrent(ctx context.Context, task *api.Task, caller host.RuntimeEffectCaller, stored executionwire.WorkerGrantMaterial) error {
	current, err := p.Resolve(ctx, task, caller)
	if err != nil {
		return err
	}
	a, err := json.Marshal(current, json.Deterministic(true))
	if err != nil {
		return err
	}
	b, err := json.Marshal(stored, json.Deterministic(true))
	if err != nil {
		return err
	}
	if !bytes.Equal(a, b) {
		return execution.ErrUnsafe
	}
	return nil
}

func (p *Producer) previousWriter(ctx context.Context, scope authority.WorkloadScope, expected executionwire.RetainedData, taskID string, candidate release.ContainerBundle, target release.ContainerTarget, until time.Time) (release.ContainerBundle, executionwire.RetainedData, error) {
	history, err := p.authority.ListRuntimeEffectHistory(ctx, scope)
	if err != nil {
		return release.ContainerBundle{}, expected, err
	}
	var latest *authority.RuntimeEffect
	var material executionwire.WorkerGrantMaterial
	for i := range history {
		record := history[i]
		var candidate executionwire.WorkerGrantMaterial
		if err := protocol.DecodeStrict(record.Material, &candidate, 1<<20); err != nil {
			return release.ContainerBundle{}, expected, err
		}
		if candidate.Volume.VolumeID != expected.VolumeID {
			continue
		}
		// The current task's acquisition retains its original prior writer material.
		if record.TaskID == taskID {
			return candidate.RetainedContainer, candidate.Retained, nil
		}
		if latest == nil || record.Sequence > latest.Sequence {
			copy := record
			latest = &copy
			material = candidate
		}
	}
	if latest == nil {
		retained, err := execution.VerifyNativeRetainedProvenance(ctx, candidate, p.roots, target, expected, time.Now().UTC(), until, p.open)
		return release.ContainerBundle{}, retained, err
	}
	envelope, err := trust.DecodeEnvelope(material.Container.Claim)
	if err != nil {
		return release.ContainerBundle{}, expected, err
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return release.ContainerBundle{}, expected, err
	}
	expected.SourceArchitecture = claim.Architecture
	// The latest possible writer can have changed the disk even when start outcome
	// was uncertain. Never fall back to the older placement artifact.
	_, expected.SourceArtifactSHA256, _ = strings.Cut(claim.Image, "@sha256:")
	expected.SourceTreeSHA256 = claim.SourceTreeSHA256
	previousTarget := release.ContainerTarget{Cell: strings.ToUpper(p.cell), Environment: p.environment, Role: "terrabase", Architecture: claim.Architecture}
	retained, err := execution.VerifyRetainedProvenance(ctx, material.Container, p.roots, previousTarget, expected, p.open)
	return material.Container, retained, err
}

func qualifiedUser(ctx context.Context, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget, open func(context.Context, string) (io.ReadCloser, error)) (uint32, uint32, error) {
	verified, err := execution.VerifyStatefulDeclared(ctx, bundle, roots, target, time.Now().UTC(), time.Now().UTC().Add(time.Second), open)
	if err != nil {
		return 0, 0, err
	}
	user := verified.ImageConfig().User
	u, g, ok := strings.Cut(user, ":")
	uid, e1 := strconv.ParseUint(u, 10, 32)
	gid, e2 := strconv.ParseUint(g, 10, 32)
	if !ok || e1 != nil || e2 != nil || uid == 0 || gid == 0 {
		return 0, 0, execution.ErrUnsafe
	}
	return uint32(uid), uint32(gid), nil
}
