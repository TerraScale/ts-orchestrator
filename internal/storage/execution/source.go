//go:build linux

package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	containerdoci "github.com/containerd/containerd/v2/pkg/oci"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

// Source is the production worker adapter. Only its concrete signed session,
// OCI evidence reader and actual container observer can establish a binding.
type Source struct {
	session   *WorkerSession
	runtime   RuntimeObserver
	roots     trust.Keyring
	evidence  releasechannel.Location
	stateRoot string
	mu        sync.Mutex
	entries   map[string]*sourceEntry
}

type sourceEntry struct {
	grant        VerifiedWorkerGrant
	material     WorkerGrantMaterial
	desired      host.Desired
	registration host.Registration
	proof        VerifiedStateful
	binding      Binding
	pins         *RuntimePins
	observed     RuntimeObservation
	publication  *publication
	revoked      bool
}

func NewSource(session *WorkerSession, observer RuntimeObserver, roots trust.Keyring, evidence releasechannel.Location, stateRoot string) (*Source, error) {
	if session == nil || observer.Client == nil || observer.Client != session.client || len(roots) == 0 || evidence.Client == nil || evidence.Namespace == "" || evidence.Bucket == "" ||
		!filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || stateRoot == "/" || os.Geteuid() != 0 {
		return nil, ErrUnsafe
	}
	if err := verifySourceDirectory(stateRoot, 0o700); err != nil {
		return nil, err
	}
	rootCopy := make(trust.Keyring, len(roots))
	for id, key := range roots {
		rootCopy[id] = slices.Clone(key)
	}
	source := &Source{session: session, runtime: observer, roots: rootCopy, evidence: evidence, stateRoot: stateRoot, entries: make(map[string]*sourceEntry)}
	if err := session.bindSource(source); err != nil {
		return nil, err
	}
	return source, nil
}

func verifySourceDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm() != mode {
		return ErrUnsafe
	}
	return nil
}

func (s *Source) Hooks() *Hooks { return &Hooks{Worker: s.session, Bindings: s} }

func (s *Source) openEvidence(ctx context.Context, digest string) (io.ReadCloser, error) {
	return releasechannel.ReadContainerEvidence(ctx, s.evidence, "terrabase", digest)
}

func (s *Source) admit(ctx context.Context, task *api.Task) (*sourceEntry, error) {
	if s == nil || s.session == nil || ctx == nil || ctx.Err() != nil || !Stateful(task) {
		return nil, ErrUnsafe
	}
	grant, err := s.session.Resolve(ctx, task)
	if err != nil {
		return nil, err
	}
	material, err := grant.Material()
	if err != nil {
		return nil, err
	}
	var desired host.Desired
	var registration host.Registration
	if err := protocol.DecodeStrict(material.Desired, &desired, 64<<10); err != nil {
		return nil, err
	}
	if err := protocol.DecodeStrict(material.Registration, &registration, 64<<10); err != nil {
		return nil, err
	}
	if err := host.ValidateContainerDesired(desired, registration); err != nil {
		return nil, err
	}
	identity := grant.Identity()
	launch := desired.ManagedMember
	if registration.Node != identity.HostNode || registration.Cell != identity.Cell || registration.PublicKey != identity.HostPublicKey ||
		registration.NATSUserPublicKey != identity.NATSUserPublicKey || registration.Generation != identity.RegistrationGeneration ||
		registration.ManagedOCI.InstanceID != identity.InstanceID || task.NodeID != identity.NodeID || !digestValid(material.BootDescriptorSHA256) ||
		material.DesiredGeneration != desired.Generation || material.PlacementGeneration != registration.ManagedPlacement.IntentGeneration ||
		material.PlacementSHA256 != registration.ManagedPlacement.IntentPayloadDigest || material.RosterSHA256 != registration.ManagedPlacement.CanonicalRosterDigest ||
		material.MemberRevision == 0 || !digestValid(material.MemberSHA256) || material.HostAttempt != launch.Member.HostAttempt ||
		material.Scope != memberstatus.Scope(launch.Member.Scope) || material.MemberAuthority != memberstatus.Authority(launch.Authority) ||
		material.Volume.DatabaseID != material.Scope.DatabaseID || material.Volume.PartitionID != registration.ManagedPlacement.PartitionID ||
		material.Volume.InstanceID != identity.InstanceID || material.Volume.HostCreateKey != launch.OCI.CreateKey ||
		material.Volume.VolumeID != launch.VolumeID || material.Volume.AttachmentID != launch.AttachmentID || material.Volume.AttachmentETag != launch.AttachmentETag ||
		material.Volume.Device != launch.Runtime.DevicePath || material.Volume.FileSystemUUID != launch.Runtime.FileSystemUUID || material.Volume.FileSystemType != launch.Runtime.FileSystemType ||
		material.Mount.DevicePath != material.Volume.Device || material.Mount.MountPath != launch.Runtime.MountPath || material.Mount.FileSystemUUID != material.Volume.FileSystemUUID ||
		material.Mount.FileSystemType != material.Volume.FileSystemType || material.Retained.DatabaseID != material.Volume.DatabaseID || material.Retained.PartitionID != material.Volume.PartitionID ||
		material.Retained.VolumeID != material.Volume.VolumeID || material.Retained.FileSystemUUID != material.Volume.FileSystemUUID || material.Retained.FileSystemType != material.Volume.FileSystemType {
		return nil, fmt.Errorf("%w: signed task/member/host/volume mapping differs", ErrUnsafe)
	}
	instance, err := bootstrapstart.NewIMDSClient().FetchInstanceID(ctx)
	if err != nil || instance != identity.InstanceID {
		return nil, fmt.Errorf("%w: local OCI instance differs", ErrUnsafe)
	}
	cpu, err := HostCPUProfile()
	if err != nil {
		return nil, err
	}
	target := release.ContainerTarget{Cell: strings.ToUpper(registration.Cell), Environment: registration.Environment, Role: "terrabase", Architecture: runtime.GOARCH}
	previousTarget := target
	previousTarget.Architecture = material.Retained.SourceArchitecture
	var retained RetainedData
	if len(material.RetainedContainer.Claim) == 0 {
		retained, err = VerifyNativeRetainedProvenance(ctx, material.Container, s.roots, target, material.Retained, time.Now().UTC(), grant.Deadline(), s.openEvidence)
	} else {
		retained, err = VerifyRetainedProvenance(ctx, material.RetainedContainer, s.roots, previousTarget, material.Retained, s.openEvidence)
	}
	if err != nil {
		return nil, err
	}
	proof, err := VerifyStatefulCurrent(ctx, material.Container, s.roots, target, retained, cpu, time.Now().UTC(), grant.Deadline(), s.openEvidence)
	if err != nil {
		return nil, err
	}
	if err := s.session.VerifyCurrent(ctx, task, grant); err != nil {
		return nil, err
	}
	key := grant.TaskSHA256()
	s.mu.Lock()
	existing := s.entries[key]
	if existing != nil {
		if existing.revoked || existing.grant.AdmissionSHA256() != grant.AdmissionSHA256() {
			s.mu.Unlock()
			return nil, ErrUnsafe
		}
		s.mu.Unlock()
		return existing, nil
	}
	s.mu.Unlock()
	directory := filepath.Join(s.stateRoot, "stateful-drain", key)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := verifySourceDirectory(filepath.Dir(directory), 0o700); err != nil {
		return nil, err
	}
	if err := verifySourceDirectory(directory, 0o700); err != nil {
		return nil, err
	}
	store, err := memberstatus.NewFileStore(filepath.Join(directory, "request.json"))
	if err != nil {
		return nil, err
	}
	entry := &sourceEntry{grant: grant, material: material, desired: desired, registration: registration, proof: proof}
	_, controlSocket, _, err := host.ContainerMemberPaths(material.RuntimeRoot, *launch)
	if err != nil {
		return nil, err
	}
	client, err := memberstatus.NewClient(controlSocket, material.Scope, material.MemberAuthority, func(ctx context.Context) (memberstatus.ProcessObservation, error) {
		s.mu.Lock()
		pins, revoked := entry.pins, entry.revoked
		s.mu.Unlock()
		if pins == nil || revoked {
			return memberstatus.ProcessObservation{}, ErrUnsafe
		}
		if err := s.session.VerifyCurrent(ctx, task, grant); err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		actual, err := s.runtime.Observe(ctx, *pins)
		if err != nil || actual.State != containerd.Running {
			return memberstatus.ProcessObservation{}, errors.Join(ErrUnsafe, err)
		}
		return actual.Process, nil
	})
	if err != nil {
		return nil, err
	}
	entry.binding = Binding{TaskSHA256: key, AdmissionSHA256: grant.AdmissionSHA256(), Epoch: grant.Epoch(), Volume: material.Volume, Member: client, DrainStore: store, Survivor: material.Survivor, OperationID: material.OperationID}
	s.mu.Lock()
	if current := s.entries[key]; current != nil {
		s.mu.Unlock()
		if current.grant.AdmissionSHA256() != grant.AdmissionSHA256() {
			return nil, ErrUnsafe
		}
		return current, nil
	}
	s.entries[key] = entry
	s.mu.Unlock()
	return entry, nil
}

func (s *Source) VerifyTaskBinding(ctx context.Context, task *api.Task) (Binding, error) {
	entry, err := s.admit(ctx, task)
	if err != nil {
		return Binding{}, err
	}
	return entry.binding, nil
}

func (s *Source) ResolveRuntime(ctx context.Context, task *api.Task) (RuntimePins, error) {
	entry, err := s.admit(ctx, task)
	if err != nil {
		return RuntimePins{}, err
	}
	material := entry.material
	imageConfig := entry.proof.ImageConfig()
	uidText, gidText, ok := strings.Cut(imageConfig.User, ":")
	uid, uidErr := strconv.ParseUint(uidText, 10, 32)
	gid, gidErr := strconv.ParseUint(gidText, 10, 32)
	if !ok || uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || uint32(uid) != material.Mount.UID || uint32(gid) != material.Mount.GID ||
		len(imageConfig.Entrypoint) != 1 || !filepath.IsAbs(imageConfig.Entrypoint[0]) || filepath.Clean(imageConfig.Entrypoint[0]) != imageConfig.Entrypoint[0] {
		return RuntimePins{}, ErrUnsafe
	}
	generic := task.Spec.GetGeneric()
	if generic == nil || generic.Kind != StatefulContainerKind || generic.Payload == nil || generic.Payload.TypeUrl != StatefulContainerTypeURL || len(generic.Payload.Value) > 128<<10 {
		return RuntimePins{}, ErrUnsafe
	}
	var containerSpec api.ContainerSpec
	if err := containerSpec.Unmarshal(generic.Payload.Value); err != nil {
		return RuntimePins{}, err
	}
	expected := &api.ContainerSpec{Image: entry.proof.Container().Claim().Image, User: imageConfig.User}
	if !proto.Equal(&containerSpec, expected) || task.Spec.Resources == nil || task.Spec.Resources.Limits == nil || task.Spec.Resources.Reservations == nil ||
		!proto.Equal(task.Spec.Resources.Limits, task.Spec.Resources.Reservations) || len(task.Spec.Resources.Limits.Generic) != 0 || task.Spec.Resources.SwapBytes != nil || task.Spec.Resources.MemorySwappiness != nil ||
		uint64(task.Spec.Resources.Limits.MemoryBytes) != entry.desired.ManagedMember.CgroupMemoryMaxBytes || task.Spec.Resources.Limits.NanoCPUs < 10_000_000 ||
		task.Spec.Resources.Limits.NanoCPUs > int64(entry.registration.Capacity.CPU)*1_000_000_000 {
		return RuntimePins{}, ErrUnsafe
	}
	plan, err := host.PrepareContainerMember(ctx, material.RuntimeRoot, host.WorkloadIdentity{UID: uint32(uid), GID: uint32(gid)}, entry.desired, entry.registration, imageConfig.Entrypoint[0], entry.grant.AdmissionSHA256())
	if err != nil {
		return RuntimePins{}, err
	}
	defer plan.Close()
	if plan.MountPath != material.Mount.MountPath {
		return RuntimePins{}, ErrUnsafe
	}
	if err := s.ensurePublication(ctx, task, entry, plan); err != nil {
		return RuntimePins{}, err
	}
	limits := task.Spec.Resources.Limits
	base, err := containerdoci.GenerateSpec(namespaces.WithNamespace(ctx, "terrascale"), s.runtime.Client, &containers.Container{ID: "ts-" + task.ID}, containerdoci.WithDefaultSpec(), containerdoci.WithRootFSReadonly(), containerdoci.WithHostNamespace(runtimespec.NetworkNamespace), containerdoci.WithNoNewPrivileges, containerdoci.WithCapabilities(nil), containerdoci.WithUIDGID(uint32(uid), uint32(gid)), containerdoci.WithMemoryLimit(uint64(limits.MemoryBytes)), containerdoci.WithMemorySwap(limits.MemoryBytes), containerdoci.WithPidsLimit(256), containerdoci.WithCPUCFS(limits.NanoCPUs/10_000, 100_000))
	if err != nil {
		return RuntimePins{}, err
	}
	base.Process.Args = append(slices.Clone(imageConfig.Entrypoint), plan.Workload.Args...)
	base.Process.Cwd = imageConfig.WorkingDir
	if base.Process.Cwd == "" {
		base.Process.Cwd = "/"
	}
	environment := make(map[string]string, len(imageConfig.Env)+len(plan.Workload.Env))
	for _, value := range imageConfig.Env {
		key, value, ok := strings.Cut(value, "=")
		if !ok || key == "" || strings.ContainsAny(key, "\x00\r\n") || strings.ContainsRune(value, 0) {
			return RuntimePins{}, ErrUnsafe
		}
		if _, duplicate := environment[key]; duplicate {
			return RuntimePins{}, ErrUnsafe
		}
		environment[key] = value
	}
	for key, value := range plan.Workload.Env {
		environment[key] = value
	}
	base.Process.Env = nil
	for _, key := range slices.Sorted(maps.Keys(environment)) {
		base.Process.Env = append(base.Process.Env, key+"="+environment[key])
	}
	base.Mounts = append(base.Mounts, runtimespec.Mount{Source: plan.MountPath, Destination: plan.MountPath, Type: "bind", Options: []string{"bind", "rw", "nosuid", "nodev", "noexec", "noatime"}}, runtimespec.Mount{Source: plan.MaterialPath, Destination: plan.MaterialPath, Type: "bind", Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}}, runtimespec.Mount{Source: plan.ControlDirectory, Destination: plan.ControlDirectory, Type: "bind", Options: []string{"bind", "rw", "nosuid", "nodev", "noexec"}}, runtimespec.Mount{Source: plan.PublicationSocket, Destination: plan.PublicationSocket, Type: "bind", Options: []string{"bind", "rw", "nosuid", "nodev", "noexec"}})
	pins := RuntimePins{Task: task.Copy(), ContainerSpecSHA256: entry.binding.TaskSHA256, Image: expected.Image, Process: *base.Process, Resources: *base.Linux.Resources, Mounts: base.Mounts, Namespaces: base.Linux.Namespaces, Volume: material.Mount, VolumeDestination: material.Mount.MountPath}
	if err := s.session.VerifyCurrent(ctx, task, entry.grant); err != nil {
		return RuntimePins{}, err
	}
	s.mu.Lock()
	if entry.revoked {
		s.mu.Unlock()
		return RuntimePins{}, ErrUnsafe
	}
	if previous := entry.pins; previous != nil {
		if previous.ContainerSpecSHA256 != pins.ContainerSpecSHA256 || previous.Image != pins.Image || previous.Volume != pins.Volume || previous.VolumeDestination != pins.VolumeDestination || !reflect.DeepEqual(previous.Process, pins.Process) || !reflect.DeepEqual(previous.Resources, pins.Resources) || !reflect.DeepEqual(previous.Mounts, pins.Mounts) || !reflect.DeepEqual(previous.Namespaces, pins.Namespaces) {
			s.mu.Unlock()
			return RuntimePins{}, ErrUnsafe
		}
		pins = *previous
	} else {
		entry.pins = &pins
	}
	s.mu.Unlock()
	return pins, nil
}

func (s *Source) RecordRuntime(ctx context.Context, task *api.Task, caller RuntimeObservation) error {
	pins, err := s.ResolveRuntime(ctx, task)
	if err != nil {
		return errors.Join(err, s.retainLateRuntime(task, caller))
	}
	actual, err := s.runtime.Observe(ctx, pins)
	if err != nil || actual != caller {
		return errors.Join(ErrUnsafe, err)
	}
	if err := s.session.TrackRuntime(ctx, task, pins, actual); err != nil {
		return err
	}
	s.mu.Lock()
	entry := s.entries[pins.ContainerSpecSHA256]
	if entry == nil || entry.revoked {
		s.mu.Unlock()
		return ErrUnsafe
	}
	entry.observed = actual
	s.mu.Unlock()
	return nil
}

// retainLateRuntime records a concrete process created while authority expired.
// It grants no execution: TrackRuntime immediately stops a closing session.
func (s *Source) retainLateRuntime(task *api.Task, caller RuntimeObservation) error {
	hash, err := TaskSHA256(task)
	if err != nil {
		return err
	}
	s.mu.Lock()
	entry := s.entries[hash]
	var pins *RuntimePins
	if entry != nil {
		pins = entry.pins
	}
	s.mu.Unlock()
	if pins == nil {
		return ErrUnsafe
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	actual, err := s.runtime.Observe(ctx, *pins)
	if err != nil || actual != caller {
		return errors.Join(ErrUnsafe, err)
	}
	return s.session.TrackRuntime(ctx, task, *pins, actual)
}

func (s *Source) VerifyRemoval(ctx context.Context, task *api.Task, binding Binding) error {
	entry, err := s.admit(ctx, task)
	if err != nil || entry.binding != binding {
		return errors.Join(ErrUnsafe, err)
	}
	final, found, err := binding.DrainStore.ReadComplete()
	if err != nil || !found || final.Receipt == nil || final.Receipt.Scope != entry.material.Scope || final.Receipt.Authority != entry.material.MemberAuthority ||
		final.OperationID != binding.OperationID || final.Receipt.Peer.Origin.MemberID != binding.Survivor.MemberID || final.Receipt.Peer.Origin.Incarnation != binding.Survivor.Incarnation {
		return errors.Join(ErrUnsafe, err)
	}
	s.mu.Lock()
	observed := entry.observed
	s.mu.Unlock()
	if observed.Process.PID < 2 || final.Receipt.DrainedProcess.PID != observed.Process.ProtocolPID() {
		return ErrUnsafe
	}
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	container, err := s.runtime.Client.LoadContainer(ctx, "ts-"+task.ID)
	if err != nil {
		return err
	}
	labels, err := container.Labels(ctx)
	if err != nil || labels["terrascale.task"] != task.ID || labels["terrascale.service"] != task.ServiceID || labels["terrascale.task-binding"] != binding.TaskSHA256 {
		return errors.Join(ErrUnsafe, err)
	}
	process, err := container.Task(ctx, nil)
	if err != nil {
		return err
	}
	status, err := process.Status(ctx)
	if err != nil || status.Status != containerd.Stopped {
		return errors.Join(ErrUnsafe, err)
	}
	pids, err := process.Pids(ctx)
	if err != nil || len(pids) != 0 {
		return errors.Join(ErrUnsafe, err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", observed.Process.PID)); !errors.Is(err, os.ErrNotExist) {
		return ErrUnsafe
	}
	return s.session.VerifyCurrent(ctx, task, entry.grant)
}
