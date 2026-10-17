//go:build linux

package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/moby/swarmkit/v2/api"
	"golang.org/x/sys/unix"
)

type backupObservation struct {
	binding host.ManagedContainerRuntime
	status  memberstatus.Status
	proof   *memberstatus.ServingProof
	mount   *hostvolume.MountWitness
}

// startBackup retains only this admitted task's backup reconciliation. Withdrawal
// cancels the requests before the independent session watchdog stops its writer.
func (s *Source) startBackup(task *api.Task, entry *sourceEntry) error {
	agent, ok := s.session.transport.(*host.Agent)
	if !ok || agent == nil {
		return ErrUnsafe
	}
	s.mu.Lock()
	if entry.revoked {
		s.mu.Unlock()
		return ErrUnsafe
	}
	if entry.backupCancel != nil {
		s.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	entry.backupCancel = cancel
	s.mu.Unlock()
	task = task.Copy()
	go func() {
		defer cancel()
		for {
			_ = s.reconcileHeldBackup(ctx, agent, task, entry)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return nil
}

// A Prepare can take longer than one renewable grant. Source withdrawal cancels
// this context at the independent watchdog boundary, before its writer is stopped.
func (s *Source) reconcileHeldBackup(ctx context.Context, agent *host.Agent, task *api.Task, entry *sourceEntry) error {
	grant, err := s.session.Resolve(ctx, task)
	if err != nil {
		return err
	}
	held := &workerHeld{session: s.session, hash: grant.TaskSHA256(), admission: grant.AdmissionSHA256()}
	held.active.Store(true)
	defer held.active.Store(false)
	ctx = context.WithValue(ctx, workerHeldKey{}, held)
	if err := s.session.CheckHeld(ctx, task); err != nil {
		return err
	}
	err = s.reconcileBackup(ctx, agent, task, entry)
	return errors.Join(err, s.session.CheckHeld(ctx, task))
}

func (s *Source) observeBackup(ctx context.Context, task *api.Task, entry *sourceEntry) (_ backupObservation, err error) {
	if err := s.session.CheckHeld(ctx, task); err != nil {
		return backupObservation{}, err
	}
	current, err := s.admit(ctx, task)
	if err != nil || current != entry {
		return backupObservation{}, errors.Join(ErrUnsafe, err)
	}
	grant, err := s.session.Resolve(ctx, task)
	if err != nil {
		return backupObservation{}, err
	}
	s.mu.Lock()
	pins, observed, publisher, revoked := entry.pins, entry.observed, entry.publication, entry.revoked
	s.mu.Unlock()
	if pins == nil || publisher == nil || revoked || observed.State != containerd.Running {
		return backupObservation{}, ErrUnsafe
	}
	select {
	case <-publisher.done:
		return backupObservation{}, ErrUnsafe
	default:
	}
	actual, err := s.runtime.Observe(ctx, *pins)
	if err != nil || actual != observed || actual.Process.ProtocolPID() != 1 {
		return backupObservation{}, errors.Join(ErrUnsafe, err)
	}
	mount, err := hostvolume.ObserveMount(pins.Volume)
	if err != nil {
		return backupObservation{}, err
	}
	defer func() {
		if err != nil {
			mount.Close()
		}
	}()
	if err := mount.VerifyContainerMount(actual.Process.PID, pins.VolumeDestination); err != nil {
		return backupObservation{}, err
	}
	_, control, publicationPath, err := host.ContainerMemberPaths(entry.material.RuntimeRoot, *entry.desired.ManagedMember)
	if err != nil || publicationPath != publisher.path {
		return backupObservation{}, errors.Join(ErrUnsafe, err)
	}
	controlStat, _, err := backupSocket(control, entry.material.Mount.UID, entry.material.Mount.GID, 0o602)
	if err != nil {
		return backupObservation{}, err
	}
	publicationStat, publicationFile, err := backupSocket(publicationPath, 0, entry.material.Mount.GID, 0o660)
	if err != nil || !os.SameFile(publicationFile, publisher.file) {
		return backupObservation{}, errors.Join(ErrUnsafe, err)
	}
	status, err := entry.binding.Member.Status(ctx)
	if err != nil || status.Process.PID != actual.Process.ProtocolPID() || !status.Local.StorageRecovered || !status.Local.ReplicationListenerReady {
		return backupObservation{}, errors.Join(ErrUnsafe, err)
	}
	var serving *memberstatus.ServingProof
	if status.Serving {
		proof, err := entry.binding.Member.ServingProofForPeer(ctx, status, entry.desired.ManagedMember.Runtime.ReplicationPeerMemberID)
		if err != nil {
			return backupObservation{}, err
		}
		serving = &proof
	}
	if err := host.VerifyContainerCredentialGeneration(entry.material.RuntimeRoot, entry.desired,
		host.WorkloadIdentity{UID: entry.material.Mount.UID, GID: entry.material.Mount.GID}, status.CredentialGeneration); err != nil {
		return backupObservation{}, err
	}
	var mounted unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, pins.Volume.MountPath, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &mounted); err != nil || mounted.Mask&unix.STATX_MNT_ID == 0 || mounted.Mnt_id == 0 {
		return backupObservation{}, errors.Join(ErrUnsafe, err)
	}
	if err := mount.Recheck(); err != nil {
		return backupObservation{}, err
	}
	if err := s.session.CheckHeld(ctx, task); err != nil {
		return backupObservation{}, err
	}
	cgroup, ok := strings.CutPrefix(actual.Process.Cgroup, "0::")
	if !ok {
		return backupObservation{}, ErrUnsafe
	}
	binding := host.ManagedContainerRuntime{TaskID: task.ID, TaskSHA256: grant.TaskSHA256(), AdmissionSHA256: grant.AdmissionSHA256(), EffectID: grant.EffectID(),
		ContainerID: actual.ContainerID, HostPID: actual.Process.PID, MemberPID: actual.Process.ProtocolPID(), KernelStart: actual.Process.KernelStart,
		Cgroup: strings.TrimSuffix(cgroup, "\n"), PIDNamespace: actual.PIDNamespace, MountNamespace: actual.MountNamespace, MountID: mounted.Mnt_id,
		ControlDevice: uint64(controlStat.Dev), ControlInode: controlStat.Ino, PublicationDevice: uint64(publicationStat.Dev), PublicationInode: publicationStat.Ino}
	return backupObservation{binding: binding, status: status, proof: serving, mount: mount}, nil
}

func backupSocket(path string, uid, gid, mode uint32) (*syscall.Stat_t, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode {
		return nil, nil, ErrUnsafe
	}
	return stat, info, nil
}

func (s *Source) backupReport(entry *sourceEntry, observation backupObservation) host.ManagedRuntimeReport {
	launch, volume := entry.desired.ManagedMember, entry.material.Mount
	return host.ManagedRuntimeReport{Container: &observation.binding, ServingProof: observation.proof, ClientCredentialGeneration: observation.status.CredentialGeneration,
		Member: launch.Member, Authority: launch.Authority, OCI: launch.OCI, VolumeID: launch.VolumeID,
		AttachmentID: launch.AttachmentID, AttachmentETag: launch.AttachmentETag,
		FileSystemUUID: volume.FileSystemUUID, FileSystemType: volume.FileSystemType, MountDevice: volume.DevicePath, MountPath: volume.MountPath,
		MountID: observation.binding.MountID, ProcessPID: observation.binding.HostPID, ProcessStart: observation.binding.KernelStart,
		ProcessCgroup: observation.binding.Cgroup, ProcessBootID: observation.status.Process.StartNonce,
		StorageRecovered: observation.status.Local.StorageRecovered, ListenerReady: observation.status.Local.ReplicationListenerReady}
}

func (s *Source) reconcileBackup(ctx context.Context, agent *host.Agent, task *api.Task, entry *sourceEntry) error {
	before, err := s.observeBackup(ctx, task, entry)
	if err != nil {
		return err
	}
	defer before.mount.Close()
	if err := agent.BackupRuntimeReport(ctx, entry.desired, s.backupReport(entry, before)); err != nil {
		return err
	}
	command, _, err := agent.BackupCommand(ctx, entry.desired.Role)
	if err != nil || command == nil {
		return err
	}
	if command.Epoch != entry.grant.Epoch() || !command.MatchesContainer(entry.desired, entry.registration, before.binding, s.session.identity.HostSessionID) ||
		command.ExpectedProcess != before.status.Process {
		return memberstatus.ErrStaleBinding
	}
	result, err := relayBackup(ctx, entry.binding.Member, *command)
	if err != nil {
		return err
	}
	after, err := s.observeBackup(ctx, task, entry)
	if err != nil {
		return err
	}
	defer after.mount.Close()
	if before.binding != after.binding || before.status.Process != after.status.Process || before.status.CredentialGeneration != after.status.CredentialGeneration {
		return memberstatus.ErrStaleBinding
	}
	if err := before.mount.Recheck(); err != nil {
		return err
	}
	if err := agent.BackupRuntimeReport(ctx, entry.desired, s.backupReport(entry, after)); err != nil {
		return err
	}
	if err := s.session.CheckHeld(ctx, task); err != nil {
		return err
	}
	return agent.BackupResult(ctx, result)
}

// relayBackup uses the same authenticated client held by the Source binding.
// The member verifies each signed R3 envelope and every Unix peer exchange.
func relayBackup(ctx context.Context, client *memberstatus.Client, command host.ManagedBackupCommand) (host.ManagedBackupResult, error) {
	result := host.ManagedBackupResult{Command: command}
	limit := 8 << 10
	if command.Kind == "complete" || command.Kind == "complete-status" {
		limit = 30 << 10
	}
	sum := sha256.Sum256(command.Envelope)
	if len(command.Envelope) == 0 || len(command.Envelope) > limit || hex.EncodeToString(sum[:]) != command.EnvelopeSHA256 {
		return result, ErrUnsafe
	}
	var err error
	switch command.Kind {
	case "prepare":
		result.CutEnvelope, err = client.BackupPrepare(ctx, bytes.Clone(command.Envelope))
	case "abort":
		err = client.BackupAbort(ctx, bytes.Clone(command.Envelope))
	case "cut-proof":
		err = client.BackupCutProofWire(ctx, bytes.Clone(command.Envelope))
	case "barrier":
		_, err = client.BackupBarrier(ctx, bytes.Clone(command.Envelope))
	case "publish":
		result.ReceiptEnvelope, err = client.BackupPublish(ctx, bytes.Clone(command.Envelope))
	case "complete":
		err = client.BackupComplete(ctx, bytes.Clone(command.Envelope))
	case "complete-status":
		// Recover a terminal result without replaying an expired Release.
	default:
		return result, ErrUnsafe
	}
	if err != nil {
		return result, err
	}
	result.Status, err = client.BackupOperationStatus(ctx, command.OperationID)
	return result, err
}
