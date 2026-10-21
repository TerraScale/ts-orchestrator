//go:build linux

package host

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// ManagedContainerRuntime is inert host transport. Only the held execution.Source
// derives it from containerd, kernel namespaces and retained filesystem objects.
type ManagedContainerRuntime struct {
	TaskID            string `json:"task_id"`
	TaskSHA256        string `json:"task_sha256"`
	AdmissionSHA256   string `json:"admission_sha256"`
	EffectID          string `json:"effect_id"`
	ContainerID       string `json:"container_id"`
	HostPID           int    `json:"host_pid"`
	MemberPID         int    `json:"member_pid"`
	KernelStart       string `json:"kernel_start"`
	Cgroup            string `json:"cgroup"`
	PIDNamespace      uint64 `json:"pid_namespace"`
	MountNamespace    uint64 `json:"mount_namespace"`
	MountID           uint64 `json:"mount_id"`
	ControlDevice     uint64 `json:"control_device"`
	ControlInode      uint64 `json:"control_inode"`
	PublicationDevice uint64 `json:"publication_device"`
	PublicationInode  uint64 `json:"publication_inode"`
}

func (binding ManagedContainerRuntime) valid() bool {
	return binding.TaskID != "" && lowerHex(binding.TaskSHA256, 64) && lowerHex(binding.AdmissionSHA256, 64) &&
		entityid.Valid(binding.EffectID) && binding.ContainerID == "ts-"+binding.TaskID &&
		binding.HostPID >= 2 && binding.MemberPID == 1 && binding.KernelStart != "" &&
		binding.Cgroup == "/terrascale/"+binding.ContainerID && binding.PIDNamespace != 0 && binding.MountNamespace != 0 &&
		binding.MountID != 0 && binding.ControlDevice != 0 && binding.ControlInode != 0 &&
		binding.PublicationDevice != 0 && binding.PublicationInode != 0
}

func managedReportMemberPID(report *ManagedRuntimeReport) int {
	if report.Container != nil {
		return report.Container.MemberPID
	}
	return report.ProcessPID
}

// MatchesContainer checks an independently observed Source binding against the
// exact signed desired and controller-selected process; it grants no execution.
func (command ManagedBackupCommand) MatchesContainer(desired Desired, registration Registration, binding ManagedContainerRuntime, sessionID string) bool {
	return command.Container != nil && *command.Container == binding && command.SessionID == sessionID &&
		command.matchesDesired(desired, registration)
}

// BackupCommand, BackupResult and BackupRuntimeReport retain the existing
// authenticated host session. They transport evidence; they do not create it.
func (a *Agent) BackupCommand(ctx context.Context, role string) (*ManagedBackupCommand, bool, error) {
	if _, _, err := a.executionLease(); err != nil {
		return nil, false, err
	}
	reply, err := a.fetchManagedBackupCommand(ctx, role)
	if err != nil {
		return nil, false, err
	}
	if _, _, err := a.executionLease(); err != nil {
		return nil, false, err
	}
	return reply.Command, reply.Pending, nil
}

func (a *Agent) BackupResult(ctx context.Context, result ManagedBackupResult) error {
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	var accepted ManagedBackupResult
	if err := a.request(ctx, "backup-result", result, &accepted); err != nil {
		return err
	}
	if !sameJSON(accepted, result) {
		return errors.New("backup result acknowledgment differs from submitted evidence")
	}
	_, _, err := a.executionLease()
	return err
}

func (a *Agent) BackupRuntimeReport(ctx context.Context, desired Desired, observed ManagedRuntimeReport) error {
	if observed.Container == nil || desired.Node != a.cfg.Node || desired.Cell != a.cfg.Cell {
		return errors.New("container backup report lacks exact local host identity")
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	report := a.reportFor(desired, "running", nil)
	report.Managed = &observed
	if err := validateManagedReportForDesired(report, desired); err != nil {
		return err
	}
	return a.publishReport(ctx, report)
}

// VerifyContainerCredentialGeneration preserves the on-disk production
// credential state check while a held member cannot supply serving evidence.
func VerifyContainerCredentialGeneration(root string, desired Desired, identity WorkloadIdentity, generation uint64) error {
	if desired.ManagedMember == nil {
		return errors.New("container backup lacks signed member")
	}
	paths, err := runtimePaths(root, *desired.ManagedMember)
	if err != nil {
		return err
	}
	_, state, err := readManagedCredentialState(filepath.Join(paths.material, managedCredentialFileName), identity)
	if err != nil || state.Generation > 1 && generation != state.Generation {
		return errors.Join(errors.New("backup process credential generation changed"), err)
	}
	return nil
}
