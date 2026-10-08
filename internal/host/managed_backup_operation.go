//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
)

const maxBackupRelayBytes = 8 << 10
const maxBackupCompleteRelayBytes = 30 << 10

// ManagedBackupCommand is a host relay of an already committed R3 envelope.
// It has no signing key, backup credentials or data key.
type ManagedBackupCommand struct {
	OperationID       string               `json:"operation_id"`
	DatabaseID        string               `json:"database_id"`
	PartitionID       string               `json:"partition_id"`
	MemberID          string               `json:"member_id"`
	Node              string               `json:"node"`
	Role              string               `json:"role"`
	Kind              string               `json:"kind"`
	ProofMemberID     string               `json:"proof_member_id,omitempty"`
	RefreshAtMS       uint64               `json:"refresh_at_ms,omitzero"`
	Epoch             uint64               `json:"epoch"`
	DesiredGeneration uint64               `json:"desired_generation"`
	DesiredDigest     string               `json:"desired_digest"`
	Member            ManagedMemberBinding `json:"member"`
	Authority         MemberAuthority      `json:"authority"`
	OCI               ManagedOCIBinding    `json:"oci"`
	ExpectedProcess   memberstatus.Process `json:"expected_process"`
	Envelope          []byte               `json:"envelope"`
	EnvelopeSHA256    string               `json:"envelope_sha256"`
}

type ManagedBackupResult struct {
	Command         ManagedBackupCommand               `json:"command"`
	CutEnvelope     []byte                             `json:"cut_envelope,omitempty"`
	ReceiptEnvelope []byte                             `json:"receipt_envelope,omitempty"`
	Status          memberstatus.BackupOperationStatus `json:"status"`
}

type managedBackupQuery struct {
	Role string `json:"role"`
}

type managedBackupReply struct {
	Command *ManagedBackupCommand `json:"command,omitempty"`
	Pending bool                  `json:"pending"`
}

type backupOperationReader interface {
	ReadBackupOperation(context.Context, string, string) (authority.BackupOperationRecord, uint64, error)
}

func managedBackupCommandKey(cell, node, role string) string {
	return "managed-backup." + cell + "." + node + "." + role
}

func managedBackupResultKey(cell, node, role string) string {
	return "managed-backup-result." + cell + "." + node + "." + role
}

func (command ManagedBackupCommand) matchesDesired(desired Desired, registration Registration) bool {
	launch := desired.ManagedMember
	return command.Node == desired.Node && command.Role == desired.Role &&
		command.DesiredGeneration == desired.Generation && command.DesiredDigest == desired.Digest &&
		command.Epoch != 0 && !desired.Withdrawn && launch != nil && launch.Runtime != nil &&
		command.Member == launch.Member && command.Authority == launch.Authority &&
		command.OCI == launch.OCI && command.Member.Scope.MemberID == command.MemberID &&
		registration.ManagedMember != nil && *registration.ManagedMember == command.Member &&
		registration.ManagedOCI != nil && *registration.ManagedOCI == command.OCI &&
		registration.ManagedPlacement != nil &&
		registration.ManagedPlacement.DatabaseID == command.DatabaseID &&
		registration.ManagedPlacement.PartitionID == command.PartitionID &&
		command.ExpectedProcess.PID >= 2 && lowerHex(command.ExpectedProcess.StartNonce, 32)
}

func (command ManagedBackupCommand) matchesRecord(record authority.BackupOperationRecord) bool {
	if command.OperationID != record.OperationID || command.DatabaseID != record.DatabaseID ||
		command.PartitionID != record.PartitionID ||
		!slices.Contains([]string{"prepare", "abort", "cut-proof", "barrier", "publish", "complete-status", "complete"}, command.Kind) {
		return false
	}
	var memberFound bool
	for _, member := range record.Roster {
		if member.MemberID == command.MemberID && member.Node == command.Node && member.Role == command.Role &&
			member.Incarnation == command.Member.Scope.Incarnation &&
			member.TLSLeafSHA256 == command.Authority.TLSLeafSHA256 {
			memberFound = true
			break
		}
	}
	if !memberFound {
		return false
	}
	want, err := backupRelayEnvelope(record, command.MemberID, command.Kind, command.ProofMemberID)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(want)
	limit := maxBackupRelayBytes
	if command.Kind == "complete" || command.Kind == "complete-status" {
		limit = maxBackupCompleteRelayBytes
	}
	return len(want) > 0 && len(want) <= limit &&
		bytes.Equal(command.Envelope, want) && command.EnvelopeSHA256 == hex.EncodeToString(sum[:])
}

func backupRelayEnvelope(record authority.BackupOperationRecord, memberID, kind, proofMemberID string) ([]byte, error) {
	switch kind {
	case "prepare":
		if proofMemberID == "" && record.State != "aborting" && record.State != "aborted" &&
			len(record.AbortEnvelope) == 0 {
			return record.PrepareEnvelope, nil
		}
	case "abort":
		if proofMemberID == "" && slices.Contains([]string{"aborting", "uncertain", "aborted"}, record.State) {
			return record.AbortEnvelope, nil
		}
	case "cut-proof":
		if record.State == "barrier" && proofMemberID != "" && proofMemberID != memberID {
			for _, member := range record.Roster {
				if member.MemberID == proofMemberID && len(member.CutEnvelope) > 0 &&
					len(member.CutLeafDER) > 0 && len(member.CutLeafDER) <= 4096 {
					return json.Marshal(struct {
						Version     uint64 `json:"version"`
						CutEnvelope string `json:"cut_envelope"`
						LeafDER     string `json:"leaf_der"`
					}{1, base64.RawURLEncoding.EncodeToString(member.CutEnvelope),
						base64.RawURLEncoding.EncodeToString(member.CutLeafDER)})
				}
			}
		}
	case "barrier":
		if record.State == "barrier" && proofMemberID == "" {
			return record.BarrierEnvelope, nil
		}
	case "publish":
		if record.State == "publishing" && memberID == record.OwnerMemberID && proofMemberID == "" {
			return record.CompletionEnvelope, nil
		}
	case "complete-status", "complete":
		if record.State == "releasing" && proofMemberID == "" {
			return record.CompleteRelease, nil
		}
	}
	return nil, errors.New("backup relay is not authorized by current R3 state")
}

// RequestManagedBackupOperation derives a relay solely from the current R3
// allocation. Its caller cannot supply or substitute signed envelope bytes.
func (c *Controller) RequestManagedBackupOperation(ctx context.Context, epoch uint64,
	databaseID, partitionID, memberID, kind string,
) error {
	if err := c.guard(ctx, epoch); err != nil {
		return err
	}
	reader, ok := c.mutations.(backupOperationReader)
	if !ok {
		return errors.New("backup R3 operation reader is unavailable")
	}
	record, _, err := reader.ReadBackupOperation(ctx, databaseID, partitionID)
	if err != nil {
		return err
	}
	var rosterMember authority.BackupOperationMember
	for _, candidate := range record.Roster {
		if candidate.MemberID == memberID {
			rosterMember = candidate
			break
		}
	}
	proofMemberID := ""
	if suffix, ok := strings.CutPrefix(kind, "cut-proof/"); ok {
		kind, proofMemberID = "cut-proof", suffix
	}
	if rosterMember.Node == "" || !slices.Contains([]string{"prepare", "abort", "cut-proof", "barrier", "publish", "complete-status", "complete"}, kind) {
		return errors.New("backup relay member or kind is invalid")
	}
	registration, _, found, err := c.readRegistration(ctx, rosterMember.Node)
	if err != nil || !found || c.managedVerifier == nil ||
		!slices.Contains(registration.Roles, rosterMember.Role) {
		return errors.Join(errors.New("backup relay host registration is unavailable"), err)
	}
	if err := c.managedVerifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return err
	}
	desired, _, found, err := c.readDesired(ctx, rosterMember.Node, rosterMember.Role)
	if err != nil || !found || desired.ManagedMember == nil || desired.ManagedMember.Runtime == nil {
		return errors.Join(errors.New("backup relay desired is unavailable"), err)
	}
	session, _, found, err := c.sessionSnapshot(ctx, sessionKey(c.cell, rosterMember.Node))
	if err != nil || !found || session.RegistrationGeneration != registration.Generation ||
		!time.Now().Before(session.ExpiresAt) {
		return errors.Join(errors.New("backup relay host session is unavailable"), err)
	}
	report, _, found, err := c.reportSnapshot(ctx, reportKey(c.cell, rosterMember.Node, rosterMember.Role))
	if err != nil || !found || report.SessionID != session.SessionID ||
		report.Generation != desired.Generation || report.Digest != desired.Digest ||
		report.State != "running" || time.Since(report.ObservedAt) >= ReportMaxAge ||
		report.ObservedAt.After(time.Now().Add(maxClockSkew)) ||
		validateManagedReportForDesired(report, desired) != nil ||
		report.Managed == nil || report.Managed.ProcessPID < 2 ||
		!lowerHex(report.Managed.ProcessBootID, 32) {
		return errors.Join(errors.New("backup relay lacks a current native process report"), err)
	}
	envelope, err := backupRelayEnvelope(record, memberID, kind, proofMemberID)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(envelope)
	var refreshAtMS uint64
	if kind == "complete-status" {
		refreshAtMS = uint64(time.Now().UnixMilli())
	}
	if kind == "barrier" && memberID == record.OwnerMemberID &&
		len(record.CandidateEnvelope) == 0 {
		all := true
		for _, member := range record.Roster {
			all = all && member.BarrierAcknowledged
		}
		if all {
			refreshAtMS = uint64(time.Now().UnixMilli())
		}
	}
	command := ManagedBackupCommand{OperationID: record.OperationID, DatabaseID: databaseID,
		PartitionID: partitionID, MemberID: memberID, Node: rosterMember.Node, Role: rosterMember.Role,
		Kind: kind, ProofMemberID: proofMemberID, RefreshAtMS: refreshAtMS,
		Epoch: epoch, DesiredGeneration: desired.Generation, DesiredDigest: desired.Digest,
		Member: desired.ManagedMember.Member, Authority: desired.ManagedMember.Authority,
		OCI: desired.ManagedMember.OCI,
		ExpectedProcess: memberstatus.Process{PID: report.Managed.ProcessPID,
			StartNonce: report.Managed.ProcessBootID}, Envelope: bytes.Clone(envelope),
		EnvelopeSHA256: hex.EncodeToString(sum[:])}
	if !command.matchesDesired(desired, registration) || !command.matchesRecord(record) {
		return errors.New("backup relay differs from current R3 allocation or desired")
	}
	key := managedBackupCommandKey(c.cell, command.Node, command.Role)
	for range 8 {
		var prior ManagedBackupCommand
		revision, found, err := c.get(ctx, key, &prior)
		if err != nil {
			return err
		}
		if found && sameJSON(prior, command) {
			return nil
		}
		if err := c.guard(ctx, epoch); err != nil {
			return err
		}
		if _, err := c.cas(ctx, key, command, revision); err == nil {
			return nil
		} else if !casConflict(err) {
			return err
		}
	}
	return errors.New("backup relay command contention")
}

func (c *Controller) serveManagedBackupCommand(ctx context.Context, req request,
	registration Registration,
) (any, error) {
	var query managedBackupQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if !slices.Contains(registration.Roles, query.Role) {
		return nil, errors.New("backup relay role is not registered")
	}
	desired, _, found, err := c.readDesired(ctx, req.Node, query.Role)
	if err != nil {
		return nil, err
	}
	if !found || desired.Withdrawn || desired.ManagedMember == nil ||
		desired.ManagedMember.Runtime == nil || registration.ManagedPlacement == nil {
		return managedBackupReply{}, nil
	}
	if err := validateDesired(desired, c.cell, registration); err != nil {
		return nil, errors.Join(errors.New("backup relay desired changed"), err)
	}
	reader, ok := c.mutations.(backupOperationReader)
	if !ok {
		// Without R3, an empty command key cannot prove that no member is held.
		return nil, errors.New("backup R3 operation reader is unavailable")
	}
	record, _, err := reader.ReadBackupOperation(ctx,
		registration.ManagedPlacement.DatabaseID, registration.ManagedPlacement.PartitionID)
	if errors.Is(err, authority.ErrNotFound) {
		return managedBackupReply{}, nil
	}
	if err != nil {
		return nil, err
	}
	if record.State == "aborted" {
		return managedBackupReply{}, nil
	}
	if c.managedVerifier == nil {
		return nil, errors.New("backup relay registration verifier is unavailable")
	}
	if err := c.managedVerifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return nil, err
	}
	member := desired.ManagedMember.Member.Scope
	if !slices.ContainsFunc(record.Roster, func(row authority.BackupOperationMember) bool {
		return row.Node == req.Node && row.Role == query.Role &&
			row.MemberID == member.MemberID && row.Incarnation == member.Incarnation &&
			row.TLSLeafSHA256 == desired.ManagedMember.Authority.TLSLeafSHA256
	}) {
		return managedBackupReply{}, nil
	}
	var command ManagedBackupCommand
	_, found, err = c.get(ctx, managedBackupCommandKey(c.cell, req.Node, query.Role), &command)
	if err != nil {
		return nil, err
	}
	if !found {
		return managedBackupReply{Pending: true}, nil
	}
	var result ManagedBackupResult
	_, resultFound, err := c.get(ctx, managedBackupResultKey(c.cell, req.Node, query.Role), &result)
	if err != nil {
		return nil, err
	}
	if !command.matchesDesired(desired, registration) || !command.matchesRecord(record) {
		// An R3 Abort may overtake an old Prepare command. Keep the member
		// in backup reconciliation while the controller persists the new
		// command, including when the member is held or was restarted.
		return managedBackupReply{Pending: true}, nil
	}
	if resultFound && sameJSON(result.Command, command) {
		return managedBackupReply{Pending: true}, nil
	}
	return managedBackupReply{Command: &command, Pending: true}, nil
}

func (c *Controller) storeManagedBackupResult(ctx context.Context, req request,
	registration Registration,
) (any, error) {
	var result ManagedBackupResult
	if err := decodeStrict(req.Payload, &result); err != nil {
		return nil, err
	}
	command := result.Command
	if req.Node != command.Node || !slices.Contains(registration.Roles, command.Role) {
		return nil, errors.New("backup result host identity differs")
	}
	var current ManagedBackupCommand
	_, found, err := c.get(ctx, managedBackupCommandKey(c.cell, command.Node, command.Role), &current)
	if err != nil || !found || !sameJSON(current, command) {
		return nil, errors.Join(errors.New("backup result lacks exact host command"), err)
	}
	desired, _, found, err := c.readDesired(ctx, command.Node, command.Role)
	if err != nil || !found || !command.matchesDesired(desired, registration) ||
		result.Status.OperationID != command.OperationID || result.Status.Version != 1 ||
		result.Status.BackupSet == "" || result.Status.Attempt == 0 ||
		command.Kind == "prepare" && (result.Status.State != "pending" ||
			len(result.CutEnvelope) == 0 || len(result.CutEnvelope) > maxBackupRelayBytes) ||
		command.Kind == "abort" && (result.Status.State != "failed" ||
			result.Status.ErrorCode != "aborted" || len(result.CutEnvelope) != 0) ||
		command.Kind == "cut-proof" && (result.Status.State != "pending" ||
			len(result.CutEnvelope) != 0 || len(result.ReceiptEnvelope) != 0) ||
		command.Kind == "barrier" && (result.Status.State != "pending" ||
			result.Status.BarrierSHA256 != command.EnvelopeSHA256) ||
		command.Kind == "publish" && (result.Status.State != "pending" ||
			len(result.ReceiptEnvelope) == 0 || len(result.ReceiptEnvelope) > 18<<10 ||
			result.Status.PublishedHeadReceipt != string(result.ReceiptEnvelope)) ||
		command.Kind == "complete-status" &&
			(result.Status.State != "pending" && result.Status.State != "complete" ||
				len(result.CutEnvelope) != 0 || len(result.ReceiptEnvelope) != 0) ||
		command.Kind == "complete" && (result.Status.State != "complete" ||
			len(result.CutEnvelope) != 0 || len(result.ReceiptEnvelope) != 0) {
		return nil, errors.Join(errors.New("backup result is not a matching durable member observation"), err)
	}
	reader, ok := c.mutations.(backupOperationReader)
	if !ok {
		return nil, errors.New("backup R3 operation reader is unavailable")
	}
	record, _, err := reader.ReadBackupOperation(ctx, command.DatabaseID, command.PartitionID)
	if err != nil || !command.matchesRecord(record) ||
		result.Status.Nonce != record.Nonce || result.Status.Ordinal != record.Ordinal ||
		result.Status.Attempt != record.Attempt || result.Status.BackupSet != record.BackupSet ||
		result.Status.SourceScopeDigest != record.SourceScopeDigest ||
		result.Status.SourceAuthoritySHA256 != record.SourceAuthoritySHA256 ||
		result.Status.SourceTargetDigest != record.SourceTargetDigest ||
		result.Status.BackupTargetDigest != record.BackupTargetDigest {
		return nil, errors.Join(errors.New("backup result differs from current R3 operation"), err)
	}
	if (command.Kind == "complete" ||
		command.Kind == "complete-status" && result.Status.State == "complete") &&
		(result.Status.HeadGeneration != record.HeadGeneration ||
			result.Status.PublishedHeadReceipt != string(record.PublicationReceipt)) {
		return nil, errors.New("backup Complete result differs from committed publication")
	}
	key := managedBackupResultKey(c.cell, command.Node, command.Role)
	for range 8 {
		var old ManagedBackupResult
		revision, found, err := c.get(ctx, key, &old)
		if err != nil {
			return nil, err
		}
		if found && sameJSON(old.Command, command) {
			if !sameJSON(old, result) {
				return nil, memberstatus.ErrOperationConflict
			}
			return old, nil
		}
		if _, err := c.cas(ctx, key, result, revision); err == nil {
			return result, nil
		} else if !casConflict(err) {
			return nil, err
		}
	}
	return nil, errors.New("backup result contention")
}

func (c *Controller) ReadManagedBackupResult(ctx context.Context, node, role string,
) (ManagedBackupResult, bool, error) {
	var result ManagedBackupResult
	_, found, err := c.get(ctx, managedBackupResultKey(c.cell, node, role), &result)
	if err != nil || !found {
		return ManagedBackupResult{}, false, err
	}
	var command ManagedBackupCommand
	_, current, err := c.get(ctx, managedBackupCommandKey(c.cell, node, role), &command)
	if err != nil || !current || !sameJSON(result.Command, command) {
		return ManagedBackupResult{}, false, errors.Join(errors.New("backup result is stale"), err)
	}
	return result, true, nil
}

func (a *Agent) fetchManagedBackupCommand(ctx context.Context, role string) (managedBackupReply, error) {
	var reply managedBackupReply
	if err := a.request(ctx, "backup-command", managedBackupQuery{Role: role}, &reply); err != nil {
		return managedBackupReply{}, err
	}
	return reply, nil
}

func (a *Agent) reconcileManagedBackup(ctx context.Context, desired Desired,
	registration Registration, command ManagedBackupCommand,
) error {
	if !command.matchesDesired(desired, registration) {
		return errors.New("backup command differs from current signed desired")
	}
	current, err := a.runner.Observe(ctx, desired.Role)
	if err != nil {
		return err
	}
	if !current.Running {
		return errors.New("backup member process is not running")
	}
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *desired.ManagedMember)
	if err != nil {
		return err
	}
	client, err := managedMemberClient(a.runner, desired, paths.socket)
	if err != nil {
		return err
	}
	status, err := client.Status(ctx)
	if err != nil || status.Process != command.ExpectedProcess {
		return errors.Join(memberstatus.ErrStaleBinding, err)
	}
	var cut, receipt []byte
	if command.Kind == "prepare" {
		cut, err = client.BackupPrepare(ctx, command.Envelope)
	} else if command.Kind == "abort" {
		err = client.BackupAbort(ctx, command.Envelope)
	} else if command.Kind == "cut-proof" {
		err = client.BackupCutProofWire(ctx, command.Envelope)
	} else if command.Kind == "barrier" {
		_, err = client.BackupBarrier(ctx, command.Envelope)
	} else if command.Kind == "publish" {
		receipt, err = client.BackupPublish(ctx, command.Envelope)
	} else if command.Kind == "complete" {
		err = client.BackupComplete(ctx, command.Envelope)
	} else if command.Kind == "complete-status" {
		// Recover a durable terminal member without replaying its old Release.
	} else {
		return errors.New("backup host command kind is invalid")
	}
	if err != nil {
		return err
	}
	memberStatus, err := client.BackupOperationStatus(ctx, command.OperationID)
	if err != nil {
		return err
	}
	// Every Unix request checks the peer PID, kernel start and socket inode.
	// Recheck the native start nonce after the operation/status pair so a
	// process replacement cannot return evidence for the old host command.
	currentStatus, err := client.Status(ctx)
	if err != nil || currentStatus.Process != command.ExpectedProcess {
		return errors.Join(memberstatus.ErrStaleBinding, err)
	}
	var accepted ManagedBackupResult
	return a.request(ctx, "backup-result", ManagedBackupResult{
		Command: command, CutEnvelope: cut, ReceiptEnvelope: receipt, Status: memberStatus}, &accepted)
}

// A restored held member may open its Unix socket before local recovery has
// finished. Wait for a process-bound report without requiring client serving.
func (a *Agent) waitManagedBackupProcess(ctx context.Context, desired Desired,
	expectedMount managedMount,
) error {
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := a.reportManagedBackupProcess(ctx, desired, &expectedMount)
		if err == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.Join(errors.New("backup member process did not recover"), err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// reportManagedBackupProcess refreshes the exact native process proof while
// Prepare has closed client serving. A regular managed serving report requires
// a serving proof, which a correctly held backup member cannot provide.
func (a *Agent) reportManagedBackupProcess(ctx context.Context, desired Desired,
	expectedMount *managedMount,
) error {
	launch := desired.ManagedMember
	if launch == nil || launch.Runtime == nil {
		return errors.New("backup process report lacks managed runtime")
	}
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *launch)
	if err != nil {
		return err
	}
	_, mount, socket, err := prepareManagedRuntime(ctx, a.cfg, desired, "", "")
	if err != nil {
		return err
	}
	defer mount.close()
	if expectedMount != nil {
		if err := verifyManagedMountPair(mount, *expectedMount); err != nil {
			return err
		}
	}
	if socket != paths.socket {
		return errors.New("backup process mount or socket differs from desired")
	}
	if err := verifyManagedDeviceWitness(mount); err != nil {
		return err
	}
	client, err := managedMemberClient(a.runner, desired, socket)
	if err != nil {
		return err
	}
	status, err := client.Status(ctx)
	if err != nil {
		return err
	}
	runner, ok := a.runner.(*processRunner)
	if !ok {
		return errors.New("backup process report requires native runner")
	}
	pid, start, cgroup, err := observeMemberProcess(ctx, runner, desired.Role)
	if err != nil || !backupProcessLocallyRecovered(status, pid) {
		return errors.Join(errors.New("backup member process is no longer bound"), err)
	}
	_, credentialState, err := readManagedCredentialState(
		filepath.Join(paths.material, managedCredentialFileName), a.cfg.WorkloadIdentity)
	if err != nil || credentialState.Generation > 1 &&
		status.CredentialGeneration != credentialState.Generation {
		return errors.Join(errors.New("backup process credential generation changed"), err)
	}
	if expectedMount != nil {
		if err := verifyManagedMountPair(mount, *expectedMount); err != nil {
			return err
		}
	} else if err := verifyManagedDeviceWitness(mount); err != nil {
		return err
	}
	report := a.reportFor(desired, "running", nil)
	report.Managed = &ManagedRuntimeReport{ClientCredentialGeneration: status.CredentialGeneration,
		Member: launch.Member, Authority: launch.Authority, OCI: launch.OCI,
		VolumeID: launch.VolumeID, AttachmentID: launch.AttachmentID,
		AttachmentETag: launch.AttachmentETag,
		FileSystemUUID: mount.uuid, FileSystemType: mount.fsType,
		MountDevice: mount.device, MountPath: paths.mount, MountID: mount.id,
		ProcessPID: pid, ProcessStart: start, ProcessCgroup: cgroup,
		ProcessBootID:    status.Process.StartNonce,
		StorageRecovered: status.Local.StorageRecovered,
		ListenerReady:    status.Local.ReplicationListenerReady}
	return a.publishReport(ctx, report)
}

func backupProcessLocallyRecovered(status memberstatus.Status, observedPID int) bool {
	return observedPID >= 2 && observedPID == status.Process.PID &&
		lowerHex(status.Process.StartNonce, 32) && status.Local.StorageRecovered &&
		status.Local.ReplicationListenerReady
}
