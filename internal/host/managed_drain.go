//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
)

// ManagedDrainCommand is a durable, single-use host instruction. Its survivor
// must be selected from the signed placement roster by the caller.
type ManagedDrainCommand struct {
	OperationID       string                `json:"operation_id"`
	Node              string                `json:"node"`
	Role              string                `json:"role"`
	Epoch             uint64                `json:"epoch"`
	DesiredGeneration uint64                `json:"desired_generation"`
	ExpectedETag      string                `json:"expected_etag"`
	Member            ManagedMemberBinding  `json:"member"`
	Authority         MemberAuthority       `json:"authority"`
	OCI               ManagedOCIBinding     `json:"oci"`
	VolumeID          string                `json:"volume_id"`
	AttachmentID      string                `json:"attachment_id"`
	ExpectedProcess   memberstatus.Process  `json:"expected_process"`
	Survivor          memberstatus.Survivor `json:"survivor"`
	SourceSequence    uint64                `json:"source_sequence"`
}

type ManagedDrainResult struct {
	Command  ManagedDrainCommand        `json:"command"`
	Envelope memberstatus.DrainEnvelope `json:"envelope"`
}

type managedDrainQuery struct {
	Role string `json:"role"`
}

type managedDrainReply struct {
	Command *ManagedDrainCommand `json:"command"`
}

func managedDrainKey(cell, node, role string) string {
	return "managed-drain." + cell + "." + node + "." + role
}

func managedDrainResultKey(cell, node, role string) string {
	return "managed-drain-result." + cell + "." + node + "." + role
}

func sameManagedDrainOperation(left, right ManagedDrainCommand) bool {
	left.Epoch, right.Epoch = 0, 0
	return left == right
}

func (command ManagedDrainCommand) matchesDesired(desired Desired, registration Registration) bool {
	launch := desired.ManagedMember
	return entityid.Valid(command.OperationID) &&
		command.Node == desired.Node && command.Role == desired.Role && command.Epoch != 0 &&
		command.DesiredGeneration == desired.Generation && command.ExpectedETag != "" &&
		launch != nil && launch.Runtime != nil && !desired.Withdrawn && command.Member == launch.Member &&
		command.Authority == launch.Authority && command.OCI == launch.OCI &&
		command.VolumeID == launch.VolumeID && command.AttachmentID == launch.AttachmentID &&
		registration.ManagedMember != nil && *registration.ManagedMember == command.Member &&
		registration.ManagedOCI != nil && *registration.ManagedOCI == command.OCI &&
		command.ExpectedProcess.PID >= 2 && lowerHex(command.ExpectedProcess.StartNonce, 32) &&
		command.Survivor.MemberID == launch.Runtime.ReplicationPeerMemberID &&
		command.Survivor.MemberID != command.Member.Scope.MemberID &&
		lowerHexIdentity(command.Survivor.Incarnation)
}

func drainIdentity(command ManagedDrainCommand) memberstatus.Identity {
	scope := command.Member.Scope
	authority := command.Authority
	return memberstatus.Identity{
		Process: command.ExpectedProcess,
		Scope: memberstatus.Scope{
			ClusterID: scope.ClusterID, TenantID: scope.TenantID, DatabaseID: scope.DatabaseID,
			ShardID: scope.ShardID, MemberID: scope.MemberID, Incarnation: scope.Incarnation,
		},
		Authority: memberstatus.Authority{
			Epoch: authority.Epoch, ConfigurationID: authority.ConfigurationID,
			CertificateSHA256: authority.CertificateSHA256, TLSLeafSHA256: authority.TLSLeafSHA256,
		},
	}
}

// RequestManagedDrain stores the command before any host can execute it. A
// repeated operation must carry identical pins; another operation on the same
// seat is rejected until a successor generation explicitly replaces the seat.
func (c *Controller) RequestManagedDrain(ctx context.Context, command ManagedDrainCommand) error {
	if err := c.guard(ctx, command.Epoch); err != nil {
		return err
	}
	registration, _, found, err := c.readRegistration(ctx, command.Node)
	if err != nil || !found {
		return errors.Join(errors.New("managed drain host registration is unavailable"), err)
	}
	if !slices.Contains(registration.Roles, command.Role) || registration.ManagedPlacement == nil ||
		c.managedVerifier == nil {
		return errors.New("managed drain requires an admitted placement host")
	}
	if err := c.managedVerifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return err
	}
	desired, _, found, err := c.readDesired(ctx, command.Node, command.Role)
	if err != nil || !found || !command.matchesDesired(desired, registration) {
		return errors.Join(errors.New("managed drain command differs from current signed desired"), err)
	}
	key := managedDrainKey(c.cell, command.Node, command.Role)
	var prior ManagedDrainCommand
	_, exists, err := c.get(ctx, key, &prior)
	if err != nil {
		return err
	}
	if exists {
		if !sameManagedDrainOperation(prior, command) {
			return memberstatus.ErrOperationConflict
		}
		return nil
	}
	session, _, found, err := c.sessionSnapshot(ctx, sessionKey(c.cell, command.Node))
	if err != nil || !found || session.RegistrationGeneration != registration.Generation ||
		!time.Now().Before(session.ExpiresAt) {
		return errors.Join(errors.New("managed drain host session is unavailable"), err)
	}
	report, _, found, err := c.reportSnapshot(ctx, reportKey(c.cell, command.Node, command.Role))
	if err != nil || !found || report.SessionID != session.SessionID || report.Epoch != session.Epoch ||
		report.Generation != desired.Generation || report.Digest != desired.Digest ||
		report.State != "running" || time.Since(report.ObservedAt) >= ReportMaxAge ||
		report.ObservedAt.After(time.Now().Add(maxClockSkew)) ||
		validateManagedReportForDesired(report, desired) != nil || report.Managed.ServingProof == nil ||
		report.Managed.ProcessPID != command.ExpectedProcess.PID ||
		report.Managed.ProcessBootID != command.ExpectedProcess.StartNonce ||
		report.Managed.ServingProof.Replication.LocalSourceSequence != command.SourceSequence ||
		memberstatus.VerifyReportedServing(*report.Managed.ServingProof, drainIdentity(command), command.Survivor) != nil {
		return errors.Join(errors.New("managed drain lacks a current native serving report"), err)
	}
	for range 8 {
		var old ManagedDrainCommand
		revision, found, err := c.get(ctx, key, &old)
		if err != nil {
			return err
		}
		if found {
			if !sameManagedDrainOperation(old, command) {
				return memberstatus.ErrOperationConflict
			}
			return nil
		}
		if err := c.guard(ctx, command.Epoch); err != nil {
			return err
		}
		if _, err := c.cas(ctx, key, command, revision); err == nil {
			return nil
		} else if !casConflict(err) {
			return err
		}
	}
	return errors.New("managed drain command contention")
}

func (c *Controller) serveManagedDrainCommand(ctx context.Context, req request, registration Registration) (any, error) {
	var query managedDrainQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if !slices.Contains(registration.Roles, query.Role) {
		return nil, errors.New("managed drain role is not registered")
	}
	var command ManagedDrainCommand
	_, found, err := c.get(ctx, managedDrainKey(c.cell, req.Node, query.Role), &command)
	if err != nil || !found {
		return managedDrainReply{}, err
	}
	desired, _, current, err := c.readDesired(ctx, req.Node, query.Role)
	if err != nil || !current || !command.matchesDesired(desired, registration) {
		return nil, errors.Join(errors.New("managed drain command is no longer current"), err)
	}
	if c.managedVerifier == nil {
		return nil, errors.New("managed drain verifier is unavailable")
	}
	if err := c.managedVerifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return nil, err
	}
	return managedDrainReply{Command: &command}, nil
}

func (c *Controller) storeManagedDrainResult(ctx context.Context, req request, registration Registration) (any, error) {
	var result ManagedDrainResult
	if err := decodeStrict(req.Payload, &result); err != nil {
		return nil, err
	}
	command := result.Command
	if req.Node != command.Node || !slices.Contains(registration.Roles, command.Role) {
		return nil, errors.New("managed drain result host identity differs")
	}
	var current ManagedDrainCommand
	_, found, err := c.get(ctx, managedDrainKey(c.cell, command.Node, command.Role), &current)
	if err != nil || !found || current != command {
		return nil, errors.Join(errors.New("managed drain result lacks its exact durable command"), err)
	}
	desired, _, found, err := c.readDesired(ctx, command.Node, command.Role)
	if err != nil || !found || !command.matchesDesired(desired, registration) ||
		memberstatus.VerifyReportedDrain(result.Envelope, command.OperationID,
			drainIdentity(command), command.Survivor, command.SourceSequence) != nil {
		return nil, errors.Join(errors.New("managed drain result lacks final root and survivor coverage"), err)
	}
	key := managedDrainResultKey(c.cell, command.Node, command.Role)
	for range 8 {
		var old ManagedDrainResult
		revision, found, err := c.get(ctx, key, &old)
		if err != nil {
			return nil, err
		}
		if found {
			if old.Command != result.Command || old.Envelope.ReceiptSHA256 == nil ||
				result.Envelope.ReceiptSHA256 == nil ||
				*old.Envelope.ReceiptSHA256 != *result.Envelope.ReceiptSHA256 {
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
	return nil, errors.New("managed drain result contention")
}

// ReadManagedDrainResult is a typed, durable completion observation. It does
// not constitute independent writer-stop or authorize an OCI detach.
func (c *Controller) ReadManagedDrainResult(ctx context.Context, node, role string) (ManagedDrainResult, bool, error) {
	if validateToken(node, "node") != nil || validateToken(role, "role") != nil {
		return ManagedDrainResult{}, false, errors.New("invalid managed drain result key")
	}
	var result ManagedDrainResult
	_, found, err := c.get(ctx, managedDrainResultKey(c.cell, node, role), &result)
	if err != nil || !found {
		return ManagedDrainResult{}, found, err
	}
	var command ManagedDrainCommand
	_, found, err = c.get(ctx, managedDrainKey(c.cell, node, role), &command)
	if err != nil || !found || command != result.Command {
		return ManagedDrainResult{}, false, errors.Join(errors.New("managed drain result differs from current command"), err)
	}
	if err := memberstatus.VerifyReportedDrain(result.Envelope, result.Command.OperationID,
		drainIdentity(result.Command), result.Command.Survivor, result.Command.SourceSequence); err != nil {
		return ManagedDrainResult{}, false, err
	}
	return result, true, nil
}

func (a *Agent) reconcileManagedDrain(ctx context.Context, desired Desired, registration Registration, command ManagedDrainCommand) error {
	if !command.matchesDesired(desired, registration) {
		return errors.New("managed drain command differs from signed desired")
	}
	if err := a.fetchManagedMaterial(ctx, desired, registration); err != nil {
		return err
	}
	_, mount, socket, err := prepareManagedRuntime(ctx, a.cfg, desired, "", "")
	if err != nil {
		return err
	}
	defer mount.close()
	if err := verifyManagedDeviceWitness(mount); err != nil {
		return err
	}
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *desired.ManagedMember)
	if err != nil {
		return err
	}
	certificate, err := verifyManagedMaterial(filepath.Join(paths.material, "authority.tbca"),
		desired.ManagedMember.Authority.CertificateSHA256, a.cfg.WorkloadIdentity, 1<<20)
	if err == nil {
		err = inspectManagedVolumeClaim(paths, *desired.ManagedMember, a.cfg.WorkloadIdentity, mount, certificate)
	}
	if err != nil {
		return err
	}
	client, err := managedMemberClient(a.runner, desired, socket)
	if err != nil {
		return err
	}
	store, err := memberstatus.NewFileStore(filepath.Join(a.cfg.StateRoot, a.cfg.Cell, a.cfg.Node,
		"member-drain-"+desired.Role+".json"))
	if err != nil {
		return err
	}
	record, found, err := store.Load()
	if err != nil {
		return err
	}
	if found {
		if record.Request.OperationID != command.OperationID ||
			record.Request.Expected != drainIdentity(command) || record.Survivor != command.Survivor ||
			record.SourceSequence < command.SourceSequence {
			return memberstatus.ErrOperationConflict
		}
	}
	fingerprint, err := desiredFingerprint(desired)
	if err != nil {
		return err
	}
	if err := a.stopManagedNativeRootIfChanged(desired.Role, fingerprint); err != nil {
		return err
	}
	current, err := a.runner.Observe(ctx, desired.Role)
	if err != nil {
		return err
	}
	if current.Running && (current.Digest != desired.Digest || current.Fingerprint != fingerprint ||
		current.CgroupMemoryMaxBytes != desired.ManagedMember.CgroupMemoryMaxBytes) {
		return errors.Join(memberstatus.ErrStaleBinding, a.stopManagedNativeRoot(desired.Role),
			a.runner.Stop(ctx, desired.Role))
	}
	if current.Running {
		if err := a.ensureManagedNativeRoot(ctx, desired, fingerprint); err != nil {
			return err
		}
	} else {
		if !found {
			return errors.New("managed drain source stopped before its durable request was prepared")
		}
		if err := a.restoreManagedProcessForDrain(ctx, desired, fingerprint, mount, socket); err != nil {
			return err
		}
	}
	if !found {
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if status.Process != command.ExpectedProcess || !status.Serving {
			return memberstatus.ErrStaleBinding
		}
		proof, err := client.ServingProof(ctx, status, command.Survivor)
		if err != nil {
			return err
		}
		if proof.Replication.LocalSourceSequence < command.SourceSequence {
			return memberstatus.ErrStaleBinding
		}
		if _, err := client.PrepareDrain(status, proof, command.Survivor, command.OperationID, store); err != nil {
			return err
		}
	}
	envelope, err := client.ReconcileDrain(ctx, store)
	if err != nil {
		return err
	}
	if envelope.State != "complete" {
		return nil
	}
	if err := memberstatus.VerifyReportedDrain(envelope, command.OperationID,
		drainIdentity(command), command.Survivor, command.SourceSequence); err != nil {
		return err
	}
	if err := verifyManagedDeviceWitness(mount); err != nil {
		return err
	}
	var accepted ManagedDrainResult
	if err := a.request(ctx, "drain-result", ManagedDrainResult{Command: command, Envelope: envelope}, &accepted); err != nil {
		return fmt.Errorf("publish completed managed drain: %w", err)
	}
	if accepted.Command != command || accepted.Envelope.ReceiptSHA256 == nil || envelope.ReceiptSHA256 == nil ||
		*accepted.Envelope.ReceiptSHA256 != *envelope.ReceiptSHA256 {
		return errors.New("managed drain result acknowledgment differs")
	}
	return nil
}

// A persisted Rust drain intent can resume after its native process exits.
// This path starts only the same signed desired against the same retained
// volume; it does not publish a serving report while the drain is pending.
func (a *Agent) restoreManagedProcessForDrain(ctx context.Context, desired Desired, fingerprint string, mount managedMount, socket string) (resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, a.stopManagedNativeRoot(desired.Role))
		}
	}()
	executable, err := a.fetchArtifact(ctx, desired.Role, desired.Digest)
	if err != nil {
		return err
	}
	workload, check, checkSocket, err := prepareManagedRuntime(ctx, a.cfg, desired, executable, fingerprint)
	if err != nil {
		return err
	}
	defer check.close()
	if checkSocket != socket {
		return memberstatus.ErrStaleBinding
	}
	if err := verifyManagedMountPair(check, mount); err != nil {
		return err
	}
	if err := requireManagedRoleQuiescent(a.runner, desired.Role); err != nil {
		return err
	}
	if err := removeStoppedMemberSocket(socket, a.cfg.WorkloadIdentity); err != nil {
		return err
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	if err := a.ensureManagedNativeRoot(ctx, desired, fingerprint); err != nil {
		return err
	}
	if err := a.runner.Apply(ctx, workload); err != nil {
		return err
	}
	if err := verifyManagedMountPair(check, mount); err != nil {
		return errors.Join(err, a.runner.Stop(ctx, desired.Role))
	}
	return nil
}

func (a *Agent) fetchManagedDrainCommand(ctx context.Context, role string) (*ManagedDrainCommand, error) {
	var reply managedDrainReply
	if err := a.request(ctx, "drain-command", managedDrainQuery{Role: role}, &reply); err != nil {
		return nil, err
	}
	return reply.Command, nil
}
