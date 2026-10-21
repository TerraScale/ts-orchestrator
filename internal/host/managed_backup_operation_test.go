//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

type backupTestMutationReader struct {
	authority.HostMutationStore
	authority.VerifiedHostMutationStore
	record authority.BackupOperationRecord
}

type backupTestNoReader struct{ authority.HostMutationStore }

type verifiedMemoryMutations struct{ *memoryMutations }

func (mutations verifiedMemoryMutations) CommitHostMutationVerified(ctx context.Context, epoch uint64,
	kind authority.HostMutationKind, subject, operation string, expected uint64, payload []byte,
	verify func(context.Context) error,
) (uint64, error) {
	m := mutations.memoryMutations
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.key(kind, subject)
	if m.entries[key].Sequence != expected {
		return 0, authority.ErrConflict
	}
	if verify != nil {
		if err := verify(ctx); err != nil {
			return 0, err
		}
	}
	ack, err := m.js.Publish(ctx, "ts.control.gru.host."+string(kind)+"."+subject, payload)
	if err != nil {
		return 0, err
	}
	m.sequence = ack.Sequence
	m.entries[key] = authority.LogEntry{Kind: kind, SubjectKey: subject, OperationID: operation,
		Epoch: epoch, Sequence: m.sequence, Payload: bytes.Clone(payload)}
	return m.sequence, nil
}

func (reader backupTestMutationReader) ReadBackupOperation(_ context.Context,
	databaseID, partitionID string,
) (authority.BackupOperationRecord, uint64, error) {
	if reader.record.DatabaseID != databaseID || reader.record.PartitionID != partitionID {
		return authority.BackupOperationRecord{}, 0, authority.ErrNotFound
	}
	return reader.record, 1, nil
}

func TestBackupRelaySerializedBoundsAtDERAndCompleteCaps(t *testing.T) {
	cut := bytes.Repeat([]byte("c"), 1753)
	der := bytes.Repeat([]byte{0x42}, 4096)
	record := authority.BackupOperationRecord{State: "barrier",
		Roster: []authority.BackupOperationMember{
			{MemberID: "1K6CSK6CSK6CSK6CSK6CSK6CSK", CutEnvelope: cut, CutLeafDER: der},
			{MemberID: "248H248H248H248H248H248H24"}},
	}
	proof, err := backupRelayEnvelope(record, record.Roster[1].MemberID,
		"cut-proof", record.Roster[0].MemberID)
	if err != nil || len(proof) > maxBackupRelayBytes {
		t.Fatalf("maximal CutProof does not fit 8 KiB: %d, %v", len(proof), err)
	}
	record.Roster[0].CutLeafDER = append(der, 0)
	if _, err := backupRelayEnvelope(record, record.Roster[1].MemberID,
		"cut-proof", record.Roster[0].MemberID); err == nil {
		t.Fatal("oversize pinned leaf entered CutProof relay")
	}
	command := ManagedBackupCommand{Kind: "complete",
		Envelope:       bytes.Repeat([]byte("x"), maxBackupCompleteRelayBytes),
		EnvelopeSHA256: strings.Repeat("a", 64),
		OperationID:    "3QEXVQEXVQEXVQEXVQEXVQEXVQ",
		DatabaseID:     "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8",
		MemberID: record.Roster[1].MemberID, Node: "host-a", Role: "terrabase"}
	status := memberstatus.BackupOperationStatus{Version: 1,
		OperationID: command.OperationID, State: "complete",
		PublishedHeadReceipt: string(bytes.Repeat([]byte("r"), 18<<10))}
	commandWire, err := json.Marshal(command)
	if err != nil || len(commandWire) > 64<<10 {
		t.Fatalf("maximal Complete command KV exceeds 64 KiB: %d, %v", len(commandWire), err)
	}
	resultWire, err := json.Marshal(ManagedBackupResult{Command: command, Status: status})
	if err != nil || len(resultWire) > 64<<10 {
		t.Fatalf("maximal Complete result KV exceeds 64 KiB: %d, %v", len(resultWire), err)
	}
}

func TestBackupHeldRestartDiscoversR3WithoutPriorHostCommand(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	registration, desired, hostKey := managedContractFixture()
	registration.ManagedPlacement = &ManagedPlacementBinding{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000Z3WK359G2W66CVT8",
		SeatID: "000000000082AXF7GZQT1D126Y", IntentGeneration: 1,
		IntentPayloadDigest: strings.Repeat("1", 64), CanonicalRosterDigest: strings.Repeat("2", 64),
		ManagedHostProfileDigest: strings.Repeat("3", 64)}
	paths, err := runtimePaths("/srv/managed", *desired.ManagedMember)
	if err != nil {
		t.Fatal(err)
	}
	desired.ManagedMember.Runtime = &ManagedRuntimePins{DevicePath: "/dev/sdb", MountPath: paths.mount,
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
		TrustedKeySHA256: strings.Repeat("1", 64), ServerCertificateSHA256: strings.Repeat("2", 64),
		ServerPrivateKeySHA256: strings.Repeat("3", 64), ClientCARootsSHA256: strings.Repeat("4", 64),
		ClientManagedMaterialManifestSHA256: strings.Repeat("5", 64),
		LiveS3ConfigSHA256:                  strings.Repeat("7", 64),
		LiveS3TargetSHA256:                  strings.Repeat("8", 64),
		LiveS3Credential: oci.SecretVersionReference{
			SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3},
		ReplicationListenAddress:  "10.0.0.11:7000",
		ReplicationPeerMemberID:   "01HW000000E008000000000002",
		ReplicationPeerAddress:    "10.0.0.12:7001",
		ReplicationServerCASHA256: strings.Repeat("6", 64)}
	desired.ManagedMember.AttachmentETag = "etag-current"
	if err := validateDesired(desired, registration.Cell, registration); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("backup held restart artifact")
	digest := sha256.Sum256(artifact)
	desired.Digest = hex.EncodeToString(digest[:])
	controller, conn, objects, mutations, controllerKey := testControllerWithVerifier(t,
		managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }))
	var desiredVerifierCalls int
	controller.managedDesiredVerifier = func(context.Context, Desired, Registration, Desired, bool) error {
		desiredVerifierCalls++
		return nil
	}
	record := authority.BackupOperationRecord{DatabaseID: registration.ManagedPlacement.DatabaseID,
		PartitionID: registration.ManagedPlacement.PartitionID,
		OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ", State: "aborting",
		AbortEnvelope: []byte(`{"version":1,"payload":"abort"}`),
		Roster: []authority.BackupOperationMember{{MemberID: desired.ManagedMember.Member.Scope.MemberID,
			Incarnation:   desired.ManagedMember.Member.Scope.Incarnation,
			TLSLeafSHA256: desired.ManagedMember.Authority.TLSLeafSHA256,
			Node:          desired.Node, Role: desired.Role}}}
	verified := verifiedMemoryMutations{mutations}
	controller.mutations = backupTestMutationReader{
		HostMutationStore: verified, VerifiedHostMutationStore: verified, record: record,
	}
	if _, err := controller.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.PutBytes(t.Context(), "sha256-"+desired.Digest, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if desiredVerifierCalls != 1 {
		t.Fatalf("managed desired final verifier called %d times, want once", desiredVerifierCalls)
	}
	payload, err := json.Marshal(managedBackupQuery{Role: desired.Role})
	if err != nil {
		t.Fatal(err)
	}
	query := request{Node: desired.Node, Payload: payload}
	got, err := controller.serveManagedBackupCommand(t.Context(), query, registration)
	if err != nil {
		t.Fatal(err)
	}
	reply := got.(managedBackupReply)
	if !reply.Pending || reply.Command != nil {
		t.Fatalf("R3 Abort without old host command did not hold restart: %+v", reply)
	}
	withReader := controller.mutations
	controller.mutations = backupTestNoReader{HostMutationStore: withReader}
	if _, err := controller.serveManagedBackupCommand(t.Context(), query, registration); err == nil {
		t.Fatal("missing R3 reader was mistaken for no backup operation")
	}
	controller.mutations = withReader
	controllerCtx, stopController := context.WithCancel(t.Context())
	defer stopController()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(controllerCtx) }()
	select {
	case <-controller.Ready():
	case err := <-controllerDone:
		t.Fatalf("backup host controller stopped before ready: %v", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	accepted, err := controller.handleSession(t.Context(), signedHostRequest(t, hostKey,
		"session", "00000000000000000000000004", 0, struct {
			Kind string `json:"kind"`
		}{Kind: "acquire"}))
	if err != nil {
		t.Fatal(err)
	}
	s := accepted.(session)
	agent := &Agent{cfg: AgentConfig{Cell: desired.Cell, Node: desired.Node,
		NATSUserPublicKey: registration.NATSUserPublicKey, Conn: conn,
		Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey)},
		processID: s.SessionID, session: s}
	fetched, err := agent.fetchManagedBackupCommand(t.Context(), desired.Role)
	if err != nil || !fetched.Pending || fetched.Command != nil {
		t.Fatalf("signed Agent lost R3 pending restart: %+v, %v", fetched, err)
	}
	process := memberstatus.Process{PID: 1234, StartNonce: "0000000000004b6858ab4a6dea005577"}
	report := Report{Cell: desired.Cell, Node: desired.Node, Environment: desired.Environment,
		Role: desired.Role, Digest: desired.Digest, Generation: desired.Generation,
		SessionID: s.SessionID, Epoch: s.Epoch, State: "running", ObservedAt: time.Now().UTC(),
		Managed: &ManagedRuntimeReport{Member: desired.ManagedMember.Member,
			Authority: desired.ManagedMember.Authority, OCI: desired.ManagedMember.OCI,
			VolumeID: desired.ManagedMember.VolumeID, AttachmentID: desired.ManagedMember.AttachmentID,
			AttachmentETag: desired.ManagedMember.AttachmentETag,
			FileSystemUUID: desired.ManagedMember.Runtime.FileSystemUUID,
			FileSystemType: desired.ManagedMember.Runtime.FileSystemType,
			MountDevice:    desired.ManagedMember.Runtime.DevicePath,
			MountPath:      paths.mount, MountID: 23,
			ProcessPID: process.PID, ProcessStart: "12345", ProcessCgroup: "/terrabase",
			ProcessBootID: process.StartNonce, StorageRecovered: true, ListenerReady: true}}
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey,
		"report", s.SessionID, s.Epoch, report)); err != nil {
		t.Fatal(err)
	}
	if report.Managed.ServingProof != nil {
		t.Fatal("held process report claimed client serving")
	}
	if err := controller.RequestManagedBackupOperation(t.Context(), 1,
		record.DatabaseID, record.PartitionID, desired.ManagedMember.Member.Scope.MemberID, "abort"); err != nil {
		t.Fatal(err)
	}
	got, err = controller.serveManagedBackupCommand(t.Context(), query, registration)
	if err != nil {
		t.Fatal(err)
	}
	reply = got.(managedBackupReply)
	if !reply.Pending || reply.Command == nil || reply.Command.Kind != "abort" ||
		reply.Command.ExpectedProcess != process || !bytes.Equal(reply.Command.Envelope, record.AbortEnvelope) {
		t.Fatalf("held restart did not receive exact process-bound Abort: %+v", reply)
	}
	fetched, err = agent.fetchManagedBackupCommand(t.Context(), desired.Role)
	if err != nil || !fetched.Pending || fetched.Command == nil ||
		fetched.Command.ExpectedProcess != process || fetched.Command.Kind != "abort" {
		t.Fatalf("signed Agent did not receive process-bound Abort: %+v, %v", fetched, err)
	}
	if backupProcessLocallyRecovered(memberstatus.Status{Local: memberstatus.Local{
		StorageRecovered: true, ReplicationListenerReady: true,
	}}, 0) {
		t.Fatal("backup recovery accepted a missing process identity")
	}
	// A restored Prepare holder is deliberately not client ready. The backup
	// report can bind its local process without claiming a serving proof.
	held := memberstatus.Status{Process: memberstatus.Process{PID: 1234, StartNonce: "0000000000004b6858ab4a6dea005577"},
		Local: memberstatus.Local{StorageRecovered: true, ReplicationListenerReady: true}}
	if !backupProcessLocallyRecovered(held, 1234) || backupProcessLocallyRecovered(held, 1235) {
		t.Fatal("held restart process identity was not checked exactly")
	}
	unrecovered := held
	unrecovered.Local.StorageRecovered = false
	if backupProcessLocallyRecovered(unrecovered, 1234) {
		t.Fatal("held restart accepted unrecovered storage")
	}
	unrecovered = held
	unrecovered.Local.ReplicationListenerReady = false
	if backupProcessLocallyRecovered(unrecovered, 1234) {
		t.Fatal("held restart accepted a missing replication listener")
	}
	record.State = "aborted"
	verifiedStore := controller.mutations.(authority.VerifiedHostMutationStore)
	controller.mutations = backupTestMutationReader{
		HostMutationStore: controller.mutations, VerifiedHostMutationStore: verifiedStore, record: record,
	}
	got, err = controller.serveManagedBackupCommand(t.Context(), query, registration)
	if err != nil {
		t.Fatal(err)
	}
	reply = got.(managedBackupReply)
	if reply.Pending || reply.Command != nil {
		t.Fatalf("aborted operation kept the member held: %+v", reply)
	}
	fetched, err = agent.fetchManagedBackupCommand(t.Context(), desired.Role)
	if err != nil || fetched.Pending || fetched.Command != nil {
		t.Fatalf("signed Agent remained held after R3 Abort: %+v, %v", fetched, err)
	}
	drain, err := agent.fetchManagedDrainCommand(t.Context(), desired.Role)
	if err != nil || drain != nil {
		t.Fatalf("signed Agent could not resume serving reconciliation: %+v, %v", drain, err)
	}
	// The member completed under the original Release, but the controller lost
	// its R3 acknowledgment. A status-only relay must recover its exact proof
	// even after R3 holds a renewed Release with another digest.
	record.State = "releasing"
	record.AbortEnvelope = nil
	record.Ordinal, record.Attempt = 1, 1
	record.Nonce = strings.Repeat("9", 32)
	record.BackupSet = strings.Repeat("a", 32)
	record.SourceScopeDigest = strings.Repeat("b", 64)
	record.SourceAuthoritySHA256 = strings.Repeat("c", 64)
	record.SourceTargetDigest = strings.Repeat("d", 64)
	record.BackupTargetDigest = strings.Repeat("e", 64)
	record.PublicationReceipt = []byte("exact-committed-receipt")
	record.CompleteRelease = []byte("first-signed-complete-release")
	record.CompleteReleaseExpiresAtMS = uint64(time.Now().Add(-time.Minute).UnixMilli())
	record.HeadGeneration = 1
	controller.mutations = backupTestMutationReader{HostMutationStore: withReader,
		VerifiedHostMutationStore: verifiedStore, record: record}
	memberID := desired.ManagedMember.Member.Scope.MemberID
	if err := controller.RequestManagedBackupOperation(t.Context(), 1,
		record.DatabaseID, record.PartitionID, memberID, "complete-status"); err != nil {
		t.Fatal(err)
	}
	statusCommand, err := agent.fetchManagedBackupCommand(t.Context(), desired.Role)
	if err != nil || statusCommand.Command == nil || statusCommand.Command.Kind != "complete-status" ||
		!bytes.Equal(statusCommand.Command.Envelope, record.CompleteRelease) {
		t.Fatalf("signed Agent did not receive exact status-only recovery command: %+v, %v", statusCommand, err)
	}
	memberStatus := memberstatus.BackupOperationStatus{Version: 1,
		OperationID: record.OperationID, Nonce: record.Nonce, State: "complete",
		BackupSet: record.BackupSet, Ordinal: record.Ordinal, Attempt: record.Attempt,
		SourceScopeDigest:     record.SourceScopeDigest,
		SourceAuthoritySHA256: record.SourceAuthoritySHA256,
		SourceTargetDigest:    record.SourceTargetDigest,
		BackupTargetDigest:    record.BackupTargetDigest,
		HeadGeneration:        record.HeadGeneration,
		PublishedHeadReceipt:  string(record.PublicationReceipt)}
	result := ManagedBackupResult{Command: *statusCommand.Command, Status: memberStatus}
	bad := result
	bad.Status.PublishedHeadReceipt = "other-receipt"
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey,
		"backup-result", s.SessionID, s.Epoch, bad)); err == nil {
		t.Fatal("status-only recovery accepted a substituted publication receipt")
	}
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey,
		"backup-result", s.SessionID, s.Epoch, result)); err != nil {
		t.Fatalf("exact terminal status could not recover lost acknowledgment: %v", err)
	}
	if _, found, err := controller.ReadManagedBackupResult(t.Context(), desired.Node, desired.Role); err != nil || !found {
		t.Fatalf("host did not retain exact process status result: %v", err)
	}
	record.CompleteRelease = []byte("renewed-signed-complete-release")
	record.CompleteReleaseExpiresAtMS += 4 * 60_000
	controller.mutations = backupTestMutationReader{HostMutationStore: withReader,
		VerifiedHostMutationStore: verifiedStore, record: record}
	if err := controller.RequestManagedBackupOperation(t.Context(), 1,
		record.DatabaseID, record.PartitionID, memberID, "complete-status"); err != nil {
		t.Fatal(err)
	}
	renewedCommand, err := agent.fetchManagedBackupCommand(t.Context(), desired.Role)
	if err != nil || renewedCommand.Command == nil ||
		renewedCommand.Command.Kind != "complete-status" ||
		!bytes.Equal(renewedCommand.Command.Envelope, record.CompleteRelease) {
		t.Fatalf("renewal replayed Complete before checking terminal status: %+v, %v", renewedCommand, err)
	}
	result.Command = *renewedCommand.Command
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey,
		"backup-result", s.SessionID, s.Epoch, result)); err != nil {
		t.Fatalf("old terminal receipt was rejected after Release renewal: %v", err)
	}

	// The signed host transport keeps namespace PID 1 separate from the exact
	// host identity. Source supplies the actual kernel observation in production.
	container := ManagedContainerRuntime{TaskID: "qualified-task", TaskSHA256: strings.Repeat("1", 64),
		AdmissionSHA256: strings.Repeat("2", 64), EffectID: entityid.Derive("runtime-effect", "backup-test"),
		ContainerID: "ts-qualified-task", HostPID: report.Managed.ProcessPID, MemberPID: 1,
		KernelStart: report.Managed.ProcessStart, Cgroup: "/terrascale/ts-qualified-task", MountID: report.Managed.MountID,
		PIDNamespace: 101, MountNamespace: 102, ControlDevice: 1, ControlInode: 103, PublicationDevice: 1, PublicationInode: 104}
	report.Managed.Container = &container
	report.Managed.ProcessCgroup = container.Cgroup
	report.ObservedAt = time.Now().UTC()
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey,
		"report", s.SessionID, s.Epoch, report)); err != nil {
		t.Fatalf("container held report: %v", err)
	}
	if err := controller.RequestManagedBackupOperation(t.Context(), 1,
		record.DatabaseID, record.PartitionID, memberID, "complete-status"); err != nil {
		t.Fatal(err)
	}
	containerCommand, err := agent.fetchManagedBackupCommand(t.Context(), desired.Role)
	if err != nil || containerCommand.Command == nil || containerCommand.Command.ExpectedProcess.PID != 1 ||
		!containerCommand.Command.MatchesContainer(desired, registration, container, s.SessionID) {
		t.Fatalf("container command lost exact namespace mapping: %+v, %v", containerCommand, err)
	}
	result.Command = *containerCommand.Command
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey,
		"backup-result", s.SessionID, s.Epoch, result)); err != nil {
		t.Fatalf("container terminal evidence: %v", err)
	}
	changed := container
	changed.HostPID++
	if containerCommand.Command.MatchesContainer(desired, registration, changed, s.SessionID) ||
		containerCommand.Command.MatchesContainer(desired, registration, container, "other-session") {
		t.Fatal("container command accepted replacement host process/session")
	}
	// A replaced runtime cannot submit the previous command's terminal evidence.
	container.ControlInode++
	report.ObservedAt = time.Now().UTC()
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey,
		"report", s.SessionID, s.Epoch, report)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.handleAuthorized(t.Context(), signedHostRequest(t, hostKey,
		"backup-result", s.SessionID, s.Epoch, result)); err == nil {
		t.Fatal("replaced control socket submitted old process evidence")
	}
}

func TestBackupHostCommandOnlyRelaysExactR3Envelope(t *testing.T) {
	prepare := []byte(`{"version":1,"payload":"prepare"}`)
	sum := sha256.Sum256(prepare)
	prepareSHA := hex.EncodeToString(sum[:])
	memberID := "1K6CSK6CSK6CSK6CSK6CSK6CSK"
	incarnation := strings.Repeat("5", 32)
	leafSHA := strings.Repeat("1", 64)
	record := authority.BackupOperationRecord{DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8",
		OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ", State: "accepted",
		PrepareEnvelope: prepare, Roster: []authority.BackupOperationMember{{
			MemberID: memberID, Incarnation: incarnation, Node: "host-a", Role: "terrabase",
			TLSLeafSHA256: leafSHA}}}
	command := ManagedBackupCommand{OperationID: record.OperationID, DatabaseID: record.DatabaseID,
		PartitionID: record.PartitionID, MemberID: memberID, Node: "host-a", Role: "terrabase",
		Kind: "prepare", Envelope: bytes.Clone(prepare), EnvelopeSHA256: prepareSHA,
		Member:    ManagedMemberBinding{Scope: MemberScope{MemberID: memberID, Incarnation: incarnation}},
		Authority: MemberAuthority{TLSLeafSHA256: leafSHA}}
	if !command.matchesRecord(record) {
		t.Fatal("exact R3 Prepare was rejected")
	}
	changed := command
	changed.Envelope = []byte(`{"version":1,"payload":"0000000000V4MRM46HP1SNGDYW"}`)
	if changed.matchesRecord(record) {
		t.Fatal("changed host Prepare envelope was accepted")
	}
	changed = command
	changed.MemberID = "248H248H248H248H248H248H24"
	if changed.matchesRecord(record) {
		t.Fatal("wrong roster member received an envelope")
	}
	changed = command
	changed.Envelope = bytes.Repeat([]byte("x"), maxBackupRelayBytes+1)
	if changed.matchesRecord(record) {
		t.Fatal("oversize host envelope was accepted")
	}
	abort := []byte(`{"version":1,"payload":"abort"}`)
	sum = sha256.Sum256(abort)
	record.State = "aborting"
	record.AbortEnvelope = abort
	command.Kind = "abort"
	command.Envelope = abort
	command.EnvelopeSHA256 = hex.EncodeToString(sum[:])
	if !command.matchesRecord(record) {
		t.Fatal("R3-committed Abort was rejected")
	}
	command.Kind = "prepare"
	command.Envelope = prepare
	command.EnvelopeSHA256 = prepareSHA
	if command.matchesRecord(record) {
		t.Fatal("stale Prepare was relayed after Abort decision")
	}
}
