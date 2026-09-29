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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
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

func TestBackupHeldRestartDiscoversR3WithoutPriorHostCommand(t *testing.T) {
	registration, desired, hostKey := managedContractFixture()
	registration.ManagedPlacement = &ManagedPlacementBinding{DatabaseID: "db-main", PartitionID: "partition-a",
		SeatID: "permanent-a", IntentGeneration: 1,
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
		ReplicationListenAddress:  "127.0.0.1:7000",
		ReplicationPeerMemberID:   "018f0000-0000-7000-8000-000000000002",
		ReplicationPeerAddress:    "127.0.0.1:7001",
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
		OperationID: "77777777-7777-7777-7777-777777777777", State: "aborting",
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
		"session", strings.Repeat("4", 32), 0, struct {
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
	process := memberstatus.Process{PID: 1234, StartNonce: strings.Repeat("5", 32)}
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
	held := memberstatus.Status{Process: memberstatus.Process{PID: 1234, StartNonce: strings.Repeat("5", 32)},
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
}

func TestBackupHostCommandOnlyRelaysExactR3Envelope(t *testing.T) {
	prepare := []byte(`{"version":1,"payload":"prepare"}`)
	sum := sha256.Sum256(prepare)
	prepareSHA := hex.EncodeToString(sum[:])
	memberID := "33333333-3333-3333-3333-333333333333"
	incarnation := strings.Repeat("5", 32)
	leafSHA := strings.Repeat("1", 64)
	record := authority.BackupOperationRecord{DatabaseID: "database-a", PartitionID: "partition-a",
		OperationID: "77777777-7777-7777-7777-777777777777", State: "accepted",
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
	changed.Envelope = []byte(`{"version":1,"payload":"other"}`)
	if changed.matchesRecord(record) {
		t.Fatal("changed host Prepare envelope was accepted")
	}
	changed = command
	changed.MemberID = "44444444-4444-4444-4444-444444444444"
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
