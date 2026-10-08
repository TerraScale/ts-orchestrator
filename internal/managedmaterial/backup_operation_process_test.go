//go:build linux

package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type backupProcessPacket struct {
	Version               uint64                `json:"version"`
	DatabaseID            string                `json:"database_id"`
	PartitionID           string                `json:"partition_id"`
	AuthorityPKCS8Hex     string                `json:"authority_pkcs8_hex"`
	SourceScopeDigest     string                `json:"source_scope_digest"`
	SourceAuthoritySHA256 string                `json:"source_authority_sha256"`
	SourceConfigurationID string                `json:"source_configuration_id"`
	SourceTargetDigest    string                `json:"source_target_digest"`
	BackupSet             string                `json:"backup_set"`
	BackupTargetDigest    string                `json:"backup_target_digest"`
	SignerKeyID           string                `json:"signer_key_id"`
	OwnerMemberID         string                `json:"owner_member_id"`
	Roster                []backupProcessMember `json:"roster"`
}

type backupProcessMember struct {
	Origin                string                 `json:"origin"`
	MemberID              string                 `json:"member_id"`
	Incarnation           string                 `json:"incarnation"`
	TLSLeafSHA256         string                 `json:"tls_leaf_sha256"`
	Node                  string                 `json:"node"`
	Role                  string                 `json:"role"`
	SocketPath            string                 `json:"socket_path"`
	ServerCertificatePath string                 `json:"server_certificate_path"`
	PID                   int                    `json:"pid"`
	UID                   uint32                 `json:"uid"`
	GID                   uint32                 `json:"gid"`
	KernelStart           string                 `json:"kernel_start"`
	Cgroup                string                 `json:"cgroup"`
	Scope                 memberstatus.Scope     `json:"scope"`
	Authority             memberstatus.Authority `json:"authority"`
}

type backupProcessResult struct {
	Version         uint64 `json:"version"`
	OperationID     string `json:"operation_id"`
	Nonce           string `json:"nonce"`
	Ordinal         uint64 `json:"ordinal"`
	Attempt         uint64 `json:"attempt"`
	PrepareEnvelope string `json:"prepare_envelope"`
	PrepareSHA256   string `json:"prepare_sha256"`
	AbortSHA256     string `json:"abort_sha256"`
}

// TestBackupGoRustProcessBridge runs only when the Rust process fixture hands
// us live nonroot members. It uses the production R3 allocator, signing core,
// Cut verifier and process-bound Unix client. The full host Agent/desired path
// has a separate integration gate and is not implied by this test.
func TestBackupGoRustProcessBridge(t *testing.T) {
	packetPath := tier.Qualification(t, "TS_D10_PROCESS_PACKET")[0]
	resultPath := os.Getenv("TS_D10_PROCESS_RESULT")
	if resultPath == "" {
		t.Fatal("Rust live-process result path was not supplied")
	}
	packetInfo, err := os.Lstat(packetPath)
	if err != nil || !packetInfo.Mode().IsRegular() || packetInfo.Mode().Perm() != 0o600 {
		t.Fatal("Rust private-key packet is not a root-only regular file", err)
	}
	packetOwner, ok := packetInfo.Sys().(*syscall.Stat_t)
	if !ok || packetOwner.Uid != 0 || packetOwner.Gid != 0 {
		t.Fatal("Rust private-key packet owner is not root")
	}
	data, err := os.ReadFile(packetPath)
	if err != nil || len(data) == 0 || len(data) > 32<<10 {
		t.Fatal("read bounded root-only Rust process packet", err)
	}
	var packet backupProcessPacket
	if err := json.Unmarshal(data, &packet, json.RejectUnknownMembers(true)); err != nil ||
		packet.Version != 1 || len(packet.Roster) != 2 {
		t.Fatal("invalid Rust process packet", err)
	}
	der, err := hex.DecodeString(packet.AuthorityPKCS8Hex)
	if err != nil {
		t.Fatal("invalid private-key encoding")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal("invalid authority PKCS#8 key")
	}
	signer, ok := parsed.(ed25519.PrivateKey)
	if !ok || backupKeyID(signer.Public().(ed25519.PublicKey)) != packet.SignerKeyID {
		t.Fatal("Rust process signer differs from its pinned public key")
	}
	manifest := BackupManifestPayload{Version: 1,
		SourceScopeDigest: packet.SourceScopeDigest, SourceAuthoritySHA256: packet.SourceAuthoritySHA256,
		SourceConfigurationID: packet.SourceConfigurationID, SourceTargetDigest: packet.SourceTargetDigest,
		BackupSet: packet.BackupSet, BackupTargetDigest: packet.BackupTargetDigest,
		SignerKeyID: packet.SignerKeyID, OwnerMemberID: packet.OwnerMemberID}
	receipt := PreparationReceipt{AuthoritySHA256: packet.SourceAuthoritySHA256,
		AuthorityConfigurationID: packet.SourceConfigurationID}
	bundle := InitialBundle{}
	roster := make([]authority.BackupOperationMember, 0, len(packet.Roster))
	var owner *backupProcessMember
	for index := range packet.Roster {
		member := &packet.Roster[index]
		if member.MemberID == packet.OwnerMemberID {
			owner = member
		}
		certificate, err := os.ReadFile(member.ServerCertificatePath)
		if err != nil {
			t.Fatal("read exact Rust member certificate", err)
		}
		receipt.Spec.Members[index] = InitialMember{MemberID: member.MemberID,
			Incarnation: member.Incarnation}
		receipt.Members[index] = MemberPins{MemberID: member.MemberID,
			TLSLeafSHA256: member.TLSLeafSHA256}
		bundle.Members[index] = MemberBundle{MemberID: member.MemberID,
			TLSLeafSHA256: member.TLSLeafSHA256,
			Files:         map[string]File{"server.crt": {Contents: certificate}}}
		roster = append(roster, authority.BackupOperationMember{Origin: member.Origin,
			MemberID: member.MemberID, Incarnation: member.Incarnation,
			TLSLeafSHA256: member.TLSLeafSHA256, Node: member.Node, Role: member.Role})
	}
	if owner == nil || !slices.IsSortedFunc(roster, func(a, b authority.BackupOperationMember) int {
		return strings.Compare(a.Origin, b.Origin)
	}) {
		t.Fatal("Rust process roster is unsorted or lacks owner")
	}
	manifest.OwnerIncarnation = owner.Incarnation
	js := backupProcessJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	runtime, err := authority.Start(ctx, js, authority.Config{Scope: "gru", CandidateID: "0000000000VYN4VJQR62ZHXCS7", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch,
		packet.DatabaseID, packet.PartitionID, "d10-proof-placement", 0, []byte("live-rust-members"))
	if err != nil {
		t.Fatal(err)
	}
	producer := BackupOperationProducer{Store: runtime}
	record, sequence, err := producer.allocatePrepareWithMaterial(ctx, epoch,
		packet.DatabaseID, packet.PartitionID, placementSequence, roster,
		time.Now().UTC(), receipt, manifest, signer, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	ownerClient := backupProcessClient(t, *owner)
	cut, err := ownerClient.BackupPrepare(ctx, record.PrepareEnvelope)
	if err != nil {
		t.Fatal("Go process-bound owner Prepare failed:", err)
	}
	var ownerLeafDER []byte
	if _, err := verifyCutWithBundleLeaf(record, owner.MemberID, cut, receipt, bundle,
		&ownerLeafDER); err != nil {
		t.Fatal("Rust owner Cut failed Go leaf verification:", err)
	}
	heldStatus, err := ownerClient.BackupOperationStatus(ctx, record.OperationID)
	if err != nil || heldStatus.State != "pending" || heldStatus.Nonce != record.Nonce ||
		heldStatus.Ordinal != record.Ordinal || heldStatus.Attempt != record.Attempt ||
		heldStatus.BackupSet != record.BackupSet ||
		heldStatus.SourceScopeDigest != record.SourceScopeDigest ||
		heldStatus.SourceAuthoritySHA256 != record.SourceAuthoritySHA256 ||
		heldStatus.SourceTargetDigest != record.SourceTargetDigest ||
		heldStatus.BackupTargetDigest != record.BackupTargetDigest {
		t.Fatal("Rust owner hold status differs from R3 record:", heldStatus, err)
	}
	for index := range record.Roster {
		if record.Roster[index].MemberID == owner.MemberID {
			record.Roster[index].CutEnvelope = bytes.Clone(cut)
			record.Roster[index].CutLeafDER = ownerLeafDER
		}
	}
	sequence, err = runtime.CommitBackupOperation(ctx, epoch, packet.DatabaseID,
		packet.PartitionID, sequence, record)
	if err != nil {
		t.Fatal(err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	record, sequence, err = producer.beginAbortWithMaterial(ctx, epoch,
		packet.DatabaseID, packet.PartitionID, time.Now().UTC(), manifest, signer)
	if err != nil {
		t.Fatal(err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	for _, member := range packet.Roster {
		// Rust intentionally receives the peer's Abort before its Prepare.
		if member.MemberID == owner.MemberID {
			continue
		}
		record, sequence = backupProcessAbortMember(t, ctx, runtime, record,
			sequence, member)
	}
	record, sequence = backupProcessAbortMember(t, ctx, runtime, record, sequence, *owner)
	if record.State != "aborted" {
		t.Fatal("R3 did not reach roster-wide aborted state")
	}
	aborted := record
	backupProcessBarrierAttempt(t, ctx, runtime, producer, packet, placementSequence,
		roster, receipt, bundle, manifest, signer)
	prepareSum := sha256.Sum256(aborted.PrepareEnvelope)
	abortSum := sha256.Sum256(aborted.AbortEnvelope)
	result := backupProcessResult{Version: 1, OperationID: aborted.OperationID,
		Nonce: aborted.Nonce, Ordinal: aborted.Ordinal, Attempt: aborted.Attempt,
		PrepareEnvelope: string(aborted.PrepareEnvelope), PrepareSHA256: hex.EncodeToString(prepareSum[:]),
		AbortSHA256: hex.EncodeToString(abortSum[:])}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("create root-only process result:", err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func backupProcessBarrierAttempt(t *testing.T, ctx context.Context, runtime *authority.Runtime,
	producer BackupOperationProducer, packet backupProcessPacket, placementSequence uint64,
	roster []authority.BackupOperationMember, receipt PreparationReceipt, bundle InitialBundle,
	manifest BackupManifestPayload, signer ed25519.PrivateKey,
) {
	t.Helper()
	epoch := runtime.Current().Epoch
	record, sequence, err := producer.allocatePrepareWithMaterial(ctx, epoch,
		packet.DatabaseID, packet.PartitionID, placementSequence, roster,
		time.Now().UTC(), receipt, manifest, signer, func(context.Context) error { return nil })
	if err != nil || record.Attempt != 2 || record.Ordinal != 1 {
		t.Fatalf("R3 did not allocate the next attempt after Abort: %+v, %v", record, err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	var cutAt uint64
	barrierRoster := make([]backupBarrierMember, len(record.Roster))
	for index, member := range packet.Roster {
		client := backupProcessClient(t, member)
		cutEnvelope, err := client.BackupPrepare(ctx, record.PrepareEnvelope)
		if err != nil {
			t.Fatalf("member %s did not accept next Prepare: %v", member.MemberID, err)
		}
		var leafDER []byte
		cut, err := verifyCutWithBundleLeaf(record, member.MemberID, cutEnvelope,
			receipt, bundle, &leafDER)
		if err != nil || len(leafDER) == 0 || len(leafDER) > 4096 {
			t.Fatalf("member %s Cut or pinned DER is invalid: %v", member.MemberID, err)
		}
		record.Roster[index].CutEnvelope = bytes.Clone(cutEnvelope)
		record.Roster[index].CutLeafDER = leafDER
		barrierRoster[index] = backupBarrierMember{cut.Origin, cut.MemberID, cut.Incarnation,
			cut.RootSHA256, cut.RootGeneration, cut.NativeCommitSeq,
			cut.AppliedSequence, cut.DurableSequence}
		cutAt = max(cutAt, cut.HeldAtMS)
	}
	record.State = "held"
	sequence, err = runtime.CommitBackupOperation(ctx, epoch, record.DatabaseID,
		record.PartitionID, sequence, record)
	if err != nil {
		t.Fatalf("R3 did not commit both exact Cut+DER rows: %v", err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	expires, err := backupCompleteExpiry(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	barrier, err := signBackupOperation(backupBarrierDomain, backupBarrierWire{
		backupBinding: bindingFor(record), SourceCutAtMS: cutAt,
		ExpiresAtMS: expires, SignerKeyID: manifest.SignerKeyID,
		Roster: barrierRoster}, signer)
	if err != nil || len(barrier) > 8<<10 {
		t.Fatalf("sign bounded R3 Barrier: %v", err)
	}
	record.BarrierEnvelope = barrier
	record.State = "barrier"
	sequence, err = runtime.CommitBackupOperation(ctx, epoch, record.DatabaseID,
		record.PartitionID, sequence, record)
	if err != nil {
		t.Fatalf("R3 did not commit exact Barrier before relay: %v", err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	barrierSHA := backupSHA(barrier)
	for _, target := range packet.Roster {
		client := backupProcessClient(t, target)
		for _, source := range record.Roster {
			if source.MemberID == target.MemberID {
				continue
			}
			if err := client.BackupCutProof(ctx, source.CutEnvelope, source.CutLeafDER); err != nil {
				t.Fatalf("member %s rejected peer %s committed Cut+DER: %v",
					target.MemberID, source.MemberID, err)
			}
		}
		ack, err := client.BackupBarrier(ctx, record.BarrierEnvelope)
		if err != nil || ack != barrierSHA {
			t.Fatalf("member %s did not durably acknowledge R3 Barrier: %s, %v",
				target.MemberID, ack, err)
		}
		status, err := client.BackupOperationStatus(ctx, record.OperationID)
		if err != nil || status.State != "pending" || status.BarrierSHA256 != barrierSHA ||
			status.HeadGeneration != 0 || status.OperationID != record.OperationID ||
			status.Nonce != record.Nonce || status.Ordinal != record.Ordinal ||
			status.Attempt != record.Attempt {
			t.Fatalf("member %s post-Barrier status differs from R3: %+v, %v",
				target.MemberID, status, err)
		}
		record, sequence, err = producer.AcknowledgeBarrier(ctx, epoch, record, sequence,
			target.MemberID, ack)
		if err != nil {
			t.Fatalf("R3 did not commit member %s Barrier ack: %v", target.MemberID, err)
		}
		assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	}
	record, sequence, err = producer.beginAbortWithMaterial(ctx, epoch,
		record.DatabaseID, record.PartitionID, time.Now().UTC(), manifest, signer)
	if err != nil {
		t.Fatalf("pre-publication Abort after Barrier was not committed: %v", err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	for _, member := range packet.Roster {
		record, sequence = backupProcessAbortMember(t, ctx, runtime, record, sequence, member)
	}
	if record.State != "aborted" {
		t.Fatal("Barrier attempt did not finish roster-wide Abort cleanup")
	}
	t.Logf("process-bound R3 Barrier attempt %s had two durable acknowledgments at %s",
		record.OperationID, barrierSHA)
}

func backupProcessAbortMember(t *testing.T, ctx context.Context, runtime *authority.Runtime,
	record authority.BackupOperationRecord, sequence uint64, member backupProcessMember,
) (authority.BackupOperationRecord, uint64) {
	t.Helper()
	client := backupProcessClient(t, member)
	if err := client.BackupAbort(ctx, record.AbortEnvelope); err != nil {
		t.Fatal("Go process-bound Abort failed:", err)
	}
	status, err := client.BackupOperationStatus(ctx, record.OperationID)
	if err != nil || status.State != "failed" || status.ErrorCode != "aborted" ||
		status.Ordinal != record.Ordinal || status.Attempt != record.Attempt ||
		status.Nonce != record.Nonce || status.BackupSet != record.BackupSet ||
		status.SourceScopeDigest != record.SourceScopeDigest ||
		status.SourceAuthoritySHA256 != record.SourceAuthoritySHA256 ||
		status.SourceTargetDigest != record.SourceTargetDigest ||
		status.BackupTargetDigest != record.BackupTargetDigest {
		t.Fatal("Rust Abort status differs from R3 record:", status, err)
	}
	for index := range record.Roster {
		if record.Roster[index].MemberID == member.MemberID {
			record.Roster[index].AbortAcknowledged = true
		}
	}
	if !slices.ContainsFunc(record.Roster, func(row authority.BackupOperationMember) bool {
		return !row.AbortAcknowledged
	}) {
		record.State = "aborted"
	}
	committed, err := runtime.CommitBackupOperation(ctx, runtime.Current().Epoch,
		record.DatabaseID, record.PartitionID, sequence, record)
	if err != nil {
		t.Fatal(err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, committed)
	return record, committed
}

func assertBackupProcessReadback(t *testing.T, ctx context.Context, runtime *authority.Runtime,
	record authority.BackupOperationRecord, sequence uint64,
) {
	t.Helper()
	read, observed, err := runtime.ReadBackupOperation(ctx, record.DatabaseID, record.PartitionID)
	want, wantErr := json.Marshal(record)
	actual, actualErr := json.Marshal(read)
	if err != nil || wantErr != nil || actualErr != nil || observed != sequence ||
		!bytes.Equal(want, actual) {
		t.Fatalf("R3 exact operation readback failed: sequence=%d/%d error=%v", observed, sequence, err)
	}
}

func backupProcessClient(t *testing.T, member backupProcessMember) *memberstatus.Client {
	t.Helper()
	observe := func(ctx context.Context) (memberstatus.ProcessObservation, error) {
		if err := ctx.Err(); err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		path := filepath.Join("/proc", strconv.Itoa(member.PID))
		info, err := os.Stat(path)
		if err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != member.UID || stat.Gid != member.GID {
			return memberstatus.ProcessObservation{}, errors.New("Rust member process owner changed")
		}
		statBytes, err := os.ReadFile(filepath.Join(path, "stat"))
		if err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		closeName := bytes.LastIndexByte(statBytes, ')')
		if closeName < 0 {
			return memberstatus.ProcessObservation{}, errors.New("Rust member process stat is invalid")
		}
		fields := strings.Fields(string(statBytes[closeName+1:]))
		if len(fields) <= 19 || fields[19] != member.KernelStart {
			return memberstatus.ProcessObservation{}, errors.New("Rust member process start changed")
		}
		cgroup, err := os.ReadFile(filepath.Join(path, "cgroup"))
		if err != nil || strings.TrimSpace(string(cgroup)) != member.Cgroup {
			return memberstatus.ProcessObservation{}, errors.New("Rust member process cgroup changed")
		}
		return memberstatus.ProcessObservation{PID: member.PID, UID: member.UID,
			GID: member.GID, KernelStart: member.KernelStart, Cgroup: member.Cgroup}, nil
	}
	client, err := memberstatus.NewClient(member.SocketPath, member.Scope, member.Authority, observe)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(t.Context())
	if err != nil || status.Process.PID != member.PID || status.Scope != member.Scope ||
		status.Authority != member.Authority {
		t.Fatal("Rust member status differs from process packet:", err)
	}
	return client
}

func backupProcessJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1,
		JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js
}
