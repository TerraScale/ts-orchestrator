//go:build linux

package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
)

type backupCompleteProcessResult struct {
	Version            uint64 `json:"version"`
	OperationID        string `json:"operation_id"`
	Nonce              string `json:"nonce"`
	Ordinal            uint64 `json:"ordinal"`
	Attempt            uint64 `json:"attempt"`
	CandidateEnvelope  string `json:"candidate_envelope"`
	CompletionEnvelope string `json:"completion_envelope"`
}

// TestBackupGoRustCompleteProcessBridge stops at the durable publishing
// transition. The Rust parent test owns the Completion POST, lost response,
// restart and receipt replay. This bridge verifies live owner-signed Candidate
// bytes with the production wire and frontier validators. It does not exercise
// the producer methods that require a Go PreparationService CurrentBundle.
func TestBackupGoRustCompleteProcessBridge(t *testing.T) {
	runBackupGoRustCompleteProcessBridge(t, false)
}

// TestBackupGoRustFullProducerProcessBridge uses an authenticated, versioned
// Go material object and R3 preparation receipt before the live Rust caller.
// The separate full-material packet leaves the accepted direct bridge packet
// and its test selector unchanged.
func TestBackupGoRustFullProducerProcessBridge(t *testing.T) {
	tier.Qualification(t, "TS_D10_FULL_MATERIAL_PACKET")
	runBackupGoRustCompleteProcessBridge(t, true)
}

func runBackupGoRustCompleteProcessBridge(t *testing.T, fullProducer bool) {
	t.Helper()
	packetPath := tier.Qualification(t, "TS_D10_PROCESS_PACKET")[0]
	resultPath := os.Getenv("TS_D10_PROCESS_RESULT")
	if resultPath == "" {
		t.Fatal("Rust live-process result path was not supplied")
	}
	packet, signer, manifest, receipt, bundle, roster, owner :=
		backupCompleteProcessMaterial(t, packetPath)
	js := backupProcessJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: "gru", CandidateID: "0000000000Z5PQQEQKXJAW7SWD", Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	producer := BackupOperationProducer{Store: runtime}
	if fullProducer {
		material := backupFullProcessMaterial(t, ctx, runtime, packet, signer,
			os.Getenv("TS_D10_FULL_MATERIAL_PACKET"))
		producer.Preparation = material.preparation
		receipt, bundle, manifest = material.receipt, material.bundle, material.manifest
	}
	placementSequence, err := runtime.CommitPlacementIntent(ctx, epoch,
		packet.DatabaseID, packet.PartitionID, "d10-complete-placement", 0, []byte("live-rust-members"))
	if err != nil {
		t.Fatal(err)
	}
	var record authority.BackupOperationRecord
	var sequence uint64
	if fullProducer {
		record, sequence, err = producer.AllocatePrepare(ctx, epoch,
			packet.DatabaseID, packet.PartitionID, placementSequence, roster,
			time.Now().UTC(), func(context.Context) error { return nil })
	} else {
		record, sequence, err = producer.allocatePrepareWithMaterial(ctx, epoch,
			packet.DatabaseID, packet.PartitionID, placementSequence, roster,
			time.Now().UTC(), receipt, manifest, signer, func(context.Context) error { return nil })
	}
	if err != nil {
		t.Fatal(err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)

	cuts := make([]BackupCut, len(record.Roster))
	barrierRoster := make([]backupBarrierMember, len(record.Roster))
	var cutAt uint64
	for index, member := range packet.Roster {
		client := backupProcessClient(t, member)
		wire, err := client.BackupPrepare(ctx, record.PrepareEnvelope)
		if err != nil {
			t.Fatalf("member %s Prepare failed: %v", member.MemberID, err)
		}
		var leafDER []byte
		var cut BackupCut
		if fullProducer {
			cut, leafDER, err = producer.VerifyCutWithLeaf(ctx, record, member.MemberID, wire)
		} else {
			cut, err = verifyCutWithBundleLeaf(record, member.MemberID, wire, receipt, bundle, &leafDER)
		}
		if err != nil || len(leafDER) == 0 || len(leafDER) > 4096 {
			t.Fatalf("member %s signed Cut or pinned DER is invalid: %v", member.MemberID, err)
		}
		record.Roster[index].CutEnvelope = bytes.Clone(wire)
		record.Roster[index].CutLeafDER = bytes.Clone(leafDER)
		cuts[index] = cut
		barrierRoster[index] = backupBarrierMember{
			cut.Origin, cut.MemberID, cut.Incarnation, cut.RootSHA256,
			cut.RootGeneration, cut.NativeCommitSeq, cut.AppliedSequence, cut.DurableSequence,
		}
		cutAt = max(cutAt, cut.HeldAtMS)
	}
	record.State = "held"
	sequence, err = runtime.CommitBackupOperation(ctx, epoch,
		record.DatabaseID, record.PartitionID, sequence, record)
	if err != nil {
		t.Fatal("commit exact Cut+DER rows:", err)
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	if fullProducer {
		record, sequence, err = producer.CommitBarrier(ctx, epoch, record, sequence, time.Now().UTC())
		if err != nil {
			t.Fatal("production CommitBarrier rejected exact live Cuts:", err)
		}
	} else {
		expires, err := backupCompleteExpiry(time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		barrier, signErr := signBackupOperation(backupBarrierDomain, backupBarrierWire{
			backupBinding: bindingFor(record), SourceCutAtMS: cutAt,
			ExpiresAtMS: expires, SignerKeyID: manifest.SignerKeyID, Roster: barrierRoster,
		}, signer)
		if signErr != nil || len(barrier) > 8<<10 {
			t.Fatalf("sign bounded R3 Barrier: %v", signErr)
		}
		record.BarrierEnvelope = barrier
		record.State = "barrier"
		sequence, err = runtime.CommitBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, sequence, record)
		if err != nil {
			t.Fatal("commit exact Barrier before relay:", err)
		}
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	barrier := record.BarrierEnvelope
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
		ack, err := client.BackupBarrier(ctx, barrier)
		if err != nil || ack != barrierSHA {
			t.Fatalf("member %s Barrier acknowledgment differs: %s, %v",
				target.MemberID, ack, err)
		}
		record, sequence, err = producer.AcknowledgeBarrier(ctx, epoch, record, sequence,
			target.MemberID, ack)
		if err != nil {
			t.Fatalf("commit member %s Barrier acknowledgment: %v", target.MemberID, err)
		}
		assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	}
	ownerClient := backupProcessClient(t, owner)
	if ack, err := ownerClient.BackupBarrier(ctx, barrier); err != nil || ack != barrierSHA {
		t.Fatalf("owner Barrier refresh failed: %s, %v", ack, err)
	}
	var candidateWire []byte
	for {
		status, err := ownerClient.BackupOperationStatus(ctx, record.OperationID)
		if err != nil || status.State != "pending" || status.OperationID != record.OperationID ||
			status.Nonce != record.Nonce || status.Ordinal != record.Ordinal ||
			status.Attempt != record.Attempt || status.BarrierSHA256 != barrierSHA {
			t.Fatalf("owner Candidate status differs from committed R3 Barrier: %+v, %v", status, err)
		}
		if status.CandidateEnvelope != "" {
			candidateWire = []byte(status.CandidateEnvelope)
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("owner Candidate was not durable before process deadline:", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	var candidate backupCandidateWire
	if fullProducer {
		candidate, err = producer.VerifyCandidate(ctx, record, candidateWire)
		if err != nil {
			t.Fatal("production VerifyCandidate rejected live owner proof:", err)
		}
		t.Logf("producer stage=VerifyCandidate candidate_sha256=%s", backupSHA(candidateWire))
		record, sequence, err = producer.AcceptCandidate(ctx, epoch, record, sequence, candidateWire)
		if err != nil {
			t.Fatal("production AcceptCandidate rejected live owner proof:", err)
		}
	} else {
		ownerRow, ownerErr := backupOwner(record, manifest)
		if ownerErr != nil {
			t.Fatal(ownerErr)
		}
		ownerPublic, publicErr := backupOwnerPublic(ownerRow)
		if publicErr != nil {
			t.Fatal(publicErr)
		}
		if err := decodeCanonicalBackupSigned(candidateWire, backupCandidateDomain,
			ownerPublic, 8<<10, &candidate); err != nil ||
			!candidateMatches(record, ownerRow, candidate, ownerPublic, cuts) {
			t.Fatalf("live owner Candidate failed signed exact-frontier validation: %v", err)
		}
		record.CandidateEnvelope = bytes.Clone(candidateWire)
		sequence, err = runtime.CommitBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, sequence, record)
		if err != nil {
			t.Fatal("commit exact verified Candidate:", err)
		}
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	if fullProducer {
		t.Logf("producer stage=AcceptCandidate r3_sequence=%d candidate_sha256=%s",
			sequence, backupSHA(record.CandidateEnvelope))
	}
	if fullProducer {
		record, sequence, err = producer.CommitCompletion(ctx, epoch, record, sequence, time.Now().UTC())
		if err != nil {
			t.Fatal("production CommitCompletion rejected accepted Candidate:", err)
		}
	} else {
		expires, expiryErr := backupCompleteExpiry(time.Now().UTC())
		if expiryErr != nil {
			t.Fatal(expiryErr)
		}
		completionWire, signErr := signBackupOperation(backupCompletionDomain, backupCompletionWire{
			backupBinding: bindingFor(record), PointSHA256: candidate.PointSHA256,
			ClosureSHA256:          candidate.ClosureSHA256,
			PreviousHeadSHA256:     candidate.PreviousHeadSHA256,
			ExpectedHeadGeneration: candidate.ExpectedHeadGeneration,
			SelectedFrontier:       slices.Clone(candidate.SelectedFrontier),
			ExpiresAtMS:            expires, SignerKeyID: manifest.SignerKeyID,
		}, signer)
		if signErr != nil || len(completionWire) > 8<<10 {
			t.Fatalf("sign bounded exact Candidate Completion: %v", signErr)
		}
		record.CompletionEnvelope = completionWire
		record.State = "publishing"
		sequence, err = runtime.CommitBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, sequence, record)
		if err != nil {
			t.Fatal("commit Completion before owner delivery:", err)
		}
	}
	assertBackupProcessReadback(t, ctx, runtime, record, sequence)
	if fullProducer {
		t.Logf("producer stage=CommitCompletion r3_sequence=%d completion_sha256=%s",
			sequence, backupSHA(record.CompletionEnvelope))
	}
	completionWire := record.CompletionEnvelope
	result := backupCompleteProcessResult{Version: 1, OperationID: record.OperationID,
		Nonce: record.Nonce, Ordinal: record.Ordinal, Attempt: record.Attempt,
		CandidateEnvelope: string(candidateWire), CompletionEnvelope: string(completionWire)}
	backupCompleteProcessWriteResult(t, resultPath, result)
	t.Logf("R3 committed live owner Candidate %s and Completion %s for %s",
		backupSHA(candidateWire), backupSHA(completionWire), record.OperationID)
	if fullProducer {
		t.Logf("full producer CurrentBundle, VerifyCandidate, AcceptCandidate and CommitCompletion returned successfully at R3 sequence %d", sequence)
	}
}

func backupCompleteProcessMaterial(t *testing.T, path string) (backupProcessPacket,
	ed25519.PrivateKey, BackupManifestPayload, PreparationReceipt, InitialBundle,
	[]authority.BackupOperationMember, backupProcessMember,
) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("Rust private-key packet is not a root-only regular file", err)
	}
	ownerInfo, ok := info.Sys().(*syscall.Stat_t)
	if !ok || ownerInfo.Uid != 0 || ownerInfo.Gid != 0 {
		t.Fatal("Rust private-key packet owner is not root")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 32<<10 {
		t.Fatal("read bounded Rust process packet", err)
	}
	var packet backupProcessPacket
	if err := json.Unmarshal(data, &packet, json.RejectUnknownMembers(true)); err != nil ||
		packet.Version != 1 || len(packet.Roster) != 2 {
		t.Fatal("invalid Rust process packet", err)
	}
	der, err := hex.DecodeString(packet.AuthorityPKCS8Hex)
	if err != nil {
		t.Fatal("invalid authority PKCS#8 encoding", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal("invalid authority PKCS#8 key", err)
	}
	signer, ok := parsed.(ed25519.PrivateKey)
	if !ok || backupKeyID(signer.Public().(ed25519.PublicKey)) != packet.SignerKeyID {
		t.Fatal("Rust process signer differs from pinned public key")
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
	var owner backupProcessMember
	for index, member := range packet.Roster {
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
	if owner.MemberID == "" || !slices.IsSortedFunc(roster,
		func(a, b authority.BackupOperationMember) int { return strings.Compare(a.Origin, b.Origin) }) {
		t.Fatal("Rust process roster is unsorted or lacks owner")
	}
	manifest.OwnerIncarnation = owner.Incarnation
	return packet, signer, manifest, receipt, bundle, roster, owner
}

func backupCompleteProcessWriteResult(t *testing.T, path string, result backupCompleteProcessResult) {
	t.Helper()
	wire, err := json.Marshal(result)
	if err != nil || len(wire) == 0 || len(wire) > 64<<10 {
		t.Fatal("encode bounded complete process result", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("create root-only complete process result", err)
	}
	if _, err := file.Write(wire); err != nil {
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
