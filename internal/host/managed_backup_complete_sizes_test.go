//go:build linux

package host

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func backupHostRequestFrame(t *testing.T, key ed25519.PrivateKey, operation, node string,
	payload any,
) (request, []byte) {
	t.Helper()
	const sessionID = "014D2PF2DBSQQG28T5CY4TQKFF"
	agent := &Agent{cfg: AgentConfig{Cell: "gru", Node: node,
		NATSUserPublicKey: testNATSUserKey(node), Identity: key},
		processID: sessionID, session: session{Epoch: 1}}
	req, err := agent.makeRequest(operation, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRequest(req, key.Public().(ed25519.PublicKey), "gru", time.Now().UTC()); err != nil {
		t.Fatalf("verify signed host request: %v", err)
	}
	wire, err := protocol.EncodeJSON(req.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	return req, wire
}

func backupControllerResponseFrame(t *testing.T, req request, payload any,
	controllerKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	payloadWire, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	responseWire, err := protocol.EncodeJSON(response{
		Nonce: req.Nonce, Node: req.Node, SessionID: req.SessionID,
		Epoch: req.Epoch, Operation: req.Operation, Payload: payloadWire,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC()
	signed, err := protocol.SignEnvelope(responseWire, protocol.EnvelopeScope{
		Region: "gru", Kind: "host.response." + req.Operation, Actor: "controller",
		OperationID: req.Nonce, Epoch: req.Epoch,
	}, issued, issued.Add(requestTTL), controllerKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded protocol.Envelope
	if err := protocol.DecodeStrict(wire, &decoded, 64<<10); err != nil {
		t.Fatalf("decode signed host response frame: %v", err)
	}
	if err := protocol.VerifyEnvelope(decoded, protocol.EnvelopeScope{
		Region: "gru", Kind: "host.response." + req.Operation, Actor: "controller",
		OperationID: req.Nonce, Epoch: req.Epoch,
	}, controllerKey.Public().(ed25519.PublicKey), time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: requestTTL, ClockSkew: maxClockSkew,
	}); err != nil {
		t.Fatalf("verify signed host response frame: %v", err)
	}
	return wire
}

func backupSizeCommand(envelope []byte, kind string) ManagedBackupCommand {
	leafSHA := "e28d33b97bf0f79144c0d7b5e90bdbb94cc0e98fb7c3305e93557a7d43e186bb"
	sum := sha256.Sum256(envelope)
	return ManagedBackupCommand{
		OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ",
		DatabaseID:  "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8",
		MemberID: "1K6CSK6CSK6CSK6CSK6CSK6CSK", Node: "host-a", Role: "terrabase",
		Kind: kind, Epoch: 1, DesiredGeneration: 1,
		DesiredDigest: strings.Repeat("a", 64),
		Member: ManagedMemberBinding{HostAttempt: 1, Scope: MemberScope{
			ClusterID: "0H248H248H248H248H248H248H", TenantID: "1248H248H248H248H248H248H2",
			DatabaseID: "0000000000WVSMBJNMAWCDJBSK", ShardID: 1,
			MemberID:    "1K6CSK6CSK6CSK6CSK6CSK6CSK",
			Incarnation: "2NANANANANANANANANANANANAN",
		}},
		Authority: MemberAuthority{Epoch: 1, ConfigurationID: strings.Repeat("c", 64),
			CertificateSHA256: strings.Repeat("d", 64), TLSLeafSHA256: leafSHA},
		OCI: ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1..host-a",
			Owner: "terrascale", FleetGeneration: 1, CreateKey: "0000000000R58Y74PAABAQ7X2V"},
		ExpectedProcess: memberstatus.Process{PID: 1234, StartNonce: "00000000009DM5HATADQN00NBQ"},
		Envelope:        bytes.Clone(envelope), EnvelopeSHA256: hex.EncodeToString(sum[:]),
	}
}

func backupSizeSignedEnvelopeAtMost(t *testing.T, limit int, signer ed25519.PrivateKey) []byte {
	t.Helper()
	type envelope struct {
		Version   uint64 `json:"version"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	for payloadSize := 3 * limit / 4; payloadSize >= 0; payloadSize-- {
		payload := bytes.Repeat([]byte("p"), payloadSize)
		preimage := append([]byte("TB-SIZE-ONLY\x00"), payload...)
		wire, err := jsonv2.Marshal(envelope{Version: 1,
			Payload:   base64.RawURLEncoding.EncodeToString(payload),
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, preimage))})
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) <= limit {
			return wire
		}
	}
	t.Fatalf("could not construct signed-envelope-shaped size model at %d bytes", limit)
	return nil
}

func maximalCompleteStatus(receipt []byte, memberCount int) memberstatus.BackupOperationStatus {
	const maxUint = ^uint64(0)
	status := memberstatus.BackupOperationStatus{
		Version: 1, OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ",
		Nonce: strings.Repeat("9", 32), State: "complete", BackupSet: strings.Repeat("a", 32),
		Ordinal: maxUint - 1, Attempt: maxUint,
		SourceScopeDigest: strings.Repeat("b", 64), SourceAuthoritySHA256: strings.Repeat("c", 64),
		SourceTargetDigest: strings.Repeat("d", 64), BackupTargetDigest: strings.Repeat("e", 64),
		SourceCutAtMS: maxUint, CompletedAtMS: maxUint,
		PointSHA256: strings.Repeat("f", 64), ClosureSHA256: strings.Repeat("1", 64),
		CatalogHeadSHA256: strings.Repeat("2", 64), HeadGeneration: maxUint - 1,
		ErrorCode: "", BarrierSHA256: strings.Repeat("3", 64),
		PublishedHeadReceipt: string(receipt),
	}
	status.SelectedFrontier = make([]memberstatus.BackupFrontierRow, memberCount)
	for index := range status.SelectedFrontier {
		status.SelectedFrontier[index] = memberstatus.BackupFrontierRow{
			Origin:          fmt.Sprintf("%032x", index+1) + strings.Repeat("a1", 16),
			AppliedSequence: maxUint,
		}
	}
	return status
}

func TestBackupCompleteGoldenReleaseFitsHostRelayAndSerializedRecords(t *testing.T) {
	data, err := os.ReadFile("../../testdata/backup-complete-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Candidate struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"candidate"`
		PublishedHead struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"published_head"`
		CompleteRelease struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"complete_release"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.PublishedHead.EnvelopeJSON == "" || fixture.CompleteRelease.EnvelopeJSON == "" {
		t.Fatal("Complete fixture lacks its signed receipt or Release")
	}

	const (
		operationID = "3QEXVQEXVQEXVQEXVQEXVQEXVQ"
		memberID    = "1K6CSK6CSK6CSK6CSK6CSK6CSK"
		incarnation = "2NANANANANANANANANANANANAN"
		leafSHA     = "e28d33b97bf0f79144c0d7b5e90bdbb94cc0e98fb7c3305e93557a7d43e186bb"
	)
	release := []byte(fixture.CompleteRelease.EnvelopeJSON)
	receipt := []byte(fixture.PublishedHead.EnvelopeJSON)
	candidate := []byte(fixture.Candidate.EnvelopeJSON)
	record := authority.BackupOperationRecord{
		DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8", OperationID: operationID,
		State: "releasing", CompleteRelease: release, PublicationReceipt: receipt,
		Roster: []authority.BackupOperationMember{{MemberID: memberID, Incarnation: incarnation,
			TLSLeafSHA256: leafSHA, Node: "host-a", Role: "terrabase"}},
	}
	command := backupSizeCommand(release, "complete")
	for _, kind := range []string{"complete", "complete-status"} {
		t.Run(kind, func(t *testing.T) {
			command.Kind = kind
			got, err := backupRelayEnvelope(record, memberID, kind, "")
			if err != nil || !bytes.Equal(got, release) || !command.matchesRecord(record) {
				t.Fatalf("host did not relay the exact committed Complete Release: %v", err)
			}
		})
	}

	command.Kind = "complete"
	commandWire, err := json.Marshal(command)
	if err != nil || len(commandWire) > 64<<10 {
		t.Fatalf("golden Complete command exceeds 64 KiB host record: %d bytes, %v", len(commandWire), err)
	}
	replyWire, err := json.Marshal(managedBackupReply{Command: &command, Pending: true})
	if err != nil || len(replyWire) > 64<<10 {
		t.Fatalf("golden Complete relay reply exceeds 64 KiB: %d bytes, %v", len(replyWire), err)
	}
	status := memberstatus.BackupOperationStatus{
		Version: 1, OperationID: operationID, Nonce: strings.Repeat("9", 32),
		State: "complete", BackupSet: strings.Repeat("a", 32), Ordinal: 1, Attempt: 1,
		SourceScopeDigest: strings.Repeat("1", 64), SourceAuthoritySHA256: strings.Repeat("2", 64),
		SourceTargetDigest: strings.Repeat("3", 64), BackupTargetDigest: strings.Repeat("4", 64),
		SourceCutAtMS: 1, CompletedAtMS: 2, PointSHA256: strings.Repeat("5", 64),
		ClosureSHA256: strings.Repeat("6", 64), CatalogHeadSHA256: strings.Repeat("7", 64),
		HeadGeneration: 1, SelectedFrontier: []memberstatus.BackupFrontierRow{
			{Origin: strings.Repeat("8", 64), AppliedSequence: 10},
			{Origin: strings.Repeat("9", 64), AppliedSequence: 10},
		}, ErrorCode: "", BarrierSHA256: strings.Repeat("a", 64),
		CandidateEnvelope: string(candidate), PublishedHeadReceipt: string(receipt),
	}
	result := ManagedBackupResult{Command: command, Status: status}
	resultWire, err := json.Marshal(result)
	if err != nil || len(resultWire) > 64<<10 {
		t.Fatalf("golden Complete result exceeds 64 KiB host record: %d bytes, %v", len(resultWire), err)
	}
	t.Logf("golden Complete Release=%d B command=%d B reply=%d B result=%d B (64 KiB caps)",
		len(release), len(commandWire), len(replyWire), len(resultWire))
	hostKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	controllerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	commandRequest, commandRequestWire := backupHostRequestFrame(t, hostKey,
		"backup-command", command.Node, managedBackupQuery{Role: command.Role})
	commandReplyWire := backupControllerResponseFrame(t, commandRequest,
		managedBackupReply{Command: &command, Pending: true}, controllerKey)
	resultRequest, resultRequestWire := backupHostRequestFrame(t, hostKey,
		"backup-result", command.Node, result)
	resultReplyWire := backupControllerResponseFrame(t, resultRequest, result, controllerKey)
	for name, wire := range map[string][]byte{
		"signed command request": commandRequestWire, "signed command reply": commandReplyWire,
		"signed result request": resultRequestWire, "signed result reply": resultReplyWire,
	} {
		if len(wire) > 64<<10 {
			t.Fatalf("golden %s exceeds 64 KiB: %d bytes", name, len(wire))
		}
	}

	wrongMember := command
	wrongMember.MemberID = "248H248H248H248H248H248H24"
	if wrongMember.matchesRecord(record) {
		t.Fatal("Complete relay matched a member outside the committed roster")
	}
	wrongKind := command
	wrongKind.Kind = "publish"
	if wrongKind.matchesRecord(record) {
		t.Fatal("Complete Release was authorized as a publish command")
	}

	oversizedRecord := record
	oversizedRecord.CompleteRelease = bytes.Repeat([]byte("x"), maxBackupCompleteRelayBytes+1)
	oversized := command
	oversized.Envelope = bytes.Clone(oversizedRecord.CompleteRelease)
	oversizedSum := sha256.Sum256(oversized.Envelope)
	oversized.EnvelopeSHA256 = hex.EncodeToString(oversizedSum[:])
	if oversized.matchesRecord(oversizedRecord) {
		t.Fatal("Complete relay above the 30 KiB cap was accepted")
	}
}

func TestBackupCompleteConservativeMaxSignedHostFramesFit64KiB(t *testing.T) {
	// Outer host frames use production Agent and Controller serializers and
	// signatures. Inner proof bytes are signed-envelope-shaped size models,
	// not valid BackupCut, publication receipt, or Complete Release proofs.
	const maxUint = ^uint64(0)
	hostKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	controllerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	completeEnvelope := backupSizeSignedEnvelopeAtMost(t, maxBackupCompleteRelayBytes, hostKey)
	receiptEnvelope := backupSizeSignedEnvelopeAtMost(t, 18<<10, hostKey)
	command := backupSizeCommand(completeEnvelope, "complete")
	command.DatabaseID, command.PartitionID = strings.Repeat("d", 63), strings.Repeat("p", 63)
	command.Node, command.Role = strings.Repeat("n", 63), strings.Repeat("r", 63)
	command.Epoch, command.DesiredGeneration = maxUint, maxUint
	command.DesiredDigest = strings.Repeat("a", 64)
	command.Member = ManagedMemberBinding{HostAttempt: maxUint, Scope: MemberScope{
		ClusterID: "0H248H248H248H248H248H248H", TenantID: "1248H248H248H248H248H248H2",
		DatabaseID: "1K6CSK6CSK6CSK6CSK6CSK6CSK", ShardID: maxUint,
		MemberID: command.MemberID, Incarnation: "2NANANANANANANANANANANANAN",
	}}
	command.Authority = MemberAuthority{Epoch: maxUint, ConfigurationID: strings.Repeat("c", 64),
		CertificateSHA256: strings.Repeat("d", 64), TLSLeafSHA256: strings.Repeat("e", 64)}
	command.OCI = ManagedOCIBinding{Region: "GRU",
		InstanceID: "ocid1.instance." + strings.Repeat("x", 240),
		Owner:      strings.Repeat("o", 63), FleetGeneration: maxUint, CreateKey: strings.Repeat("k", 128)}
	command.ExpectedProcess = memberstatus.Process{PID: int(^uint(0) >> 1), StartNonce: "00000000002NNZ5G4S3F5MYJ7J"}
	completeSum := sha256.Sum256(completeEnvelope)
	command.EnvelopeSHA256 = hex.EncodeToString(completeSum[:])
	commandRecord := authority.BackupOperationRecord{
		DatabaseID: command.DatabaseID, PartitionID: command.PartitionID,
		OperationID: command.OperationID, State: "releasing",
		CompleteRelease: completeEnvelope, PublicationReceipt: receiptEnvelope,
		Roster: []authority.BackupOperationMember{{MemberID: command.MemberID,
			Incarnation:   command.Member.Scope.Incarnation,
			TLSLeafSHA256: command.Authority.TLSLeafSHA256,
			Node:          command.Node, Role: command.Role}},
	}
	if !command.matchesRecord(commandRecord) {
		t.Fatal("maximum Complete command did not match its committed relay record")
	}

	commandKV, err := json.Marshal(command)
	if err != nil || len(commandKV) > 64<<10 {
		t.Fatalf("maximum Complete command exceeds 64 KiB host KV: %d bytes, %v", len(commandKV), err)
	}
	commandRequest, commandRequestWire := backupHostRequestFrame(t, hostKey,
		"backup-command", command.Node, managedBackupQuery{Role: command.Role})
	commandReplyWire := backupControllerResponseFrame(t, commandRequest,
		managedBackupReply{Command: &command, Pending: true}, controllerKey)

	result := ManagedBackupResult{Command: command, Status: maximalCompleteStatus(receiptEnvelope, 8)}
	resultKV, err := json.Marshal(result)
	if err != nil || len(resultKV) > 64<<10 {
		t.Fatalf("maximum Complete result exceeds 64 KiB host KV: %d bytes, %v", len(resultKV), err)
	}
	resultRequest, resultRequestWire := backupHostRequestFrame(t, hostKey,
		"backup-result", command.Node, result)
	resultReplyWire := backupControllerResponseFrame(t, resultRequest, result, controllerKey)
	for name, wire := range map[string][]byte{
		"signed command request": commandRequestWire, "signed command reply": commandReplyWire,
		"signed result request": resultRequestWire, "signed result reply": resultReplyWire,
	} {
		if len(wire) > 64<<10 {
			t.Fatalf("maximum Complete %s exceeds 64 KiB: %d bytes", name, len(wire))
		}
	}

	// CutProof is the other host relay that carries the admitted 4 KiB DER.
	// Its signed Cut model uses the accepted 1,753 B size assumption.
	cut := backupSizeSignedEnvelopeAtMost(t, 1753, hostKey)
	der := bytes.Repeat([]byte("d"), 4096)
	leafDERHash := sha256.Sum256(der)
	cutRecord := authority.BackupOperationRecord{OperationID: command.OperationID,
		DatabaseID: command.DatabaseID, PartitionID: command.PartitionID, State: "barrier",
		Roster: []authority.BackupOperationMember{
			{MemberID: command.MemberID, Incarnation: command.Member.Scope.Incarnation,
				TLSLeafSHA256: command.Authority.TLSLeafSHA256, Node: command.Node, Role: command.Role},
			{MemberID: "248H248H248H248H248H248H24",
				Incarnation: "36CSK6CSK6CSK6CSK6CSK6CSK6", TLSLeafSHA256: hex.EncodeToString(leafDERHash[:]),
				Node: strings.Repeat("m", 63), Role: strings.Repeat("s", 63),
				CutEnvelope: cut, CutLeafDER: der},
		},
	}
	proof, err := backupRelayEnvelope(cutRecord, command.MemberID, "cut-proof",
		cutRecord.Roster[1].MemberID)
	if err != nil || len(proof) > maxBackupRelayBytes {
		t.Fatalf("4 KiB DER CutProof exceeds 8 KiB relay: %d bytes, %v", len(proof), err)
	}
	proofCommand := backupSizeCommand(proof, "cut-proof")
	proofCommand.DatabaseID, proofCommand.PartitionID = command.DatabaseID, command.PartitionID
	proofCommand.Node, proofCommand.Role = command.Node, command.Role
	proofCommand.Member = command.Member
	proofCommand.Authority = command.Authority
	proofCommand.OCI, proofCommand.ExpectedProcess = command.OCI, command.ExpectedProcess
	proofCommand.Epoch, proofCommand.DesiredGeneration = command.Epoch, command.DesiredGeneration
	proofCommand.DesiredDigest = command.DesiredDigest
	proofRecord := ManagedBackupResult{Command: proofCommand, Status: maximalCompleteStatus(nil, 8)}
	proofRecord.Status.State = "pending"
	proofRecord.Status.PublishedHeadReceipt = ""
	proofRequest, proofRequestWire := backupHostRequestFrame(t, hostKey,
		"backup-result", proofCommand.Node, proofRecord)
	proofReplyWire := backupControllerResponseFrame(t, proofRequest, proofRecord, controllerKey)
	if len(proofRequestWire) > 64<<10 || len(proofReplyWire) > 64<<10 {
		t.Fatalf("4 KiB DER CutProof signed frames exceed 64 KiB: request=%d reply=%d",
			len(proofRequestWire), len(proofReplyWire))
	}
	t.Logf("max size model: release=%d receipt=%d commandKV=%d resultKV=%d commandReply=%d resultRequest=%d resultReply=%d CutProof=%d DER=%d proofRequest=%d proofReply=%d B",
		len(completeEnvelope), len(receiptEnvelope), len(commandKV), len(resultKV),
		len(commandReplyWire), len(resultRequestWire), len(resultReplyWire), len(proof), len(der),
		len(proofRequestWire), len(proofReplyWire))
}

func TestBackupCompleteAuthorityRecordFitsOneMiBSizeOnlyBound(t *testing.T) {
	// This conservative serializer bound uses the admitted field and roster
	// limits. The repeated proof bytes are placeholders, not signed R3 proofs.
	const maxUint = ^uint64(0)
	der := bytes.Repeat([]byte("d"), 4096)
	leafSum := sha256.Sum256(der)
	leafSHA := hex.EncodeToString(leafSum[:])
	record := authority.BackupOperationRecord{
		Version: 1, DatabaseID: strings.Repeat("d", 63), PartitionID: strings.Repeat("p", 63),
		PlacementSequence: maxUint,
		SourceScopeDigest: strings.Repeat("a", 64), SourceAuthoritySHA256: strings.Repeat("b", 64),
		SourceConfigurationID: strings.Repeat("c", 64), SourceTargetDigest: strings.Repeat("d", 64),
		BackupSet: strings.Repeat("e", 32), BackupTargetDigest: strings.Repeat("f", 64),
		OwnerMemberID: "1K6CSK6CSK6CSK6CSK6CSK6CSK", OwnerIncarnation: strings.Repeat("5", 32),
		CompletedOrdinal: maxUint - 1, AttemptHighWater: maxUint, Ordinal: maxUint - 1, Attempt: maxUint,
		OperationID: "3QEXVQEXVQEXVQEXVQEXVQEXVQ", Nonce: strings.Repeat("9", 32),
		PrepareEnvelope:            bytes.Repeat([]byte("p"), 64<<10),
		PrepareExpiresAtMS:         uint64((1 << 63) - 1 - 30_000),
		BarrierEnvelope:            bytes.Repeat([]byte("b"), 8<<10),
		CandidateEnvelope:          bytes.Repeat([]byte("c"), 8<<10),
		CompletionEnvelope:         bytes.Repeat([]byte("m"), 8<<10),
		PublicationReceipt:         bytes.Repeat([]byte("r"), 18<<10),
		CompleteRelease:            bytes.Repeat([]byte("l"), 30<<10),
		CompleteReleaseExpiresAtMS: uint64((1 << 63) - 1 - 30_000),
		HeadGeneration:             maxUint - 1, State: "complete",
		Roster:   make([]authority.BackupOperationMember, 8),
		Terminal: make([]authority.BackupTerminalReceipt, 1024),
	}
	for index := range record.Roster {
		memberID := fmt.Sprintf("33333333-3333-3333-3333-%012x", index+1)
		memberOrigin := strings.ReplaceAll(memberID, "-", "") + strings.Repeat("5", 32)
		record.Roster[index] = authority.BackupOperationMember{
			Origin: memberOrigin, MemberID: memberID,
			Incarnation: "2NANANANANANANANANANANANAN", TLSLeafSHA256: leafSHA,
			Node: strings.Repeat("n", 61) + fmt.Sprintf("%02d", index), Role: strings.Repeat("r", 63),
			CutEnvelope: bytes.Repeat([]byte("x"), 8<<10), CutLeafDER: bytes.Clone(der),
			BarrierAcknowledged: true, CompleteAcknowledged: true,
		}
	}
	record.OwnerMemberID = record.Roster[0].MemberID
	record.OwnerIncarnation = record.Roster[0].Incarnation
	for index := range record.Terminal {
		record.Terminal[index] = authority.BackupTerminalReceipt{
			OperationID: fmt.Sprintf("88888888-8888-8888-8888-%012x", index+1),
			Ordinal:     maxUint, Attempt: maxUint, State: "complete",
		}
	}
	wire, err := jsonv2.Marshal(record)
	if err != nil || len(wire) > 1<<20 {
		t.Fatalf("conservative Complete R3 payload exceeds 1 MiB: %d bytes, %v", len(wire), err)
	}
	t.Logf("size-only maximal Complete authority record=%d B (1 MiB cap)", len(wire))
}
