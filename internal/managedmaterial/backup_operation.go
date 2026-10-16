package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

const (
	backupPrepareDomain       = "TB-BACKUP-PREPARE-V1\x00"
	backupReleaseDomain       = "TB-BACKUP-RELEASE-V1\x00"
	backupCutDomain           = "TB-BACKUP-CUT-V1\x00"
	backupBarrierDomain       = "TB-BACKUP-BARRIER-V1\x00"
	backupCompletionDomain    = "TB-BACKUP-COMPLETION-V1\x00"
	backupCandidateDomain     = "TB-BACKUP-CANDIDATE-V1\x00"
	backupPublishedHeadDomain = "TB-BACKUP-PUBLISHED-HEAD-V1\x00"
)

type BackupOperationStore interface {
	ReadBackupOperation(context.Context, string, string) (authority.BackupOperationRecord, uint64, error)
	CommitBackupOperation(context.Context, uint64, string, string, uint64, authority.BackupOperationRecord) (uint64, error)
}

type verifiedBackupOperationStore interface {
	CommitBackupOperationVerified(context.Context, uint64, string, string, uint64,
		authority.BackupOperationRecord, func(context.Context) error) (uint64, error)
}

// BackupOperationProducer is the only Go signer for Prepare and Abort. Each
// method returns signed bytes only after their exact R3 record was committed
// and read back. Callers cannot obtain a deliverable envelope on ambiguity.
type BackupOperationProducer struct {
	Preparation PreparationService
	Store       BackupOperationStore
}

type backupRosterWire struct {
	Origin      string `json:"origin"`
	MemberID    string `json:"member_id"`
	Incarnation string `json:"incarnation"`
}

type backupPrepareWire struct {
	Version               uint64             `json:"version"`
	OperationID           string             `json:"operation_id"`
	Nonce                 string             `json:"nonce"`
	SourceScopeDigest     string             `json:"source_scope_digest"`
	SourceAuthoritySHA256 string             `json:"source_authority_sha256"`
	SourceConfigurationID string             `json:"source_configuration_id"`
	SourceTargetDigest    string             `json:"source_target_digest"`
	BackupSet             string             `json:"backup_set"`
	BackupTargetDigest    string             `json:"backup_target_digest"`
	Ordinal               uint64             `json:"ordinal"`
	Attempt               uint64             `json:"attempt"`
	ExpiresAtMS           uint64             `json:"expires_at_ms"`
	SignerKeyID           string             `json:"signer_key_id"`
	Roster                []backupRosterWire `json:"roster"`
}

type backupReleaseWire struct {
	Version                  uint64 `json:"version"`
	OperationID              string `json:"operation_id"`
	Nonce                    string `json:"nonce"`
	SourceScopeDigest        string `json:"source_scope_digest"`
	SourceAuthoritySHA256    string `json:"source_authority_sha256"`
	SourceConfigurationID    string `json:"source_configuration_id"`
	BackupSet                string `json:"backup_set"`
	Ordinal                  uint64 `json:"ordinal"`
	Attempt                  uint64 `json:"attempt"`
	Reason                   string `json:"reason"`
	ExpiresAtMS              uint64 `json:"expires_at_ms"`
	SignerKeyID              string `json:"signer_key_id"`
	PublicationReceiptSHA256 string `json:"publication_receipt_sha256"`
	PublicationReceipt       string `json:"publication_receipt"`
	CompletionEnvelope       string `json:"completion_envelope"`
}

// BackupCut is a member's leaf-signed, locally fsynced hold observation.
type BackupCut struct {
	Version               uint64 `json:"version"`
	OperationID           string `json:"operation_id"`
	Nonce                 string `json:"nonce"`
	SourceScopeDigest     string `json:"source_scope_digest"`
	SourceAuthoritySHA256 string `json:"source_authority_sha256"`
	SourceConfigurationID string `json:"source_configuration_id"`
	SourceTargetDigest    string `json:"source_target_digest"`
	BackupSet             string `json:"backup_set"`
	Ordinal               uint64 `json:"ordinal"`
	Attempt               uint64 `json:"attempt"`
	Origin                string `json:"origin"`
	MemberID              string `json:"member_id"`
	Incarnation           string `json:"incarnation"`
	LeafCertificateSHA256 string `json:"leaf_certificate_sha256"`
	RootSHA256            string `json:"root_sha256"`
	RootGeneration        uint64 `json:"root_generation"`
	NativeCommitSeq       uint64 `json:"native_commit_seq"`
	AppliedSequence       uint64 `json:"applied_sequence"`
	DurableSequence       uint64 `json:"durable_sequence"`
	HeldAtMS              uint64 `json:"held_at_ms"`
	SignerKeyID           string `json:"signer_key_id"`
}

func backupKeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func signBackupOperation(domain string, payload any, signer ed25519.PrivateKey) ([]byte, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("backup authority signer is invalid")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	preimage := append([]byte(domain), body...)
	wire, err := json.Marshal(backupManifestEnvelope{Version: 1,
		Payload:   base64.RawURLEncoding.EncodeToString(body),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, preimage))})
	if err != nil || len(wire) > 64<<10 {
		return nil, errors.New("backup operation envelope exceeds bound")
	}
	return wire, nil
}

func currentBackupSigner(ctx context.Context, service PreparationService, database, partition string,
) (PreparationReceipt, BackupManifestPayload, ed25519.PrivateKey, error) {
	receipt, bundle, err := service.CurrentBundle(ctx, database, partition)
	if err != nil {
		return PreparationReceipt{}, BackupManifestPayload{}, nil, err
	}
	if receipt.Spec.Backup == nil || len(bundle.Retained.AuthoritySigner) != ed25519.PrivateKeySize ||
		!bytes.Equal(bundle.Retained.AuthoritySigner.Public().(ed25519.PublicKey), bundle.Authority.TrustedKey) {
		return PreparationReceipt{}, BackupManifestPayload{}, nil, ErrMaterialConflict
	}
	manifestFile, exists := bundle.Members[0].Files[backupManifestName]
	if !exists || manifestFile.SHA256 != receipt.Members[0].Files[backupManifestName] {
		return PreparationReceipt{}, BackupManifestPayload{}, nil, ErrMaterialConflict
	}
	var envelope backupManifestEnvelope
	if err := json.Unmarshal(manifestFile.Contents, &envelope, json.RejectUnknownMembers(true)); err != nil || envelope.Version != 1 {
		return PreparationReceipt{}, BackupManifestPayload{}, nil, ErrMaterialConflict
	}
	body, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return PreparationReceipt{}, BackupManifestPayload{}, nil, ErrMaterialConflict
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(bundle.Authority.TrustedKey, append([]byte(backupManifestDomain), body...), signature) {
		return PreparationReceipt{}, BackupManifestPayload{}, nil, ErrMaterialConflict
	}
	var manifest BackupManifestPayload
	if err := json.Unmarshal(body, &manifest, json.RejectUnknownMembers(true)); err != nil ||
		manifest.SourceAuthoritySHA256 != receipt.AuthoritySHA256 ||
		manifest.SourceConfigurationID != receipt.AuthorityConfigurationID ||
		manifest.SignerKeyID != backupKeyID(bundle.Authority.TrustedKey) {
		return PreparationReceipt{}, BackupManifestPayload{}, nil, ErrMaterialConflict
	}
	return receipt, manifest, bundle.Retained.AuthoritySigner, nil
}

func validateBackupRoster(receipt PreparationReceipt, members []authority.BackupOperationMember) error {
	if len(members) != 2 {
		return ErrMaterialConflict
	}
	seen := make(map[string]bool, len(members))
	hostRoles := make(map[string]bool, len(members))
	for index, member := range members {
		hostRole := member.Node + "\x00" + member.Role
		if index > 0 && members[index-1].Origin >= member.Origin ||
			seen[member.MemberID] || hostRoles[hostRole] {
			return ErrMaterialConflict
		}
		seen[member.MemberID] = true
		hostRoles[hostRole] = true
		found := false
		for seatIndex, seat := range receipt.Spec.Members {
			if seat.MemberID == member.MemberID && seat.Incarnation == member.Incarnation &&
				receipt.Members[seatIndex].TLSLeafSHA256 == member.TLSLeafSHA256 &&
				member.Origin == authority.BackupMemberOrigin(seat.MemberID, seat.Incarnation) {
				found = true
				break
			}
		}
		if !found || member.Node == "" || member.Role == "" || len(member.CutEnvelope) != 0 ||
			len(member.CutLeafDER) != 0 || member.AbortAcknowledged ||
			member.BarrierAcknowledged || member.CompleteAcknowledged {
			return ErrMaterialConflict
		}
	}
	return nil
}

// AllocatePrepare advances one ordinal only after every prior Complete
// acknowledgment, or advances the attempt after a roster-wide Abort. The
// verifier rechecks the exact serving roster at final R3 CAS.
func (producer BackupOperationProducer) AllocatePrepare(ctx context.Context, epoch uint64,
	database, partition string, placementSequence uint64,
	members []authority.BackupOperationMember, now time.Time,
	verify func(context.Context) error,
) (authority.BackupOperationRecord, uint64, error) {
	if producer.Store == nil || epoch == 0 || placementSequence == 0 || now.IsZero() || verify == nil {
		return authority.BackupOperationRecord{}, 0, errors.New("backup operation producer is incomplete")
	}
	receipt, manifest, signer, err := currentBackupSigner(ctx, producer.Preparation, database, partition)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	return producer.allocatePrepareWithMaterial(ctx, epoch, database, partition,
		placementSequence, members, now, receipt, manifest, signer, verify)
}

// allocatePrepareWithMaterial is the allocation core after CurrentBundle has
// authenticated the pinned receipt and retained signer. It is kept separate
// so the real-process bridge can feed the Rust fixture's exact authenticated
// material pins through the same R3 commit and signing path.
func (producer BackupOperationProducer) allocatePrepareWithMaterial(ctx context.Context, epoch uint64,
	database, partition string, placementSequence uint64,
	members []authority.BackupOperationMember, now time.Time,
	receipt PreparationReceipt, manifest BackupManifestPayload, signer ed25519.PrivateKey,
	verify func(context.Context) error,
) (authority.BackupOperationRecord, uint64, error) {
	if producer.Store == nil || epoch == 0 || placementSequence == 0 || now.IsZero() || verify == nil ||
		len(signer) != ed25519.PrivateKeySize ||
		manifest.SignerKeyID != backupKeyID(signer.Public().(ed25519.PublicKey)) ||
		manifest.SourceAuthoritySHA256 != receipt.AuthoritySHA256 ||
		manifest.SourceConfigurationID != receipt.AuthorityConfigurationID {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	if err := validateBackupRoster(receipt, members); err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	prior, expected, err := producer.Store.ReadBackupOperation(ctx, database, partition)
	if err != nil && !errors.Is(err, authority.ErrNotFound) {
		return authority.BackupOperationRecord{}, 0, err
	}
	if err == nil && (prior.State != "aborted" && prior.State != "complete" ||
		prior.SourceAuthoritySHA256 != manifest.SourceAuthoritySHA256 || prior.BackupSet != manifest.BackupSet ||
		prior.State == "aborted" && prior.AttemptHighWater == math.MaxUint64 ||
		prior.State == "complete" && prior.Ordinal == math.MaxUint64) {
		return authority.BackupOperationRecord{}, 0, authority.ErrInvalidTransition
	}
	attempt := uint64(1)
	ordinal := uint64(1)
	completed := uint64(0)
	var terminal []authority.BackupTerminalReceipt
	if expected != 0 {
		completed = prior.CompletedOrdinal
		if prior.State == "aborted" {
			attempt = prior.AttemptHighWater + 1
			ordinal = prior.Ordinal
		} else {
			ordinal = prior.Ordinal + 1
		}
		terminal = append(slices.Clone(prior.Terminal), authority.BackupTerminalReceipt{
			OperationID: prior.OperationID, Ordinal: prior.Ordinal, Attempt: prior.Attempt, State: prior.State})
		if len(terminal) > 1024 {
			terminal = terminal[len(terminal)-1024:]
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	operationID := entityid.New()
	// Rust Prepare can spend two sequential 60-second stages producing a
	// durable Cut. Leave room for both stages and host polling, while staying
	// below the member's five-minute maximum signed-envelope lifetime.
	expires := now.Add(4 * time.Minute).UnixMilli()
	if expires <= 0 {
		return authority.BackupOperationRecord{}, 0, errors.New("backup prepare expiry is invalid")
	}
	roster := make([]backupRosterWire, len(members))
	for index, member := range members {
		roster[index] = backupRosterWire{member.Origin, member.MemberID, member.Incarnation}
	}
	prepare, err := signBackupOperation(backupPrepareDomain, backupPrepareWire{
		Version: 1, OperationID: operationID, Nonce: hex.EncodeToString(nonce[:]),
		SourceScopeDigest: manifest.SourceScopeDigest, SourceAuthoritySHA256: manifest.SourceAuthoritySHA256,
		SourceConfigurationID: manifest.SourceConfigurationID, SourceTargetDigest: manifest.SourceTargetDigest,
		BackupSet: manifest.BackupSet, BackupTargetDigest: manifest.BackupTargetDigest,
		Ordinal: ordinal, Attempt: attempt, ExpiresAtMS: uint64(expires), SignerKeyID: manifest.SignerKeyID,
		Roster: roster}, signer)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	record := authority.BackupOperationRecord{Version: 1, DatabaseID: database,
		PartitionID: partition, PlacementSequence: placementSequence,
		SourceScopeDigest: manifest.SourceScopeDigest, SourceAuthoritySHA256: manifest.SourceAuthoritySHA256,
		SourceConfigurationID: manifest.SourceConfigurationID, SourceTargetDigest: manifest.SourceTargetDigest,
		BackupSet: manifest.BackupSet, BackupTargetDigest: manifest.BackupTargetDigest,
		OwnerMemberID: manifest.OwnerMemberID, OwnerIncarnation: manifest.OwnerIncarnation,
		CompletedOrdinal: completed, Ordinal: ordinal, Attempt: attempt,
		AttemptHighWater: attempt, OperationID: operationID,
		Nonce: hex.EncodeToString(nonce[:]), PrepareEnvelope: prepare,
		PrepareExpiresAtMS: uint64(expires), State: "accepted",
		Roster: slices.Clone(members), Terminal: terminal}
	verifiedStore, ok := producer.Store.(verifiedBackupOperationStore)
	if !ok {
		return authority.BackupOperationRecord{}, 0, errors.New("backup operation store lacks final admission verification")
	}
	sequence, err := verifiedStore.CommitBackupOperationVerified(ctx, epoch,
		database, partition, expected, record, verify)
	return producer.confirmBackupCommit(ctx, database, partition, record, sequence, err)
}

// BeginAbort persists one exact signed Abort before it can reach either host.
// An already accepted Abort is reused byte for byte while its expiry is valid.
func (producer BackupOperationProducer) BeginAbort(ctx context.Context, epoch uint64,
	database, partition string, now time.Time,
) (authority.BackupOperationRecord, uint64, error) {
	if producer.Store == nil || epoch == 0 || now.IsZero() {
		return authority.BackupOperationRecord{}, 0, errors.New("backup operation producer is incomplete")
	}
	_, manifest, signer, err := currentBackupSigner(ctx, producer.Preparation, database, partition)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	return producer.beginAbortWithMaterial(ctx, epoch, database, partition, now, manifest, signer)
}

func (producer BackupOperationProducer) beginAbortWithMaterial(ctx context.Context, epoch uint64,
	database, partition string, now time.Time, manifest BackupManifestPayload,
	signer ed25519.PrivateKey,
) (authority.BackupOperationRecord, uint64, error) {
	if producer.Store == nil || epoch == 0 || now.IsZero() ||
		len(signer) != ed25519.PrivateKeySize ||
		manifest.SignerKeyID != backupKeyID(signer.Public().(ed25519.PublicKey)) {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	record, expected, err := producer.Store.ReadBackupOperation(ctx, database, partition)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	if record.State == "aborted" || record.State == "publishing" ||
		record.State == "releasing" || record.State == "complete" {
		return authority.BackupOperationRecord{}, 0, authority.ErrInvalidTransition
	}
	if manifest.BackupSet != record.BackupSet || manifest.SourceAuthoritySHA256 != record.SourceAuthoritySHA256 ||
		manifest.SourceConfigurationID != record.SourceConfigurationID ||
		manifest.SourceScopeDigest != record.SourceScopeDigest {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	if len(record.AbortEnvelope) != 0 && now.UnixMilli() <= int64(record.AbortExpiresAtMS)+30_000 {
		return record, expected, nil
	}
	// Abort may queue behind an in-progress Prepare at the member gate.
	expires := now.Add(4 * time.Minute).UnixMilli()
	if expires <= 0 || uint64(expires) <= record.AbortExpiresAtMS {
		return authority.BackupOperationRecord{}, 0, errors.New("backup abort expiry cannot advance")
	}
	wire, err := signBackupOperation(backupReleaseDomain, backupReleaseWire{
		Version: 1, OperationID: record.OperationID, Nonce: record.Nonce,
		SourceScopeDigest: record.SourceScopeDigest, SourceAuthoritySHA256: record.SourceAuthoritySHA256,
		SourceConfigurationID: record.SourceConfigurationID, BackupSet: record.BackupSet,
		Ordinal: record.Ordinal, Attempt: record.Attempt, Reason: "abort",
		ExpiresAtMS: uint64(expires), SignerKeyID: manifest.SignerKeyID,
		PublicationReceiptSHA256: strings.Repeat("0", 64)}, signer)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	record.AbortEnvelope = wire
	record.AbortExpiresAtMS = uint64(expires)
	record.State = "aborting"
	sequence, err := producer.Store.CommitBackupOperation(ctx, epoch, database, partition, expected, record)
	return producer.confirmBackupCommit(ctx, database, partition, record, sequence, err)
}

// A possibly committed CAS never releases a signed envelope until an exact
// authoritative R3 readback confirms the full record and its sequence.
func (producer BackupOperationProducer) confirmBackupCommit(ctx context.Context,
	database, partition string, want authority.BackupOperationRecord,
	committedSequence uint64, commitErr error,
) (authority.BackupOperationRecord, uint64, error) {
	if commitErr != nil && !errors.Is(commitErr, authority.ErrOutcomeUnknown) {
		return authority.BackupOperationRecord{}, 0, commitErr
	}
	observed, sequence, err := producer.Store.ReadBackupOperation(ctx, database, partition)
	if err != nil || sequence == 0 ||
		commitErr == nil && sequence != committedSequence {
		return authority.BackupOperationRecord{}, 0,
			errors.Join(authority.ErrOutcomeUnknown, commitErr, err)
	}
	intended, marshalErr := json.Marshal(want)
	actual, readMarshalErr := json.Marshal(observed)
	if marshalErr != nil || readMarshalErr != nil || !bytes.Equal(intended, actual) {
		return authority.BackupOperationRecord{}, 0,
			errors.Join(authority.ErrOutcomeUnknown, commitErr, marshalErr, readMarshalErr)
	}
	return observed, sequence, nil
}

// VerifyCut uses the first DER leaf from the exact authenticated material
// bundle, then checks every operation and roster field before returning it.
func (producer BackupOperationProducer) VerifyCut(ctx context.Context,
	record authority.BackupOperationRecord, memberID string, wire []byte,
) (BackupCut, error) {
	cut, _, err := producer.VerifyCutWithLeaf(ctx, record, memberID, wire)
	return cut, err
}

// VerifyCutWithLeaf returns the exact authenticated DER used to verify the
// signed Cut. R3 stores both bytes so a later host relay has no material lookup.
func (producer BackupOperationProducer) VerifyCutWithLeaf(ctx context.Context,
	record authority.BackupOperationRecord, memberID string, wire []byte,
) (BackupCut, []byte, error) {
	if len(wire) == 0 || len(wire) > 8<<10 {
		return BackupCut{}, nil, ErrMaterialConflict
	}
	receipt, bundle, err := producer.Preparation.CurrentBundle(ctx, record.DatabaseID, record.PartitionID)
	if err != nil {
		return BackupCut{}, nil, err
	}
	var leaf []byte
	cut, err := verifyCutWithBundleLeaf(record, memberID, wire, receipt, bundle, &leaf)
	return cut, leaf, err
}

func verifyCutWithBundleLeaf(record authority.BackupOperationRecord, memberID string, wire []byte,
	receipt PreparationReceipt, bundle InitialBundle, leafDER *[]byte,
) (BackupCut, error) {
	if len(wire) == 0 || len(wire) > 8<<10 {
		return BackupCut{}, ErrMaterialConflict
	}
	var member authority.BackupOperationMember
	index := -1
	for candidate, rosterMember := range record.Roster {
		if rosterMember.MemberID == memberID {
			member = rosterMember
			index = candidate
			break
		}
	}
	if index < 0 || index >= len(bundle.Members) {
		return BackupCut{}, ErrMaterialConflict
	}
	bundleIndex := -1
	for candidate, pinned := range receipt.Members {
		if pinned.MemberID == memberID {
			bundleIndex = candidate
			break
		}
	}
	if bundleIndex < 0 || member.TLSLeafSHA256 != receipt.Members[bundleIndex].TLSLeafSHA256 {
		return BackupCut{}, ErrMaterialConflict
	}
	block, _ := pem.Decode(bundle.Members[bundleIndex].Files["server.crt"].Contents)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 || len(block.Bytes) > 4096 {
		return BackupCut{}, ErrMaterialConflict
	}
	leafSHA := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(leafSHA[:]) != member.TLSLeafSHA256 {
		return BackupCut{}, ErrMaterialConflict
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return BackupCut{}, err
	}
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return BackupCut{}, ErrMaterialConflict
	}
	var envelope backupManifestEnvelope
	if err := json.Unmarshal(wire, &envelope, json.RejectUnknownMembers(true)); err != nil || envelope.Version != 1 {
		return BackupCut{}, ErrMaterialConflict
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonicalEnvelope, wire) {
		return BackupCut{}, ErrMaterialConflict
	}
	body, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != envelope.Payload {
		return BackupCut{}, ErrMaterialConflict
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != envelope.Signature ||
		!ed25519.Verify(public, append([]byte(backupCutDomain), body...), signature) {
		return BackupCut{}, ErrMaterialConflict
	}
	var cut BackupCut
	if err := json.Unmarshal(body, &cut, json.RejectUnknownMembers(true)); err != nil {
		return BackupCut{}, ErrMaterialConflict
	}
	canonical, err := json.Marshal(cut)
	if err != nil || !bytes.Equal(canonical, body) || cut.Version != 1 ||
		cut.OperationID != record.OperationID || cut.Nonce != record.Nonce ||
		cut.SourceScopeDigest != record.SourceScopeDigest ||
		cut.SourceAuthoritySHA256 != record.SourceAuthoritySHA256 ||
		cut.SourceConfigurationID != record.SourceConfigurationID ||
		cut.SourceTargetDigest != record.SourceTargetDigest || cut.BackupSet != record.BackupSet ||
		cut.Ordinal != record.Ordinal || cut.Attempt != record.Attempt ||
		cut.Origin != member.Origin || cut.MemberID != member.MemberID ||
		cut.Incarnation != member.Incarnation || cut.LeafCertificateSHA256 != member.TLSLeafSHA256 ||
		!lowerHexDigest(cut.RootSHA256) || cut.RootGeneration == 0 || cut.NativeCommitSeq == 0 ||
		cut.DurableSequence < cut.AppliedSequence || cut.HeldAtMS == 0 ||
		cut.SignerKeyID != backupKeyID(public) {
		return BackupCut{}, ErrMaterialConflict
	}
	if leafDER != nil {
		*leafDER = bytes.Clone(block.Bytes)
	}
	return cut, nil
}
