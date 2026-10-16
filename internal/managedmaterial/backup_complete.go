package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type backupBinding struct {
	Version               uint64 `json:"version"`
	OperationID           string `json:"operation_id"`
	Nonce                 string `json:"nonce"`
	SourceScopeDigest     string `json:"source_scope_digest"`
	SourceAuthoritySHA256 string `json:"source_authority_sha256"`
	SourceConfigurationID string `json:"source_configuration_id"`
	SourceTargetDigest    string `json:"source_target_digest"`
	BackupSet             string `json:"backup_set"`
	BackupTargetDigest    string `json:"backup_target_digest"`
	Ordinal               uint64 `json:"ordinal"`
	Attempt               uint64 `json:"attempt"`
}

func bindingFor(record authority.BackupOperationRecord) backupBinding {
	return backupBinding{1, record.OperationID, record.Nonce, record.SourceScopeDigest,
		record.SourceAuthoritySHA256, record.SourceConfigurationID, record.SourceTargetDigest,
		record.BackupSet, record.BackupTargetDigest, record.Ordinal, record.Attempt}
}

type backupBarrierMember struct {
	Origin          string `json:"origin"`
	MemberID        string `json:"member_id"`
	Incarnation     string `json:"incarnation"`
	RootSHA256      string `json:"root_sha256"`
	RootGeneration  uint64 `json:"root_generation"`
	NativeCommitSeq uint64 `json:"native_commit_seq"`
	AppliedSequence uint64 `json:"applied_sequence"`
	DurableSequence uint64 `json:"durable_sequence"`
}

type backupBarrierWire struct {
	backupBinding
	SourceCutAtMS uint64                `json:"source_cut_at_ms"`
	ExpiresAtMS   uint64                `json:"expires_at_ms"`
	SignerKeyID   string                `json:"signer_key_id"`
	Roster        []backupBarrierMember `json:"roster"`
}

type backupFrontierWire struct {
	Origin          string `json:"origin"`
	AppliedSequence uint64 `json:"applied_sequence"`
}

type backupCandidateWire struct {
	backupBinding
	OwnerOrigin                string               `json:"owner_origin"`
	OwnerMemberID              string               `json:"owner_member_id"`
	OwnerIncarnation           string               `json:"owner_incarnation"`
	OwnerLeafCertificateSHA256 string               `json:"owner_leaf_certificate_sha256"`
	PrepareSHA256              string               `json:"prepare_sha256"`
	BarrierSHA256              string               `json:"barrier_sha256"`
	CandidateFileSHA256        string               `json:"candidate_file_sha256"`
	PointSHA256                string               `json:"point_sha256"`
	ClosureSHA256              string               `json:"closure_sha256"`
	PreviousHeadSHA256         string               `json:"previous_head_sha256"`
	ExpectedHeadGeneration     uint64               `json:"expected_head_generation"`
	SelectedFrontier           []backupFrontierWire `json:"selected_frontier"`
	SignerKeyID                string               `json:"signer_key_id"`
}

type backupCompletionWire struct {
	backupBinding
	PointSHA256            string               `json:"point_sha256"`
	ClosureSHA256          string               `json:"closure_sha256"`
	PreviousHeadSHA256     string               `json:"previous_head_sha256"`
	ExpectedHeadGeneration uint64               `json:"expected_head_generation"`
	SelectedFrontier       []backupFrontierWire `json:"selected_frontier"`
	ExpiresAtMS            uint64               `json:"expires_at_ms"`
	SignerKeyID            string               `json:"signer_key_id"`
}

type backupPublishedHeadWire struct {
	backupBinding
	OwnerOrigin           string `json:"owner_origin"`
	OwnerMemberID         string `json:"owner_member_id"`
	OwnerIncarnation      string `json:"owner_incarnation"`
	OwnerLeafDER          string `json:"owner_leaf_der"`
	LeafCertificateSHA256 string `json:"leaf_certificate_sha256"`
	PrepareSHA256         string `json:"prepare_sha256"`
	BarrierSHA256         string `json:"barrier_sha256"`
	CompletionSHA256      string `json:"completion_sha256"`
	PointSHA256           string `json:"point_sha256"`
	ClosureSHA256         string `json:"closure_sha256"`
	PreviousHeadSHA256    string `json:"previous_head_sha256"`
	HeadGeneration        uint64 `json:"head_generation"`
	CatalogHeadBytes      string `json:"catalog_head_bytes"`
	CatalogHeadSHA256     string `json:"catalog_head_sha256"`
	SignerKeyID           string `json:"signer_key_id"`
}

func backupSHA(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func decodeCanonicalBackupSigned(wire []byte, domain string, public ed25519.PublicKey,
	limit int, payload any,
) error {
	if len(wire) == 0 || len(wire) > limit || len(public) != ed25519.PublicKeySize {
		return ErrMaterialConflict
	}
	var outer backupManifestEnvelope
	if err := json.Unmarshal(wire, &outer, json.RejectUnknownMembers(true)); err != nil || outer.Version != 1 {
		return ErrMaterialConflict
	}
	canonical, err := json.Marshal(outer)
	if err != nil || !bytes.Equal(canonical, wire) {
		return ErrMaterialConflict
	}
	body, err := base64.RawURLEncoding.DecodeString(outer.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != outer.Payload {
		return ErrMaterialConflict
	}
	signature, err := base64.RawURLEncoding.DecodeString(outer.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != outer.Signature ||
		!ed25519.Verify(public, append([]byte(domain), body...), signature) {
		return ErrMaterialConflict
	}
	if err := json.Unmarshal(body, payload, json.RejectUnknownMembers(true)); err != nil {
		return ErrMaterialConflict
	}
	canonical, err = json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, body) {
		return ErrMaterialConflict
	}
	return nil
}

func backupOwner(record authority.BackupOperationRecord, manifest BackupManifestPayload) (authority.BackupOperationMember, error) {
	if record.OwnerMemberID != manifest.OwnerMemberID || record.OwnerIncarnation != manifest.OwnerIncarnation {
		return authority.BackupOperationMember{}, ErrMaterialConflict
	}
	for _, member := range record.Roster {
		if member.MemberID == manifest.OwnerMemberID && member.Incarnation == manifest.OwnerIncarnation &&
			len(member.CutLeafDER) != 0 && len(member.CutLeafDER) <= 4096 {
			return member, nil
		}
	}
	return authority.BackupOperationMember{}, ErrMaterialConflict
}

func backupOwnerPublic(member authority.BackupOperationMember) (ed25519.PublicKey, error) {
	if len(member.CutLeafDER) == 0 || len(member.CutLeafDER) > 4096 ||
		backupSHA(member.CutLeafDER) != member.TLSLeafSHA256 {
		return nil, ErrMaterialConflict
	}
	leaf, err := x509.ParseCertificate(member.CutLeafDER)
	if err != nil {
		return nil, err
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, ErrMaterialConflict
	}
	return public, nil
}

func candidateMatches(record authority.BackupOperationRecord, owner authority.BackupOperationMember,
	candidate backupCandidateWire, public ed25519.PublicKey, cuts []BackupCut,
) bool {
	if candidate.backupBinding != bindingFor(record) ||
		candidate.OwnerOrigin != owner.Origin || candidate.OwnerMemberID != owner.MemberID ||
		candidate.OwnerIncarnation != owner.Incarnation ||
		candidate.OwnerLeafCertificateSHA256 != owner.TLSLeafSHA256 ||
		candidate.PrepareSHA256 != backupSHA(record.PrepareEnvelope) ||
		candidate.BarrierSHA256 != backupSHA(record.BarrierEnvelope) ||
		!lowerHexDigest(candidate.CandidateFileSHA256) ||
		!lowerHexDigest(candidate.PointSHA256) || !lowerHexDigest(candidate.ClosureSHA256) ||
		!lowerHexDigest(candidate.PreviousHeadSHA256) ||
		candidate.ExpectedHeadGeneration != record.Ordinal ||
		candidate.SignerKeyID != backupKeyID(public) ||
		len(candidate.SelectedFrontier) != len(record.Roster) {
		return false
	}
	if record.Ordinal == 1 && candidate.PreviousHeadSHA256 != string(bytes.Repeat([]byte{'0'}, 64)) ||
		record.Ordinal != 1 && candidate.PreviousHeadSHA256 == string(bytes.Repeat([]byte{'0'}, 64)) {
		return false
	}
	for index, row := range candidate.SelectedFrontier {
		if row.Origin != record.Roster[index].Origin ||
			row.AppliedSequence != cuts[index].AppliedSequence {
			return false
		}
	}
	return true
}

// The selected frontier must be verified against the signed Cuts. It is not a
// controller assertion about V3 closure; every Rust member checks that proof.
func (producer BackupOperationProducer) VerifyCandidate(ctx context.Context,
	record authority.BackupOperationRecord, wire []byte,
) (backupCandidateWire, error) {
	_, manifest, _, err := currentBackupSigner(ctx, producer.Preparation, record.DatabaseID, record.PartitionID)
	if err != nil {
		return backupCandidateWire{}, err
	}
	owner, err := backupOwner(record, manifest)
	if err != nil {
		return backupCandidateWire{}, err
	}
	public, err := backupOwnerPublic(owner)
	if err != nil {
		return backupCandidateWire{}, err
	}
	cuts := make([]BackupCut, len(record.Roster))
	for index, member := range record.Roster {
		cut, err := producer.VerifyCut(ctx, record, member.MemberID, member.CutEnvelope)
		if err != nil {
			return backupCandidateWire{}, err
		}
		cuts[index] = cut
	}
	var candidate backupCandidateWire
	if err := decodeCanonicalBackupSigned(wire, backupCandidateDomain, public, 8<<10, &candidate); err != nil ||
		!candidateMatches(record, owner, candidate, public, cuts) {
		return backupCandidateWire{}, ErrMaterialConflict
	}
	return candidate, nil
}

func backupFrontierEqual(left, right []backupFrontierWire) bool {
	return slices.Equal(left, right)
}

func currentBackupCompleteSigner(ctx context.Context, producer BackupOperationProducer,
	record authority.BackupOperationRecord,
) (BackupManifestPayload, ed25519.PrivateKey, error) {
	_, manifest, signer, err := currentBackupSigner(ctx, producer.Preparation, record.DatabaseID, record.PartitionID)
	if err != nil || manifest.SourceScopeDigest != record.SourceScopeDigest ||
		manifest.SourceAuthoritySHA256 != record.SourceAuthoritySHA256 ||
		manifest.SourceConfigurationID != record.SourceConfigurationID ||
		manifest.SourceTargetDigest != record.SourceTargetDigest ||
		manifest.BackupSet != record.BackupSet || manifest.BackupTargetDigest != record.BackupTargetDigest {
		return BackupManifestPayload{}, nil, errors.Join(ErrMaterialConflict, err)
	}
	return manifest, signer, nil
}

func commitBackupExact(ctx context.Context, producer BackupOperationProducer, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64,
) (authority.BackupOperationRecord, uint64, error) {
	committed, err := producer.Store.CommitBackupOperation(ctx, epoch, record.DatabaseID,
		record.PartitionID, sequence, record)
	return producer.confirmBackupCommit(ctx, record.DatabaseID, record.PartitionID,
		record, committed, err)
}

func backupCompleteExpiry(now time.Time) (uint64, error) {
	if now.IsZero() || now.UnixMilli() <= 0 {
		return 0, ErrMaterialConflict
	}
	return uint64(now.Add(4 * time.Minute).UnixMilli()), nil
}

func signCompleteRelease(record authority.BackupOperationRecord, receipt []byte,
	expires uint64, manifest BackupManifestPayload, signer ed25519.PrivateKey,
) ([]byte, error) {
	wire, err := signBackupOperation(backupReleaseDomain, backupReleaseWire{
		Version: 1, OperationID: record.OperationID, Nonce: record.Nonce,
		SourceScopeDigest:     record.SourceScopeDigest,
		SourceAuthoritySHA256: record.SourceAuthoritySHA256,
		SourceConfigurationID: record.SourceConfigurationID,
		BackupSet:             record.BackupSet, Ordinal: record.Ordinal, Attempt: record.Attempt,
		Reason: "complete", ExpiresAtMS: expires, SignerKeyID: manifest.SignerKeyID,
		PublicationReceiptSHA256: backupSHA(receipt),
		PublicationReceipt:       base64.RawURLEncoding.EncodeToString(receipt),
		CompletionEnvelope:       base64.RawURLEncoding.EncodeToString(record.CompletionEnvelope)}, signer)
	if err != nil || len(wire) > 30<<10 {
		return nil, errors.Join(ErrMaterialConflict, err)
	}
	return wire, nil
}

// CommitBarrier signs one roster-wide source cut after every exact Cut and
// pinned leaf is already in R3. It commits before any CutProof or Barrier relay.
func (producer BackupOperationProducer) CommitBarrier(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64, now time.Time,
) (authority.BackupOperationRecord, uint64, error) {
	if producer.Store == nil || epoch == 0 || record.State != "held" ||
		len(record.BarrierEnvelope) != 0 {
		return authority.BackupOperationRecord{}, 0, authority.ErrInvalidTransition
	}
	manifest, signer, err := currentBackupCompleteSigner(ctx, producer, record)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	expires, err := backupCompleteExpiry(now)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	roster := make([]backupBarrierMember, len(record.Roster))
	var cutAt uint64
	for index, member := range record.Roster {
		cut, leaf, err := producer.VerifyCutWithLeaf(ctx, record, member.MemberID, member.CutEnvelope)
		if err != nil || !bytes.Equal(leaf, member.CutLeafDER) {
			return authority.BackupOperationRecord{}, 0, errors.Join(ErrMaterialConflict, err)
		}
		cutAt = max(cutAt, cut.HeldAtMS)
		roster[index] = backupBarrierMember{cut.Origin, cut.MemberID, cut.Incarnation,
			cut.RootSHA256, cut.RootGeneration, cut.NativeCommitSeq,
			cut.AppliedSequence, cut.DurableSequence}
	}
	wire, err := signBackupOperation(backupBarrierDomain, backupBarrierWire{
		backupBinding: bindingFor(record), SourceCutAtMS: cutAt,
		ExpiresAtMS: expires, SignerKeyID: manifest.SignerKeyID, Roster: roster}, signer)
	if err != nil || len(wire) > 8<<10 {
		return authority.BackupOperationRecord{}, 0, errors.Join(ErrMaterialConflict, err)
	}
	record.BarrierEnvelope = wire
	record.State = "barrier"
	return commitBackupExact(ctx, producer, epoch, record, sequence)
}

func (producer BackupOperationProducer) AcknowledgeBarrier(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64, memberID, barrierSHA string,
) (authority.BackupOperationRecord, uint64, error) {
	if record.State != "barrier" || len(record.BarrierEnvelope) == 0 ||
		barrierSHA != backupSHA(record.BarrierEnvelope) {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	record.Roster = slices.Clone(record.Roster)
	for index := range record.Roster {
		if record.Roster[index].MemberID == memberID {
			if record.Roster[index].BarrierAcknowledged {
				return record, sequence, nil
			}
			record.Roster[index].BarrierAcknowledged = true
			return commitBackupExact(ctx, producer, epoch, record, sequence)
		}
	}
	return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
}

func (producer BackupOperationProducer) AcceptCandidate(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64, wire []byte,
) (authority.BackupOperationRecord, uint64, error) {
	if record.State != "barrier" || len(record.CandidateEnvelope) != 0 {
		return authority.BackupOperationRecord{}, 0, authority.ErrInvalidTransition
	}
	for _, member := range record.Roster {
		if !member.BarrierAcknowledged {
			return authority.BackupOperationRecord{}, 0, authority.ErrFenced
		}
	}
	if _, err := producer.VerifyCandidate(ctx, record, wire); err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	record.CandidateEnvelope = bytes.Clone(wire)
	return commitBackupExact(ctx, producer, epoch, record, sequence)
}

// CommitCompletion moves R3 into its irreversible publishing state before the
// owner receives the Completion. Abort and point replacement are then fenced.
func (producer BackupOperationProducer) CommitCompletion(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64, now time.Time,
) (authority.BackupOperationRecord, uint64, error) {
	if record.State != "barrier" || len(record.CandidateEnvelope) == 0 ||
		len(record.CompletionEnvelope) != 0 {
		return authority.BackupOperationRecord{}, 0, authority.ErrInvalidTransition
	}
	manifest, signer, err := currentBackupCompleteSigner(ctx, producer, record)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	candidate, err := producer.VerifyCandidate(ctx, record, record.CandidateEnvelope)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	expires, err := backupCompleteExpiry(now)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	wire, err := signBackupOperation(backupCompletionDomain, backupCompletionWire{
		backupBinding: bindingFor(record), PointSHA256: candidate.PointSHA256,
		ClosureSHA256:          candidate.ClosureSHA256,
		PreviousHeadSHA256:     candidate.PreviousHeadSHA256,
		ExpectedHeadGeneration: candidate.ExpectedHeadGeneration,
		SelectedFrontier:       slices.Clone(candidate.SelectedFrontier),
		ExpiresAtMS:            expires, SignerKeyID: manifest.SignerKeyID}, signer)
	if err != nil || len(wire) > 8<<10 {
		return authority.BackupOperationRecord{}, 0, errors.Join(ErrMaterialConflict, err)
	}
	record.CompletionEnvelope = wire
	record.State = "publishing"
	return commitBackupExact(ctx, producer, epoch, record, sequence)
}

// CommitOwnerReceipt checks the owner's signed readback proof, then persists
// both that exact proof and its controller-signed Release before peer delivery.
func (producer BackupOperationProducer) CommitOwnerReceipt(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64, receipt []byte, now time.Time,
) (authority.BackupOperationRecord, uint64, error) {
	if record.State != "publishing" || len(record.PublicationReceipt) != 0 ||
		len(record.CompleteRelease) != 0 {
		return authority.BackupOperationRecord{}, 0, authority.ErrInvalidTransition
	}
	manifest, signer, err := currentBackupCompleteSigner(ctx, producer, record)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	owner, err := backupOwner(record, manifest)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	public, err := backupOwnerPublic(owner)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	candidate, err := producer.VerifyCandidate(ctx, record, record.CandidateEnvelope)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	var proof backupPublishedHeadWire
	if err := decodeCanonicalBackupSigned(receipt, backupPublishedHeadDomain, public, 18<<10, &proof); err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	der, err := base64.RawURLEncoding.DecodeString(proof.OwnerLeafDER)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != proof.OwnerLeafDER ||
		!bytes.Equal(der, owner.CutLeafDER) {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	head, err := base64.RawURLEncoding.DecodeString(proof.CatalogHeadBytes)
	if err != nil || base64.RawURLEncoding.EncodeToString(head) != proof.CatalogHeadBytes ||
		!verifyBackupCatalogHeadBytes(head, record, candidate.PreviousHeadSHA256) {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	if proof.backupBinding != bindingFor(record) || proof.OwnerOrigin != owner.Origin ||
		proof.OwnerMemberID != owner.MemberID || proof.OwnerIncarnation != owner.Incarnation ||
		proof.LeafCertificateSHA256 != owner.TLSLeafSHA256 ||
		proof.PrepareSHA256 != backupSHA(record.PrepareEnvelope) ||
		proof.BarrierSHA256 != backupSHA(record.BarrierEnvelope) ||
		proof.CompletionSHA256 != backupSHA(record.CompletionEnvelope) ||
		proof.PointSHA256 != candidate.PointSHA256 ||
		proof.ClosureSHA256 != candidate.ClosureSHA256 ||
		proof.PreviousHeadSHA256 != candidate.PreviousHeadSHA256 ||
		proof.HeadGeneration != record.Ordinal ||
		proof.CatalogHeadSHA256 != backupSHA(head) ||
		proof.SignerKeyID != backupKeyID(public) {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	expires, err := backupCompleteExpiry(now)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	release, err := signCompleteRelease(record, receipt, expires, manifest, signer)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, err
	}
	record.PublicationReceipt = bytes.Clone(receipt)
	record.CompleteRelease = release
	record.CompleteReleaseExpiresAtMS = expires
	record.HeadGeneration = proof.HeadGeneration
	record.State = "releasing"
	return commitBackupExact(ctx, producer, epoch, record, sequence)
}

// EnsureCurrentCompleteRelease renews only the signed Release after its old
// validity window and clock skew have passed. A terminal member may still
// carry the old Release digest, so callers must inspect process-bound status
// before asking the host to deliver a renewed Release.
func (producer BackupOperationProducer) EnsureCurrentCompleteRelease(ctx context.Context,
	epoch uint64, record authority.BackupOperationRecord, sequence uint64, now time.Time,
) (authority.BackupOperationRecord, uint64, bool, error) {
	if producer.Store == nil || epoch == 0 || record.State != "releasing" || now.IsZero() {
		return authority.BackupOperationRecord{}, 0, false, authority.ErrInvalidTransition
	}
	if err := producer.VerifyCommittedPublication(ctx, record); err != nil {
		return authority.BackupOperationRecord{}, 0, false, err
	}
	manifest, signer, err := currentBackupCompleteSigner(ctx, producer, record)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, false, err
	}
	var prior backupReleaseWire
	if err := decodeCanonicalBackupSigned(record.CompleteRelease, backupReleaseDomain,
		signer.Public().(ed25519.PublicKey), 30<<10, &prior); err != nil ||
		prior.ExpiresAtMS != record.CompleteReleaseExpiresAtMS {
		return authority.BackupOperationRecord{}, 0, false, ErrMaterialConflict
	}
	nowMS := now.UnixMilli()
	if nowMS < int64(prior.ExpiresAtMS)-5_000 {
		return record, sequence, true, nil
	}
	if nowMS <= int64(prior.ExpiresAtMS)+30_000 {
		return record, sequence, false, nil
	}
	expires, err := backupCompleteExpiry(now)
	if err != nil || expires <= prior.ExpiresAtMS {
		return authority.BackupOperationRecord{}, 0, false, ErrMaterialConflict
	}
	wire, err := signCompleteRelease(record, record.PublicationReceipt, expires, manifest, signer)
	if err != nil {
		return authority.BackupOperationRecord{}, 0, false, err
	}
	record.CompleteRelease = wire
	record.CompleteReleaseExpiresAtMS = expires
	committed, nextSequence, err := commitBackupExact(ctx, producer, epoch, record, sequence)
	return committed, nextSequence, err == nil, err
}

func (producer BackupOperationProducer) AcknowledgeComplete(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64, memberID string,
	statusHeadGeneration uint64, statusReceipt []byte,
) (authority.BackupOperationRecord, uint64, error) {
	if record.State != "releasing" || statusHeadGeneration != record.HeadGeneration ||
		!bytes.Equal(statusReceipt, record.PublicationReceipt) {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	record.Roster = slices.Clone(record.Roster)
	found := false
	all := true
	for index := range record.Roster {
		if record.Roster[index].MemberID == memberID {
			record.Roster[index].CompleteAcknowledged = true
			found = true
		}
		all = all && record.Roster[index].CompleteAcknowledged
	}
	if !found {
		return authority.BackupOperationRecord{}, 0, ErrMaterialConflict
	}
	if all {
		record.State = "complete"
		record.CompletedOrdinal = record.Ordinal
	}
	return commitBackupExact(ctx, producer, epoch, record, sequence)
}

// VerifyCommittedPublication authenticates the exact proof chain before a
// status response exposes durable historical bytes from the authority log.
func (producer BackupOperationProducer) VerifyCommittedPublication(ctx context.Context,
	record authority.BackupOperationRecord,
) error {
	if record.State != "barrier" && record.State != "publishing" &&
		record.State != "releasing" && record.State != "complete" {
		return nil
	}
	manifest, signer, err := currentBackupCompleteSigner(ctx, producer, record)
	if err != nil {
		return err
	}
	authorityPublic := signer.Public().(ed25519.PublicKey)
	var barrier backupBarrierWire
	if err := decodeCanonicalBackupSigned(record.BarrierEnvelope, backupBarrierDomain,
		authorityPublic, 8<<10, &barrier); err != nil ||
		barrier.backupBinding != bindingFor(record) ||
		barrier.SignerKeyID != manifest.SignerKeyID || len(barrier.Roster) != len(record.Roster) {
		return ErrMaterialConflict
	}
	var cutAt uint64
	for index, member := range record.Roster {
		cut, leaf, err := producer.VerifyCutWithLeaf(ctx, record, member.MemberID, member.CutEnvelope)
		if err != nil || !bytes.Equal(leaf, member.CutLeafDER) {
			return ErrMaterialConflict
		}
		cutAt = max(cutAt, cut.HeldAtMS)
		want := backupBarrierMember{cut.Origin, cut.MemberID, cut.Incarnation,
			cut.RootSHA256, cut.RootGeneration, cut.NativeCommitSeq,
			cut.AppliedSequence, cut.DurableSequence}
		if barrier.Roster[index] != want {
			return ErrMaterialConflict
		}
	}
	if barrier.SourceCutAtMS != cutAt || barrier.ExpiresAtMS == 0 {
		return ErrMaterialConflict
	}
	if len(record.CandidateEnvelope) == 0 {
		return nil
	}
	candidate, err := producer.VerifyCandidate(ctx, record, record.CandidateEnvelope)
	if err != nil {
		return err
	}
	if len(record.CompletionEnvelope) == 0 {
		return nil
	}
	var completion backupCompletionWire
	if err := decodeCanonicalBackupSigned(record.CompletionEnvelope, backupCompletionDomain,
		authorityPublic, 8<<10, &completion); err != nil ||
		completion.backupBinding != bindingFor(record) ||
		completion.PointSHA256 != candidate.PointSHA256 ||
		completion.ClosureSHA256 != candidate.ClosureSHA256 ||
		completion.PreviousHeadSHA256 != candidate.PreviousHeadSHA256 ||
		completion.ExpectedHeadGeneration != candidate.ExpectedHeadGeneration ||
		!backupFrontierEqual(completion.SelectedFrontier, candidate.SelectedFrontier) ||
		completion.ExpiresAtMS == 0 || completion.SignerKeyID != manifest.SignerKeyID {
		return ErrMaterialConflict
	}
	if len(record.PublicationReceipt) == 0 {
		return nil
	}
	owner, err := backupOwner(record, manifest)
	if err != nil {
		return err
	}
	ownerPublic, err := backupOwnerPublic(owner)
	if err != nil {
		return err
	}
	var receipt backupPublishedHeadWire
	if err := decodeCanonicalBackupSigned(record.PublicationReceipt,
		backupPublishedHeadDomain, ownerPublic, 18<<10, &receipt); err != nil ||
		receipt.backupBinding != bindingFor(record) || receipt.OwnerOrigin != owner.Origin ||
		receipt.OwnerMemberID != owner.MemberID || receipt.OwnerIncarnation != owner.Incarnation ||
		receipt.LeafCertificateSHA256 != owner.TLSLeafSHA256 ||
		receipt.PrepareSHA256 != backupSHA(record.PrepareEnvelope) ||
		receipt.BarrierSHA256 != backupSHA(record.BarrierEnvelope) ||
		receipt.CompletionSHA256 != backupSHA(record.CompletionEnvelope) ||
		receipt.PointSHA256 != candidate.PointSHA256 ||
		receipt.ClosureSHA256 != candidate.ClosureSHA256 ||
		receipt.PreviousHeadSHA256 != candidate.PreviousHeadSHA256 ||
		receipt.HeadGeneration != record.Ordinal ||
		receipt.SignerKeyID != backupKeyID(ownerPublic) {
		return ErrMaterialConflict
	}
	ownerDER, err := base64.RawURLEncoding.DecodeString(receipt.OwnerLeafDER)
	if err != nil || base64.RawURLEncoding.EncodeToString(ownerDER) != receipt.OwnerLeafDER ||
		!bytes.Equal(ownerDER, owner.CutLeafDER) {
		return ErrMaterialConflict
	}
	head, err := base64.RawURLEncoding.DecodeString(receipt.CatalogHeadBytes)
	if err != nil || base64.RawURLEncoding.EncodeToString(head) != receipt.CatalogHeadBytes ||
		!verifyBackupCatalogHeadBytes(head, record, candidate.PreviousHeadSHA256) ||
		receipt.CatalogHeadSHA256 != backupSHA(head) {
		return ErrMaterialConflict
	}
	var release backupReleaseWire
	if err := decodeCanonicalBackupSigned(record.CompleteRelease, backupReleaseDomain,
		authorityPublic, 30<<10, &release); err != nil ||
		release.Version != 1 || release.OperationID != record.OperationID ||
		release.Nonce != record.Nonce || release.SourceScopeDigest != record.SourceScopeDigest ||
		release.SourceAuthoritySHA256 != record.SourceAuthoritySHA256 ||
		release.SourceConfigurationID != record.SourceConfigurationID ||
		release.BackupSet != record.BackupSet || release.Ordinal != record.Ordinal ||
		release.Attempt != record.Attempt || release.Reason != "complete" ||
		release.ExpiresAtMS != record.CompleteReleaseExpiresAtMS || release.SignerKeyID != manifest.SignerKeyID ||
		release.PublicationReceiptSHA256 != backupSHA(record.PublicationReceipt) ||
		release.PublicationReceipt != base64.RawURLEncoding.EncodeToString(record.PublicationReceipt) ||
		release.CompletionEnvelope != base64.RawURLEncoding.EncodeToString(record.CompletionEnvelope) {
		return ErrMaterialConflict
	}
	return nil
}
