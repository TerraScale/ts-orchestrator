package databaseadmission

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"time"
)

// BranchRestoreEvidence is emitted only after installing a parent snapshot
// under the child's identity and data key. It is independent of serving proof.
type BranchRestoreEvidence struct {
	RecoveryPointID        string `json:"recovery_point_id"`
	JournalCut             string `json:"journal_cut"`
	RestoreEpoch           uint64 `json:"restore_epoch"`
	RestoreProvider        string `json:"restore_provider"`
	SchemaVersion          int    `json:"schema_version"`
	Environment            string `json:"environment"`
	TenantID               string `json:"tenant_id"`
	ProjectID              string `json:"project_id"`
	ParentDatabaseID       string `json:"parent_database_id"`
	DatabaseID             string `json:"database_id"`
	KeyVersion             string `json:"key_version"`
	OperationID            string `json:"operation_id"`
	MemberIdentity         string `json:"member_identity"`
	Region                 string `json:"region"`
	SourceSnapshotDigest   string `json:"source_snapshot_digest"`
	RestoredSnapshotDigest string `json:"restored_snapshot_digest"`
	CutDigest              string `json:"cut_digest"`
	Nonce                  string `json:"nonce"`
	ObservedAtUnixMS       int64  `json:"observed_at_unix_ms"`
}

type BranchRestoreConfig struct {
	Capture func(context.Context, Record, Record, string) (SignedReadiness, error)
	Keys    map[string]ReadinessKey
	Restore func(context.Context, Record, string) ([]SignedReadiness, error)
}

func validateBranchRestore(r Record, receipts []SignedReadiness, nonce string, keys map[string]ReadinessKey, now time.Time) error {
	if r.Request.ParentDatabaseID == "" || len(receipts) != len(r.Targets) || !validDigest(nonce) {
		return ErrInvalid
	}
	frozen, err := validateBranchSource(r, r.BranchSource, keys, time.Time{})
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	restored := map[string]string{}
	source, cut := "", ""
	for _, signed := range receipts {
		if len(signed.Payload) == 0 || len(signed.Payload) > 32<<10 || len(signed.Signature) != ed25519.SignatureSize {
			return ErrInvalid
		}
		var proof BranchRestoreEvidence
		if json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil {
			return ErrInvalid
		}
		if keys != nil {
			key, ok := keys[proof.MemberIdentity]
			if !ok || key.KeyID != signed.KeyID || len(key.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(key.PublicKey, append([]byte("terrabase-database-branch-restore-v1\x00"), signed.Payload...), signed.Signature) {
				return ErrInvalid
			}
		}
		index := slices.IndexFunc(r.Targets, func(t Target) bool { return t.ServerIdentity == proof.MemberIdentity })
		if index < 0 || seen[proof.MemberIdentity] {
			return ErrInvalid
		}
		if proof.SchemaVersion != 1 || proof.Environment != r.Request.Environment || proof.TenantID != r.Request.TenantID || proof.ProjectID != r.Request.ProjectID || proof.ParentDatabaseID != r.Request.ParentDatabaseID || proof.DatabaseID != r.DatabaseID || proof.KeyVersion != r.KeyVersion || proof.OperationID != PlacementOperationID(r.Request) || proof.Region != r.Targets[index].Region || proof.Nonce != nonce || proof.ObservedAtUnixMS <= 0 {
			return ErrInvalid
		}
		if proof.RecoveryPointID != frozen.RecoveryPointID || proof.SourceSnapshotDigest != frozen.SourceSnapshotDigest || proof.CutDigest != frozen.CutDigest {
			return ErrInvalid
		}
		if !validRestoreProvider(proof.RestoreProvider) || !validJournalCut(proof.JournalCut) || proof.RestoreEpoch == 0 || proof.JournalCut != frozen.JournalCut || proof.RestoreEpoch != frozen.RestoreEpoch || proof.RestoreProvider != frozen.RestoreProvider {
			return ErrInvalid
		}
		if !validDigest(proof.SourceSnapshotDigest) || !validDigest(proof.RestoredSnapshotDigest) || !validDigest(proof.CutDigest) {
			return ErrInvalid
		}
		if source != "" && (source != proof.SourceSnapshotDigest || cut != proof.CutDigest) {
			return ErrInvalid
		}
		if previous, exists := restored[proof.Region]; exists && previous != proof.RestoredSnapshotDigest {
			return ErrInvalid
		}
		if !now.IsZero() {
			observed := time.UnixMilli(proof.ObservedAtUnixMS)
			if observed.Before(now.Add(-time.Minute)) || observed.After(now.Add(5*time.Second)) {
				return ErrInvalid
			}
		}
		seen[proof.MemberIdentity] = true
		source, cut = proof.SourceSnapshotDigest, proof.CutDigest
		restored[proof.Region] = proof.RestoredSnapshotDigest
	}
	return nil
}

func (p *Pipeline) restoreBranch(ctx context.Context, r *Record) error {
	if r.Request.ParentDatabaseID == "" {
		return nil
	}
	config := p.config.BranchRestore
	if config == nil {
		return ErrInvalid
	}
	if err := p.captureBranchSource(ctx, r); err != nil {
		return err
	}
	if len(r.BranchEvidence) != 0 {
		return validateBranchRestore(*r, r.BranchEvidence, r.BranchNonce, config.Keys, time.Time{})
	}
	if err := p.config.CheckAuthority(ctx); err != nil {
		return err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	nonce := hex.EncodeToString(random[:])
	receipts, err := config.Restore(ctx, *r, nonce)
	if err != nil {
		return err
	}
	if err := validateBranchRestore(*r, receipts, nonce, config.Keys, time.Now()); err != nil {
		return err
	}
	if err := p.config.CheckAuthority(ctx); err != nil {
		return err
	}
	r.BranchEvidence, r.BranchNonce = receipts, nonce
	return p.save(ctx, r)
}
