package databaseadmission

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"time"
)

// BranchSource is frozen once before any target replica starts restoring.
// Its signed payload uses BranchSourceEvidence and a distinct source domain.
type BranchSource struct {
	Evidence SignedReadiness `json:"evidence"`
	Nonce    string          `json:"nonce"`
}
type BranchSourceEvidence struct {
	SchemaVersion        int    `json:"schema_version"`
	Environment          string `json:"environment"`
	TenantID             string `json:"tenant_id"`
	ProjectID            string `json:"project_id"`
	ParentDatabaseID     string `json:"parent_database_id"`
	DatabaseID           string `json:"database_id"`
	KeyVersion           string `json:"key_version"`
	OperationID          string `json:"operation_id"`
	MemberIdentity       string `json:"member_identity"`
	Region               string `json:"region"`
	RecoveryPointID      string `json:"recovery_point_id"`
	SourceSnapshotDigest string `json:"source_snapshot_digest"`
	CutDigest            string `json:"cut_digest"`
	Nonce                string `json:"nonce"`
	ObservedAtUnixMS     int64  `json:"observed_at_unix_ms"`
}

func validateBranchSource(r Record, source *BranchSource, keys map[string]ReadinessKey, now time.Time) (BranchSourceEvidence, error) {
	var proof BranchSourceEvidence
	if source == nil || r.Request.ParentDatabaseID == "" || !validDigest(source.Nonce) {
		return proof, ErrInvalid
	}
	signed := source.Evidence
	if len(signed.Payload) == 0 || len(signed.Payload) > 32<<10 || len(signed.Signature) != ed25519.SignatureSize || json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil {
		return proof, ErrInvalid
	}
	if keys != nil {
		key, ok := keys[proof.MemberIdentity]
		if !ok || key.KeyID != signed.KeyID || len(key.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(key.PublicKey, append([]byte("terrabase-database-branch-source-v1\x00"), signed.Payload...), signed.Signature) {
			return proof, ErrInvalid
		}
	}
	if proof.SchemaVersion != 1 || proof.Environment != r.Request.Environment || proof.TenantID != r.Request.TenantID || proof.ProjectID != r.Request.ProjectID || proof.ParentDatabaseID != r.Request.ParentDatabaseID || proof.DatabaseID != r.DatabaseID || proof.KeyVersion != r.KeyVersion || proof.OperationID != PlacementOperationID(r.Request) || proof.Nonce != source.Nonce || !canonicalID.MatchString(proof.RecoveryPointID) || !validDigest(proof.SourceSnapshotDigest) || !validDigest(proof.CutDigest) || proof.ObservedAtUnixMS <= 0 {
		return proof, ErrInvalid
	}
	if _, err := HostSubject(proof.MemberIdentity); err != nil {
		return proof, ErrInvalid
	}
	if !now.IsZero() {
		observed := time.UnixMilli(proof.ObservedAtUnixMS)
		if observed.Before(now.Add(-time.Minute)) || observed.After(now.Add(5*time.Second)) {
			return proof, ErrInvalid
		}
	}
	return proof, nil
}
func (p *Pipeline) captureBranchSource(ctx context.Context, r *Record) error {
	config := p.config.BranchRestore
	if r.BranchSource != nil {
		_, err := validateBranchSource(*r, r.BranchSource, config.Keys, time.Time{})
		return err
	}
	records, err := p.config.Journal.List(ctx)
	if err != nil {
		return err
	}
	var parent *Record
	for _, record := range records {
		if record.DatabaseID == r.Request.ParentDatabaseID {
			parent = new(record)
			break
		}
	}
	if parent == nil || len(parent.Targets) == 0 || parent.State != "ready" {
		return ErrConflict
	}
	if err := p.config.CheckAuthority(ctx); err != nil {
		return err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	nonce := hex.EncodeToString(random[:])
	receipt, err := config.Capture(ctx, *r, *parent, nonce)
	if err != nil {
		return err
	}
	source := &BranchSource{Evidence: receipt, Nonce: nonce}
	proof, err := validateBranchSource(*r, source, config.Keys, time.Now())
	if err != nil {
		return err
	}
	target := parent.Targets[0]
	if proof.MemberIdentity != target.ServerIdentity || proof.Region != target.Region {
		return ErrInvalid
	}
	if err := p.config.CheckAuthority(ctx); err != nil {
		return err
	}
	r.BranchSource = source
	return p.save(ctx, r)
}
