package databaseadmission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"reflect"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type SignedReadiness struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type PhysicalReadiness struct {
	SnapshotDigest      string `json:"snapshot_digest"`
	WALCheckpointDigest string `json:"wal_checkpoint_digest"`
}
type CausalReadiness struct {
	CutDigest  string            `json:"cut_digest"`
	Frontier   map[string]uint64 `json:"frontier"`
	RootDigest string            `json:"root_digest"`
}
type Readiness struct {
	SchemaVersion    int               `json:"schema_version"`
	Environment      string            `json:"environment"`
	TenantID         string            `json:"tenant_id"`
	ProjectID        string            `json:"project_id"`
	DatabaseID       string            `json:"database_id"`
	KeyVersion       string            `json:"key_version"`
	OperationID      string            `json:"operation_id"`
	MemberIdentity   string            `json:"member_identity"`
	Region           string            `json:"region"`
	MembershipEpoch  uint64            `json:"membership_epoch"`
	Generation       uint64            `json:"generation"`
	PlacementDigest  string            `json:"placement_digest"`
	Physical         PhysicalReadiness `json:"physical"`
	Causal           CausalReadiness   `json:"causal"`
	ObservedAtUnixMS uint64            `json:"observed_at_unix_ms"`
	Nonce            string            `json:"nonce"`
}
type ReadinessKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}
type ReadinessConfig struct {
	// Keys are pinned by admitted engine SPIFFE identity, never by receipt input.
	Keys    map[string]ReadinessKey
	Collect func(context.Context, Record, string) ([]SignedReadiness, error)
}

func validateReadinessKeys(keys map[string]ReadinessKey) error {
	seen := map[string]bool{}
	for identity, key := range keys {
		if _, err := HostSubject(identity); err != nil {
			return ErrInvalid
		}
		if len(key.KeyID) == 0 || len(key.KeyID) > 128 || len(key.PublicKey) != ed25519.PublicKeySize || seen[string(key.PublicKey)] {
			return ErrInvalid
		}
		seen[string(key.PublicKey)] = true
	}
	return nil
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}
func validateReadinessSet(record Record, receipts []SignedReadiness, nonce string, keys map[string]ReadinessKey, now time.Time) error {
	return validateReadinessOperation(record, PlacementOperationID(record.Request), receipts, nonce, keys, now)
}

// ValidateRelocationReadiness authenticates the successor operation without
// rewriting the original database-create operation or its readiness history.
func ValidateRelocationReadiness(record Record, operation string, receipts []SignedReadiness, nonce string, keys map[string]ReadinessKey, now time.Time) error {
	if operation == "" || keys == nil || now.IsZero() || ValidateRecord(record) != nil || validateReadinessKeys(keys) != nil {
		return ErrInvalid
	}
	return validateReadinessOperation(record, operation, receipts, nonce, keys, now)
}
func validateReadinessOperation(record Record, operation string, receipts []SignedReadiness, nonce string, keys map[string]ReadinessKey, now time.Time) error {
	if len(receipts) != len(record.Targets) || !validDigest(nonce) {
		return ErrInvalid
	}
	byHost := map[string]Readiness{}
	for _, signed := range receipts {
		if len(signed.Payload) == 0 || len(signed.Payload) > 32<<10 || len(signed.Signature) != ed25519.SignatureSize {
			return ErrInvalid
		}
		var proof Readiness
		if json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil {
			return ErrInvalid
		}
		key, found := keys[proof.MemberIdentity]
		if keys != nil {
			if !found || key.KeyID != signed.KeyID || len(key.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(key.PublicKey, append([]byte("terrabase-database-readiness-v1\x00"), signed.Payload...), signed.Signature) {
				return ErrInvalid
			}
		}
		if _, duplicate := byHost[proof.MemberIdentity]; duplicate {
			return ErrInvalid
		}
		targetIndex := slices.IndexFunc(record.Targets, func(t Target) bool { return t.ServerIdentity == proof.MemberIdentity })
		if targetIndex < 0 {
			return ErrInvalid
		}
		target := record.Targets[targetIndex]
		stage := new(pb.PlacementStageRequest)
		if proto.Unmarshal(target.Proposal, stage) != nil || stage.Proposal == nil {
			return ErrInvalid
		}
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(stage.Proposal)
		if err != nil {
			return ErrInvalid
		}
		digest := sha256.Sum256(encoded)
		if proof.SchemaVersion != 1 || proof.Environment != record.Request.Environment || proof.TenantID != record.Request.TenantID || proof.ProjectID != record.Request.ProjectID || proof.DatabaseID != record.DatabaseID || proof.KeyVersion != record.KeyVersion || proof.OperationID != operation || proof.Region != target.Region || proof.MembershipEpoch != stage.Proposal.Epoch || proof.Generation != stage.Proposal.Generation || proof.PlacementDigest != hex.EncodeToString(digest[:]) || proof.Nonce != nonce {
			return ErrInvalid
		}
		if !validDigest(proof.Physical.SnapshotDigest) || !validDigest(proof.Physical.WALCheckpointDigest) || !validDigest(proof.Causal.CutDigest) || !validDigest(proof.Causal.RootDigest) || proof.Causal.Frontier == nil || len(proof.Causal.Frontier) > 20 || proof.ObservedAtUnixMS == 0 || proof.ObservedAtUnixMS > 1<<63-1 {
			return ErrInvalid
		}
		for origin := range proof.Causal.Frontier {
			if origin != strings.ToLower(origin) || !slices.Contains(record.Request.Regions, strings.ToUpper(origin)) {
				return ErrInvalid
			}
		}
		if !now.IsZero() {
			observed := time.UnixMilli(int64(proof.ObservedAtUnixMS))
			if observed.After(now.Add(5*time.Second)) || observed.Before(now.Add(-time.Minute)) {
				return ErrInvalid
			}
		}
		byHost[proof.MemberIdentity] = proof
	}
	physical := map[string]PhysicalReadiness{}
	var causal *CausalReadiness
	for _, target := range record.Targets {
		proof := byHost[target.ServerIdentity]
		if old, found := physical[target.Region]; found && old != proof.Physical {
			return ErrInvalid
		}
		physical[target.Region] = proof.Physical
		if causal != nil && !reflect.DeepEqual(*causal, proof.Causal) {
			return ErrInvalid
		}
		copy := proof.Causal
		causal = &copy
	}
	return nil
}
func (p *Pipeline) establishReadiness(ctx context.Context, record Record) error {
	if p.config.Readiness == nil {
		return nil
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	nonce := hex.EncodeToString(random[:])
	receipts, err := p.config.Readiness.Collect(ctx, record, nonce)
	if err != nil {
		return err
	}
	if err = validateReadinessSet(record, receipts, nonce, p.config.Readiness.Keys, time.Now().UTC()); err != nil {
		return err
	}
	if err = p.config.CheckAuthority(ctx); err != nil {
		return err
	}
	record.ReadyEvidence = receipts
	record.ReadinessNonce = nonce
	record.State = "ready"
	return p.save(ctx, &record)
}
func sameReadiness(a, b []SignedReadiness) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].KeyID != b[i].KeyID || !bytes.Equal(a[i].Payload, b[i].Payload) || !bytes.Equal(a[i].Signature, b[i].Signature) {
			return false
		}
	}
	return true
}
