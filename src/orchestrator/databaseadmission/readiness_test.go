package databaseadmission

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func readinessFixture(t *testing.T, r Record, nonce string) ([]SignedReadiness, map[string]ReadinessKey, map[string]ed25519.PrivateKey) {
	t.Helper()
	receipts := []SignedReadiness{}
	keys := map[string]ReadinessKey{}
	private := map[string]ed25519.PrivateKey{}
	for _, target := range r.Targets {
		public, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[target.ServerIdentity] = ReadinessKey{KeyID: target.MemberID, PublicKey: public}
		private[target.ServerIdentity] = secret
		stage := new(pb.PlacementStageRequest)
		if proto.Unmarshal(target.Proposal, stage) != nil {
			t.Fatal("proposal")
		}
		encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(stage.Proposal)
		digest := sha256.Sum256(encoded)
		proof := Readiness{SchemaVersion: 1, Environment: r.Request.Environment, TenantID: r.Request.TenantID, ProjectID: r.Request.ProjectID, DatabaseID: r.DatabaseID, KeyVersion: r.KeyVersion, OperationID: PlacementOperationID(r.Request), MemberIdentity: target.ServerIdentity, Region: target.Region, MembershipEpoch: stage.Proposal.Epoch, Generation: stage.Proposal.Generation, PlacementDigest: hex.EncodeToString(digest[:]), Physical: PhysicalReadiness{strings.Repeat("a", 64), strings.Repeat("b", 64)}, Causal: CausalReadiness{strings.Repeat("c", 64), map[string]uint64{strings.ToLower(r.Targets[0].Region): 10}, strings.Repeat("d", 64)}, ObservedAtUnixMS: uint64(time.Now().UnixMilli()), Nonce: nonce}
		payload, _ := json.Marshal(proof)
		receipts = append(receipts, SignedReadiness{target.MemberID, payload, ed25519.Sign(secret, append([]byte("terrabase-database-readiness-v1\x00"), payload...))})
	}
	return receipts, keys, private
}
func TestReadinessRequiresExactSignedRF2AndCausalBoundary(t *testing.T) {
	record := journalFixture(t)
	nonce := strings.Repeat("e", 64)
	receipts, keys, private := readinessFixture(t, record, nonce)
	if err := validateReadinessSet(record, receipts, nonce, keys, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"physical", "causal", "nonce", "scope", "epoch", "stale", "signer"} {
		t.Run(mutation, func(t *testing.T) {
			changed := append([]SignedReadiness(nil), receipts...)
			var proof Readiness
			_ = json.Unmarshal(changed[1].Payload, &proof)
			switch mutation {
			case "physical":
				proof.Physical.WALCheckpointDigest = strings.Repeat("f", 64)
			case "causal":
				proof.Causal.Frontier[strings.ToLower(record.Targets[0].Region)]++
			case "nonce":
				proof.Nonce = strings.Repeat("a", 64)
			case "scope":
				proof.ProjectID = record.DatabaseID
			case "epoch":
				proof.MembershipEpoch++
			case "stale":
				proof.ObservedAtUnixMS = uint64(time.Now().Add(-2 * time.Minute).UnixMilli())
			case "signer":
				changed[1].KeyID = "foreign"
			}
			changed[1].Payload, _ = json.Marshal(proof)
			changed[1].Signature = ed25519.Sign(private[proof.MemberIdentity], append([]byte("terrabase-database-readiness-v1\x00"), changed[1].Payload...))
			if validateReadinessSet(record, changed, nonce, keys, time.Now()) == nil {
				t.Fatal("inconsistent evidence accepted")
			}
		})
	}
	if validateReadinessSet(record, receipts[:1], nonce, keys, time.Now()) == nil {
		t.Fatal("one host established RF2")
	}
}
func TestReadyEvidencePersistsOnlyAfterVerifiedCollection(t *testing.T) {
	journal := NewMemoryJournal()
	record := journalFixture(t)
	key := ScopeKey(record.Request)
	revision, err := journal.Save(t.Context(), key, 0, record)
	if err != nil {
		t.Fatal(err)
	}
	record.Revision = revision
	record.Wrapped = journalWrapped(record)
	record.State = "placement_pending"
	for i := range record.Targets {
		record.Targets[i].Installed = true
		record.Targets[i].Proposed = true
	}
	record.Revision, err = journal.Save(t.Context(), key, record.Revision, record)
	if err != nil {
		t.Fatal(err)
	}
	config := pipelineConfig(t, journal)
	// Collection receives a fresh unpredictable challenge, then signs actual
	// boundary observations. The test source signs equivalent installed cuts.
	_, keys, private := readinessFixture(t, record, strings.Repeat("e", 64))
	config.Readiness = &ReadinessConfig{Keys: keys, Collect: func(_ context.Context, r Record, nonce string) ([]SignedReadiness, error) {
		values, _, _ := readinessFixture(t, r, nonce)
		for i := range values {
			var proof Readiness
			_ = json.Unmarshal(values[i].Payload, &proof)
			values[i].KeyID = keys[proof.MemberIdentity].KeyID
			values[i].Signature = ed25519.Sign(private[proof.MemberIdentity], append([]byte("terrabase-database-readiness-v1\x00"), values[i].Payload...))
		}
		return values, nil
	}}
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = pipeline.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	ready, _, err := journal.Load(t.Context(), key)
	if err != nil || ready.State != "ready" || len(ready.ReadyEvidence) != 2 {
		t.Fatal("proof not durably retained", err)
	}
	if result(ready).State != "ready" {
		t.Fatal("verified readiness not exposed")
	}
}
