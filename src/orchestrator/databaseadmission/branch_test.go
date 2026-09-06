package databaseadmission

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"
)

func TestBranchRestoreRequiresEveryTargetAndParentBoundSignatures(t *testing.T) {
	record := journalFixture(t)
	record.Request.ParentDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	nonce := strings.Repeat("a", 64)
	now := time.Now()
	keys := map[string]ReadinessKey{}
	var receipts []SignedReadiness
	for _, target := range record.Targets {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[target.ServerIdentity] = ReadinessKey{KeyID: target.MemberID, PublicKey: public}
		proof := BranchRestoreEvidence{SchemaVersion: 1, Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, ParentDatabaseID: record.Request.ParentDatabaseID, DatabaseID: record.DatabaseID, KeyVersion: record.KeyVersion, OperationID: PlacementOperationID(record.Request), MemberIdentity: target.ServerIdentity, Region: target.Region, SourceSnapshotDigest: strings.Repeat("b", 64), RestoredSnapshotDigest: strings.Repeat("c", 64), CutDigest: strings.Repeat("d", 64), Nonce: nonce, ObservedAtUnixMS: now.UnixMilli()}
		payload, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, SignedReadiness{KeyID: target.MemberID, Payload: payload, Signature: ed25519.Sign(private, append([]byte("terrabase-database-branch-restore-v1\x00"), payload...))})
	}
	if err := validateBranchRestore(record, receipts, nonce, keys, now); err != nil {
		t.Fatal(err)
	}
	if err := validateBranchRestore(record, receipts[:1], nonce, keys, now); err == nil {
		t.Fatal("partial RF2 restore accepted")
	}
	changed := record
	changed.Request.ParentDatabaseID = record.DatabaseID
	if err := validateBranchRestore(changed, receipts, nonce, keys, now); err == nil {
		t.Fatal("receipt accepted for different parent")
	}
	if err := validateBranchRestore(record, receipts, strings.Repeat("e", 64), keys, now); err == nil {
		t.Fatal("replayed nonce accepted")
	}
	if err := validateBranchRestore(record, receipts, nonce, keys, now.Add(2*time.Minute)); err == nil {
		t.Fatal("stale receipt accepted")
	}
	receipts[0].Signature[0] ^= 1
	if err := validateBranchRestore(record, receipts, nonce, keys, now); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestBranchAdmissionWithoutRestoreCannotAllocateEmptyDatabase(t *testing.T) {
	journal := NewMemoryJournal()
	pipeline, err := New(pipelineConfig(t, journal))
	if err != nil {
		t.Fatal(err)
	}
	request := journalFixture(t).Request
	request.ParentDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	if _, err := pipeline.Accept(t.Context(), request); err == nil {
		t.Fatal("branch without restore accepted")
	}
	records, err := journal.List(t.Context())
	if err != nil || len(records) != 0 {
		t.Fatal("unrestorable branch persisted", err)
	}
}

type branchParentJournal struct {
	Journal
	parent Record
}

func (j branchParentJournal) List(context.Context) ([]Record, error) { return []Record{j.parent}, nil }

func TestBranchParentScopeAndImmutablePlacement(t *testing.T) {
	parent := journalFixture(t)
	parent.State = "ready"
	request := parent.Request
	request.Name = "branch"
	request.ParentDatabaseID = parent.DatabaseID
	authorized := false
	pipeline := &Pipeline{config: Config{Journal: branchParentJournal{parent: parent}, Authorize: func(_ context.Context, source Request) error {
		authorized = source.Name == parent.Request.Name
		return nil
	}}}
	if err := pipeline.validateParent(t.Context(), request); err != nil || !authorized {
		t.Fatal("parent was not authorized", err)
	}
	for _, change := range []func(*Request){
		func(r *Request) { r.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FAX" },
		func(r *Request) { r.Environment = "other" },
		func(r *Request) { r.Regions = []string{"FRA"} },
		func(r *Request) { r.Residency = "br-only" },
	} {
		changed := request
		change(&changed)
		if err := pipeline.validateParent(t.Context(), changed); err == nil {
			t.Fatal("parent constraint bypass accepted", changed)
		}
	}
	parent.State = "placement_pending"
	pipeline.config.Journal = branchParentJournal{parent: parent}
	if err := pipeline.validateParent(t.Context(), request); err == nil {
		t.Fatal("unready parent accepted")
	}
}
