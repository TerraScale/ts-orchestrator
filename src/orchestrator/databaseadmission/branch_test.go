package databaseadmission

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"slices"
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
		proof := BranchRestoreEvidence{RecoveryPointID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", SchemaVersion: 1, Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, ParentDatabaseID: record.Request.ParentDatabaseID, DatabaseID: record.DatabaseID, KeyVersion: record.KeyVersion, OperationID: PlacementOperationID(record.Request), MemberIdentity: target.ServerIdentity, Region: target.Region, SourceSnapshotDigest: strings.Repeat("b", 64), RestoredSnapshotDigest: strings.Repeat("c", 64), CutDigest: strings.Repeat("d", 64), Nonce: nonce, ObservedAtUnixMS: now.UnixMilli()}
		if record.BranchSource == nil {
			source := BranchSourceEvidence{SchemaVersion: 1, Environment: proof.Environment, TenantID: proof.TenantID, ProjectID: proof.ProjectID, ParentDatabaseID: proof.ParentDatabaseID, DatabaseID: proof.DatabaseID, KeyVersion: proof.KeyVersion, OperationID: proof.OperationID, MemberIdentity: proof.MemberIdentity, Region: proof.Region, RecoveryPointID: proof.RecoveryPointID, SourceSnapshotDigest: proof.SourceSnapshotDigest, CutDigest: proof.CutDigest, Nonce: nonce, ObservedAtUnixMS: proof.ObservedAtUnixMS}
			data, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			record.BranchSource = &BranchSource{Nonce: nonce, Evidence: SignedReadiness{KeyID: target.MemberID, Payload: data, Signature: ed25519.Sign(private, append([]byte("terrabase-database-branch-source-v1\x00"), data...))}}
		}
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
	pipeline := &Pipeline{config: Config{Journal: branchParentJournal{parent: parent}, Authorize: func(_ context.Context, source Request) error {
		return nil
	}}}
	if err := pipeline.validateParent(t.Context(), request); err != nil {
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

func TestBranchRestoreTransportBindsHostAndAuthorityOperation(t *testing.T) {
	record := journalFixture(t)
	record.Request.ParentDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
	target := record.Targets[0]
	config := HostConfig{Environment: record.Request.Environment, Region: target.Region, MemberID: target.MemberID}
	request := BranchRestoreRequest{Capture: true, Admission: Admission{CreatedAt: record.CreatedAt.UnixMilli(), Request: record.Request, DatabaseID: record.DatabaseID, KeyVersion: record.KeyVersion, Region: target.Region, MemberID: target.MemberID}, AuthorityOperationID: PlacementOperationID(record.Request), Nonce: strings.Repeat("a", 64)}
	if request.Admission.CreatedAt != record.CreatedAt.UnixMilli() {
		t.Fatal("branch restore changed authoritative creation timestamp")
	}
	if err := validateBranchRestoreRequest(config, request); err != nil {
		t.Fatal(err)
	}
	request.Admission.CreatedAt = 0
	if validateBranchRestoreRequest(config, request) == nil {
		t.Fatal("zero creation timestamp accepted")
	}
	request.Admission.CreatedAt = record.CreatedAt.UnixMilli()
	wrong := request
	wrong.Admission.MemberID = record.Targets[1].MemberID
	if err := validateBranchRestoreRequest(config, wrong); err == nil {
		t.Fatal("wrong host accepted")
	}
	wrong = request
	wrong.AuthorityOperationID = "unbound"
	if err := validateBranchRestoreRequest(config, wrong); err == nil {
		t.Fatal("unbound operation accepted")
	}
	_, subscribe, err := HostPermissions(target.ServerIdentity)
	subject, _ := BranchRestoreSubject(target.ServerIdentity)
	if err != nil || !slices.Contains(subscribe, subject) {
		t.Fatal("branch host grant missing", err)
	}
	other, _ := BranchRestoreSubject(record.Targets[1].ServerIdentity)
	if slices.Contains(subscribe, other) {
		t.Fatal("cross-host branch grant")
	}
}
