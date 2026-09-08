package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type relocationWorkflowIssuer struct {
	plan             placementrelocation.Plan
	key              ed25519.PrivateKey
	prepares, issues int
	issueErr         error
}

func (i *relocationWorkflowIssuer) Head(context.Context, string) (placementtransition.Signed, error) {
	return i.plan.PriorProof, nil
}
func (i *relocationWorkflowIssuer) Load(context.Context, string) (placementtransition.Signed, error) {
	return placementtransition.Signed{}, placementtransition.ErrMissing
}
func (i *relocationWorkflowIssuer) Prepare(_ context.Context, request placementtransition.Request) (placementtransition.Signed, error) {
	i.prepares++
	digest, err := placementtransition.RequestDigest(request)
	if err != nil {
		return placementtransition.Signed{}, err
	}
	return placementtransition.SignEvidence("issuer", i.key, placementtransition.Prepared{SchemaVersion: 1, Kind: "prepared_epoch", Request: request, RequestDigest: digest, PriorGeneration: request.Generation - 1, PreviousProofDigest: placementrelocation.BytesDigest(i.plan.PriorProof.Payload), AuthorityEpoch: 1, LeaseID: "lease-1", JournalRevision: 1})
}
func (i *relocationWorkflowIssuer) Issue(context.Context, placementtransition.Request, *placementtransition.Signed, []placementtransition.Signed) (placementtransition.Signed, error) {
	i.issues++
	return placementtransition.Signed{}, i.issueErr
}

// Seed genuine journal admission/progress records. Readiness evidence is signed
// test evidence for the original admitted tuple; it never qualifies successor
// readiness, whose callbacks below must remain unreachable.
func relocationWorkflowAdmission(t *testing.T, journal *databaseadmission.NATSJournal) databaseadmission.Record {
	t.Helper()
	record, _ := transitionFixture(t)
	record.CreatedAt = time.Now().UTC()
	record.State = "accepted"
	for n := range record.Targets {
		target := &record.Targets[n]
		target.Installed = false
		target.Provision.CryptoEndpoint = "https://unit-crypto.kms.sa-saopaulo-1.oraclecloud.com"
		target.Provision.KEKID = "ocid1.key.oc1.sa-saopaulo-1.unit"
		target.Provision.KEKVersionID = "ocid1.keyversion.oc1.sa-saopaulo-1.unit"
	}
	for n := range record.PlacementTargets {
		record.PlacementTargets[n].Proposed = false
	}
	var err error
	record.Revision, err = journal.Save(t.Context(), databaseadmission.ScopeKey(record.Request), 0, record)
	if err != nil {
		t.Fatal("seed immutable admission", err)
	}
	record.State = "ready"
	for n := range record.Targets {
		record.Targets[n].Installed = true
	}
	for n := range record.PlacementTargets {
		record.PlacementTargets[n].Proposed = true
	}
	for _, purpose := range []string{"data", "backup", "checkpoint"} {
		p := record.Targets[0].Provision
		p.Binding.Purpose = purpose
		record.Wrapped = append(record.Wrapped, keylease.Entry{Binding: p.Binding, CryptoEndpoint: p.CryptoEndpoint, KEKID: p.KEKID, KEKVersionID: p.KEKVersionID, Ciphertext: "wrapped-" + purpose, LeaseSeconds: p.LeaseSeconds, NotAfter: p.NotAfter})
	}
	record.ReadinessNonce = strings.Repeat("e", 64)
	for _, target := range record.Targets {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		stage := newPlacementStageRequest(target.Proposal)
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(stage.Proposal)
		if err != nil {
			t.Fatal(err)
		}
		proof := databaseadmission.Readiness{SchemaVersion: 1, Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID, KeyVersion: record.KeyVersion, OperationID: databaseadmission.PlacementOperationID(record.Request), MemberIdentity: target.ServerIdentity, Region: target.Region, MembershipEpoch: stage.Proposal.Epoch, Generation: stage.Proposal.Generation, PlacementDigest: placementrelocation.BytesDigest(encoded), Physical: databaseadmission.PhysicalReadiness{SnapshotDigest: strings.Repeat("a", 64), WALCheckpointDigest: strings.Repeat("b", 64)}, Causal: databaseadmission.CausalReadiness{CutDigest: strings.Repeat("c", 64), Frontier: map[string]uint64{"gru": 10}, RootDigest: strings.Repeat("d", 64)}, ObservedAtUnixMS: uint64(time.Now().UnixMilli()), Nonce: record.ReadinessNonce}
		payload, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		record.ReadyEvidence = append(record.ReadyEvidence, databaseadmission.SignedReadiness{KeyID: target.MemberID, Payload: payload, Signature: ed25519.Sign(key, append([]byte("terrabase-database-readiness-v1\x00"), payload...))})
	}
	record.Revision, err = journal.Save(t.Context(), databaseadmission.ScopeKey(record.Request), record.Revision, record)
	if err != nil {
		t.Fatal("seed ready admission", err)
	}
	return record
}

func TestHostRelocationUnknownStageRestartRequiresFinalProof(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	store := openRotationTestLeaseStore(t, t.Context(), connection, true)
	lease := rotationTestLease(1, "global-controller-gru-relocation-workflow")
	putRotationTestLease(t, t.Context(), store, lease)
	config := authorityjournal.Config{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: 1, LeaseID: lease.LeaseId}
	admissionConfig := databaseadmission.NATSJournalConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: 1, LeaseID: lease.LeaseId}
	admission, err := databaseadmission.NewNATSJournal(admissionConfig)
	if err != nil {
		t.Fatal(err)
	}
	record := relocationWorkflowAdmission(t, admission)
	request, err := transitionRequest(record)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := placementtransition.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := placementtransition.SignEvidence("issuer", key, placementtransition.Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: request, RequestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	removed := record.PlacementTargets[0]
	stage := newPlacementStageRequest(removed.Proposal)
	candidate := placementrelocation.Target{MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FAZ", Region: removed.Region}
	candidate.ServerIdentity = "spiffe://terrascale.tech/" + stage.Proposal.Environment + "/terrabase-member/" + stage.Proposal.Cluster + "/" + candidate.MemberID
	revisions := map[string]uint64{candidate.ServerIdentity: 0}
	for _, target := range record.PlacementTargets {
		revisions[target.ServerIdentity] = 1
	}
	plan, err := placementrelocation.Build(placementrelocation.BuildInput{OperationID: "remove-stage/placement", RemovedIdentity: removed.ServerIdentity, Replacement: candidate, PriorProof: prior, PriorStage: removed.Proposal, Records: []databaseadmission.Record{record}, Revisions: revisions})
	if err != nil {
		t.Fatal(err)
	}
	unknown := errors.New("Stage applied but reply lost")
	noProof := errors.New("final epoch proof unavailable")
	issuer := &relocationWorkflowIssuer{plan: plan, key: key, issueErr: noProof}
	stages, drains, installs := 0, 0, 0
	stageUnknown := true
	retainedStage := map[string][]byte{}
	makeWorker := func() *productionHostRelocation {
		journal, err := placementrelocation.New(config)
		if err != nil {
			t.Fatal(err)
		}
		restartedAdmission, err := databaseadmission.NewNATSJournal(admissionConfig)
		if err != nil {
			t.Fatal(err)
		}
		return &productionHostRelocation{Journal: journal, Admission: restartedAdmission, Issuer: issuer, ProofKey: public, Check: func(context.Context) error { return nil }, Plan: func(context.Context, hostremoval.RemovalRequest, []databaseadmission.Record) (placementrelocation.Plan, error) {
			return plan, nil
		}, Install: func(context.Context, placementrelocation.Plan) error { installs++; return nil }, Stage: func(_ context.Context, host, op string, request *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
			stages++
			encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if previous := retainedStage[host]; previous != nil && string(previous) != string(encoded) {
				t.Fatal("restart changed Stage intent")
			}
			if op != plan.OperationID {
				t.Fatal("restart changed operation")
			}
			retainedStage[host] = encoded
			if stageUnknown {
				return nil, unknown
			}
			return &pb.PlacementProposalResponse{Revision: request.ExpectedRevision + 1, Proposal: request.Proposal, Status: pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING}, nil
		}, Drain: func(context.Context, placementtransition.Request, placementtransition.Proof) ([]placementtransition.Signed, error) {
			drains++
			return nil, nil
		}, Deliver: func(context.Context, string, string, uint64, placementtransition.Signed) (*pb.PlacementAcceptanceResponse, error) {
			t.Fatal("delivered without final proof")
			return nil, nil
		}, Usage: func(context.Context, string, []databaseadmission.Record) error {
			t.Fatal("usage without final proof")
			return nil
		}, Ready: func(context.Context, string, []databaseadmission.Record) ([]databaseadmission.Record, error) {
			t.Fatal("readiness without final proof")
			return nil, nil
		}}
	}
	worker := makeWorker()
	revision, replacements, err := worker.Capture(t.Context(), hostremoval.RemovalRequest{OperationID: "remove-stage", Member: hostremoval.MemberObservation{Identity: removed.ServerIdentity}}, nil)
	if err != nil || len(replacements) != 1 {
		t.Fatalf("capture: %v %+v", err, replacements)
	}
	for attempt := range 2 {
		if attempt == 1 {
			worker = makeWorker()
		}
		if err := worker.Replace(t.Context(), replacements[0]); !errors.Is(err, unknown) {
			t.Fatalf("unknown Stage attempt %d: %v", attempt, err)
		}
		if stages != attempt+1 || drains != 0 || issuer.issues != 0 || issuer.prepares != 1 {
			t.Fatalf("Stage uncertainty crossed effect boundary: stages=%d drains=%d issues=%d prepares=%d", stages, drains, issuer.issues, issuer.prepares)
		}
	}
	stageUnknown = false
	worker = makeWorker()
	if err := worker.Replace(t.Context(), replacements[0]); !errors.Is(err, noProof) {
		t.Fatalf("missing final proof: %v", err)
	}
	if drains != 1 || issuer.issues != 1 || issuer.prepares != 1 {
		t.Fatalf("retained prepare/retry: drains=%d issues=%d prepares=%d", drains, issuer.issues, issuer.prepares)
	}
	if err := worker.Fence(t.Context(), "remove-stage", removed.ServerIdentity, replacements); err == nil {
		t.Fatal("missing proof authorized host removal")
	}
	if err := worker.Revalidate(t.Context(), "remove-stage", removed.ServerIdentity, revision); err == nil {
		t.Fatal("uncommitted successor authorized host removal")
	}
	retained, err := worker.Journal.Load(t.Context(), plan.OperationID)
	if err != nil || retained.Ready || len(retained.Accepted.Payload) > 0 || len(retained.Prepared.Payload) == 0 {
		t.Fatalf("unexpected durable stage: %+v %v", retained, err)
	}
	current, err := worker.Admission.CurrentRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := placementrelocation.Digest([]databaseadmission.Record{record})
	after, _ := placementrelocation.Digest(current)
	if before != after {
		t.Fatal("incomplete successor changed admitted current placement")
	}
	if installs != 3 {
		t.Fatalf("expected idempotent install retry, got %d", installs)
	}
}
