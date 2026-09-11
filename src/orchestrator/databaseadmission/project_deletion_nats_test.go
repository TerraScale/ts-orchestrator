package databaseadmission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNATSProjectDeletionFenceCapturesPendingAdmissionBeforeFence(t *testing.T) {
	journal, cleanup := projectDeletionNATSJournal(t)
	defer cleanup()
	pipeline := projectDeletionPipeline(t, journal)
	request := projectDeletionCreateRequest("before-fence")
	accepted, err := pipeline.Accept(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State != "accepted" {
		t.Fatalf("accepted state=%q", accepted.State)
	}
	deletion, err := journal.BeginProjectDeletion(t.Context(), ProjectDeletionRequest{
		Environment: "production", TenantID: request.TenantID, ProjectID: request.ProjectID,
		OperationID: "01ARZ3NDEKTSV4RRFFQ69G5FC0", PolicyFingerprint: "policy-v1",
	}, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(deletion.Targets) != 1 || deletion.Targets[0].Identity.DatabaseID != accepted.DatabaseID {
		t.Fatalf("fence snapshot omitted pending admission: %+v", deletion.Targets)
	}
	if _, err := pipeline.Accept(t.Context(), projectDeletionCreateRequest("after-fence")); !errors.Is(err, ErrConflict) {
		t.Fatalf("post-fence create error=%v, want ErrConflict", err)
	}
}

func TestNATSProjectDeletionFenceWinsBeforePipelineFinalSave(t *testing.T) {
	journal, cleanup := projectDeletionNATSJournal(t)
	defer cleanup()
	config := pipelineConfig(t, journal)
	planned := make(chan struct{})
	release := make(chan struct{})
	basePlan := config.Plan
	config.Plan = func(ctx context.Context, record Record) (Plan, error) {
		close(planned)
		<-release
		return basePlan(ctx, record)
	}
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	request := projectDeletionCreateRequest("racing-create")
	result := make(chan error, 1)
	go func() {
		_, acceptErr := pipeline.Accept(t.Context(), request)
		result <- acceptErr
	}()
	<-planned
	_, err = journal.BeginProjectDeletion(t.Context(), ProjectDeletionRequest{
		Environment: "production", TenantID: request.TenantID, ProjectID: request.ProjectID,
		OperationID: "01ARZ3NDEKTSV4RRFFQ69G5FC1", PolicyFingerprint: "policy-v1",
	}, time.Unix(1_700_000_001, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrConflict) {
		t.Fatalf("fenced final save error=%v, want ErrConflict", err)
	}
	deletion, err := journal.BeginProjectDeletion(t.Context(), ProjectDeletionRequest{
		Environment: "production", TenantID: request.TenantID, ProjectID: request.ProjectID,
		OperationID: "01ARZ3NDEKTSV4RRFFQ69G5FC1", PolicyFingerprint: "policy-v1",
	}, time.Unix(1_700_000_002, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(deletion.Targets) != 0 {
		t.Fatalf("fenced create leaked into snapshot: %+v", deletion.Targets)
	}
}

func TestNATSProjectDeletionFenceWinsBeforeBranchFinalSave(t *testing.T) {
	journal, cleanup := projectDeletionNATSJournal(t)
	defer cleanup()
	source := restoreSourceFixture(t, journal)
	config := pipelineConfig(t, journal)
	basePlan := config.Plan
	planned := make(chan struct{})
	release := make(chan struct{})
	config.Plan = func(ctx context.Context, record Record) (Plan, error) {
		close(planned)
		<-release
		return basePlan(ctx, record)
	}
	config.BranchRestore = &BranchRestoreConfig{Keys: map[string]ReadinessKey{"unused": {}}}
	pipeline := &Pipeline{config: config}
	request := source.Request
	request.Name = "branch-racing"
	request.OperationID = "branch-racing-operation"
	request.ParentDatabaseID = source.DatabaseID
	request.RecoveryPointID = strings.Repeat("a", 64)
	request.JournalCut = "cut-1"
	request.RestoreEpoch = 1
	request.RestoreProvider = "oci"
	result := make(chan error, 1)
	go func() { _, err := pipeline.Accept(t.Context(), request); result <- err }()
	<-planned
	beginProjectFence(t, journal, request, "01ARZ3NDEKTSV4RRFFQ69G5FC3")
	close(release)
	if err := <-result; !errors.Is(err, ErrConflict) {
		t.Fatalf("fenced branch final save error=%v, want ErrConflict", err)
	}
}

func TestNATSProjectDeletionFenceWinsBeforeRestoreFinalSave(t *testing.T) {
	journal, cleanup := projectDeletionNATSJournal(t)
	defer cleanup()
	source := restoreSourceFixture(t, journal)
	config := pipelineConfig(t, journal)
	resolved := make(chan struct{})
	release := make(chan struct{})
	config.Restore = &RestoreConfig{
		Resolve: func(context.Context, Record, RestoreSelection) (RestoreAdmissionFacts, error) {
			close(resolved)
			<-release
			facts := restoreFactsFixture()
			facts.SourceDigest = RestoreSourceDigest(source)
			return facts, nil
		},
		Restore: func(context.Context, Record) ([]byte, error) { return nil, errors.New("unreachable") },
	}
	pipeline := &Pipeline{config: config}
	request := RestoreRequest{Environment: source.Request.Environment, TenantID: source.Request.TenantID, ProjectID: source.Request.ProjectID, SourceDatabaseID: source.DatabaseID, Name: "restore-racing", OperationID: "restore-racing-operation", Selection: RestoreSelection{Kind: "latest"}}
	result := make(chan error, 1)
	go func() { _, err := pipeline.AcceptRestore(t.Context(), request); result <- err }()
	<-resolved
	projectFenceRequest := requestToProjectDeletion(request, "01ARZ3NDEKTSV4RRFFQ69G5FC4")
	if _, err := journal.BeginProjectDeletion(t.Context(), projectFenceRequest, time.Unix(1_700_000_010, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrConflict) {
		t.Fatalf("fenced restore final save error=%v, want ErrConflict", err)
	}
}

func TestNATSProjectDeletionFenceReplayAndStaleReaderAfterRestart(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	connection := cluster.connect(t)
	store := openAdmissionLeaseStore(t, ctx, connection, true)
	candidate := "global-controller-gru-project-restart"
	putAdmissionLease(t, ctx, store, admissionLease(1, candidate))
	firstJournal := newAdmissionJournalClient(t, connection, 1, candidate)
	request := ProjectDeletionRequest{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAZ", OperationID: "01ARZ3NDEKTSV4RRFFQ69G5FC5", PolicyFingerprint: "policy-v1"}
	first, err := firstJournal.BeginProjectDeletion(ctx, request, time.Unix(1_700_000_020, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	cluster.restart(t)
	connection = cluster.connect(t)
	store = openAdmissionLeaseStore(t, ctx, connection, false)
	putAdmissionLease(t, ctx, store, admissionLease(2, "global-controller-gru-project-restart-2"))
	stale := newAdmissionJournalClient(t, connection, 1, candidate)
	if _, _, err := stale.Load(ctx, projectDeletionKey(request)); !errors.Is(err, ErrEpochFenced) {
		t.Fatalf("stale project-deletion read error=%v, want ErrEpochFenced", err)
	}
	if _, err := stale.BeginProjectDeletion(ctx, request, time.Unix(1_700_000_021, 0).UTC()); !errors.Is(err, ErrEpochFenced) {
		t.Fatalf("stale project-deletion write error=%v, want ErrEpochFenced", err)
	}
	live := newAdmissionJournalClient(t, connection, 2, "global-controller-gru-project-restart-2")
	replay, err := live.BeginProjectDeletion(ctx, request, time.Unix(1_700_000_022, 0).UTC())
	if err != nil || replay.RequestedAt != first.RequestedAt || replay.Revision != first.Revision {
		t.Fatalf("restart replay changed durable fence: first=%+v replay=%+v err=%v", first, replay, err)
	}
}

func beginProjectFence(t *testing.T, journal *NATSJournal, request Request, operation string) {
	t.Helper()
	if _, err := journal.BeginProjectDeletion(t.Context(), ProjectDeletionRequest{Environment: request.Environment, TenantID: request.TenantID, ProjectID: request.ProjectID, OperationID: operation, PolicyFingerprint: "policy-v1"}, time.Unix(1_700_000_010, 0).UTC()); err != nil {
		t.Fatal(err)
	}
}

func requestToProjectDeletion(request RestoreRequest, operation string) ProjectDeletionRequest {
	return ProjectDeletionRequest{Environment: request.Environment, TenantID: request.TenantID, ProjectID: request.ProjectID, OperationID: operation, PolicyFingerprint: "policy-v1"}
}

func projectDeletionNATSJournal(t *testing.T) (*NATSJournal, func()) {
	t.Helper()
	cluster := newAdmissionJournalCluster(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	connection := cluster.connect(t)
	store := openAdmissionLeaseStore(t, ctx, connection, true)
	candidate := "global-controller-gru-project-deletion"
	putAdmissionLease(t, ctx, store, admissionLease(1, candidate))
	journal := newAdmissionJournalClient(t, connection, 1, candidate)
	return journal, func() {
		cancel()
		connection.Close()
	}
}

func projectDeletionPipeline(t *testing.T, journal Journal) *Pipeline {
	t.Helper()
	config := pipelineConfig(t, journal)
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return pipeline
}

func projectDeletionCreateRequest(name string) Request {
	return Request{
		Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
		Name: name, OperationID: fmt.Sprintf("project-deletion-%s", name), Regions: []string{"GRU"},
	}
}
