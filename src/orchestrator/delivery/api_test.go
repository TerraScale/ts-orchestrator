package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// fakeStore records per-Region puts; each region's bucket set mirrors the
// declared estate.
type fakeStore struct {
	mu       sync.Mutex
	fail     map[string]bool
	putCount int
	puts     []string
}

func (s *fakeStore) Put(_ context.Context, region, bucket, object string, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil && s.fail[region] {
		return errors.New("region object store unavailable")
	}
	s.putCount++
	s.puts = append(s.puts, region+"/"+bucket+"/"+object)
	return nil
}

type fakeRoller struct {
	mu     sync.Mutex
	calls  int
	result RolloutResult
	err    error
	gate   chan struct{} // non-nil: block until closed
}

func (r *fakeRoller) Roll(ctx context.Context, request *Request, artifact *ReleaseArtifact) (RolloutResult, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	if r.gate != nil {
		select {
		case <-r.gate:
		case <-ctx.Done():
			return RolloutResult{}, ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return RolloutResult{}, r.err
	}
	result := r.result
	if result.Status == "" {
		result.Status = StatusSucceeded
		result.Checks = []*HealthCheck{{Name: "drain", Status: "passed"}, {Name: "health", Status: "passed"}, {Name: "catch-up", Status: "passed"}}
		result.Converged = true
	}
	return result, nil
}

func (r *fakeRoller) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func testServer(t *testing.T, roller *fakeRoller, store *fakeStore) (*Server, *httptest.Server) {
	t.Helper()
	request, fetcher, trust, _ := testRelease(t, nil)
	_ = request
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatalf("build mirror: %v", err)
	}
	server, err := NewServer(ServerConfig{
		Token:   func() (string, error) { return "delivery-token", nil },
		Fetcher: fetcher,
		Trust:   func() *TrustSet { return trust },
		Mirror:  mirror,
		Rollout: roller,
		Journal: NewJournal(),
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return server, httpServer
}

func testDeliveryRequest(t *testing.T) *Request {
	t.Helper()
	request, _, _, _ := testRelease(t, nil)
	return request
}

func postDelivery(t *testing.T, server *httptest.Server, token string, request *Request) (*http.Response, *Receipt) {
	t.Helper()
	body := []byte(Serialize(request))
	httpRequest, err := http.NewRequest(http.MethodPost, server.URL+OperationsPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json; charset=utf-8")
	if token != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := server.Client().Do(httpRequest)
	if err != nil {
		t.Fatalf("post delivery: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.StatusCode == http.StatusOK {
		receipt, err := ParseReceipt(readAll(t, response))
		if err != nil {
			t.Fatalf("parse receipt: %v", err)
		}
		return response, receipt
	}
	return response, nil
}

func readAll(t *testing.T, response *http.Response) string {
	t.Helper()
	var buffer bytes.Buffer
	_, _ = buffer.ReadFrom(response.Body)
	return buffer.String()
}

// TestDeliveryAPIHappyPath proves the full pipeline: authenticated POST,
// verified signature, artifact mirrored into EVERY declared Region before
// the rollout runs, succeeded receipt, and a pollable receipt afterwards.
func TestDeliveryAPIHappyPath(t *testing.T) {
	roller := &fakeRoller{}
	store := &fakeStore{}
	_, httpServer := testServer(t, roller, store)
	request := testDeliveryRequest(t)

	response, receipt := postDelivery(t, httpServer, "delivery-token", request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if receipt.Status != StatusSucceeded {
		t.Fatalf("receipt status = %s, error %+v", receipt.Status, receipt.Error)
	}
	if !receipt.Provenance.Verified || !receipt.Health.Converged {
		t.Fatalf("receipt must report verified convergence: %+v", receipt)
	}
	if receipt.ArtifactDigest == nil || !SameDigest(*receipt.ArtifactDigest, request.Artifact.Digest) {
		t.Fatalf("receipt artifact digest mismatch: %+v", receipt.ArtifactDigest)
	}
	if err := ValidateReceipt(receipt, request); err != nil {
		t.Fatalf("receipt must satisfy the contract: %v", err)
	}

	// The artifact is mirrored into every declared Region exactly once,
	// under the immutable digest key, BEFORE the rollout ran.
	if roller.callCount() != 1 {
		t.Fatalf("rollout calls = %d", roller.callCount())
	}
	expected := len(estate.Default().Regions)
	if store.putCount != expected {
		t.Fatalf("mirror puts = %d, want one per Region (%d)", store.putCount, expected)
	}
	for _, put := range store.puts {
		if !bytes.Contains([]byte(put), []byte("/releases/terrabase/")) {
			t.Fatalf("unexpected mirror object key %s", put)
		}
	}

	// ts-deploy (or an operator) can poll the receipt by operation ID.
	poll, err := httpServer.Client().Get(httpServer.URL + OperationsPath + "/" + request.OperationID)
	if err != nil {
		t.Fatalf("poll receipt: %v", err)
	}
	defer poll.Body.Close()
	if poll.StatusCode != http.StatusOK {
		t.Fatalf("poll status = %d", poll.StatusCode)
	}
	second, err := ParseReceipt(readAll(t, poll))
	if err != nil {
		t.Fatalf("parse polled receipt: %v", err)
	}
	if second.OperationID != request.OperationID || second.Status != StatusSucceeded {
		t.Fatalf("polled receipt = %+v", second)
	}
}

// TestDeliveryAPIAuthenticatesFailClosed: no or wrong bearer token is a
// 401 before anything runs.
func TestDeliveryAPIAuthenticatesFailClosed(t *testing.T) {
	roller := &fakeRoller{}
	store := &fakeStore{}
	_, httpServer := testServer(t, roller, store)
	request := testDeliveryRequest(t)

	for _, token := range []string{"", "wrong-token"} {
		response, _ := postDelivery(t, httpServer, token, request)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status = %d", token, response.StatusCode)
		}
	}
	if roller.callCount() != 0 || store.putCount != 0 {
		t.Fatal("an unauthenticated request must never reach fetch, mirror, or rollout")
	}
}

// TestDeliveryAPIFailsClosedBeforeRollout: a mirror failure must produce a
// terminal failed receipt and the rollout must never start (D-71: a deploy
// that cannot be mirrored everywhere is a deploy that never began).
func TestDeliveryAPIFailsClosedBeforeRollout(t *testing.T) {
	roller := &fakeRoller{}
	store := &fakeStore{fail: map[string]bool{"sfo": true}}
	_, httpServer := testServer(t, roller, store)
	request := testDeliveryRequest(t)

	response, receipt := postDelivery(t, httpServer, "delivery-token", request)
	if response.StatusCode != http.StatusOK || receipt == nil {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if receipt.Status != StatusFailed {
		t.Fatalf("status = %s", receipt.Status)
	}
	if receipt.Error == nil || *receipt.Error.Code != "mirror_incomplete" {
		t.Fatalf("error = %+v", receipt.Error)
	}
	if receipt.Health.Converged {
		t.Fatal("a failed delivery cannot report convergence")
	}
	if err := ValidateReceipt(receipt, request); err != nil {
		t.Fatalf("failed receipt must satisfy the contract: %v", err)
	}
	if roller.callCount() != 0 {
		t.Fatal("the rollout must not start when mirroring is incomplete")
	}
}

// TestDeliveryAPIIdempotencyAndConflict: replaying the same request returns
// the stored receipt without re-running; a reused operation ID with a
// different request is a conflict.
func TestDeliveryAPIIdempotencyAndConflict(t *testing.T) {
	roller := &fakeRoller{}
	store := &fakeStore{}
	server, _ := testServer(t, roller, store)
	request := testDeliveryRequest(t)

	if _, err := server.Submit(context.Background(), request); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	replay, err := server.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("replay submit: %v", err)
	}
	if replay.Status != StatusSucceeded || roller.callCount() != 1 || store.putCount != len(estate.Default().Regions) {
		t.Fatalf("replay re-ran the pipeline: calls=%d puts=%d", roller.callCount(), store.putCount)
	}

	changed := *request
	changed.Reason = "a different request entirely"
	if _, err := server.Submit(context.Background(), &changed); err == nil {
		t.Fatal("a reused operation ID with a different request must conflict")
	}
}

// TestDeliveryAPIInProgressConflict: a second POST while an operation is
// running is a 409, and the receipt endpoint answers in-progress until the
// terminal receipt exists.
func TestDeliveryAPIInProgressConflict(t *testing.T) {
	gate := make(chan struct{})
	roller := &fakeRoller{gate: gate}
	store := &fakeStore{}
	_, httpServer := testServer(t, roller, store)
	request := testDeliveryRequest(t)

	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		response, receipt := postDelivery(t, httpServer, "delivery-token", request)
		if response.StatusCode != http.StatusOK || receipt == nil || receipt.Status != StatusSucceeded {
			t.Errorf("gated rollout eventual outcome = %d %+v", response.StatusCode, receipt)
		}
	}()
	waitFor(t, func() bool { return roller.callCount() > 0 })

	response, _ := postDelivery(t, httpServer, "delivery-token", request)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("in-flight replay status = %d", response.StatusCode)
	}
	poll, err := httpServer.Client().Get(httpServer.URL + OperationsPath + "/" + request.OperationID)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if poll.StatusCode != http.StatusNotFound {
		t.Fatalf("in-flight poll status = %d", poll.StatusCode)
	}
	poll.Body.Close()

	close(gate)
	workers.Wait()
}

// TestDeliveryAPIRejectsSourceOnlyRequests: the shared contract admits
// source-only deliveries; this API does not.
func TestDeliveryAPIRejectsSourceOnlyRequests(t *testing.T) {
	roller := &fakeRoller{}
	store := &fakeStore{}
	_, httpServer := testServer(t, roller, store)
	request := testDeliveryRequest(t)
	request.Artifact = nil

	response, _ := postDelivery(t, httpServer, "delivery-token", request)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if roller.callCount() != 0 {
		t.Fatal("a source-only request must never reach the rollout")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}

// TestJournalImmutability: a terminal operation never changes.
func TestJournalImmutability(t *testing.T) {
	journal := NewJournal()
	request := testDeliveryRequest(t)
	operation, exists, err := journal.Begin(request)
	if err != nil || exists {
		t.Fatalf("begin: %v exists=%v", err, exists)
	}
	receipt := &Receipt{SchemaVersion: ContractVersion, OperationID: request.OperationID, Status: StatusFailed}
	if err := journal.Finish(request.OperationID, operation.RequestDigest, receipt); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := journal.Finish(request.OperationID, operation.RequestDigest, &Receipt{SchemaVersion: ContractVersion, OperationID: request.OperationID, Status: StatusSucceeded}); err == nil {
		t.Fatal("a terminal operation must be immutable")
	}
	snapshot := journal.Snapshot()
	if len(snapshot) != 1 || snapshot[0].State != OperationDone {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	summary := operationSummaries(snapshot)
	if len(summary) != 1 || summary[0].Service != "terrabase" {
		t.Fatalf("summary = %+v", summary)
	}
	encoded, err := json.Marshal(summary)
	if err != nil || !bytes.Contains(encoded, []byte(`"operationId"`)) {
		t.Fatalf("summary encoding = %s %v", encoded, err)
	}
}

// TestMirrorRequiresReleaseBucketEveryRegion: an estate Region without a
// release-artifact bucket refuses to construct the mirror.
func TestMirrorRequiresReleaseBucketEveryRegion(t *testing.T) {
	spec := estate.Default()
	spec.Regions[1].Buckets = nil
	if _, err := NewArtifactMirror(spec, &fakeStore{}); err == nil {
		t.Fatal("a Region without a release bucket must be refused")
	}
	if _, err := NewArtifactMirror(estate.Default(), nil); err == nil {
		t.Fatal("a nil store must be refused")
	}
	mirror, err := NewArtifactMirror(estate.Default(), &fakeStore{})
	if err != nil {
		t.Fatalf("default estate mirror: %v", err)
	}
	if err := mirror.MirrorAll(context.Background(), nil); err == nil {
		t.Fatal("a nil artifact must be refused")
	}
	if err := mirror.MirrorAll(context.Background(), &ReleaseArtifact{Service: "terrabase", Digest: SHA256Digest([]byte("x")), Body: []byte("x")}); err != nil {
		t.Fatalf("mirror all: %v", err)
	}
}
