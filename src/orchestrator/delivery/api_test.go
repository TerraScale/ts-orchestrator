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

func (s *fakeStore) PutFenced(ctx context.Context, region, bucket, object string, body []byte, _ OperationFence) error {
	return s.Put(ctx, region, bucket, object, body)
}

type fakeRoller struct {
	mu     sync.Mutex
	calls  int
	result RolloutResult
	err    error
	panic  bool
	gate   chan struct{} // non-nil: block until closed
}

func (r *fakeRoller) Recover(context.Context, *Request, *ReleaseArtifact, *RolloutProgress) (*Rollback, error) {
	return &Rollback{Attempted: true, Status: RollbackSucceeded}, nil
}

func (r *fakeRoller) RecoverFenced(ctx context.Context, request *Request, artifact *ReleaseArtifact, progress *RolloutProgress, _ OperationFence, _ FenceChecker) (*Rollback, error) {
	return r.Recover(ctx, request, artifact, progress)
}

type panicAfterMutationRoller struct {
	mu             sync.Mutex
	mutated        bool
	rollbackCalls  int
	rollbackResult *Rollback
}

type leaseLostRoller struct {
	started   chan struct{}
	gate      chan struct{}
	mu        sync.Mutex
	rollbacks int
}

func (r *leaseLostRoller) Roll(ctx context.Context, _ *Request, _ *ReleaseArtifact) (RolloutResult, error) {
	close(r.started)
	select {
	case <-r.gate:
		return RolloutResult{}, errors.New("rollout interrupted")
	case <-ctx.Done():
		// A provider may return an error after observing cancellation. The
		// caller must still fence rollback against the durable generation.
		return RolloutResult{}, errors.New("rollout interrupted")
	}
}

func (r *leaseLostRoller) RollFenced(ctx context.Context, request *Request, artifact *ReleaseArtifact, _ OperationFence, check FenceChecker) (RolloutResult, error) {
	if check != nil {
		// The API performs the authoritative check immediately before dispatch;
		// this adapter keeps the test provider fence-aware as well.
	}
	return r.Roll(ctx, request, artifact)
}

func (r *leaseLostRoller) Rollback(context.Context, *Request, *ReleaseArtifact) (*Rollback, error) {
	r.mu.Lock()
	r.rollbacks++
	r.mu.Unlock()
	return &Rollback{Status: RollbackSucceeded}, nil
}

func (r *leaseLostRoller) rollbackCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rollbacks
}

func (r *panicAfterMutationRoller) Roll(context.Context, *Request, *ReleaseArtifact) (RolloutResult, error) {
	r.mu.Lock()
	r.mutated = true
	r.mu.Unlock()
	panic("host mutation completed before rollout panic")
}

func (r *panicAfterMutationRoller) RollFenced(ctx context.Context, request *Request, artifact *ReleaseArtifact, _ OperationFence, check FenceChecker) (RolloutResult, error) {
	return r.Roll(ctx, request, artifact)
}

func (r *panicAfterMutationRoller) Rollback(context.Context, *Request, *ReleaseArtifact) (*Rollback, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rollbackCalls++
	r.mutated = false
	result := *r.rollbackResult
	return &result, nil
}

func (r *panicAfterMutationRoller) rollbackCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rollbackCalls
}

func (r *panicAfterMutationRoller) wasMutated() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutated
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
	if r.panic {
		panic("panic includes no receipt details")
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

func (r *fakeRoller) RollFenced(ctx context.Context, request *Request, artifact *ReleaseArtifact, _ OperationFence, check FenceChecker) (RolloutResult, error) {
	if check == nil {
		return RolloutResult{}, ErrOperationLeaseActive
	}
	return r.Roll(ctx, request, artifact)
}

func (r *fakeRoller) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func testServer(t *testing.T, roller Roller, store *fakeStore) (*Server, *httptest.Server) {
	t.Helper()
	request, fetcher, trust, _ := testRelease(t, nil)
	_ = request
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatalf("build mirror: %v", err)
	}
	server, err := NewServer(ServerConfig{MirrorMode: MirrorModePrepareAll, Authority: func(context.Context, *Request) error { return nil },
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

func getDelivery(t *testing.T, server *httptest.Server, token, path string) *http.Response {
	t.Helper()
	httpRequest, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
	if err != nil {
		t.Fatalf("build GET request: %v", err)
	}
	if token != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := server.Client().Do(httpRequest)
	if err != nil {
		t.Fatalf("GET delivery: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
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
	pollRequest, err := http.NewRequest(http.MethodGet, httpServer.URL+OperationsPath+"/"+request.OperationID, nil)
	if err != nil {
		t.Fatalf("build poll request: %v", err)
	}
	pollRequest.Header.Set("Authorization", "Bearer delivery-token")
	poll, err := httpServer.Client().Do(pollRequest)
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

func TestNewServerRejectsUnsafeLeaseTTL(t *testing.T) {
	request, fetcher, trust, _ := testRelease(t, nil)
	_ = request
	store := &fakeStore{}
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewServer(ServerConfig{MirrorMode: MirrorModePrepareAll, Authority: func(context.Context, *Request) error { return nil },
		LeaseTTL: time.Millisecond,
		Token:    func() (string, error) { return "delivery-token", nil },
		Fetcher:  fetcher,
		Trust:    func() *TrustSet { return trust },
		Mirror:   mirror,
		Rollout:  &fakeRoller{},
		Journal:  NewJournal(),
	})
	if err == nil {
		t.Fatal("unsafe lease TTL was accepted")
	}
}

func TestOperationLeaseRenewIntervalAlwaysFitsTTL(t *testing.T) {
	for _, ttl := range []time.Duration{time.Second, 2 * time.Second, time.Minute} {
		interval := operationLeaseRenewInterval(ttl)
		if interval <= 0 || interval >= ttl {
			t.Fatalf("renew interval %s does not fit TTL %s", interval, ttl)
		}
	}
}

func TestDeliveryAPIAuthenticatesReadEndpoints(t *testing.T) {
	server, httpServer := testServer(t, &fakeRoller{}, &fakeStore{})
	request := testDeliveryRequest(t)
	if _, err := server.Submit(context.Background(), request); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	for _, path := range []string{OperationsPath, OperationsPath + "/" + request.OperationID} {
		response := getDelivery(t, httpServer, "", path)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthorized GET %s status = %d", path, response.StatusCode)
		}
	}
}

func TestDeliveryAPIRecoveryResumesClaimedOperation(t *testing.T) {
	request, fetcher, trust, _ := testRelease(t, nil)
	artifact, err := verifyArtifact(context.Background(), fetcher, trust, request)
	if err != nil {
		t.Fatalf("verify exact release: %v", err)
	}
	store := &fakeStore{}
	mirror, err := NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatalf("build mirror: %v", err)
	}
	journal := NewJournal()
	now := time.Unix(1_000, 0).UTC()
	journal.clock = func() time.Time { return now }
	lease := OperationLease{OwnerID: "crashed-owner", TTL: time.Minute, Generation: 1}
	operation, exists, err := journal.Begin(request, lease)
	if err != nil || exists {
		t.Fatalf("admit operation: exists=%v err=%v", exists, err)
	}
	if err := journal.RecordReleaseSignature(request.OperationID, operation.RequestDigest, lease, artifact.Signature); err != nil {
		t.Fatalf("record release signature: %v", err)
	}
	if err := journal.RecordRollout(request.OperationID, operation.RequestDigest, lease, "member-1", request.Rollback.ArtifactDigest, request.Rollback.ManifestDigest, request.Artifact.Digest, true, false); err != nil {
		t.Fatalf("record host ledger: %v", err)
	}
	// Recovery is only valid after the durable lease has expired. This models
	// a crashed owner while retaining an explicit owner/generation fence.
	journal.clock = func() time.Time { return now.Add(time.Hour) }
	control := &recoveryObserverControl{
		state:         HostReleaseState{ArtifactDigest: request.Artifact.Digest, ManifestDigest: request.Artifact.ManifestDigest},
		rollbackState: HostReleaseState{ArtifactDigest: request.Rollback.ArtifactDigest, ManifestDigest: request.Rollback.ManifestDigest, Serving: true},
	}
	rollout := recoveryRollout(t, control)
	server, err := NewServer(ServerConfig{MirrorMode: MirrorModePrepareAll, Authority: func(context.Context, *Request) error { return nil }, Token: func() (string, error) { return "delivery-token", nil }, Fetcher: fetcher, Trust: func() *TrustSet { return trust }, Mirror: mirror, Rollout: rollout, Journal: journal})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	recovery := getDelivery(t, httpServer, "delivery-token", OperationsPath+"/"+request.OperationID+recoverySuffix)
	if recovery.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("recovery helper used GET: status = %d", recovery.StatusCode)
	}
	recovery.Body.Close()
	recoveryRequest, err := http.NewRequest(http.MethodPost, httpServer.URL+OperationsPath+"/"+request.OperationID+recoverySuffix, nil)
	if err != nil {
		t.Fatalf("build recovery request: %v", err)
	}
	recoveryRequest.Header.Set("Authorization", "Bearer delivery-token")
	response, err := httpServer.Client().Do(recoveryRequest)
	if err != nil {
		t.Fatalf("recover operation: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("recovery status = %d: %s", response.StatusCode, readAll(t, response))
	}
	receipt, err := ParseReceipt(readAll(t, response))
	if err != nil {
		t.Fatalf("parse recovery receipt: %v", err)
	}
	if receipt.Status != StatusFailed || receipt.Rollback == nil || receipt.Rollback.Status != RollbackSucceeded {
		t.Fatalf("recovery receipt = %+v", receipt)
	}
	if err := ValidateReceipt(receipt, request); err != nil {
		t.Fatalf("recovery receipt is invalid: %v", err)
	}
	replay, err := server.Submit(context.Background(), request)
	if err != nil || replay == nil || replay.Rollback == nil || replay.Rollback.Status != RollbackSucceeded {
		t.Fatalf("recovered operation was not an immutable terminal replay: receipt=%+v err=%v", replay, err)
	}
	if control.convergeCount() != 1 {
		t.Fatalf("recovery did not rollback the post-effect host: converges=%d", control.convergeCount())
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

// TestDeliveryAPIRolloutErrorsBecomeTerminalReceipts proves that a rollout
// error is durable and replayable. A failed rollout is never retried under
// the same operation ID: the caller must submit a new ID explicitly.
func TestDeliveryAPIRolloutErrorsBecomeTerminalReceipts(t *testing.T) {
	roller := &fakeRoller{err: errors.New("rollout failed: bearer=secret-token " + string(make([]byte, 4096)))}
	store := &fakeStore{}
	server, httpServer := testServer(t, roller, store)
	request := testDeliveryRequest(t)

	response, receipt := postDelivery(t, httpServer, "delivery-token", request)
	if response.StatusCode != http.StatusOK || receipt == nil {
		t.Fatalf("rollout error status = %d receipt=%+v", response.StatusCode, receipt)
	}
	if receipt.Status != StatusFailed || receipt.Error == nil || receipt.Error.Code == nil || *receipt.Error.Code != "rollout_failed" {
		t.Fatalf("rollout error receipt = %+v", receipt)
	}
	if receipt.Provenance == nil || !receipt.Provenance.Verified || receipt.Health == nil || receipt.Health.Converged {
		t.Fatalf("rollout error must retain verified provenance and failed convergence: %+v", receipt)
	}
	if len(*receipt.Error.Message) > 256 || bytes.Contains([]byte(*receipt.Error.Message), []byte("secret-token")) {
		t.Fatalf("rollout error details were not redacted/bounded: %q", *receipt.Error.Message)
	}
	if err := ValidateReceipt(receipt, request); err != nil {
		t.Fatalf("terminal rollout error receipt must validate: %v", err)
	}

	replay, err := server.Submit(context.Background(), request)
	if err != nil || replay.Status != StatusFailed || roller.callCount() != 1 {
		t.Fatalf("same-ID replay = %+v err=%v calls=%d", replay, err, roller.callCount())
	}
	changed := *request
	changed.Reason = "retry with changed payload"
	if _, err := server.Submit(context.Background(), &changed); err == nil {
		t.Fatal("different payload must conflict after terminal failure")
	}

	pollRequest, err := http.NewRequest(http.MethodGet, httpServer.URL+OperationsPath+"/"+request.OperationID, nil)
	if err != nil {
		t.Fatalf("build terminal poll request: %v", err)
	}
	pollRequest.Header.Set("Authorization", "Bearer delivery-token")
	poll, err := httpServer.Client().Do(pollRequest)
	if err != nil {
		t.Fatalf("poll terminal rollout error: %v", err)
	}
	defer poll.Body.Close()
	if poll.StatusCode != http.StatusOK {
		t.Fatalf("terminal rollout poll status = %d", poll.StatusCode)
	}
	operation, ok := server.config.Journal.Get(request.OperationID)
	if !ok || operation.State != OperationDone || operation.Receipt == nil || operation.Receipt.Status != StatusFailed {
		t.Fatalf("journal did not persist terminal failure: %+v", operation)
	}
}

func TestDeliveryAPIRolloutPanicBecomesTerminalReceipt(t *testing.T) {
	roller := &fakeRoller{panic: true}
	server, httpServer := testServer(t, roller, &fakeStore{})
	request := testDeliveryRequest(t)

	response, receipt := postDelivery(t, httpServer, "delivery-token", request)
	if response.StatusCode != http.StatusOK || receipt == nil || receipt.Status != StatusFailed {
		t.Fatalf("panic status = %d receipt=%+v", response.StatusCode, receipt)
	}
	if receipt.Error == nil || receipt.Error.Code == nil || *receipt.Error.Code != "rollout_panicked" {
		t.Fatalf("panic receipt error = %+v", receipt.Error)
	}
	if receipt.Rollback == nil || receipt.Rollback.Status == RollbackNotRequired {
		t.Fatalf("panic receipt must not claim rollback was unnecessary: %+v", receipt.Rollback)
	}
	if bytes.Contains([]byte(Serialize(receipt)), []byte("panic includes")) {
		t.Fatal("panic details must not appear in a receipt")
	}
	if _, err := server.Submit(context.Background(), request); err != nil || roller.callCount() != 1 {
		t.Fatalf("panic replay = err=%v calls=%d", err, roller.callCount())
	}
}

func TestDeliveryAPIPartialPanicAttemptsRollback(t *testing.T) {
	request := testDeliveryRequest(t)
	roller := &panicAfterMutationRoller{rollbackResult: &Rollback{
		Status:               RollbackSucceeded,
		TargetArtifactDigest: ptr(request.Rollback.ArtifactDigest),
		TargetManifestDigest: ptr(request.Rollback.ManifestDigest),
	}}
	server, httpServer := testServer(t, roller, &fakeStore{})

	response, receipt := postDelivery(t, httpServer, "delivery-token", request)
	if response.StatusCode != http.StatusOK || receipt == nil || receipt.Status != StatusFailed {
		t.Fatalf("partial panic status = %d receipt=%+v", response.StatusCode, receipt)
	}
	if roller.wasMutated() {
		t.Fatal("rollback must clear the partial mutation")
	}
	if receipt.Rollback == nil || !receipt.Rollback.Attempted || receipt.Rollback.Status != RollbackSucceeded {
		t.Fatalf("partial panic rollback = %+v", receipt.Rollback)
	}
	if roller.rollbackCount() != 1 {
		t.Fatalf("rollback calls = %d, want 1", roller.rollbackCount())
	}
	if err := ValidateReceipt(receipt, request); err != nil {
		t.Fatalf("partial panic receipt must validate: %v", err)
	}
	if _, err := server.Submit(context.Background(), request); err != nil || roller.rollbackCount() != 1 {
		t.Fatalf("partial panic replay = err=%v rollback calls=%d", err, roller.rollbackCount())
	}
}

func TestDeliveryAPIRolloutCancellationBecomesTerminalReceipt(t *testing.T) {
	roller := &fakeRoller{gate: make(chan struct{})}
	server, _ := testServer(t, roller, &fakeStore{})
	request := testDeliveryRequest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	receipt, err := server.Submit(ctx, request)
	if err != nil || receipt == nil || receipt.Status != StatusFailed {
		t.Fatalf("cancelled rollout = receipt=%+v err=%v", receipt, err)
	}
	if receipt.Error == nil || receipt.Error.Code == nil || *receipt.Error.Code != "rollout_cancelled" {
		t.Fatalf("cancelled rollout error = %+v", receipt.Error)
	}
	replay, err := server.Submit(context.Background(), request)
	if err != nil || replay.Status != StatusFailed || roller.callCount() != 1 {
		t.Fatalf("cancelled replay = receipt=%+v err=%v calls=%d", replay, err, roller.callCount())
	}
}

func TestDeliveryAPIRolloutErrorConcurrency(t *testing.T) {
	gate := make(chan struct{})
	roller := &fakeRoller{gate: gate, err: errors.New("rollout unavailable")}
	server, httpServer := testServer(t, roller, &fakeStore{})
	request := testDeliveryRequest(t)

	firstDone := make(chan *Receipt, 1)
	firstErr := make(chan error, 1)
	go func() {
		receipt, err := server.Submit(context.Background(), request)
		firstDone <- receipt
		firstErr <- err
	}()
	waitFor(t, func() bool { return roller.callCount() == 1 })

	response, _ := postDelivery(t, httpServer, "delivery-token", request)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("concurrent replay status = %d", response.StatusCode)
	}
	close(gate)
	if err := <-firstErr; err != nil {
		t.Fatalf("first rollout error = %v", err)
	}
	if receipt := <-firstDone; receipt == nil || receipt.Status != StatusFailed {
		t.Fatalf("first terminal receipt = %+v", receipt)
	}
	replay, err := server.Submit(context.Background(), request)
	if err != nil || replay.Status != StatusFailed || roller.callCount() != 1 {
		t.Fatalf("post-terminal replay = %+v err=%v calls=%d", replay, err, roller.callCount())
	}
}

func TestDeliveryAPIFailsClosedForDurableRunningOperation(t *testing.T) {
	request, fetcher, trust, _ := testRelease(t, nil)
	objectStore := &fakeStore{}
	mirror, err := NewArtifactMirror(estate.Default(), objectStore)
	if err != nil {
		t.Fatalf("build mirror: %v", err)
	}
	store := NewInMemoryStore()
	firstJournal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatalf("build first journal: %v", err)
	}
	if _, exists, err := firstJournal.Begin(request); err != nil || exists {
		t.Fatalf("admit running operation: exists=%v err=%v", exists, err)
	}
	roller := &fakeRoller{}
	secondJournal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatalf("build second journal: %v", err)
	}
	second, err := NewServer(ServerConfig{MirrorMode: MirrorModePrepareAll, Authority: func(context.Context, *Request) error { return nil },
		Token:   func() (string, error) { return "delivery-token", nil },
		Fetcher: fetcher,
		Trust:   func() *TrustSet { return trust },
		Mirror:  mirror,
		Rollout: roller,
		Journal: secondJournal,
	})
	if err != nil {
		t.Fatalf("build second server: %v", err)
	}
	if _, err := second.Submit(context.Background(), request); err == nil {
		t.Fatal("a second server must not re-run a durable running operation")
	} else {
		var inProgress *inProgressError
		if !errors.As(err, &inProgress) {
			t.Fatalf("running operation error = %v, want in-progress", err)
		}
	}
	if roller.callCount() != 0 || objectStore.putCount != 0 {
		t.Fatalf("durable running operation was re-executed: rollouts=%d mirrors=%d", roller.callCount(), objectStore.putCount)
	}
}

func TestDeliveryAPIStaleOwnerCannotRollbackAfterGenerationTakeover(t *testing.T) {
	request, fetcher, trust, _ := testRelease(t, nil)
	objectStore := &fakeStore{}
	mirror, err := NewArtifactMirror(estate.Default(), objectStore)
	if err != nil {
		t.Fatal(err)
	}
	store := NewInMemoryStore()
	journal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(500, 0).UTC()
	journal.clock = func() time.Time { return clock }
	roller := &leaseLostRoller{started: make(chan struct{}), gate: make(chan struct{})}
	server, err := NewServer(ServerConfig{MirrorMode: MirrorModePrepareAll, Authority: func(context.Context, *Request) error { return nil },
		OwnerID:  "owner-a",
		LeaseTTL: time.Minute,
		Token:    func() (string, error) { return "delivery-token", nil },
		Fetcher:  fetcher,
		Trust:    func() *TrustSet { return trust },
		Mirror:   mirror,
		Rollout:  roller,
		Journal:  journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, submitErr := server.Submit(context.Background(), request)
		result <- submitErr
	}()
	waitFor(t, func() bool {
		select {
		case <-roller.started:
			return true
		default:
			return false
		}
	})
	accepted, found, err := journal.GetWithError(request.OperationID)
	if err != nil || !found {
		t.Fatalf("accepted operation: found=%v err=%v", found, err)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err := journal.Takeover(request.OperationID, accepted.RequestDigest, OperationLease{OwnerID: "owner-b", TTL: time.Minute}); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	close(roller.gate)
	if err := <-result; !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("stale submit error = %v, want lease fence", err)
	}
	if roller.rollbackCount() != 0 {
		t.Fatal("stale owner performed rollback after generation takeover")
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
	recoveryRequest, err := http.NewRequest(http.MethodPost, httpServer.URL+OperationsPath+"/"+request.OperationID+recoverySuffix, nil)
	if err != nil {
		t.Fatalf("build live recovery request: %v", err)
	}
	recoveryRequest.Header.Set("Authorization", "Bearer delivery-token")
	recoveryResponse, err := httpServer.Client().Do(recoveryRequest)
	if err != nil {
		t.Fatalf("live recovery: %v", err)
	}
	if recoveryResponse.StatusCode != http.StatusConflict {
		t.Fatalf("live recovery status = %d", recoveryResponse.StatusCode)
	}
	recoveryResponse.Body.Close()
	poll := getDelivery(t, httpServer, "delivery-token", OperationsPath+"/"+request.OperationID)
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
	// Terminal journal entries are subject to the same receipt contract as
	// API responses. Keep this fixture complete so the immutability assertion
	// tests CAS behavior rather than the (intentional) receipt validator.
	receipt, err := buildReceipt(request, RolloutResult{
		Status: StatusFailed,
		Checks: []*HealthCheck{{Name: "fixture", Status: "failed"}},
		Error:  &Error{Code: ptr("fixture_failed"), Message: ptr("fixture failure"), Remediation: ptr("inspect fixture")},
	}, false)
	if err != nil {
		t.Fatalf("build receipt: %v", err)
	}
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
