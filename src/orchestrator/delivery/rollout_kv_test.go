package delivery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// fakeKVPublisher records the ordering hook's calls together with the host
// and edge progress observed at each call, so tests prove publication fires
// only after the estate serves the release.
type fakeKVPublisher struct {
	mu        sync.Mutex
	calls     []string
	observed  []string
	observe   func() string
	control   *fakeControl
	converged []int
	cordons   []int
	err       error
}

func (p *fakeKVPublisher) PublishKV(_ context.Context, service, digest string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, service+"="+digest)
	if p.observe != nil {
		p.observed = append(p.observed, p.observe())
	}
	if p.control != nil {
		converges, cordonSeq := p.control.snapshot()
		p.converged = append(p.converged, len(converges))
		p.cordons = append(p.cordons, len(cordonSeq))
	}
	return p.err
}

func (p *fakeKVPublisher) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *fakeKVPublisher) call(i int) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i >= len(p.calls) {
		return ""
	}
	return p.calls[i]
}

var kvTestHosts = map[string][]string{
	"gru": {"gru-member-1", "gru-member-2"},
	"sfo": {"sfo-member-1", "sfo-member-2"},
	"fra": {"fra-member-1", "fra-member-2"},
}

func kvHostsReady(control *fakeControl, reports *HostReports, digest string, skipHealth ...string) {
	skipped := map[string]bool{}
	for _, host := range skipHealth {
		skipped[host] = true
	}
	for _, hosts := range kvTestHosts {
		for _, host := range hosts {
			control.drainReady[host] = true
			if !skipped[host] {
				reports.FeedHealth(host, digest, true)
			}
			reports.FeedCatchUp(host, true)
		}
	}
}

// TestRolloutPublishesKVAfterEveryHostGate: the KV publish ordering hook
// fires exactly once, with the exact artifact identity, only after every
// host converged and uncordoned (D-67).
func TestRolloutPublishesKVAfterEveryHostGate(t *testing.T) {
	control := newFakeControl()
	reports := NewHostReports()
	kv := &fakeKVPublisher{control: control}
	rollout, err := NewRollout(RolloutConfig{
		Spec:        estate.Default(),
		Hosts:       fakeInventory{hosts: kvTestHosts},
		Control:     control,
		Gates:       []Gate{HealthGate{Source: reports}, CatchUpGate{Source: reports}},
		GateTimeout: 2 * time.Second,
		KV:          kv,
	})
	if err != nil {
		t.Fatalf("build rollout: %v", err)
	}
	request := testDeliveryRequest(t)
	artifact := rolloutArtifact()
	kvHostsReady(control, reports, artifact.Digest)

	result, err := rollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusSucceeded || !result.Converged {
		t.Fatalf("result = %+v", result)
	}
	if kv.callCount() != 1 || kv.call(0) != "terrabase="+artifact.Digest {
		t.Fatalf("kv calls = %v, want one publish of the artifact identity", kv.calls)
	}
	// Every host converged and every host was uncordoned before publication:
	// six converges and six cordon+uncordon pairs must already be recorded.
	kv.mu.Lock()
	converged, cordons := kv.converged[0], kv.cordons[0]
	kv.mu.Unlock()
	if converged != 6 || cordons != 12 {
		t.Fatalf("kv published after %d converges and %d cordons, want 6 and 12", converged, cordons)
	}
	last := result.Checks[len(result.Checks)-1]
	if last.Name != "kv-publish:terrabase" || last.Status != "passed" {
		t.Fatalf("last check = %+v, want the passed kv-publish check", last)
	}
	if len(result.Checks) != 3*6+1 {
		t.Fatalf("checks = %d, want three gates per host plus the kv publish", len(result.Checks))
	}
	if err := ValidateReceipt(mustReceipt(t, request, result), request); err != nil {
		t.Fatalf("result must map onto a valid receipt: %v", err)
	}
}

// TestRolloutGateFailureNeverPublishesKV: a failed or rolled-back run never
// publishes the KV maps; the periodic KV writer owns state instead.
func TestRolloutGateFailureNeverPublishesKV(t *testing.T) {
	control := newFakeControl()
	reports := NewHostReports()
	kv := &fakeKVPublisher{}
	rollout, err := NewRollout(RolloutConfig{
		Spec:        estate.Default(),
		Hosts:       fakeInventory{hosts: kvTestHosts},
		Control:     control,
		Gates:       []Gate{HealthGate{Source: reports}, CatchUpGate{Source: reports}},
		GateTimeout: 2 * time.Second,
		KV:          kv,
	})
	if err != nil {
		t.Fatalf("build rollout: %v", err)
	}
	request := testDeliveryRequest(t)
	artifact := rolloutArtifact()
	// The canary never reports health: the run rolls back at the first gate.
	kvHostsReady(control, reports, artifact.Digest, "gru-member-1")

	result, err := rollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusRolledBack {
		t.Fatalf("status = %s", result.Status)
	}
	if kv.callCount() != 0 {
		t.Fatalf("kv calls = %v, want none on a rolled-back run", kv.calls)
	}
}

// TestRolloutKVPublishFailureFailsTheRunWithoutRollback: a converged estate
// is never rolled back because a KV write failed; the receipt reports the
// incomplete run instead of claiming success.
func TestRolloutKVPublishFailureFailsTheRunWithoutRollback(t *testing.T) {
	control := newFakeControl()
	reports := NewHostReports()
	kv := &fakeKVPublisher{control: control, err: errors.New("kv write rejected")}
	rollout, err := NewRollout(RolloutConfig{
		Spec:        estate.Default(),
		Hosts:       fakeInventory{hosts: kvTestHosts},
		Control:     control,
		Gates:       []Gate{HealthGate{Source: reports}, CatchUpGate{Source: reports}},
		GateTimeout: 2 * time.Second,
		KV:          kv,
	})
	if err != nil {
		t.Fatalf("build rollout: %v", err)
	}
	request := testDeliveryRequest(t)
	artifact := rolloutArtifact()
	kvHostsReady(control, reports, artifact.Digest)

	result, err := rollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("status = %s", result.Status)
	}
	if result.Error == nil || *result.Error.Code != "kv_publish_failed" {
		t.Fatalf("error = %+v", result.Error)
	}
	if !result.Converged {
		t.Fatal("the estate converged before the KV publish failed")
	}
	if result.Rollback == nil || result.Rollback.Attempted || result.Rollback.Status != RollbackNotRequired {
		t.Fatalf("rollback = %+v, want not required", result.Rollback)
	}
	if convergeCount(control) != 6 {
		t.Fatalf("converges = %d, want the six forward converges only", convergeCount(control))
	}
	kv.mu.Lock()
	converged, cordons := kv.converged[0], kv.cordons[0]
	kv.mu.Unlock()
	if converged != 6 || cordons != 12 {
		t.Fatalf("kv attempted after %d converges and %d cordons, want 6 and 12", converged, cordons)
	}
	if err := ValidateReceipt(mustReceipt(t, request, result), request); err != nil {
		t.Fatalf("result must map onto a valid receipt: %v", err)
	}
}

// TestRolloutWorkerPromotionPublishesKV: site deliveries publish KV after
// the Worker promotion; package (Snippet) deliveries never publish because
// the sync gate reads no KV (D-58).
func TestRolloutWorkerPromotionPublishesKV(t *testing.T) {
	promoter := &fakeEdgePromoter{}
	kv := &fakeKVPublisher{observe: func() string { return promoter.worker }}
	edgeRollout, err := NewRollout(RolloutConfig{
		Spec:  estate.Default(),
		Hosts: fakeInventory{hosts: map[string][]string{}},
		Edge:  promoter,
		KV:    kv,
	})
	if err != nil {
		t.Fatalf("build edge rollout: %v", err)
	}

	request := testDeliveryRequest(t)
	request.Artifact.Kind = "site"
	artifact := rolloutArtifact()
	result, err := edgeRollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusSucceeded {
		t.Fatalf("result = %+v", result)
	}
	if kv.callCount() != 1 || kv.call(0) != "terrabase="+artifact.Digest {
		t.Fatalf("kv calls = %v, want one publish of the artifact identity", kv.calls)
	}
	kv.mu.Lock()
	observed := kv.observed[0]
	kv.mu.Unlock()
	if observed != artifact.Digest {
		t.Fatalf("kv published before the worker served the digest: observed %q", observed)
	}

	requestPackage := testDeliveryRequest(t)
	requestPackage.Artifact.Kind = "package"
	result, err = edgeRollout.Roll(context.Background(), requestPackage, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusSucceeded {
		t.Fatalf("result = %+v", result)
	}
	if kv.callCount() != 1 {
		t.Fatalf("kv calls = %v, want no publish for a Snippet delivery", kv.calls)
	}
	for _, check := range result.Checks {
		if strings.HasPrefix(check.Name, "kv-publish:") {
			t.Fatalf("snippet receipt carried %v", check.Name)
		}
	}
}

// TestRolloutFencedKVPublishChecksFence: the KV publish seam is fenced; a
// lost lease between Worker promotion and publication blocks the write and
// fails the run without edge rollback.
func TestRolloutFencedKVPublishChecksFence(t *testing.T) {
	promoter := &fakeEdgePromoter{}
	kv := &fakeKVPublisher{}
	edgeRollout, err := NewRollout(RolloutConfig{
		Spec:  estate.Default(),
		Hosts: fakeInventory{hosts: map[string][]string{}},
		Edge:  promoter,
		KV:    kv,
	})
	if err != nil {
		t.Fatalf("build edge rollout: %v", err)
	}
	request := testDeliveryRequest(t)
	request.Artifact.Kind = "site"
	request.Rollback.Kind = "site"
	artifact := rolloutArtifact()
	calls := 0
	fenceLost := errors.New("fence lost")
	result, rollErr := edgeRollout.RollFenced(context.Background(), request, artifact, OperationFence{
		OperationID:   "op",
		RequestDigest: "digest",
		OwnerID:       "owner",
		Generation:    1,
	}, func(OperationFence) error {
		calls++
		// Call 1 is RollFenced's own admission check, call 2 fences the
		// Worker promotion, and call 3 must fence the KV publish.
		if calls >= 3 {
			return fenceLost
		}
		return nil
	})
	if rollErr != nil {
		t.Fatalf("roll: %v", rollErr)
	}
	// The first two fence checks admitted the Worker promotion; the third
	// gates the KV publish, so the promotion stands but no KV write happens.
	if calls != 3 || promoter.worker != artifact.Digest {
		t.Fatalf("fence calls = %d, worker = %q", calls, promoter.worker)
	}
	if kv.callCount() != 0 {
		t.Fatalf("kv calls = %v, want none after the fence was lost", kv.calls)
	}
	if result.Status != StatusFailed || result.Error == nil || *result.Error.Code != "kv_publish_failed" {
		t.Fatalf("result = %+v", result)
	}
	if result.Rollback == nil || result.Rollback.Attempted {
		t.Fatalf("rollback = %+v, want unattempted", result.Rollback)
	}
	if err := ValidateReceipt(mustReceipt(t, request, result), request); err != nil {
		t.Fatalf("result must map onto a valid receipt: %v", err)
	}
}
