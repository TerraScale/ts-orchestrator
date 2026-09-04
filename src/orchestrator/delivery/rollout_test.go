package delivery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// fakeInventory lists a fixed host set per Region.
type fakeInventory struct {
	hosts map[string][]string
}

func (i fakeInventory) Hosts(_ context.Context, region string) ([]string, error) {
	return i.hosts[region], nil
}

// fakeControl records the rollout's host-command sequence. drainReady lists
// hosts that ever report drained; hosts missing from it never drain.
type fakeControl struct {
	mu         sync.Mutex
	drainReady map[string]bool
	converges  []string // "host=digestHex" in order
	cordoned   map[string]bool
	cordonSeq  []string // "host=true|false" in order
	failFor    string   // converge fails for this host
}

func newFakeControl() *fakeControl {
	return &fakeControl{drainReady: map[string]bool{}, cordoned: map[string]bool{}}
}

func (c *fakeControl) Cordon(_ context.Context, host string, cordoned bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cordoned[host] = cordoned
	c.cordonSeq = append(c.cordonSeq, fmt.Sprintf("%s=%t", host, cordoned))
	return nil
}

func (c *fakeControl) DrainStatus(_ context.Context, host string) (DrainReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return DrainReport{Cordoned: c.cordoned[host], Drained: c.drainReady[host] && c.cordoned[host]}, nil
}

func (c *fakeControl) Converge(_ context.Context, host string, plan []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failFor == host {
		return errors.New("converge rejected")
	}
	c.converges = append(c.converges, host+"="+planDigest(plan))
	return nil
}

func (c *fakeControl) snapshot() (converges []string, cordons []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.converges...), append([]string(nil), c.cordonSeq...)
}

// planDigest extracts the artifact digest hex out of a serialized plan
// ({"artifactDigest":{"value":"<hex>"}}).
func planDigest(plan []byte) string {
	encoded := string(plan)
	start := strings.Index(encoded, `"artifactDigest":{"value":"`)
	if start < 0 {
		return "?"
	}
	rest := encoded[start+len(`"artifactDigest":{"value":"`):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "?"
	}
	return rest[:end]
}

func rolloutTestBed(t *testing.T) (*Rollout, *fakeControl, *HostReports) {
	t.Helper()
	control := newFakeControl()
	for _, host := range []string{"gru-member-1", "gru-member-2", "sfo-member-1", "sfo-member-2", "fra-member-1", "fra-member-2"} {
		control.drainReady[host] = true
	}
	reports := NewHostReports()
	rollout, err := NewRollout(RolloutConfig{
		Spec: estate.Default(),
		Hosts: fakeInventory{hosts: map[string][]string{
			"gru": {"gru-member-1", "gru-member-2"},
			"sfo": {"sfo-member-1", "sfo-member-2"},
			"fra": {"fra-member-1", "fra-member-2"},
		}},
		Control:     control,
		Gates:       []Gate{HealthGate{Source: reports}, CatchUpGate{Source: reports}},
		GateTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("build rollout: %v", err)
	}
	return rollout, control, reports
}

func rolloutArtifact() *ReleaseArtifact {
	body := []byte("terrabase-release-bytes")
	return &ReleaseArtifact{Service: "terrabase", Digest: SHA256Digest(body), Body: body}
}

// TestRolloutHappyPath: canary first, then host by host across Regions in
// declaration order, every host drained before converge, gated, and
// uncordoned.
func TestRolloutHappyPath(t *testing.T) {
	rollout, control, reports := rolloutTestBed(t)
	request := testDeliveryRequest(t)
	artifact := rolloutArtifact()
	for _, host := range []string{"gru-member-1", "gru-member-2", "sfo-member-1", "sfo-member-2", "fra-member-1", "fra-member-2"} {
		reports.FeedHealth(host, artifact.Digest, true)
		reports.FeedCatchUp(host, true)
	}

	result, err := rollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusSucceeded || !result.Converged {
		t.Fatalf("result = %+v", result)
	}
	converges, cordons := control.snapshot()
	want := []string{
		"gru-member-1", "gru-member-2", "sfo-member-1", "sfo-member-2", "fra-member-1", "fra-member-2",
	}
	if len(converges) != len(want) {
		t.Fatalf("converges = %v", converges)
	}
	for i, host := range want {
		if !strings.HasPrefix(converges[i], host+"=") {
			t.Fatalf("converge order = %v, want %s at %d", converges, host, i)
		}
		if !strings.HasSuffix(converges[i], strings.TrimPrefix(artifact.Digest, "sha256:")) {
			t.Fatalf("converge %s did not carry the artifact digest: %s", host, converges[i])
		}
	}
	if len(cordons) != 2*len(want) {
		t.Fatalf("cordon sequence = %v", cordons)
	}
	for _, host := range want {
		if control.cordoned[host] {
			t.Fatalf("host %s stayed cordoned after success", host)
		}
	}
	// Three gates per host in receipts: drain, health, catch-up.
	if len(result.Checks) != 3*len(want) {
		t.Fatalf("checks = %d, want %d", len(result.Checks), 3*len(want))
	}
	if err := ValidateReceipt(mustReceipt(t, request, result), request); err != nil {
		t.Fatalf("result must map onto a valid receipt: %v", err)
	}
}

// TestRolloutGateFailureRollsBackEverythingTouched: a gate failing on the
// third host rolls the two converged hosts and the failed host back to the
// prior artifact, newest first.
func TestRolloutGateFailureRollsBackEverythingTouched(t *testing.T) {
	rollout, control, reports := rolloutTestBed(t)
	request := testDeliveryRequest(t)
	artifact := rolloutArtifact()
	for _, host := range []string{"gru-member-1", "gru-member-2", "sfo-member-2", "fra-member-1", "fra-member-2"} {
		reports.FeedHealth(host, artifact.Digest, true)
		reports.FeedCatchUp(host, true)
	}
	// sfo-member-1 never reports health: its health gate fails closed.
	reports.FeedCatchUp("sfo-member-1", true)

	result, err := rollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusRolledBack {
		t.Fatalf("status = %s, checks %+v", result.Status, result.Checks)
	}
	if result.Rollback == nil || !result.Rollback.Attempted || result.Rollback.Status != RollbackSucceeded {
		t.Fatalf("rollback = %+v", result.Rollback)
	}
	if result.Rollback.TargetArtifactDigest == nil || *result.Rollback.TargetArtifactDigest != request.Rollback.ArtifactDigest {
		t.Fatalf("rollback digest = %+v", result.Rollback.TargetArtifactDigest)
	}
	converges, _ := control.snapshot()
	// Three forward converges, then rollback of exactly the touched hosts in
	// reverse order: sfo-member-1, gru-member-2, gru-member-1.
	wantOrder := []string{
		"gru-member-1=", "gru-member-2=", "sfo-member-1=",
		"sfo-member-1=", "gru-member-2=", "gru-member-1=",
	}
	if len(converges) != len(wantOrder) {
		t.Fatalf("converges = %v", converges)
	}
	for i, prefix := range wantOrder {
		if !strings.HasPrefix(converges[i], prefix) {
			t.Fatalf("converge order = %v, want prefix %s at %d", converges, prefix, i)
		}
	}
	rollbackHex := strings.TrimPrefix(request.Rollback.ArtifactDigest, "sha256:")
	for i := 3; i < len(converges); i++ {
		if !strings.HasSuffix(converges[i], rollbackHex) {
			t.Fatalf("rollback converge carried the wrong digest: %s", converges[i])
		}
	}
	for _, host := range []string{"gru-member-1", "gru-member-2", "sfo-member-1"} {
		if control.cordoned[host] {
			t.Fatalf("host %s stayed cordoned after rollback", host)
		}
	}
	if control.cordoned["sfo-member-2"] || control.cordoned["fra-member-1"] {
		t.Fatal("untouched hosts must never be cordoned")
	}
	if err := ValidateReceipt(mustReceipt(t, request, result), request); err != nil {
		t.Fatalf("result must map onto a valid receipt: %v", err)
	}
}

// TestRolloutCanaryRejection: a gate failing on the canary touches nothing
// else; the canary is rolled back and the receipt reports rolled_back.
func TestRolloutCanaryRejection(t *testing.T) {
	rollout, control, reports := rolloutTestBed(t)
	request := testDeliveryRequest(t)
	artifact := rolloutArtifact()
	for _, host := range []string{"gru-member-2", "sfo-member-1", "sfo-member-2", "fra-member-1", "fra-member-2"} {
		reports.FeedHealth(host, artifact.Digest, true)
		reports.FeedCatchUp(host, true)
	}
	reports.FeedCatchUp("gru-member-1", true)
	// The canary never reports health.

	result, err := rollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusRolledBack {
		t.Fatalf("status = %s", result.Status)
	}
	converges, _ := control.snapshot()
	if len(converges) != 2 || !strings.HasPrefix(converges[0], "gru-member-1=") || !strings.HasPrefix(converges[1], "gru-member-1=") {
		t.Fatalf("canary rejection must converge only the canary, forward then back: %v", converges)
	}
	if !strings.HasSuffix(converges[1], strings.TrimPrefix(request.Rollback.ArtifactDigest, "sha256:")) {
		t.Fatalf("canary rollback digest = %s", converges[1])
	}
	if err := ValidateReceipt(mustReceipt(t, request, result), request); err != nil {
		t.Fatalf("result must map onto a valid receipt: %v", err)
	}
}

// TestRolloutWithoutRollbackArtifactFailsClosed: no declared prior artifact
// means the failure is reported failed, not rolled_back.
func TestRolloutWithoutRollbackArtifactFailsClosed(t *testing.T) {
	rollout, control, reports := rolloutTestBed(t)
	request := testDeliveryRequest(t)
	request.Rollback = nil
	artifact := rolloutArtifact()
	for _, host := range []string{"gru-member-2", "sfo-member-1", "sfo-member-2", "fra-member-1", "fra-member-2"} {
		reports.FeedHealth(host, artifact.Digest, true)
		reports.FeedCatchUp(host, true)
	}

	result, err := rollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("status = %s", result.Status)
	}
	if result.Rollback == nil || result.Rollback.Attempted {
		t.Fatalf("rollback = %+v", result.Rollback)
	}
	if result.Error == nil || *result.Error.Code != "rollout_gate_failed" {
		t.Fatalf("error = %+v", result.Error)
	}
	if err := ValidateReceipt(mustReceipt(t, request, result), request); err != nil {
		t.Fatalf("result must map onto a valid receipt: %v", err)
	}
	_, _ = control.snapshot()
}

// TestRolloutDrainTimeoutFailsTheStep: a host that never drains fails the
// drain gate and triggers rollback.
func TestRolloutDrainTimeoutFailsTheStep(t *testing.T) {
	control := newFakeControl()
	for _, host := range []string{"gru-member-2", "sfo-member-1", "sfo-member-2", "fra-member-1", "fra-member-2"} {
		control.drainReady[host] = true
	}
	// gru-member-1 (the canary) never drains.
	reports := NewHostReports()
	rollout, err := NewRollout(RolloutConfig{
		Spec: estate.Default(),
		Hosts: fakeInventory{hosts: map[string][]string{
			"gru": {"gru-member-1", "gru-member-2"},
			"sfo": {"sfo-member-1", "sfo-member-2"},
			"fra": {"fra-member-1", "fra-member-2"},
		}},
		Control:     control,
		Gates:       []Gate{HealthGate{Source: reports}, CatchUpGate{Source: reports}},
		GateTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build rollout: %v", err)
	}
	request := testDeliveryRequest(t)
	result, err := rollout.Roll(context.Background(), request, rolloutArtifact())
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusRolledBack {
		t.Fatalf("status = %s", result.Status)
	}
	failedDrain := false
	for _, check := range result.Checks {
		if check.Status == "failed" && strings.HasPrefix(check.Name, "drain:") {
			failedDrain = true
		}
	}
	if !failedDrain {
		t.Fatalf("no failed drain check in %+v", result.Checks)
	}
}

// TestRolloutEdgePromotion: site deliveries ride the Worker promoter;
// package deliveries ride the Snippet promoter; failures roll back to the
// prior edge digest.
func TestRolloutEdgePromotion(t *testing.T) {
	promoter := &fakeEdgePromoter{}
	_, control, _ := rolloutTestBed(t)
	edgeRollout, err := NewRollout(RolloutConfig{
		Spec:    estate.Default(),
		Hosts:   fakeInventory{hosts: map[string][]string{}},
		Control: control,
		Edge:    promoter,
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
	if result.Status != StatusSucceeded || !result.Converged {
		t.Fatalf("result = %+v", result)
	}
	if promoter.worker != artifact.Digest {
		t.Fatalf("worker promotion digest = %s", promoter.worker)
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
	if promoter.snippet != artifact.Digest {
		t.Fatalf("snippet promotion digest = %s", promoter.snippet)
	}

	failing := &fakeEdgePromoter{failWorker: true}
	failingRollout, err := NewRollout(RolloutConfig{Spec: estate.Default(), Hosts: fakeInventory{hosts: map[string][]string{}}, Control: control, Edge: failing})
	if err != nil {
		t.Fatalf("build failing rollout: %v", err)
	}
	result, err = failingRollout.Roll(context.Background(), request, artifact)
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if result.Status != StatusRolledBack || result.Rollback == nil || !result.Rollback.Attempted {
		t.Fatalf("result = %+v rollback=%+v", result, result.Rollback)
	}

	// A missing promoter is a typed failure, not a panic.
	bare, err := NewRollout(RolloutConfig{Spec: estate.Default(), Hosts: fakeInventory{hosts: map[string][]string{}}})
	if err != nil {
		t.Fatalf("build bare rollout: %v", err)
	}
	result, err = bare.Roll(context.Background(), request, artifact)
	if err != nil || result.Status != StatusFailed || result.Error == nil || *result.Error.Code != "edge_promoter_missing" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

type fakeEdgePromoter struct {
	worker     string
	snippet    string
	failWorker bool
}

func (p *fakeEdgePromoter) PromoteWorker(_ context.Context, service, digest string) error {
	if p.failWorker {
		p.failWorker = false
		return errors.New("gradual deployment rejected")
	}
	p.worker = digest
	return nil
}

func (p *fakeEdgePromoter) PromoteSnippet(_ context.Context, service, digest string) error {
	p.snippet = digest
	return nil
}

// TestRolloutValidatesTargetsAndComponents: undeclared Regions and unknown
// components fail closed before any host is touched.
func TestRolloutValidatesTargetsAndComponents(t *testing.T) {
	rollout, control, _ := rolloutTestBed(t)
	request := testDeliveryRequest(t)
	request.Target.Regions = []string{"gru", "mars"}
	result, err := rollout.Roll(context.Background(), request, rolloutArtifact())
	if err != nil || result.Status != StatusFailed || result.Error == nil || *result.Error.Code != "target_invalid" {
		t.Fatalf("result = %+v err = %v", result, err)
	}

	unknown := testDeliveryRequest(t)
	unknownArtifact := rolloutArtifact()
	unknownArtifact.Service = "not-a-component"
	result, err = rollout.Roll(context.Background(), unknown, unknownArtifact)
	if err != nil || result.Status != StatusFailed {
		t.Fatalf("result = %+v err = %v", result, err)
	}
	if convergeCount(control) != 0 {
		t.Fatal("an invalid delivery must converge nothing")
	}
}

func convergeCount(control *fakeControl) int {
	converges, _ := control.snapshot()
	return len(converges)
}

// mustReceipt maps a result onto its receipt shape for validation.
func mustReceipt(t *testing.T, request *Request, result RolloutResult) *Receipt {
	t.Helper()
	receipt, err := buildReceipt(request, result, true)
	if err != nil {
		t.Fatalf("build receipt: %v", err)
	}
	return receipt
}
