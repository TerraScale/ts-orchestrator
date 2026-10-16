package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

func nativeRegressionProfile() WorkloadProfile {
	return WorkloadProfile{Env: map[string]string{terrabase.EnvPeers: "ctl-1=10.0.0.11:9466", terrabase.EnvAdminPort: "9465", terrabase.EnvPeerPort: "9466"},
		Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}}
}

func nativeRegressionAdopt(t *testing.T, f *retainedConsumerFixture, profile WorkloadProfile, generation uint64) nativeProfileProvenance {
	t.Helper()
	p := f.adopt(t, map[string]WorkloadProfile{terrabase.Role: profile}, generation)
	kv, err := f.history.js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: cellSpecBucket, History: 4,
		MaxValueSize: cellspec.MaxSignedBytes, Storage: jetstream.FileStorage, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(t.Context(), cellSpecKey, p.Spec); err != nil {
		t.Fatal(err)
	}
	f.history.services.kv = kv
	return p
}

type nativeRegressionPlanner struct {
	history  *nativeHistory
	deadline time.Time
	delay    bool
	nodes    int
}

func (p nativeRegressionPlanner) Plan(ctx context.Context, i delivery.Intent) ([]host.Desired, error) {
	if p.delay {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Until(p.deadline)):
		}
	}
	profile, err := p.history.profile(ctx, i)
	if err != nil {
		return nil, err
	}
	var result []host.Desired
	for index := range p.nodes {
		result = append(result, host.Desired{Cell: i.Cell, Node: fmt.Sprintf("ctl-%d", index+1), Role: i.Role, Environment: i.Environment,
			AuthorityEpoch: i.AuthorityEpoch, Generation: i.Generation, Digest: i.ArtifactDigest, Args: profile.Args, Env: profile.Env, Secrets: profile.Secrets})
	}
	return result, nil
}

type nativeRegressionWriter struct {
	history     *nativeHistory
	fixture     *retainedConsumerFixture
	deadline    time.Time
	delaySecond bool
	mu          sync.Mutex
	attempts    int
	writes      []host.Desired
}

func (w *nativeRegressionWriter) ApplyDesired(ctx context.Context, d host.Desired) (host.Receipt, error) {
	w.mu.Lock()
	w.attempts++
	attempt := w.attempts
	w.mu.Unlock()
	if w.delaySecond && attempt == 2 {
		select {
		case <-ctx.Done():
			return host.Receipt{}, ctx.Err()
		case <-time.After(time.Until(w.deadline)):
		}
	}
	if err := w.history.allowDesired(ctx, d); err != nil {
		return host.Receipt{}, err
	}
	if w.fixture != nil {
		payload, err := json.Marshal(d)
		if err != nil {
			return host.Receipt{}, err
		}
		key := d.Cell + "." + d.Node + "." + d.Role
		wire, err := json.Marshal(struct {
			Version     int                        `json:"version"`
			Kind        authority.HostMutationKind `json:"kind"`
			Scope       string                     `json:"scope"`
			SubjectKey  string                     `json:"subject_key"`
			OperationID string                     `json:"operation_id"`
			Epoch       uint64                     `json:"epoch"`
			Payload     []byte                     `json:"payload"`
		}{1, authority.MutationDesired, d.Cell, key, entityid.New(), d.AuthorityEpoch, payload})
		if err != nil {
			return host.Receipt{}, err
		}
		if _, err := w.history.js.Publish(ctx, protocol.Control(d.Cell, "host", string(authority.MutationDesired), key), wire); err != nil {
			return host.Receipt{}, err
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, d)
	return host.Receipt{Generation: d.Generation, Revision: 1}, nil
}

func nativeRegressionDelivery(t *testing.T, f *retainedConsumerFixture, planner delivery.Planner, writer delivery.DesiredWriter) *delivery.Service {
	t.Helper()
	js := f.history.js
	service, err := delivery.Open(t.Context(), delivery.Config{Conn: js.Conn(), JS: js, Cell: "gru", Replicas: 1,
		Verifier: f.codec, ArtifactVerifier: f.codec, AuthorizeArtifact: func(context.Context, string, delivery.ArtifactRecord) error { return nil },
		Authorize: func(context.Context, string, delivery.Intent) error { return nil }, Planner: planner, Writer: writer,
		Fencer: f.history.fencer})
	if err != nil {
		t.Fatal(err)
	}
	f.history.deliveries = service
	go func() { _ = service.Run(t.Context()) }()
	return service
}

func nativeRegressionReceipt(t *testing.T, service *delivery.Service, intent delivery.Intent, status string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		r, err := service.StatusFor(ctx, intent)
		if err == nil && r.Status == status {
			return
		}
		if err == nil && r.Status != "pending" {
			t.Fatalf("receipt=%+v, want %s", r, status)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("receipt status=%s err=%v, want %s", r.Status, err, status)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNativeExpiredForwardSettlesDelayedAndPartialDelivery(t *testing.T) {
	for _, delayed := range []bool{true, false} {
		t.Run(fmt.Sprintf("delayed-planning-%t", delayed), func(t *testing.T) {
			f := newRetainedConsumerFixture(t)
			profile := nativeRegressionProfile()
			proof := nativeRegressionAdopt(t, f, profile, 1)
			binding := f.binding(t, terrabase.Role, profile, proof, 1)
			binding.Intent.DesiredReplicas = 2
			binding.Fingerprint, _ = binding.Intent.Fingerprint()
			binding.Deadline = time.Now().Add(350 * time.Millisecond)
			f.save(t, terrabase.Role, nativeReleaseHistory{Schema: 1, Pending: &binding})
			writer := &nativeRegressionWriter{history: f.history, deadline: binding.Deadline, delaySecond: !delayed}
			service := nativeRegressionDelivery(t, f, nativeRegressionPlanner{history: f.history, deadline: binding.Deadline, delay: delayed, nodes: 2}, writer)
			if err := service.SubmitVerified(t.Context(), binding.Intent, servicePinsActor); err != nil {
				t.Fatal(err)
			}
			want, writes := "rejected", 0
			if !delayed {
				want, writes = "held", 1
			}
			nativeRegressionReceipt(t, service, binding.Intent, want)
			writer.mu.Lock()
			got, attempts := len(writer.writes), writer.attempts
			writer.mu.Unlock()
			if got != writes || !delayed && attempts != 2 {
				t.Fatalf("writes=%d attempts=%d, want writes=%d", got, attempts, writes)
			}
			_, err := f.history.prepare(t.Context(), nativePrepareRequest{Intent: binding.Intent})
			if !errors.Is(err, delivery.ErrInvalid) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expired retry=%v", err)
			}
			resumed := binding.Intent
			resumed.OperationID, resumed.Generation = entityid.New(), 2
			if _, err := f.history.prepare(t.Context(), nativePrepareRequest{Intent: resumed, ResumeOf: binding.Intent.OperationID}); !errors.Is(err, delivery.ErrInvalid) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expired resume=%v", err)
			}
			state, _, err := f.history.load(t.Context(), terrabase.Role)
			if err != nil || !state.Pending.Deadline.Equal(binding.Deadline) {
				t.Fatalf("deadline changed: %v", err)
			}
		})
	}
}

func TestNativeDeadlineExemptsCertifiedHealingAndIndependentRecovery(t *testing.T) {
	f := newRetainedConsumerFixture(t)
	profile := nativeRegressionProfile()
	proof := nativeRegressionAdopt(t, f, profile, 1)
	good := f.binding(t, terrabase.Role, profile, proof, 1)
	good.Deadline = time.Now().Add(-time.Minute)
	state := nativeReleaseHistory{Schema: 1, Pending: &good, Good: []nativeGoodRelease{{Binding: good, Nodes: []string{"ctl-1"}, GoodAt: time.Now().UTC()}}}
	f.save(t, terrabase.Role, state)
	d := host.Desired{Cell: "gru", Node: "ctl-1", Role: terrabase.Role, Environment: "test", AuthorityEpoch: 7, Generation: 1, Digest: good.Artifact.Digest, Env: profile.Env}
	if _, err := f.history.profile(t.Context(), good.Intent); err != nil {
		t.Fatal("certified profile:", err)
	}
	if err := f.history.allowDesired(t.Context(), d); err != nil {
		t.Fatal("certified healing:", err)
	}
	if _, err := f.history.prepare(t.Context(), nativePrepareRequest{Intent: good.Intent}); err != nil {
		t.Fatal("certified preparation:", err)
	}
	failed := f.binding(t, terrabase.Role, profile, proof, 2)
	failed.Deadline = good.Deadline
	state.Pending, state.Previous = &failed, new(state.Good[0])
	f.save(t, terrabase.Role, state)
	recovery := good.Intent
	recovery.OperationID, recovery.Generation = entityid.New(), 3
	if _, err := f.history.prepare(t.Context(), nativePrepareRequest{Intent: recovery, RecoveryOf: failed.Intent.OperationID}); err != nil {
		t.Fatal("independent recovery:", err)
	}
	if _, err := f.history.profile(t.Context(), recovery); err != nil {
		t.Fatal("recovery profile:", err)
	}
	d.Generation = 3
	if err := f.history.allowDesired(t.Context(), d); err != nil {
		t.Fatal("recovery desired:", err)
	}
	d.Generation, d.Digest = failed.Intent.Generation, failed.Artifact.Digest
	if err := f.history.allowDesired(t.Context(), d); !errors.Is(err, delivery.ErrInvalid) {
		t.Fatalf("superseded forward=%v", err)
	}
}

func TestNativeNearLimitSignedProfilesTenSuccessesAndRecovery(t *testing.T) {
	f := newRetainedConsumerFixture(t)
	profile := nativeRegressionProfile()
	for i := range 8 {
		profile.Env[fmt.Sprintf("NONSECRET_SETTING_%d", i)] = strings.Repeat("x", 3800)
	}
	f.host(t, placement.Resources{CPU: 2, MemoryBytes: 1 << 30, DiskBytes: 1 << 30})
	writer := &nativeRegressionWriter{history: f.history, fixture: f}
	service := nativeRegressionDelivery(t, f, nativeRegressionPlanner{history: f.history, nodes: 1}, writer)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var reports sync.WaitGroup
	reports.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Millisecond):
			}
			desired, err := f.history.hosts.ListDesired(ctx, terrabase.Role)
			if err != nil || len(desired) == 0 {
				continue
			}
			entry, err := f.state.Get(ctx, "session.gru.ctl-1")
			if err != nil {
				continue
			}
			var session struct {
				SessionID string `json:"session_id"`
				Epoch     uint64 `json:"epoch"`
			}
			if json.Unmarshal(entry.Value(), &session) != nil {
				continue
			}
			d := desired[0]
			wire, err := json.Marshal(host.Report{Cell: d.Cell, Node: d.Node, Role: d.Role, Environment: d.Environment, Generation: d.Generation, Digest: d.Digest,
				SessionID: session.SessionID, Epoch: session.Epoch, State: "running", ObservedAt: time.Now().UTC()})
			if err == nil {
				_, _ = f.state.Put(ctx, "report.gru.ctl-1."+terrabase.Role, wire)
			}
		}
	})
	defer func() { cancel(); reports.Wait() }()
	var previous nativeReleaseBinding
	for i := range 10 {
		profile = cloneNativeProfile(profile)
		profile.Env["NONSECRET_SETTING_0"] = fmt.Sprint(i) + strings.Repeat("x", 3799)
		proof := nativeRegressionAdopt(t, f, profile, uint64(i+1))
		profileWire, _ := json.Marshal(profile)
		if len(profileWire) < 30<<10 {
			t.Fatal("test profile is not near the supported limit")
		}
		binding := f.binding(t, terrabase.Role, profile, proof, uint64(i+1))
		if _, err := f.history.prepare(t.Context(), nativePrepareRequest{Intent: binding.Intent, Deadline: binding.Deadline}); err != nil {
			t.Fatalf("prepare %d: %v", i+1, err)
		}
		if err := service.SubmitVerified(t.Context(), binding.Intent, servicePinsActor); err != nil {
			t.Fatal(err)
		}
		nativeRegressionReceipt(t, service, binding.Intent, "accepted")
		ready := false
		for range 20 {
			var err error
			ready, err = f.history.observe(t.Context(), binding.Intent)
			if err != nil {
				t.Fatalf("certify %d: %v", i+1, err)
			}
			if ready {
				break
			}
			time.Sleep(40 * time.Millisecond)
		}
		if !ready {
			t.Fatalf("release %d did not certify", i+1)
		}
		previous = binding
	}
	state, _, err := f.history.load(t.Context(), terrabase.Role)
	if err != nil || len(state.Good) != 10 {
		t.Fatalf("ten signed profiles: count=%d err=%v", len(state.Good), err)
	}
	for _, g := range state.Good {
		if err := f.history.verifyProfile(terrabase.Role, g.Binding.Profile, g.Binding.Provenance); err != nil {
			t.Fatal(err)
		}
	}
	failed := f.binding(t, terrabase.Role, profile, previous.Provenance, 11)
	if _, err := f.history.prepare(t.Context(), nativePrepareRequest{Intent: failed.Intent, Deadline: failed.Deadline}); err != nil {
		t.Fatal(err)
	}
	if err := f.history.reject(t.Context(), failed.Intent, errBadRelease, 7); err != nil {
		t.Fatal(err)
	}
	recovery := previous.Intent
	recovery.OperationID, recovery.Generation = entityid.New(), 12
	if _, err := f.history.prepare(t.Context(), nativePrepareRequest{Intent: recovery, RecoveryOf: failed.Intent.OperationID}); err != nil {
		t.Fatal("recovery preparation:", err)
	}
	if err := service.SubmitVerified(t.Context(), recovery, servicePinsActor); err != nil {
		t.Fatal(err)
	}
	nativeRegressionReceipt(t, service, recovery, "accepted")
	for range 20 {
		ready, err := f.history.observe(t.Context(), recovery)
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	state, _, err = f.history.load(t.Context(), terrabase.Role)
	if err != nil || len(state.Good) != 10 || state.Good[0].Binding.Fingerprint != state.Recovery.Fingerprint ||
		!maps.Equal(state.Recovery.Profile.Env, previous.Profile.Env) || slices.ContainsFunc(state.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == failed.Fingerprint }) {
		t.Fatalf("recovery corrupted ten-good retention: count=%d err=%v", len(state.Good), err)
	}
	entry, err := f.history.kv.Get(t.Context(), terrabase.Role)
	if err != nil || len(entry.Value()) > 32<<10 || strings.Contains(string(entry.Value()), "NONSECRET_SETTING") {
		t.Fatalf("index not compact: %d %v", len(entry.Value()), err)
	}
}

func TestNativeWorstProvenanceIsChunkedAndCapacityCheckedBeforeReferences(t *testing.T) {
	f := newRetainedConsumerFixture(t)
	profile := nativeRegressionProfile()
	proof := nativeRegressionAdopt(t, f, profile, 1)
	binding := f.binding(t, terrabase.Role, profile, proof, 1)
	// Exercise every existing input's maximum byte bound, without claiming
	// that arbitrary bytes are valid trust provenance.
	binding.Provenance = nativeProfileProvenance{Manifest: make([]byte, bootstrapstart.MaxControllerManifestMetadataBytes),
		Config: make([]byte, bootstrap.MaxControllerConfigBytes), MaterialChain: make([]byte, bootstrap.MaxMaterialGenerations*(bootstrap.MaxMaterialGenerationBytes+16<<10))}
	for i := range binding.Provenance.MaterialChain {
		binding.Provenance.MaterialChain[i] = byte(i*37 + i/4093)
	}
	state := nativeReleaseHistory{Schema: 1, Pending: &binding, Previous: &nativeGoodRelease{Binding: binding, Nodes: []string{"ctl-1"}, GoodAt: time.Now().UTC()}}
	for i := range 10 {
		g := *state.Previous
		g.Binding.Intent.OperationID = entityid.Derive("worst-proof", fmt.Sprint(i))
		g.Binding.Fingerprint, _ = g.Binding.Intent.Fingerprint()
		state.Good = append(state.Good, g)
	}
	if err := f.history.checkForwardCapacity(state); err != nil {
		t.Fatal(err)
	}
	if err := f.history.save(t.Context(), 7, terrabase.Role, state, 0); err != nil {
		t.Fatal(err)
	}
	loaded, rev, err := f.history.load(t.Context(), terrabase.Role)
	if err != nil || !slices.Equal(loaded.Pending.Provenance.MaterialChain, binding.Provenance.MaterialChain) || len(loaded.Good) != 10 {
		t.Fatalf("maximum chain hydration: %v", err)
	}
	if err := f.history.verifyProfile(terrabase.Role, loaded.Pending.Profile, loaded.Pending.Provenance); err == nil {
		t.Fatal("synthetic proof passed trust validation")
	}
	oversize := *loaded.Pending
	oversize.Provenance.MaterialChain = make([]byte, len(binding.Provenance.MaterialChain)+1)
	loaded.Pending = &oversize
	if err := f.history.save(t.Context(), 7, terrabase.Role, loaded, rev); !errors.Is(err, delivery.ErrInvalid) {
		t.Fatalf("over-bound proof accepted: %v", err)
	}
	if _, next, err := f.history.load(t.Context(), terrabase.Role); err != nil || next != rev {
		t.Fatalf("failed capacity advanced reference: %d %v", next, err)
	}
	if _, _, err := encodeNativeHistory(state, 16<<10); !errors.Is(err, delivery.ErrInvalid) {
		t.Fatalf("small broker bound ignored: %v", err)
	}
}

func TestNativeSelectionErrorClassification(t *testing.T) {
	f := newRetainedConsumerFixture(t)
	profile := nativeRegressionProfile()
	proof := nativeRegressionAdopt(t, f, profile, 1)
	binding := f.binding(t, terrabase.Role, profile, proof, 1)
	if _, err := f.history.profile(t.Context(), binding.Intent); !errors.Is(err, delivery.ErrInvalid) {
		t.Fatalf("missing selection=%v", err)
	}
	f.save(t, terrabase.Role, nativeReleaseHistory{Schema: 1, Pending: &binding})
	other := binding.Intent
	other.OperationID = entityid.New()
	if _, err := f.history.profile(t.Context(), other); !errors.Is(err, delivery.ErrInvalid) {
		t.Fatalf("mismatched selection=%v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.history.profile(ctx, binding.Intent); errors.Is(err, delivery.ErrInvalid) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled metadata read=%v", err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if _, err := f.history.profile(ctx, binding.Intent); errors.Is(err, delivery.ErrInvalid) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("store deadline=%v", err)
	}
}

func TestNativeReadRetryHandlesElectionWithoutRetryingPermanentFailure(t *testing.T) {
	unavailable := &nats.APIError{Code: 503, ErrorCode: nats.JSErrCodeJetStreamNotAvailable, Description: "JetStream system temporarily unavailable"}
	calls := 0
	want := &nats.RawStreamMsg{Sequence: 7, Data: []byte("selected")}
	got, err := nativeReadRetry(t.Context(), func(ctx context.Context) (*nats.RawStreamMsg, error) {
		calls++
		if calls < 3 {
			return nil, unavailable
		}
		return want, nil
	})
	if err != nil || got != want || calls != 3 {
		t.Fatalf("election read: calls=%d value=%v err=%v", calls, got, err)
	}
	calls = 0
	_, err = nativeReadRetry(t.Context(), func(context.Context) (*nats.RawStreamMsg, error) { calls++; return nil, nats.ErrMsgNotFound })
	if !errors.Is(err, nats.ErrMsgNotFound) || calls != 1 {
		t.Fatalf("permanent metadata failure retried: calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	calls = 0
	started := time.Now()
	_, err = nativeReadRetry(ctx, func(context.Context) (*nats.RawStreamMsg, error) { calls++; return nil, unavailable })
	if err == nil || calls != 1 || time.Since(started) > time.Second || errors.Is(err, delivery.ErrInvalid) {
		t.Fatalf("bounded metadata read: calls=%d elapsed=%s err=%v", calls, time.Since(started), err)
	}
}

func TestNativeManualRecoveryDeadlineDoesNotPoisonHealthyGood(t *testing.T) {
	f := newRetainedConsumerFixture(t)
	profile := nativeRegressionProfile()
	proof := nativeRegressionAdopt(t, f, profile, 1)
	good := f.binding(t, terrabase.Role, profile, proof, 1)
	recovery := good
	recovery.Intent.OperationID, recovery.Intent.Generation = entityid.New(), 2
	recovery.Fingerprint, _ = recovery.Intent.Fingerprint()
	recovery.Deadline = time.Now().Add(-time.Minute)
	state := nativeReleaseHistory{Schema: 1, Pending: &good, Recovery: &recovery, Good: []nativeGoodRelease{{Binding: good, Nodes: []string{"ctl-1"}, GoodAt: time.Now().UTC()}}}
	f.save(t, terrabase.Role, state)
	d := host.Desired{Cell: "gru", Node: "ctl-1", Role: terrabase.Role, Environment: "test", AuthorityEpoch: 7, Generation: 2, Digest: good.Artifact.Digest, Env: profile.Env}
	checks := []func() error{
		func() error { _, err := f.history.profile(t.Context(), recovery.Intent); return err },
		func() error { return f.history.allowDesired(t.Context(), d) },
		func() error { return f.history.prepareGate(t.Context(), recovery.Intent, state) },
		func() error { _, err := f.history.observe(t.Context(), recovery.Intent); return err },
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, delivery.ErrInvalid) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("manual expiry check %d: %v", i, err)
		}
	}
	after, _, err := f.history.load(t.Context(), terrabase.Role)
	if err != nil || after.Rejected != "" || len(after.Good) != 1 || after.Good[0].Binding.Fingerprint != good.Fingerprint {
		t.Fatalf("expiry poisoned healthy good: %v", err)
	}
	if bad, err := f.history.badProfile(t.Context(), good); bad || err != nil {
		t.Fatalf("expired manual recovery marked target bad: %t %v", bad, err)
	}
	addNativeGood(&after, nativeGoodRelease{Binding: recovery, Nodes: []string{"ctl-1"}, GoodAt: time.Now().UTC()})
	f.save(t, terrabase.Role, after)
	if err := f.history.allowDesired(t.Context(), d); err != nil {
		t.Fatal("certified manual target could not heal:", err)
	}
}

func TestNativeObserveVerifiesSelectedAndBaselineBeforeFencing(t *testing.T) {
	for _, invalid := range []string{"selected", "baseline", "recovery"} {
		t.Run(invalid, func(t *testing.T) {
			f := newRetainedConsumerFixture(t)
			profile := nativeRegressionProfile()
			proof := nativeRegressionAdopt(t, f, profile, 1)
			previous := f.binding(t, terrabase.Role, profile, proof, 1)
			selected := f.binding(t, terrabase.Role, profile, proof, 2)
			state := nativeReleaseHistory{Schema: 1, Pending: &selected,
				Previous: &nativeGoodRelease{Binding: previous, Nodes: []string{"ctl-1"}, GoodAt: time.Now().UTC()}}
			if invalid == "baseline" {
				state.Previous.Binding.Provenance.Spec = []byte("invalid signed baseline")
			} else {
				selected.Provenance.Spec = []byte("invalid signed selection")
			}
			if invalid == "recovery" {
				selected.Deadline = time.Time{}
				state.Recovery = &selected
			}
			f.save(t, terrabase.Role, state)
			// A pending delivery must not hide invalid trust before fence effects.
			f.history.fences = &releaseFence{}
			if ready, err := f.history.observe(t.Context(), selected.Intent); ready || err == nil {
				t.Fatalf("invalid %s reached delivery/fence admission: ready=%t err=%v", invalid, ready, err)
			}
		})
	}
}
