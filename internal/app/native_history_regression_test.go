package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
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

func TestNativeNearLimitSignedProfilesTenSuccessesAndRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("near-limit native profile regression runs in the Slow suite")
	}
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
