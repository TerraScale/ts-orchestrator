package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
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
