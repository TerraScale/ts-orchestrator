package swarmruntime

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/moby/swarmkit/v2/api"
)

// The source delivers a release through the real control socket while a signal
// read is in flight, proving that an older replica decision loses its CAS.
type releaseDuringSignal struct {
	autoscale.Source
	release func()
}

func (s *releaseDuringSignal) Read(ctx context.Context, target autoscale.Target, signal autoscale.Signal, now time.Time) (autoscale.Reading, error) {
	if s.release != nil {
		release := s.release
		s.release = nil
		release()
	}
	return s.Source.Read(ctx, target, signal, now)
}

func TestAutoscaleManagerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cfg := serviceConfig(t, "ts-gru-1", "manager")
	manager := serviceStart(t, ctx, cfg)
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitNode(ctx, client, manager.ID(), cfg.Admission); err != nil {
		t.Fatal(err)
	}
	var healthy atomic.Bool
	healthy.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() || r.Header.Get("X-Task-ID") == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	probe := func(ctx context.Context, task *api.Task) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if err != nil {
			return err
		}
		request.Header.Set("X-Task-ID", task.ID)
		response, err := server.Client().Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("readiness returned %d", response.StatusCode)
		}
		return nil
	}
	intent := serviceIntent()
	intent.Role, intent.Replicas = "api", 0
	target := autoscale.Target{Cell: intent.Region, Environment: intent.Environment, Role: intent.Role}
	policy := ScalePolicy{Target: target, Bounds: autoscale.Bounds{Min: 2, Max: 6}, Policy: &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}}}}
	source := autoscale.NewWindowStore(0, 0)
	newScaler := func(source autoscale.Source) *Autoscaler {
		t.Helper()
		scaler, err := NewAutoscaler(client, manager.ID(), source, probe, []ScalePolicy{policy})
		if err != nil {
			t.Fatal(err)
		}
		return scaler
	}
	scaler := newScaler(source)
	if err := scaler.Tick(ctx); err != nil || scaler.Last()[target].Reason != "awaiting-release" {
		t.Fatalf("before release: %+v, %v", scaler.Last(), err)
	}
	created, err := applyService(ctx, client, intent)
	if err != nil {
		t.Fatal(err)
	}
	id := created.ID
	service := func() *api.Service {
		t.Helper()
		response, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: id})
		if err != nil {
			t.Fatal(err)
		}
		return response.Service
	}
	assertReplicas := func(want uint64) {
		t.Helper()
		if got := service().Spec.GetReplicated().Replicas; got != want {
			t.Fatalf("persisted replicas=%d, want%d; decision%+v", got, want, scaler.Last()[target])
		}
	}
	ready := func(want uint64) {
		t.Helper()
		serviceEventually(t, ctx, func() bool {
			view, err := ObserveService(ctx, client, id, probe)
			return err == nil && view.ReadyReplicas == want && view.RequestedReplicas == want
		})
	}
	tick := func() {
		t.Helper()
		if err := scaler.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	tick()
	assertReplicas(2)
	ready(2)
	before := service().Spec.Copy()
	source.Record(target, autoscale.SignalCPUUtilization, autoscale.Sample{At: time.Now(), Value: 1})
	tick()
	assertReplicas(4)
	ready(4)
	before.GetReplicated().Replicas = 4
	if after := service().Spec.Copy(); !reflect.DeepEqual(before, after) {
		t.Fatal("autoscale changed release fields beyond replicas")
	}

	policy.Policy.Signals = append(policy.Policy.Signals, autoscale.Signal{Name: autoscale.SignalMemoryUtilization, Target: 0.5})
	source = autoscale.NewWindowStore(0, 0)
	source.Record(target, autoscale.SignalCPUUtilization, autoscale.Sample{At: time.Now(), Value: 0.1})
	scaler = newScaler(source)
	tick()
	assertReplicas(4)
	if got := scaler.Last()[target].Reason; got != autoscale.ReasonScaleDownSignalGap {
		t.Fatalf("missing-signal hold=%q", got)
	}
	source.Record(target, autoscale.SignalMemoryUtilization, autoscale.Sample{At: time.Now(), Value: 0.1})
	tick()
	assertReplicas(2)
	ready(2)
	if err := scaler.SetPolicies([]ScalePolicy{{Target: target, Bounds: autoscale.Bounds{}}}); err != nil {
		t.Fatal(err)
	}
	tick()
	assertReplicas(0)
	policy.Policy = &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}}}
	source = autoscale.NewWindowStore(0, 0)
	source.Record(target, autoscale.SignalCPUUtilization, autoscale.Sample{At: time.Now(), Value: 1})
	scaler = newScaler(source)
	tick()
	assertReplicas(2)
	ready(2)

	// Lifecycle RUNNING cannot authorize overwriting rollback history while
	// application readiness is unhealthy, even for a bounds correction.
	healthy.Store(false)
	if err := scaler.SetPolicies([]ScalePolicy{{Target: target, Bounds: autoscale.Bounds{}}}); err != nil {
		t.Fatal(err)
	}
	tick()
	assertReplicas(2)
	if got := scaler.Last()[target].Reason; got != "unready-replicas" {
		t.Fatalf("HTTP-unhealthy replicas did not hold: %s", got)
	}
	healthy.Store(true)
	racing := &releaseDuringSignal{Source: source, release: func() {
		intent.Container.Image = "example.invalid/fixture@sha256:" + strings.Repeat("b", 64)
		if _, err := applyService(ctx, client, intent); err != nil {
			t.Fatal(err)
		}
	}}
	scaler = newScaler(racing)
	if err := scaler.Tick(ctx); err == nil {
		t.Fatal("stale replica update did not conflict with concurrent release")
	}
	assertReplicas(2)
	if got := runtimeDigest(service().Spec); got != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("stale replica update overwrote release image: %s", got)
	}
	if len(scaler.Last()) != 0 || len(scaler.history) != 0 {
		t.Fatal("failed CAS published a result or advanced decision history")
	}
	healthy.Store(false)
	if err := scaler.SetPolicies([]ScalePolicy{{Target: target, Bounds: autoscale.Bounds{}}}); err != nil {
		t.Fatal(err)
	}
	tick()
	assertReplicas(2)
	current := service()
	if current.PreviousSpec == nil || runtimeDigest(*current.PreviousSpec) != "sha256:"+strings.Repeat("a", 64) {
		t.Fatal("autoscale overwrote the last healthy release while readiness was pending")
	}

	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	workerCfg := serviceConfig(t, "autoscale-worker", "container")
	workerCfg.Admission.ManagerAddress, err = manager.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	workerCfg.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
	worker := serviceStart(t, ctx, workerCfg)
	follower, err := NewAutoscaler(client, worker.ID(), source, probe, []ScalePolicy{{Target: target, Bounds: autoscale.Bounds{}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := follower.Tick(ctx); err != nil || len(follower.Last()) != 0 {
		t.Fatalf("worker performed manager policy evaluation: %+v, %v", follower.Last(), err)
	}
	assertReplicas(2)

	duplicate := intent
	duplicate.ID = entityid.Derive("autoscale-duplicate", intent.ID)
	if _, err := applyService(ctx, client, duplicate); err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(ctx); err == nil {
		t.Fatal("ambiguous service identity authorized a replica update")
	}
	assertReplicas(2)
}
