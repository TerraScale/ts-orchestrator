package swarmruntime

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/moby/swarmkit/v2/api"
)

// The source can deliver a release through the real control socket while a
// signal read is in flight, proving that an older scale decision loses its CAS.
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
	manager := nodeFixtureStart(t, ctx, nodeFixtureConfig(t, "founder", "manager"))
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := autoscale.Target{Cell: "integration", Environment: "production", Role: "api"}
	policy := ScalePolicy{Target: target, Bounds: autoscale.Bounds{Min: 2, Max: 6}, Policy: &autoscale.Policy{
		Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}},
	}}
	source := autoscale.NewWindowStore(0, 0)
	scaler, err := NewAutoscaler(client, manager.ID(), source, []ScalePolicy{policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(ctx); err != nil || scaler.Last()[target].Reason != "awaiting-release" {
		t.Fatalf("before release: %+v, %v", scaler.Last(), err)
	}
	created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: &api.ServiceSpec{
		Annotations: api.Annotations{Name: "autoscale-proof", Labels: map[string]string{
			LabelRegion: target.Cell, LabelEnvironment: target.Environment, LabelRole: target.Role, "preserve": "release-label",
		}},
		Task: api.TaskSpec{
			Runtime: &api.TaskSpec_Container{Container: &api.ContainerSpec{
				Image: "example.invalid/api@sha256:" + strings.Repeat("a", 64),
				Env:   []string{"SERVICE=api"},
			}},
			Placement: &api.Placement{Constraints: []string{"node.labels.host-role==container"}},
		},
		Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 0}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	id := created.Service.ID
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
			t.Fatalf("persisted replicas = %d, want %d", got, want)
		}
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertReplicas(2)
	// Bounds-only policy drains through the same upstream replica field.
	if err := scaler.SetPolicies([]ScalePolicy{{Target: target, Bounds: autoscale.Bounds{}}}); err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertReplicas(0)
	if err := scaler.SetPolicies([]ScalePolicy{policy}); err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertReplicas(2)
	before := service().Spec.Copy()
	source.Record(target, autoscale.SignalCPUUtilization, autoscale.Sample{At: time.Now(), Value: 1})
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertReplicas(4)
	before.GetReplicated().Replicas = 4
	if after := service().Spec.Copy(); !reflect.DeepEqual(before, after) {
		t.Fatalf("autoscale changed release fields:\nbefore %+v\nafter %+v", before, after)
	}

	// Missing memory data blocks removal even though CPU recommends fewer tasks.
	policy.Policy.Signals = append(policy.Policy.Signals, autoscale.Signal{Name: autoscale.SignalMemoryUtilization, Target: 0.5})
	source = autoscale.NewWindowStore(0, 0)
	source.Record(target, autoscale.SignalCPUUtilization, autoscale.Sample{At: time.Now(), Value: 0.1})
	scaler, err = NewAutoscaler(client, manager.ID(), source, []ScalePolicy{policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertReplicas(4)
	if got := scaler.Last()[target].Reason; got != autoscale.ReasonScaleDownSignalGap {
		t.Fatalf("missing-signal hold = %q", got)
	}
	source.Record(target, autoscale.SignalMemoryUtilization, autoscale.Sample{At: time.Now(), Value: 0.1})
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertReplicas(2)

	// A concurrent release changes the version after observation. The stale
	// replica update must preserve the release and commit no decision history.
	policy.Policy = &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}}}
	source = autoscale.NewWindowStore(0, 0)
	source.Record(target, autoscale.SignalCPUUtilization, autoscale.Sample{At: time.Now(), Value: 1})
	racing := &releaseDuringSignal{Source: source, release: func() {
		current := service()
		current.Spec.Task.GetContainer().Image = "example.invalid/api@sha256:" + strings.Repeat("b", 64)
		if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: id,
			ServiceVersion: &current.Meta.Version, Spec: &current.Spec}); err != nil {
			t.Fatal(err)
		}
	}}
	scaler, err = NewAutoscaler(client, manager.ID(), racing, []ScalePolicy{policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(ctx); err == nil {
		t.Fatal("stale replica update did not conflict with the concurrent release")
	}
	assertReplicas(2)
	if got := service().Spec.Task.GetContainer().Image; !strings.Contains(got, strings.Repeat("b", 64)) {
		t.Fatalf("stale replica update overwrote release image: %s", got)
	}
	if len(scaler.Last()) != 0 || len(scaler.history) != 0 {
		t.Fatal("failed CAS published a result or advanced decision history")
	}

	// A policy for an ordinary worker identity cannot mutate desired state.
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	workerCfg := nodeFixtureConfig(t, "autoscale-worker", "container")
	workerCfg.Admission.ManagerAddress, err = manager.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	workerCfg.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
	worker := nodeFixtureStart(t, ctx, workerCfg)
	follower, err := NewAutoscaler(client, worker.ID(), source, []ScalePolicy{policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := follower.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertReplicas(2)
	if len(follower.Last()) != 0 {
		t.Fatal("worker published leader autoscaling observations")
	}

	// Bounds changes must also preserve the in-flight release's rollback spec.
	if err := scaler.SetPolicies([]ScalePolicy{{Target: target, Bounds: autoscale.Bounds{}}}); err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	assertReplicas(2)
	current := service()
	if got := scaler.Last()[target].Reason; got != "release-in-progress" || current.PreviousSpec == nil ||
		!strings.Contains(current.PreviousSpec.Task.GetContainer().Image, strings.Repeat("a", 64)) {
		t.Fatalf("in-flight release lost rollback history: reason=%s, service=%+v", got, current)
	}
}
