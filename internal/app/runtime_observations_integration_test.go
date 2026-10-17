package app

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestManagedServiceObservationUsesActualManagerAndUnknownReadiness(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	state := store.NewMemoryStore(nil)
	t.Cleanup(func() { _ = state.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var blockTaskRead atomic.Bool
	var managerDeadline atomic.Pointer[time.Time]
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if blockTaskRead.Load() && strings.HasSuffix(info.FullMethod, "/GetTask") {
			if deadline, known := ctx.Deadline(); known {
				managerDeadline.Store(&deadline)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return handler(ctx, request)
	}))
	api.RegisterControlServer(server, controlapi.NewServer(state, nil, nil, nil, nil))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client := api.NewControlClient(connection)
	runtime, err := swarmruntime.ContainerRuntime(&api.ContainerSpec{Image: "example.invalid/api@sha256:" + strings.Repeat("a", 64), User: "65532:65532"})
	if err != nil {
		t.Fatal(err)
	}
	service := &api.Service{ID: strings.Repeat("b", 25), Spec: api.ServiceSpec{
		Annotations: api.Annotations{Name: "regional-api", Labels: map[string]string{
			swarmruntime.LabelIntentID: entityid.New(), swarmruntime.LabelRole: "api", swarmruntime.LabelRegion: "sa-saopaulo-1", swarmruntime.LabelEnvironment: "canary",
		}},
		Task: api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 64 << 20}}},
		Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 2}},
	}}
	if err := state.Update(func(tx store.Tx) error { return store.CreateService(tx, service) }); err != nil {
		t.Fatal(err)
	}
	views, err := observeManagedServices(ctx, client, "sa-saopaulo-1", "canary", nil)
	if err != nil || len(views) != 1 || views[0].RequestedReplicas != 2 || views[0].Readiness != "unknown" || views[0].ReadinessReason == "" || len(views[0].Tasks) != 0 || views[0].ObservedAt.IsZero() {
		t.Fatalf("unplaced service observation: %+v %v", views, err)
	}
	task := &api.Task{ID: strings.Repeat("c", 25), ServiceID: service.ID, NodeID: strings.Repeat("d", 25), Spec: service.Spec.Task,
		ServiceAnnotations: service.Spec.Annotations, DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}}
	if err := state.Update(func(tx store.Tx) error { return store.CreateTask(tx, task) }); err != nil {
		t.Fatal(err)
	}
	views, err = observeManagedServices(ctx, client, "sa-saopaulo-1", "canary", nil)
	if err != nil || len(views) != 1 || views[0].RunningReplicas != 1 || views[0].ReadyReplicas != 0 || views[0].Readiness != "unknown" || views[0].ReadinessReason == "" || len(views[0].Tasks) != 1 || views[0].Tasks[0].Ready {
		t.Fatalf("RUNNING invented application readiness: %+v %v", views, err)
	}
	views, err = observeManagedServices(ctx, client, "eu-frankfurt-1", "canary", nil)
	if err != nil || len(views) != 0 {
		t.Fatalf("foreign region service observed locally: %+v %v", views, err)
	}
	readiness := func(_ context.Context, actual *api.Task) (func(context.Context) error, time.Time, error) {
		if actual.ID != task.ID || actual.NodeID != task.NodeID || actual.ServiceID != service.ID {
			t.Fatalf("probe did not receive the actual manager task: %+v", actual)
		}
		return func(context.Context) error { return nil }, time.Now().Add(time.Minute), nil
	}
	views, err = observeManagedServices(ctx, client, "sa-saopaulo-1", "canary", readiness)
	if err != nil || len(views) != 1 || views[0].Readiness != "observed" || views[0].ReadyReplicas != 1 || !views[0].Tasks[0].Ready {
		t.Fatalf("actual task readiness was not published: %+v %v", views, err)
	}
	checks := 0
	views, err = observeManagedServices(ctx, client, "sa-saopaulo-1", "canary", func(context.Context, *api.Task) (func(context.Context) error, time.Time, error) {
		return func(context.Context) error {
			checks++
			if checks > 1 {
				return errors.New("original readiness source expired before publication")
			}
			return nil
		}, time.Now().Add(time.Minute), nil
	})
	if err != nil || len(views) != 1 || checks != 2 || views[0].Readiness != "unknown" || views[0].ReadyReplicas != 0 || views[0].Tasks[0].Ready {
		t.Fatalf("expired retained source asserted readiness: %+v %v (checks %d)", views, err, checks)
	}
	views, err = observeManagedServices(ctx, client, "sa-saopaulo-1", "canary", func(ctx context.Context, actual *api.Task) (func(context.Context) error, time.Time, error) {
		if err := state.Update(func(tx store.Tx) error {
			changed := store.GetTask(tx, actual.ID)
			changed.Status.Err = "task changed during readiness probe"
			return store.UpdateTask(tx, changed)
		}); err != nil {
			t.Fatal(err)
		}
		return readiness(ctx, actual)
	})
	if err != nil || len(views) != 1 || views[0].Readiness != "unknown" || views[0].ReadyReplicas != 0 || views[0].Tasks[0].Ready {
		t.Fatalf("changed actual task asserted readiness: %+v %v", views, err)
	}
	if err := state.Update(func(tx store.Tx) error {
		current := store.GetTask(tx, task.ID)
		current.Status.Err = ""
		return store.UpdateTask(tx, current)
	}); err != nil {
		t.Fatal(err)
	}
	views, err = observeManagedServices(ctx, client, "sa-saopaulo-1", "canary", func(ctx context.Context, actual *api.Task) (func(context.Context) error, time.Time, error) {
		if err := state.Update(func(tx store.Tx) error {
			changed := store.GetService(tx, service.ID)
			changed.Spec.Annotations.Name = "changed-during-probe"
			return store.UpdateService(tx, changed)
		}); err != nil {
			t.Fatal(err)
		}
		return readiness(ctx, actual)
	})
	if err == nil || views != nil {
		t.Fatalf("changed actual service asserted readiness: %+v %v", views, err)
	}
	secondService := service.Copy()
	secondService.ID = strings.Repeat("e", 25)
	secondService.Spec.Annotations.Name = "second-regional-api"
	secondTask := task.Copy()
	secondTask.ID, secondTask.ServiceID = strings.Repeat("f", 25), secondService.ID
	secondTask.ServiceAnnotations = secondService.Spec.Annotations
	if err := state.Update(func(tx store.Tx) error {
		if err := store.CreateService(tx, secondService); err != nil {
			return err
		}
		return store.CreateTask(tx, secondTask)
	}); err != nil {
		t.Fatal(err)
	}
	probed := 0
	firstTask := ""
	firstDeadline := time.Now().Add(5 * time.Second)
	views, err = observeManagedServices(ctx, client, "sa-saopaulo-1", "canary", func(probeCtx context.Context, actual *api.Task) (func(context.Context) error, time.Time, error) {
		probed++
		deadline := firstDeadline
		if probed == 1 {
			firstTask = actual.ID
		} else {
			if inherited, known := probeCtx.Deadline(); !known || inherited.After(firstDeadline) {
				t.Fatalf("later service probe exceeded first captured deadline: %v (known %v), want <= %v", inherited, known, firstDeadline)
			}
			deadline = firstDeadline.Add(time.Minute)
		}
		return func(context.Context) error {
			if actual.ID == firstTask && probed > 1 {
				return errors.New("first source became invalid while observing second service")
			}
			return nil
		}, deadline, nil
	})
	if err != nil || len(views) != 2 || probed != 2 {
		t.Fatalf("two-service observation did not complete: %+v %v (probed %d)", views, err, probed)
	}
	for _, view := range views {
		if len(view.Tasks) != 1 {
			t.Fatalf("two-service observation lost the actual task: %+v", view)
		}
		if view.Tasks[0].TaskID == firstTask && (view.Readiness != "unknown" || view.ReadyReplicas != 0 || view.Tasks[0].Ready) {
			t.Fatalf("later service observation revived first invalid proof: %+v", view)
		}
	}
	if err := state.Update(func(tx store.Tx) error {
		if err := store.DeleteTask(tx, secondTask.ID); err != nil {
			return err
		}
		return store.DeleteService(tx, secondService.ID)
	}); err != nil {
		t.Fatal(err)
	}
	blocked, stopBlocked := context.WithTimeout(ctx, 2*time.Second)
	defer stopBlocked()
	originalDeadline := time.Now().Add(500 * time.Millisecond)
	views, err = observeManagedServices(blocked, client, "sa-saopaulo-1", "canary", func(context.Context, *api.Task) (func(context.Context) error, time.Time, error) {
		blockTaskRead.Store(true)
		return func(context.Context) error { return nil }, originalDeadline, nil
	})
	blockTaskRead.Store(false)
	if captured := managerDeadline.Load(); captured == nil || captured.After(originalDeadline.Add(2*time.Millisecond)) {
		t.Fatalf("manager wait exceeded original proof deadline: %v, want <= %v", captured, originalDeadline)
	}
	if err == nil || views != nil {
		t.Fatalf("expired blocked manager read became an observed fleet: %+v %v", views, err)
	}

	for _, role := range []string{"terrabase", swarmruntime.FunctionWorkerRole} {
		if err := state.Update(func(tx store.Tx) error {
			current := store.GetService(tx, service.ID)
			current.Spec.Annotations.Labels[swarmruntime.LabelRole] = role
			return store.UpdateService(tx, current)
		}); err != nil {
			t.Fatal(err)
		}
		views, err = observeManagedServices(ctx, client, "sa-saopaulo-1", "canary", func(context.Context, *api.Task) (func(context.Context) error, time.Time, error) {
			t.Fatalf("%s used generic application readiness", role)
			return nil, time.Time{}, nil
		})
		if err != nil || len(views) != 1 || views[0].Readiness != "unknown" || views[0].ReadyReplicas != 0 {
			t.Fatalf("%s invented native readiness: %+v %v", role, views, err)
		}
	}
	server.Stop()
	failed, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if views, err := observeManagedServices(failed, client, "sa-saopaulo-1", "canary", nil); err == nil || views != nil {
		t.Fatalf("manager outage became an observed empty fleet: %+v %v", views, err)
	}
}
