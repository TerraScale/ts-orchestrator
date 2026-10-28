package swarmruntime

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServiceSpecLockSharedByRoot(t *testing.T) {
	state := t.TempDir()
	unlock, err := lockServiceSpecs(t.Context(), singleHostControl{state: state})
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if release, err := lockServiceSpecs(ctx, singleHostControl{state: state}); err == nil {
		release()
		t.Fatal("another client acquired the same root's spec lock")
	}
	other, err := lockServiceSpecs(t.Context(), singleHostControl{state: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	other()
}

type safetyControl struct {
	api.ControlClient
	service    *api.Service
	task       *api.Task
	conflict   bool
	onConflict func(*api.Service)
	writes     int
	machine    string
}

func (c *safetyControl) ListServices(context.Context, *api.ListServicesRequest, ...grpc.CallOption) (*api.ListServicesResponse, error) {
	return &api.ListServicesResponse{Services: []*api.Service{c.service.Copy()}}, nil
}

func (c *safetyControl) GetService(context.Context, *api.GetServiceRequest, ...grpc.CallOption) (*api.GetServiceResponse, error) {
	return &api.GetServiceResponse{Service: c.service.Copy()}, nil
}

func (c *safetyControl) ListTasks(context.Context, *api.ListTasksRequest, ...grpc.CallOption) (*api.ListTasksResponse, error) {
	return &api.ListTasksResponse{Tasks: []*api.Task{c.task.Copy()}}, nil
}

func (c *safetyControl) GetNode(context.Context, *api.GetNodeRequest, ...grpc.CallOption) (*api.GetNodeResponse, error) {
	return &api.GetNodeResponse{Node: &api.Node{Description: &api.NodeDescription{Hostname: c.machine}}}, nil
}

func (c *safetyControl) UpdateService(_ context.Context, request *api.UpdateServiceRequest, _ ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	c.writes++
	if c.conflict {
		c.conflict = false
		c.service.Meta.Version.Index++
		if c.onConflict != nil {
			c.onConflict(c.service)
		}
		return nil, status.Error(codes.Unknown, "update out of sequence")
	}
	if *request.ServiceVersion != c.service.Meta.Version {
		return nil, status.Error(codes.Unknown, "update out of sequence")
	}
	c.service.Spec = *request.Spec.Copy()
	return &api.UpdateServiceResponse{Service: c.service.Copy()}, nil
}

func safetyFixture(t *testing.T) (ServiceSpec, *safetyControl) {
	t.Helper()
	spec := ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1, Generation: 7, Region: "gru", Node: "gru-1"}
	swarm, err := spec.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	service := &api.Service{ID: "service", Spec: *swarm, SpecVersion: &api.Version{Index: 3}}
	task := &api.Task{ID: "task", ServiceID: service.ID, NodeID: "node", Spec: *swarm.Task.Copy(), SpecVersion: service.SpecVersion.Copy(),
		ServiceAnnotations: *swarm.Annotations.Copy(), DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}}
	return spec, &safetyControl{service: service, task: task, machine: "gru-1"}
}

func TestServiceSpecRetriesMetadataConflictAndRejectsStaleGeneration(t *testing.T) {
	spec, control := safetyFixture(t)
	spec.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("b", 64)
	spec.Generation++
	control.conflict = true
	if _, err := ApplyServiceSpec(t.Context(), control, spec); err != nil || control.writes != 2 {
		t.Fatalf("metadata conflict: writes=%d, error=%v", control.writes, err)
	}
	spec.Generation--
	if _, err := ApplyServiceSpec(t.Context(), control, spec); err == nil || control.writes != 2 {
		t.Fatalf("stale generation wrote the service: writes=%d, error=%v", control.writes, err)
	}
}

func TestServiceSpecDefersMetadataWriteDuringUpdate(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial read", true: "CAS retry"}[conflict], func(t *testing.T) {
			spec, control := safetyFixture(t)
			spec.Generation++
			updating := func(service *api.Service) {
				service.UpdateStatus = &api.UpdateStatus{State: api.UpdateStatus_UPDATING}
			}
			writes := 0
			if conflict {
				control.conflict, control.onConflict = true, updating
				writes = 1
			} else {
				updating(control.service)
			}
			service, err := ApplyServiceSpec(t.Context(), control, spec)
			if err != nil || control.writes != writes || service.Spec.Annotations.Labels[LabelGeneration] != "7" {
				t.Fatalf("metadata write restarted updater: service=%+v writes=%d err=%v", service, control.writes, err)
			}
			stale := spec
			stale.Generation = 6
			if _, err := ApplyServiceSpec(t.Context(), control, stale); err == nil || control.writes != writes {
				t.Fatalf("deferred metadata bypassed admission: writes=%d err=%v", control.writes, err)
			}
			control.service.UpdateStatus = &api.UpdateStatus{State: api.UpdateStatus_COMPLETED}
			service, err = ApplyServiceSpec(t.Context(), control, spec)
			if err != nil || control.writes != writes+1 || service.Spec.Annotations.Labels[LabelGeneration] != "8" {
				t.Fatalf("completed update did not accept deferred metadata: service=%+v writes=%d err=%v", service, control.writes, err)
			}
		})
	}
}

func TestServiceSpecRollbackAncestryPreservesInterveningGeneration(t *testing.T) {
	spec, control := safetyFixture(t)
	rollback := spec
	rollback.Generation, rollback.RollbackOf = 9, spec.Generation
	if _, err := ApplyServiceSpec(t.Context(), control, rollback); err != nil {
		t.Fatal(err)
	}
	// A metadata-only rollback keeps the original task and its actual generation.
	if _, err := WaitServiceSpecExact(t.Context(), control, rollback); err != nil {
		t.Fatalf("rollback rejected unchanged original task: %v", err)
	}
	control.task.ServiceAnnotations = *control.service.Spec.Annotations.Copy()
	operator := spec
	operator.Generation = 8
	if _, err := ApplyServiceSpec(t.Context(), control, operator); err != nil {
		t.Fatalf("rollback's higher timestamp fenced the intervening operator: %v", err)
	}
	if rollout, err := WaitServiceSpecExact(t.Context(), control, operator); err != nil || rollout.Tasks[0].Generation != 9 {
		t.Fatalf("operator rejected unchanged rollback task's actual generation: %+v, %v", rollout, err)
	}
	writes := control.writes
	if _, err := ApplyServiceSpec(t.Context(), control, rollback); err == nil || control.writes != writes {
		t.Fatal("stale rollback overwrote intervening operator generation")
	}
	for _, value := range []string{"-1", "8", "9", "invalid"} {
		control.service.Spec.Annotations.Labels[LabelRollbackOf] = value
		if _, err := ApplyServiceSpec(t.Context(), control, operator); err == nil || control.writes != writes {
			t.Fatalf("invalid persisted rollback ancestry %q accepted", value)
		}
	}
}

func TestServiceSpecExactEvidenceRejectsUnrelatedArtifact(t *testing.T) {
	spec, control := safetyFixture(t)
	rollout, err := WaitServiceSpecExact(t.Context(), control, spec)
	if err != nil || len(rollout.Tasks) != 1 || rollout.Tasks[0].Machine != spec.Node || rollout.Tasks[0].Image != spec.Image || rollout.Tasks[0].Ready {
		t.Fatalf("runtime evidence: %+v, %v", rollout, err)
	}
	// A founder node keeps the fixed single-host identity: the task runs on the checking machine.
	control.machine = singleHostID
	if founder, err := WaitServiceSpecExact(t.Context(), control, spec); err != nil || founder.Tasks[0].Machine != spec.Node {
		t.Fatalf("founder evidence: %+v, %v", founder, err)
	}
	control.machine = spec.Node
	// An unchanged workload retains its original task metadata in SwarmKit.
	control.task.SpecVersion.Index--
	control.task.ServiceAnnotations.Labels[LabelGeneration] = "6"
	if same, err := WaitServiceSpecExact(t.Context(), control, spec); err != nil || len(same.Tasks) != 1 || same.Tasks[0].Generation != 6 {
		t.Fatalf("unchanged artifact's actual task generation: %+v, %v", same, err)
	}

	// A ready-timeout or route change keeps the task that runs the same template.
	control.task.ServiceAnnotations.Labels[LabelReadyTimeout] = "60"
	control.task.ServiceAnnotations.Labels[LabelHostnames] = "old.example.com"
	if same, err := WaitServiceSpecExact(t.Context(), control, spec); err != nil || len(same.Tasks) != 1 {
		t.Fatalf("label-only change rejected its unchanged task: %+v, %v", same, err)
	}

	for _, change := range []func(*safetyControl){
		func(c *safetyControl) { c.task.ServiceAnnotations.Labels[LabelSecrets] = "TOKEN_FILE" },
		func(c *safetyControl) { c.task.Spec.ForceUpdate++ },
		func(c *safetyControl) { c.task.ServiceAnnotations.Labels[LabelGeneration] = "8" },
		func(c *safetyControl) { c.machine = "another-host" },
		func(c *safetyControl) { c.service.Spec.Task.ForceUpdate++ },
	} {
		spec, control := safetyFixture(t)
		change(control)
		if _, err := WaitServiceSpecExact(t.Context(), control, spec); err == nil {
			t.Fatal("unrelated task or service produced successful evidence")
		}
	}
}

func TestServiceSpecNewFloorReplacesOnlyStaleSignedRuntime(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		current    int64
		generation int64
		rollbackOf int64
		signed     bool
	}{
		{name: "rollback over signed 11", current: 11, generation: 12, rollbackOf: 10, signed: true},
		{name: "rollback over signed 13", current: 13, generation: 12, rollbackOf: 10, signed: true},
		{name: "operator below invalid signed generation", current: 13, generation: 11},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			spec, control := safetyFixture(t)
			older := &Deployment{Repository: "TerraScale/terrascale", RunID: "99", Revision: strings.Repeat("b", 40), Image: spec.Image}
			approved := *older
			approved.RunID = "100"
			spec.Generation, spec.Deployment, spec.DeploymentFloor = scenario.current, older, older
			swarm, err := spec.SwarmSpec()
			if err != nil {
				t.Fatal(err)
			}
			control.service.Spec = *swarm
			control.task.ServiceAnnotations = *swarm.Annotations.Copy()
			next := spec
			next.Generation, next.RollbackOf, next.DeploymentFloor = scenario.generation, scenario.rollbackOf, &approved
			next.Deployment = nil
			if scenario.signed {
				next.Deployment = &approved
			}
			control.conflict = true
			if _, err := ApplyServiceSpec(t.Context(), control, next); err != nil || control.writes != 2 {
				t.Fatalf("new floor did not replace invalid signed state through CAS retry: writes=%d, %v", control.writes, err)
			}
			// The workload is unchanged, so Swarm keeps its real task generation and authority.
			rollout, err := WaitServiceSpecExact(t.Context(), control, next)
			if err != nil || len(rollout.Tasks) != 1 || rollout.Tasks[0].Generation != scenario.current || rollout.Tasks[0].Deployment == nil || *rollout.Tasks[0].Deployment != *older || rollout.Tasks[0].DeploymentFloor == nil || *rollout.Tasks[0].DeploymentFloor != *older {
				t.Fatalf("exact evidence lost actual task authority: %+v, %v", rollout, err)
			}
			d, floor, err := serviceDeployment(spec.Name, control.service.Spec.Annotations.Labels)
			if err != nil || floor == nil || *floor != approved || !reflect.DeepEqual(d, next.Deployment) {
				t.Fatalf("service labels lost selected authority: %+v / %+v, %v", d, floor, err)
			}
			writes := control.writes
			spec.Generation = 20
			if _, err := ApplyServiceSpec(t.Context(), control, spec); err == nil || control.writes != writes {
				t.Fatal("old signed run regained authority with a higher generation")
			}
		})
	}
}

func TestServiceSpecHigherFloorPreservesInterveningOperator(t *testing.T) {
	spec, control := safetyFixture(t)
	older := &Deployment{Repository: "TerraScale/terrascale", RunID: "99", Revision: strings.Repeat("b", 40), Image: spec.Image}
	spec.Generation, spec.DeploymentFloor = 11, older
	swarm, err := spec.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	control.service.Spec = *swarm
	for _, run := range []string{"99", "100", "101"} {
		d := *older
		d.RunID = run
		rollback := spec
		rollback.Generation, rollback.RollbackOf, rollback.Deployment, rollback.DeploymentFloor = 12, 10, &d, &d
		if _, err := ApplyServiceSpec(t.Context(), control, rollback); err == nil || control.writes != 0 {
			t.Fatalf("run %s bypassed intervening operator generation", run)
		}
	}
	// Re-evaluate authority after a service-version conflict, including a new operator.
	signed := spec
	signed.Generation, signed.Deployment = 13, older
	swarm, err = signed.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	control.service.Spec = *swarm
	approved := *older
	approved.RunID = "100"
	rollback := spec
	rollback.Generation, rollback.RollbackOf, rollback.Deployment, rollback.DeploymentFloor = 12, 10, &approved, &approved
	control.conflict = true
	control.onConflict = func(service *api.Service) { service.Spec = swarmForTest(t, spec) }
	if _, err := ApplyServiceSpec(t.Context(), control, rollback); err == nil || control.writes != 1 {
		t.Fatalf("CAS retry overwrote intervening operator: writes=%d, %v", control.writes, err)
	}
}

func swarmForTest(t *testing.T, spec ServiceSpec) api.ServiceSpec {
	t.Helper()
	swarm, err := spec.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	return *swarm
}

func TestServiceSpecRefusesInvalidDeploymentAuthority(t *testing.T) {
	spec, _ := safetyFixture(t)
	d := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: spec.Image}
	for _, invalid := range []ServiceSpec{
		{Name: spec.Name, Image: spec.Image, Port: spec.Port, Replicas: 1, DeploymentFloor: d},
		{Name: spec.Name, Image: spec.Image, Port: spec.Port, Replicas: 1, Generation: 1, Deployment: d},
		{Name: spec.Name, Image: spec.Image, Port: spec.Port, Replicas: 1, Generation: 1, Deployment: d, DeploymentFloor: new(Deployment{Repository: d.Repository, RunID: "101", Revision: d.Revision, Image: d.Image})},
	} {
		if _, err := invalid.SwarmSpec(); err == nil {
			t.Fatal("invalid requested authority accepted")
		}
	}
	for _, mutate := range []func(*Deployment){
		func(d *Deployment) { d.RunID = "99" },
		func(d *Deployment) { d.Revision = strings.Repeat("c", 40) },
		func(d *Deployment) { d.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("c", 64) },
		func(d *Deployment) { d.Repository = "TerraScale/another" },
	} {
		spec, control := safetyFixture(t)
		spec.Deployment, spec.DeploymentFloor = d, d
		control.service.Spec = swarmForTest(t, spec)
		candidate := *d
		mutate(&candidate)
		spec.Generation++
		spec.Deployment, spec.DeploymentFloor = &candidate, &candidate
		if _, err := ApplyServiceSpec(t.Context(), control, spec); err == nil || control.writes != 0 {
			t.Fatal("stale or equivocal authority wrote runtime state")
		}
	}
	for _, value := range []string{"null", "{}", "invalid", `{"runId":"100","runId":"101"}`} {
		spec, control := safetyFixture(t)
		control.service.Spec.Annotations.Labels[LabelDeploymentFloor] = value
		spec.Generation++
		if _, err := ApplyServiceSpec(t.Context(), control, spec); err == nil || control.writes != 0 {
			t.Fatalf("invalid persisted authority %q accepted", value)
		}
	}
	spec, control := safetyFixture(t)
	spec.DeploymentFloor = d
	control.service.Spec = swarmForTest(t, spec)
	spec.Generation++
	spec.DeploymentFloor = nil
	if _, err := ApplyServiceSpec(t.Context(), control, spec); err == nil || control.writes != 0 {
		t.Fatal("operator removed the accepted runtime floor")
	}
}

func TestCompleteServiceSpecRequiresApplySnapshot(t *testing.T) {
	if err := CompleteServiceSpec(t.Context(), nil, ServiceSpec{}, nil); err == nil || !strings.Contains(err.Error(), "original apply snapshot") {
		t.Fatalf("completion accepted a missing Apply snapshot: %v", err)
	}
}

func TestDeploymentAttemptFencesRuntime(t *testing.T) {
	for _, rollback := range []int64{0, 10} {
		spec, control := safetyFixture(t)
		d := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", RunAttempt: 1, Revision: strings.Repeat("b", 40), Image: spec.Image}
		spec.Generation, spec.RollbackOf, spec.Deployment, spec.DeploymentFloor = 11, rollback, d, d
		control.service.Spec = swarmForTest(t, spec)
		next := *d
		next.RunAttempt, next.Image = 2, "ghcr.io/terrascale/web@sha256:"+strings.Repeat("c", 64)
		spec.Generation, spec.RollbackOf, spec.Image, spec.Deployment, spec.DeploymentFloor = 12, 0, next.Image, &next, &next
		// A re-run's rebuilt image retries the run, serving or rolled back.
		if err := admitServiceSpec(control.service.Spec.Annotations.Labels, spec); err != nil {
			t.Fatalf("rollback=%d: %v", rollback, err)
		}
		if next.Accepts(d) == nil {
			t.Fatal("older attempt admitted")
		}
		changed := next
		changed.Revision = strings.Repeat("e", 40)
		changed.RunAttempt++
		if next.Accepts(&changed) == nil {
			t.Fatal("rerun changed commit")
		}
	}
}
