package mesh

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Only containerd is faked at the applier boundary; Apply and Wait are production methods.
type deferredApplier struct{ swarmApplier }

func (deferredApplier) PrePull(context.Context, swarmruntime.ServiceSpec) error { return nil }

type deferredControl struct {
	api.ControlClient
	mu       sync.Mutex
	service  *api.Service
	task     *api.Task
	reads    int
	writes   int
	waiting  chan struct{}
	conflict func()
}

func (c *deferredControl) ListServices(_ context.Context, request *api.ListServicesRequest, _ ...grpc.CallOption) (*api.ListServicesResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if request.Filters != nil {
		c.reads++
		// Apply reads first, completion pins the second, and its first retry reads third.
		if c.reads == 3 {
			close(c.waiting)
		}
	}
	if c.service == nil {
		return &api.ListServicesResponse{}, nil
	}
	return &api.ListServicesResponse{Services: []*api.Service{c.service.Copy()}}, nil
}

func (c *deferredControl) GetService(context.Context, *api.GetServiceRequest, ...grpc.CallOption) (*api.GetServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.service == nil {
		return nil, status.Error(codes.NotFound, "removed")
	}
	return &api.GetServiceResponse{Service: c.service.Copy()}, nil
}

func (c *deferredControl) ListTasks(context.Context, *api.ListTasksRequest, ...grpc.CallOption) (*api.ListTasksResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &api.ListTasksResponse{Tasks: []*api.Task{c.task.Copy()}}, nil
}

func (c *deferredControl) GetNode(context.Context, *api.GetNodeRequest, ...grpc.CallOption) (*api.GetNodeResponse, error) {
	return &api.GetNodeResponse{Node: &api.Node{Description: &api.NodeDescription{Hostname: "gru-1"}}}, nil
}

func (c *deferredControl) UpdateService(_ context.Context, request *api.UpdateServiceRequest, _ ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.service.UpdateStatus != nil && c.service.UpdateStatus.State == api.UpdateStatus_UPDATING {
		return nil, errors.New("metadata restarted the active updater")
	}
	if c.conflict != nil {
		c.conflict()
		c.conflict = nil
		return nil, status.Error(codes.Unknown, "update out of sequence")
	}
	if *request.ServiceVersion != c.service.Meta.Version {
		return nil, status.Error(codes.Unknown, "update out of sequence")
	}
	c.service.Spec = *request.Spec.Copy()
	c.service.Meta.Version.Index++
	c.service.SpecVersion = c.service.Meta.Version.Copy()
	c.service.UpdateStatus = nil
	return &api.UpdateServiceResponse{Service: c.service.Copy()}, nil
}

func TestMeshApplyCompletesDeferredMetadataBeforeExactReadiness(t *testing.T) {
	for _, scenario := range []string{"completed", "newer operator", "same generation edit", "removed", "replaced", "CAS operator", "CAS equal generation edit", "CAS removal", "CAS updating", "rollback", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080,
				Replicas: 1, Generation: 7, Region: "gru", Node: "gru-1"}
			oldFloor := &Deployment{Repository: "TerraScale/terrascale", RunID: "99", Revision: strings.Repeat("b", 40), Image: spec.Image}
			spec.Deployment, spec.DeploymentFloor = oldFloor, oldFloor
			initial, err := spec.SwarmSpec()
			if err != nil {
				t.Fatal(err)
			}
			control := &deferredControl{service: &api.Service{ID: "service", Spec: *initial, SpecVersion: &api.Version{Index: 3},
				UpdateStatus: &api.UpdateStatus{State: api.UpdateStatus_UPDATING}}, waiting: make(chan struct{})}
			control.task = &api.Task{ID: "task", ServiceID: "service", NodeID: "node", Spec: *initial.Task.Copy(), SpecVersion: control.service.SpecVersion.Copy(),
				ServiceAnnotations: *initial.Annotations.Copy(), DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}}
			nextFloor := *oldFloor
			nextFloor.RunID = "100"
			requested := spec
			requested.Generation, requested.Deployment, requested.DeploymentFloor = 8, &nextFloor, &nextFloor
			want, err := requested.SwarmSpec()
			if err != nil {
				t.Fatal(err)
			}
			applier := deferredApplier{swarmApplier{client: control, revision: func(context.Context, string, string) (string, error) { return nextFloor.Revision, nil }}}
			ca, err := DeriveCA(bytes.Repeat([]byte{31}, 32))
			if err != nil {
				t.Fatal(err)
			}
			ports := freePorts(t, 2)
			node, err := start(config{region: "gru", server: "gru-1", dir: t.TempDir(), host: "127.0.0.1", localPort: ports[0], gatewayPort: ports[1],
				ca: ca, applier: applier, peersDir: t.TempDir(), address: func() (string, error) { return "10.200.0.1", nil }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(node.Close)
			payload, err := protocol.EncodeJSON(ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 8, Spec: &spec, Deployment: &nextFloor}})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan Reply, 1)
			go func() {
				message, err := node.conn.RequestWithContext(ctx, ApplySubject, payload)
				if err != nil {
					done <- Reply{Error: err.Error()}
					return
				}
				var reply Reply
				if err := protocol.DecodeTolerant(message.Data, &reply, maxWire); err != nil {
					reply.Error = err.Error()
				}
				done <- reply
			}()
			select {
			case <-control.waiting:
			case reply := <-done:
				t.Fatalf("did not wait for the active update: %+v", reply)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			operator := requested
			operator.Generation, operator.Deployment = 9, nil
			operatorSpec, err := operator.SwarmSpec()
			if err != nil {
				t.Fatal(err)
			}
			var protected *api.Service
			control.mu.Lock()
			if control.writes != 0 || !proto.Equal(&control.service.Spec, initial) {
				t.Error("metadata changed while the updater was active")
			}
			control.service.UpdateStatus.State = api.UpdateStatus_COMPLETED
			intervene := func() {
				switch scenario {
				case "newer operator", "CAS operator":
					control.service.Spec = *operatorSpec
				case "same generation edit", "CAS equal generation edit":
					control.service.Spec.Annotations.Labels["operator-note"] = "keep"
				case "removed", "CAS removal":
					control.service = nil
				case "replaced":
					control.service.ID = "replacement"
				case "CAS updating":
					control.service.UpdateStatus.State = api.UpdateStatus_UPDATING
				case "rollback":
					control.service.UpdateStatus.State = api.UpdateStatus_ROLLBACK_COMPLETED
				}
				protected = control.service.Copy()
			}
			if strings.HasPrefix(scenario, "CAS ") {
				control.conflict = intervene
			} else {
				intervene()
			}
			if scenario == "canceled" {
				// Cancel the server's wait, rather than only the requesting client.
				node.cancel()
			}
			control.mu.Unlock()
			if scenario == "CAS updating" {
				eventually(t, "CAS retry deferral", func() bool {
					control.mu.Lock()
					defer control.mu.Unlock()
					return control.reads >= 5
				})
				control.mu.Lock()
				if control.writes != 1 {
					t.Error("CAS retry wrote while the updater was active")
				}
				control.service.UpdateStatus.State = api.UpdateStatus_COMPLETED
				control.mu.Unlock()
			}
			var reply Reply
			select {
			case reply = <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			control.mu.Lock()
			defer control.mu.Unlock()
			if scenario == "completed" || scenario == "CAS updating" {
				writes := 1
				if scenario == "CAS updating" {
					writes = 2
				}
				if reply.Error != "" || len(reply.Tasks) != 1 || reply.Tasks[0].Generation != 7 || reply.Tasks[0].DeploymentFloor == nil || reply.Tasks[0].DeploymentFloor.RunID != "99" ||
					control.writes != writes || !proto.Equal(&control.service.Spec, want) {
					t.Fatalf("deferred generation/floor failed exact readiness: reply=%+v writes=%d", reply, control.writes)
				}
			} else {
				writes := 0
				if strings.HasPrefix(scenario, "CAS ") {
					writes = 1
				}
				if reply.Error == "" || control.writes != writes || !proto.Equal(control.service, protected) {
					t.Fatalf("superseded/failed wait changed runtime: reply=%+v writes=%d", reply, control.writes)
				}
			}
		})
	}
}
