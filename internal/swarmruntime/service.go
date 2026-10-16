package swarmruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

const (
	LabelIntentID           = "terrascale.intent-id"
	LabelOperationID        = "terrascale.operation-id"
	LabelRole               = "terrascale.role"
	LabelRegion             = "terrascale.region"
	LabelEnvironment        = "terrascale.environment"
	LabelHostRole           = "terrascale.host-role"
	LabelInstanceID         = "terrascale.instance-id"
	LabelExecutionScope     = "terrascale.execution-scope"
	labelReleaseSequence    = "terrascale.release-sequence"
	labelReleaseFingerprint = "terrascale.release-fingerprint"
)

var intentName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ServiceIntent is admitted product intent, not a task placement request.
// Replicas initializes a new service; subsequent releases preserve autoscaling.
type ServiceIntent struct {
	ID, OperationID, Role, Region, Environment, Architecture string
	Replicas                                                 uint64
	Container                                                *api.ContainerSpec
	Resources                                                *api.ResourceRequirements
	Ports                                                    []*api.PortConfig
	releaseSequence                                          uint64
	releaseFingerprint                                       string
}

func (i ServiceIntent) serviceSpec() (*api.ServiceSpec, error) {
	if !entityid.Valid(i.ID) || i.OperationID != "" && !entityid.Valid(i.OperationID) {
		return nil, errors.New("service intent requires a canonical entity ID")
	}
	if i.Replicas > autoscale.MaxReplicas {
		return nil, errors.New("service replicas exceed the platform limit")
	}
	for _, value := range []string{i.Role, i.Region, i.Environment} {
		if !intentName.MatchString(value) {
			return nil, errors.New("invalid service intent identity or scope")
		}
	}
	if i.Architecture != "arm64" && i.Architecture != "amd64" {
		return nil, errors.New("unsupported container architecture")
	}
	if i.Role == "terrabase" {
		return nil, errors.New("stateful services require qualified fencing and volume hooks")
	}
	// shortcut: one application endpoint is qualified, extend after multiport routing and collision scenarios.
	if len(i.Ports) > 1 {
		return nil, errors.New("container service supports one qualified application endpoint")
	}
	seenPorts := map[uint32]bool{}
	for _, port := range i.Ports {
		if port == nil || port.PublishMode != api.PublishModeHost || port.Protocol != api.ProtocolTCP || port.TargetPort != port.PublishedPort || port.PublishedPort < 1024 || port.PublishedPort > 65535 || seenPorts[port.PublishedPort] {
			return nil, errors.New("service ports require unique TCP host ports with equal target and published ports in 1024..65535")
		}
		seenPorts[port.PublishedPort] = true
	}
	runtime, err := ContainerRuntime(i.Container)
	if err != nil {
		return nil, err
	}
	task := api.TaskSpec{Runtime: runtime, Resources: i.Resources.Copy()}
	if _, err := DecodeContainer(&api.Task{ID: "validation", ServiceID: "validation", Spec: task}); err != nil {
		return nil, err
	}
	if task.Resources.Reservations == nil {
		task.Resources.Reservations = task.Resources.Limits.Copy()
	} else if !proto.Equal(task.Resources.Reservations, task.Resources.Limits) {
		return nil, errors.New("service resource reservations must equal CPU and memory limits")
	}
	task.Restart = &api.RestartPolicy{Condition: api.RestartOnAny, Delay: types.DurationProto(5 * time.Second)}
	task.Placement = &api.Placement{
		Constraints: []string{"node.labels." + LabelRegion + "==" + i.Region, "node.labels." + LabelExecutionScope + "==platform"},
		Platforms:   []*api.Platform{{OS: "linux", Architecture: i.Architecture}},
	}
	identity := sha256.Sum256([]byte(i.Environment + "/" + i.Region + "/" + i.ID))
	spec := &api.ServiceSpec{
		Annotations: api.Annotations{Name: fmt.Sprintf("ts-%x", identity[:16]), Labels: map[string]string{
			LabelIntentID: i.ID, LabelRole: i.Role, LabelRegion: i.Region, LabelEnvironment: i.Environment,
		}},
		Task:     task,
		Mode:     &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: i.Replicas}},
		Update:   &api.UpdateConfig{Parallelism: 1, Delay: 5 * time.Second, FailureAction: api.UpdateConfig_ROLLBACK, Monitor: types.DurationProto(30 * time.Second), Order: api.UpdateConfig_START_FIRST},
		Rollback: &api.UpdateConfig{Parallelism: 1, Delay: 5 * time.Second, FailureAction: api.UpdateConfig_PAUSE, Monitor: types.DurationProto(30 * time.Second), Order: api.UpdateConfig_STOP_FIRST},
	}
	if i.OperationID != "" {
		spec.Annotations.Labels[LabelOperationID] = i.OperationID
	}
	if i.releaseSequence != 0 {
		spec.Annotations.Labels[labelReleaseSequence] = strconv.FormatUint(i.releaseSequence, 10)
		spec.Annotations.Labels[labelReleaseFingerprint] = i.releaseFingerprint
	}
	if len(i.Ports) != 0 {
		spec.Update.Order = api.UpdateConfig_STOP_FIRST
		spec.Endpoint = &api.EndpointSpec{Mode: api.ResolutionModeDNSRoundRobin}
		for _, port := range i.Ports {
			spec.Endpoint.Ports = append(spec.Endpoint.Ports, port.Copy())
		}
	}
	return spec, nil
}

// applyService creates or CAS-updates one stable upstream service. SwarmKit owns
// task placement, rolling updates and lifecycle-failure rollback.
func applyService(ctx context.Context, client api.ControlClient, intent ServiceIntent) (*api.Service, error) {
	return applyServiceGuarded(ctx, client, intent, nil)
}

func applyServiceGuarded(ctx context.Context, client api.ControlClient, intent ServiceIntent, guard func(context.Context) error) (*api.Service, error) {
	spec, err := intent.serviceSpec()
	if err != nil {
		return nil, err
	}
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{spec.Annotations.Name}}})
	if err != nil {
		return nil, err
	}
	if len(listed.Services) == 0 {
		if guard != nil {
			if err := guard(ctx); err != nil {
				return nil, err
			}
		}
		created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
		if err != nil {
			return nil, err
		}
		return created.Service, nil
	}
	if len(listed.Services) != 1 {
		return nil, errors.New("ambiguous service identity")
	}
	current := listed.Services[0]
	if seq := current.Spec.Annotations.Labels[labelReleaseSequence]; seq != "" {
		floor, err := strconv.ParseUint(seq, 10, 64)
		if err != nil || floor > intent.releaseSequence || floor == intent.releaseSequence && current.Spec.Annotations.Labels[labelReleaseFingerprint] != intent.releaseFingerprint {
			return nil, errors.New("service release order cannot move backward or equivocate")
		}
	}
	for _, key := range []string{LabelIntentID, LabelRole, LabelRegion, LabelEnvironment} {
		if current.Spec.Annotations.Labels[key] != spec.Annotations.Labels[key] {
			return nil, errors.New("service ownership or scope mismatch")
		}
	}
	if current.PendingDelete || current.Spec.GetReplicated() == nil {
		return nil, errors.New("service is deleting or has unsupported mode")
	}
	spec.GetReplicated().Replicas = current.Spec.GetReplicated().Replicas
	if guard != nil {
		if err := guard(ctx); err != nil {
			return nil, err
		}
	}
	if proto.Equal(&current.Spec, spec) {
		return current, nil
	}
	updated, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: current.ID, ServiceVersion: &current.Meta.Version, Spec: spec})
	if err != nil {
		return nil, err
	}
	return updated.Service, nil
}

// ServiceObservation contains no container specification or environment values.
type ServiceObservation struct {
	ServiceID         string            `json:"service_id"`
	IntentID          string            `json:"intent_id"`
	Role              string            `json:"role"`
	Region            string            `json:"region"`
	Environment       string            `json:"environment"`
	RequestedDigest   string            `json:"requested_digest"`
	RequestedReplicas uint64            `json:"requested_replicas"`
	RunningReplicas   uint64            `json:"running_replicas"`
	ReadyReplicas     uint64            `json:"ready_replicas"`
	UpdateState       string            `json:"update_state,omitempty"`
	Tasks             []TaskObservation `json:"tasks"`
	ObservedAt        time.Time         `json:"observed_at"`
}

type TaskObservation struct {
	TaskID    string    `json:"task_id"`
	NodeID    string    `json:"node_id,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	State     string    `json:"state"`
	Ready     bool      `json:"ready"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ReadyService checks only current desired tasks and independently probes their applications.
// A service version change during the probes leaves readiness pending.
func ReadyService(ctx context.Context, client api.ControlClient, service *api.Service, probe func(context.Context, *api.Task) error) (bool, error) {
	ready, _, err := serviceReadiness(ctx, client, service, probe)
	return ready, err
}

func serviceReadiness(ctx context.Context, client api.ControlClient, service *api.Service, probe func(context.Context, *api.Task) error) (bool, bool, error) {
	if service == nil || service.Spec.GetReplicated() == nil || probe == nil {
		return false, false, errors.New("service readiness requires replicated service and application probe")
	}
	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}, UpToDate: true}})
	if err != nil {
		return false, false, err
	}
	var ready uint64
	failed := false
	for _, task := range listed.Tasks {
		if task.Status.State != api.TaskStateRunning {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := probe(probeCtx, task)
		cancel()
		if err == nil {
			ready++
		} else {
			failed = true
		}
	}
	latest, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil {
		return false, false, err
	}
	if latest.Service.Meta.Version.Index != service.Meta.Version.Index {
		return false, false, nil
	}
	return ready == service.Spec.GetReplicated().Replicas && uint64(len(listed.Tasks)) == ready, failed, nil
}

// ObserveService reads actual upstream tasks. A lifecycle RUNNING status never
// implies application readiness; callers supply their authenticated product probe.
func ObserveService(ctx context.Context, client api.ControlClient, serviceID string, probe func(context.Context, *api.Task) error) (ServiceObservation, error) {
	response, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil {
		return ServiceObservation{}, err
	}
	s := response.Service
	if s.Spec.GetReplicated() == nil {
		return ServiceObservation{}, errors.New("unsupported service mode")
	}
	view := ServiceObservation{ServiceID: s.ID, IntentID: s.Spec.Annotations.Labels[LabelIntentID], Role: s.Spec.Annotations.Labels[LabelRole], Region: s.Spec.Annotations.Labels[LabelRegion], Environment: s.Spec.Annotations.Labels[LabelEnvironment], RequestedReplicas: s.Spec.GetReplicated().Replicas, RequestedDigest: runtimeDigest(s.Spec), ObservedAt: time.Now().UTC(), Tasks: []TaskObservation{}}
	if s.UpdateStatus != nil {
		view.UpdateState = s.UpdateStatus.State.String()
	}
	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{s.ID}}})
	if err != nil {
		return ServiceObservation{}, err
	}
	for _, task := range listed.Tasks {
		observation := TaskObservation{TaskID: task.ID, NodeID: task.NodeID, Digest: runtimeDigest(api.ServiceSpec{Task: task.Spec}), State: task.Status.State.String()}
		if timestamp, err := types.TimestampFromProto(task.Status.Timestamp); err == nil {
			observation.UpdatedAt = timestamp
		}
		if task.Status.Err != "" {
			observation.Error = "task lifecycle failed"
		}
		if task.DesiredState == api.TaskStateRunning && task.Status.State == api.TaskStateRunning {
			view.RunningReplicas++
			if probe != nil {
				probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := probe(probeCtx, task)
				cancel()
				if err == nil {
					observation.Ready = true
					view.ReadyReplicas++
				} else {
					observation.Error = "application readiness probe failed"
				}
			}
		}
		view.Tasks = append(view.Tasks, observation)
	}
	slices.SortFunc(view.Tasks, func(a, b TaskObservation) int { return strings.Compare(a.TaskID, b.TaskID) })
	return view, nil
}

func runtimeDigest(spec api.ServiceSpec) string {
	g := spec.Task.GetGeneric()
	if g == nil || g.Kind != ContainerKind || g.Payload == nil {
		return ""
	}
	c := new(api.ContainerSpec)
	if c.Unmarshal(g.Payload.Value) != nil {
		return ""
	}
	_, digest, _ := strings.Cut(c.Image, "@")
	return digest
}
