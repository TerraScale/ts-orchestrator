package swarmruntime

import (
	"context"
	"crypto/sha256"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"math"
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
	LabelIntentGeneration   = "terrascale.intent-generation"
	labelIntentFingerprint  = "terrascale.intent-fingerprint"
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
	Replicas, Generation                                     uint64
	Container                                                *api.ContainerSpec
	Resources                                                *api.ResourceRequirements
	Ports                                                    []*api.PortConfig
	releaseSequence                                          uint64
	releaseFingerprint                                       string
	intentFingerprint                                        string
}

func (i ServiceIntent) serviceSpec() (*api.ServiceSpec, error) {
	if !entityid.Valid(i.ID) || i.OperationID != "" && !entityid.Valid(i.OperationID) {
		return nil, errors.New("service intent requires a canonical entity ID")
	}
	if i.Replicas > autoscale.MaxReplicas {
		return nil, errors.New("service replicas exceed the platform limit")
	}
	if i.Role == "ts-auth" && i.Replicas > 3 {
		return nil, errors.New("TSAuth replicas exceed its three controller failure domains")
	}
	for _, value := range []string{i.Role, i.Region, i.Environment} {
		if !intentName.MatchString(value) {
			return nil, errors.New("invalid service intent identity or scope")
		}
	}
	if i.Architecture != "arm64" && i.Architecture != "amd64" {
		return nil, errors.New("unsupported container architecture")
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
	if _, err := DecodeContainer(&api.Task{ID: "validation", ServiceID: "validation", Spec: task, ServiceAnnotations: api.Annotations{Labels: map[string]string{LabelRole: i.Role}}}); err != nil {
		return nil, err
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
	if i.Generation != 0 {
		spec.Annotations.Labels[LabelIntentGeneration] = strconv.FormatUint(i.Generation, 10)
		spec.Annotations.Labels[labelIntentFingerprint] = i.intentFingerprint
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
	if i.Role == "ts-auth" {
		spec.Task.Placement.Constraints = append(spec.Task.Placement.Constraints, "node.role==manager")
		spec.Task.Placement.MaxReplicas = 1
		// Three occupied controller domains leave no slot for start-first updates.
		spec.Update.Order = api.UpdateConfig_STOP_FIRST
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
	if err := checkIntentGeneration(current.Spec.Annotations.Labels, intent); err != nil {
		return nil, err
	}
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
	spec.Task.ForceUpdate = current.Spec.Task.ForceUpdate
	if intent.Generation != 0 {
		labels := current.Spec.Annotations.Labels
		if labels[LabelIntentGeneration] == spec.Annotations.Labels[LabelIntentGeneration] && labels[labelIntentFingerprint] == intent.intentFingerprint {
			// Existing tasks retain ServiceAnnotations when upstream sees no task change.
			if operation, exists := labels[LabelOperationID]; exists {
				spec.Annotations.Labels[LabelOperationID] = operation
			} else {
				delete(spec.Annotations.Labels, LabelOperationID)
			}
		} else {
			if spec.Task.ForceUpdate == math.MaxUint64 {
				return nil, errors.New("service rollout generation exhausted")
			}
			spec.Task.ForceUpdate++
		}
	}
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
	Readiness         string            `json:"readiness"`
	ReadinessReason   string            `json:"readiness_reason,omitempty"`
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
	view := ServiceObservation{ServiceID: s.ID, IntentID: s.Spec.Annotations.Labels[LabelIntentID], Role: s.Spec.Annotations.Labels[LabelRole], Region: s.Spec.Annotations.Labels[LabelRegion], Environment: s.Spec.Annotations.Labels[LabelEnvironment], RequestedReplicas: s.Spec.GetReplicated().Replicas, RequestedDigest: runtimeDigest(s.Spec), Readiness: "unknown", Tasks: []TaskObservation{}}
	if probe != nil {
		view.Readiness = "observed"
	}
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
	view.ObservedAt = time.Now().UTC()
	return view, nil
}

func runtimeDigest(spec api.ServiceSpec) string {
	c, err := containerOf(spec)
	if err != nil {
		return ""
	}
	_, digest, _ := strings.Cut(c.Image, "@")
	return digest
}

// The retained floor also uses this check, so rollback cannot erase delivery order.
func checkIntentGeneration(labels map[string]string, intent ServiceIntent) error {
	stored := labels[LabelIntentGeneration]
	if stored == "" {
		return nil
	}
	generation, err := strconv.ParseUint(stored, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != stored || generation > intent.Generation || generation == intent.Generation && labels[labelIntentFingerprint] != intent.intentFingerprint {
		return errors.New("service intent generation cannot move backward or equivocate")
	}
	return nil
}

func serviceIntentFingerprint(spec *api.ServiceSpec) (string, error) {
	spec = spec.Copy()
	// Autoscaling and an operation locator do not change the admitted workload.
	spec.Mode = nil
	spec.Task.ForceUpdate = 0
	delete(spec.Annotations.Labels, LabelOperationID)
	delete(spec.Annotations.Labels, labelIntentFingerprint)
	wire, err := json.Marshal(spec, json.Deterministic(true), jsonv1.FormatDurationAsNano(true))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}

// Labels the single-host edge (hostnames), secret injection (secrets) and
// readiness probe (ready path) read from a spec-owned service.
const (
	LabelServiceSpec = "terrascale.service-spec"
	LabelHostnames   = "terrascale.hostnames"
	LabelSecrets     = "terrascale.secrets"
	LabelReadyPath   = "terrascale.ready-path"
)

var (
	secretName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	hostname   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// ServiceSpec is one operator-declared single-host service, `deploy/m1/services/*.json`.
type ServiceSpec struct {
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Secrets   []string          `json:"secrets,omitempty"`
	Mounts    []ServiceMount    `json:"mounts,omitempty"`
	Port      uint32            `json:"port"`
	ReadyPath string            `json:"readyPath,omitempty"`
	Hostnames []string          `json:"hostnames,omitempty"`
	Replicas  uint64            `json:"replicas"`
}

type ServiceMount struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// SwarmSpec maps the declaration to an upstream service; the executor
// re-validates the container on every task.
func (s ServiceSpec) SwarmSpec() (*api.ServiceSpec, error) {
	if !intentName.MatchString(s.Name) {
		return nil, errors.New("service name must match ^[a-z][a-z0-9-]{0,62}$")
	}
	if s.Replicas != 1 {
		return nil, errors.New("single-host services run exactly one replica")
	}
	if s.Port < 1024 || s.Port > 65535 {
		return nil, errors.New("service port must be in 1024..65535")
	}
	readyPath := s.ReadyPath
	if readyPath == "" {
		readyPath = "/readyz"
	}
	if !strings.HasPrefix(readyPath, "/") || strings.ContainsAny(readyPath, "?# \t\r\n") {
		return nil, errors.New("readyPath must be an absolute URL path")
	}
	for _, list := range [][]string{s.Secrets, s.Hostnames} {
		if len(list) != len(slices.Compact(slices.Sorted(slices.Values(list)))) {
			return nil, errors.New("secrets and hostnames must not repeat")
		}
	}
	for _, name := range s.Secrets {
		if _, shadowed := s.Env[name]; shadowed || !secretName.MatchString(name) {
			return nil, fmt.Errorf("invalid or env-shadowed secret name %q", name)
		}
	}
	for _, host := range s.Hostnames {
		if len(host) > 253 || !hostname.MatchString(host) {
			return nil, fmt.Errorf("invalid hostname %q", host)
		}
	}
	container := &api.ContainerSpec{Image: s.Image, User: "65532:65532", Args: slices.Clone(s.Args)}
	for _, key := range slices.Sorted(maps.Keys(s.Env)) {
		container.Env = append(container.Env, key+"="+s.Env[key])
	}
	for _, m := range s.Mounts {
		container.Mounts = append(container.Mounts, api.Mount{Type: api.MountTypeBind, Source: m.Source, Target: m.Target})
	}
	runtime, err := ContainerRuntime(container)
	if err != nil {
		return nil, err
	}
	labels := map[string]string{LabelServiceSpec: s.Name, LabelReadyPath: readyPath}
	if len(s.Hostnames) != 0 {
		labels[LabelHostnames] = strings.Join(s.Hostnames, ",")
	}
	if len(s.Secrets) != 0 {
		labels[LabelSecrets] = strings.Join(s.Secrets, ",")
	}
	// shortcut: fixed limits, no reservations; size per service when a second host or OOM appears.
	limits := &api.Resources{NanoCPUs: 2_000_000_000, MemoryBytes: 4 << 30}
	return &api.ServiceSpec{
		Annotations: api.Annotations{Name: s.Name, Labels: labels},
		Task: api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: limits},
			Restart: &api.RestartPolicy{Condition: api.RestartOnAny, Delay: types.DurationProto(5 * time.Second)}},
		Mode:     &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: s.Replicas}},
		Update:   &api.UpdateConfig{Parallelism: 1, FailureAction: api.UpdateConfig_ROLLBACK, Monitor: types.DurationProto(30 * time.Second), Order: api.UpdateConfig_STOP_FIRST},
		Endpoint: &api.EndpointSpec{Mode: api.ResolutionModeDNSRoundRobin, Ports: []*api.PortConfig{{Protocol: api.ProtocolTCP, TargetPort: s.Port, PublishedPort: s.Port, PublishMode: api.PublishModeHost}}},
	}, nil
}

// ApplyServiceSpec creates the named service or replaces its spec in place.
func ApplyServiceSpec(ctx context.Context, client api.ControlClient, s ServiceSpec) (*api.Service, error) {
	spec, err := s.SwarmSpec()
	if err != nil {
		return nil, err
	}
	current, err := specService(ctx, client, s.Name)
	if err != nil {
		return nil, err
	}
	if current == nil {
		created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
		if err != nil {
			return nil, err
		}
		return created.Service, nil
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

// RemoveServiceSpec deletes the named service; SwarmKit stops its tasks.
func RemoveServiceSpec(ctx context.Context, client api.ControlClient, name string) error {
	current, err := specService(ctx, client, name)
	if err != nil {
		return err
	}
	if current == nil {
		return fmt.Errorf("service %q not found", name)
	}
	_, err = client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: current.ID})
	return err
}

// ServiceSpecStatus is one `service ls` row.
type ServiceSpecStatus struct {
	Name, Image       string
	Running, Replicas uint64
}

func ListServiceSpecs(ctx context.Context, client api.ControlClient) ([]ServiceSpecStatus, error) {
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return nil, err
	}
	rows := []ServiceSpecStatus{}
	for _, service := range listed.Services {
		if service.Spec.Annotations.Labels[LabelServiceSpec] == "" || service.Spec.GetReplicated() == nil {
			continue
		}
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
		if err != nil {
			return nil, err
		}
		row := ServiceSpecStatus{Name: service.Spec.Annotations.Name, Replicas: service.Spec.GetReplicated().Replicas}
		if container, err := containerOf(service.Spec); err == nil {
			row.Image = container.Image
		}
		for _, task := range tasks.Tasks {
			if task.Status.State == api.TaskStateRunning {
				row.Running++
			}
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b ServiceSpecStatus) int { return strings.Compare(a.Name, b.Name) })
	return rows, nil
}

func specService(ctx context.Context, client api.ControlClient, name string) (*api.Service, error) {
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{name}}})
	if err != nil {
		return nil, err
	}
	for _, service := range listed.Services {
		if service.Spec.Annotations.Name != name {
			continue
		}
		if service.Spec.Annotations.Labels[LabelServiceSpec] != name {
			return nil, fmt.Errorf("service %q is not owned by a service spec", name)
		}
		return service, nil
	}
	return nil, nil
}

func containerOf(spec api.ServiceSpec) (*api.ContainerSpec, error) {
	g := spec.Task.GetGeneric()
	if g == nil || g.Kind != ContainerKind || g.Payload == nil {
		return nil, errors.New("not a container service")
	}
	c := new(api.ContainerSpec)
	return c, c.Unmarshal(g.Payload.Value)
}
