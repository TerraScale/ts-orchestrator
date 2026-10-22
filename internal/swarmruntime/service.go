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
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
	"github.com/moby/swarmkit/v2/manager/orchestrator"
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

// Labels the single-host edge (hostnames) and secret injection (secrets) read
// from a spec-owned service; the probe reads LabelReadyPath.
const (
	LabelServiceSpec = "terrascale.service-spec"
	LabelHostnames   = "terrascale.hostnames"
	LabelSecrets     = "terrascale.secrets"
	// LabelSecretRefs maps each LabelSecrets key to its OCI Vault secret (JSON object of vaultsecret.Ref).
	LabelSecretRefs = "terrascale.secret-refs"
	// LabelGeneration is the mesh desired-state generation the service runs.
	LabelGeneration = "terrascale.generation"
)

var (
	secretName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	vaultID    = regexp.MustCompile(`^ocid1\.vault\.oc1\.[a-z0-9-]+\.[a-z0-9.]+$`)
	// <cell>-<rest>, cell like gru-1; <rest> must start with the service name unless sharedSecrets allows it.
	vaultName = regexp.MustCompile(`^([a-z]+-[0-9]+)-([a-z0-9][a-z0-9-]{0,200})$`)
)

// sharedSecrets lists the Vault secrets (name after the cell) another service may read, and which services.
var sharedSecrets = map[string][]string{
	"terrabase-peer-secret":           {"ts-auth", "ts-dashboard"},
	"ts-auth-dashboard-client-secret": {"ts-dashboard"},
	"cloudflare-account-id":           {"ts-auth"},
	"cloudflare-email-token":          {"ts-auth"},
	"stripe-secret-key":               {"ts-dashboard"},
	"stripe-webhook-secret":           {"ts-dashboard"},
}

var (
	hostname = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// ServiceSpec is one operator-declared single-host service, `deploy/m1/services/*.json`.
type ServiceSpec struct {
	Name      string                     `json:"name"`
	Image     string                     `json:"image"`
	Args      []string                   `json:"args,omitempty"`
	Env       map[string]string          `json:"env,omitempty"`
	Secrets   map[string]vaultsecret.Ref `json:"secrets,omitempty"`
	Mounts    []ServiceMount             `json:"mounts,omitempty"`
	Port      uint32                     `json:"port"`
	ReadyPath string                     `json:"readyPath,omitempty"`
	Hostnames []string                   `json:"hostnames,omitempty"`
	Replicas  uint64                     `json:"replicas"`
	// MilliCPU and MemoryMiB size the fully reserved budget; zero keeps the
	// 1 CPU / 4 GiB default sized for the M1 services.
	MilliCPU  uint32 `json:"milliCPU,omitempty"`
	MemoryMiB uint32 `json:"memoryMiB,omitempty"`
	// Regions lists the region tokens that run the service; empty means every
	// ordered region. The mesh reads it; the local service ignores it.
	Regions []string `json:"regions,omitempty"`
	// Generation is the mesh desired-state generation, stamped as a label.
	Generation int64 `json:"-"`
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
		readyPath = DefaultReadyPath
	}
	if !strings.HasPrefix(readyPath, "/") || strings.ContainsAny(readyPath, "?# \t\r\n") {
		return nil, errors.New("readyPath must be an absolute URL path")
	}
	if len(s.Hostnames) != len(slices.Compact(slices.Sorted(slices.Values(s.Hostnames)))) {
		return nil, errors.New("hostnames must not repeat")
	}
	var cell, vault string
	for _, name := range slices.Sorted(maps.Keys(s.Secrets)) {
		ref := s.Secrets[name]
		if _, shadowed := s.Env[name]; shadowed || !secretName.MatchString(name) {
			return nil, fmt.Errorf("invalid or env-shadowed secret name %q", name)
		}
		// Vault values reach the container only as files (W20 M5): the key names the path variable.
		if !vaultsecret.FileKey(name) {
			return nil, fmt.Errorf("secret %s must end in _FILE: Vault values are delivered as files", name)
		}
		parts := vaultName.FindStringSubmatch(ref.Name)
		if !vaultID.MatchString(ref.Vault) || parts == nil {
			return nil, fmt.Errorf("secret %s needs an OCI Vault OCID and a <cell>-<service>-<name> secret", name)
		}
		if cell == "" {
			cell, vault = parts[1], ref.Vault
		}
		// One cell, one Vault per service; a service reads only its own secrets or an allowed shared one.
		own := strings.HasPrefix(parts[2], s.Name+"-")
		if parts[1] != cell || ref.Vault != vault || !own && !slices.Contains(sharedSecrets[parts[2]], s.Name) {
			return nil, fmt.Errorf("secret %s: %s is not a %s-%s secret in this service's Vault", name, ref.Name, cell, s.Name)
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
		labels[LabelSecrets] = strings.Join(slices.Sorted(maps.Keys(s.Secrets)), ",")
		refs, err := jsonv1.Marshal(s.Secrets) // v1 sorts map keys: the label is deterministic.
		if err != nil {
			return nil, err
		}
		labels[LabelSecretRefs] = string(refs)
	}
	if s.Generation != 0 {
		labels[LabelGeneration] = strconv.FormatInt(s.Generation, 10)
	}
	// shortcut: fixed, fully reserved budget sized so the three M1 services fit one A1 host (3.75 schedulable CPUs); size per service when a host is added or one is starved.
	cpu, memory := int64(1_000_000_000), int64(4<<30)
	if s.MilliCPU != 0 {
		cpu = int64(s.MilliCPU) * 1_000_000
	}
	if s.MemoryMiB != 0 {
		memory = int64(s.MemoryMiB) << 20
	}
	if cpu < 10_000_000 || cpu > 4_000_000_000 || memory < 16<<20 || memory > 24<<30 {
		return nil, errors.New("milliCPU must be 10-4000 and memoryMiB 16-24576")
	}
	limits := &api.Resources{NanoCPUs: cpu, MemoryBytes: memory, Generic: []*api.GenericResource{genericresource.NewDiscrete(DiskResource, 10<<30)}}
	task := api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()},
		Restart: &api.RestartPolicy{Condition: api.RestartOnAny, Delay: types.DurationProto(serviceRestartDelay)}}
	// Refuse at apply what the executor would refuse on every task.
	if _, err := DecodeContainer(&api.Task{ID: "validation", ServiceID: "validation", Spec: task, ServiceAnnotations: api.Annotations{Labels: labels}}); err != nil {
		return nil, err
	}
	if _, err := DiskBytes(task.Resources); err != nil {
		return nil, err
	}
	return &api.ServiceSpec{
		Annotations: api.Annotations{Name: s.Name, Labels: labels},
		Task:        task,
		Mode:        &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: s.Replicas}},
		Update:      &api.UpdateConfig{Parallelism: 1, FailureAction: api.UpdateConfig_ROLLBACK, Monitor: types.DurationProto(serviceUpdateMonitor), Order: api.UpdateConfig_STOP_FIRST},
		Endpoint:    &api.EndpointSpec{Mode: api.ResolutionModeDNSRoundRobin, Ports: []*api.PortConfig{{Protocol: api.ProtocolTCP, TargetPort: s.Port, PublishedPort: s.Port, PublishMode: api.PublishModeHost}}},
	}, nil
}

const (
	// A crash-on-start shows within a few seconds of RUNNING; watching longer
	// only delays the update's completion and a rollback.
	serviceUpdateMonitor = 5 * time.Second
	// A crashed task's port is free once it exits; a cached image restarts in
	// well under a second, so a longer delay is pure downtime.
	serviceRestartDelay = time.Second
	// servicePoll bounds how late `service apply` notices each phase.
	servicePoll = 100 * time.Millisecond
	// serviceRollout bounds a cold pull plus start and readiness.
	serviceRollout = 2 * time.Minute
)

// ServiceRollout is the elapsed time from submission to each phase.
type ServiceRollout struct{ Running, Ready time.Duration }

// WaitServiceSpec waits until every replica of the service's current spec is
// RUNNING and passes probe (when given). A rollback or a paused update is an error.
func WaitServiceSpec(ctx context.Context, client api.ControlClient, service *api.Service, probe func(context.Context, *api.Task) error) (ServiceRollout, error) {
	ctx, cancel := context.WithTimeout(ctx, serviceRollout)
	defer cancel()
	start := time.Now()
	var rollout ServiceRollout
	if service.Spec.GetReplicated() == nil {
		return rollout, errors.New("service rollout requires a replicated service")
	}
	replicas := service.Spec.GetReplicated().Replicas
	for ; ; time.Sleep(servicePoll) {
		if err := ctx.Err(); err != nil {
			return rollout, fmt.Errorf("service %s is not ready: %w", service.Spec.Annotations.Name, err)
		}
		latest, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
		if err != nil {
			return rollout, err
		}
		if status := latest.Service.UpdateStatus; !proto.Equal(latest.Service.SpecVersion, service.SpecVersion) ||
			status != nil && status.State != api.UpdateStatus_UPDATING && status.State != api.UpdateStatus_COMPLETED {
			message := ""
			if status != nil {
				message = status.State.String() + ": " + status.Message
			}
			return rollout, fmt.Errorf("service %s update did not complete (%s)", service.Spec.Annotations.Name, message)
		}
		listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}, UpToDate: true}})
		if err != nil {
			return rollout, err
		}
		running := make([]*api.Task, 0, len(listed.Tasks))
		for _, task := range listed.Tasks {
			if task.Status.State == api.TaskStateRunning {
				running = append(running, task)
			}
		}
		if uint64(len(running)) != replicas || len(listed.Tasks) != len(running) {
			continue
		}
		if rollout.Running == 0 {
			rollout.Running = time.Since(start)
		}
		ready := true
		for _, task := range running {
			ready = ready && (probe == nil || probe(ctx, task) == nil)
		}
		if ready {
			rollout.Ready = time.Since(start)
			return rollout, nil
		}
	}
}

// ApplyServiceSpec creates the named service or replaces its spec in place.
func ApplyServiceSpec(ctx context.Context, client api.ControlClient, s ServiceSpec) (*api.Service, error) {
	spec, err := s.SwarmSpec()
	if err != nil {
		return nil, err
	}
	all, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return nil, err
	}
	if err := hostnameClaimedByOther(all.Services, s.Name, s.Hostnames); err != nil {
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

// hostnameClaimedByOther refuses a hostname another service already routes,
// so one spec cannot take over another service's public traffic.
func hostnameClaimedByOther(services []*api.Service, name string, hostnames []string) error {
	for _, svc := range services {
		if svc.Spec.Annotations.Name == name {
			continue
		}
		for owned := range strings.SplitSeq(svc.Spec.Annotations.Labels[LabelHostnames], ",") {
			if owned != "" && slices.Contains(hostnames, owned) {
				return fmt.Errorf("hostname %q is already routed to service %q", owned, svc.Spec.Annotations.Name)
			}
		}
	}
	return nil
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
	Generation        int64
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
		row.Generation, _ = strconv.ParseInt(service.Spec.Annotations.Labels[LabelGeneration], 10, 64)
		if container, err := containerOf(service.Spec); err == nil {
			row.Image = container.Image
		}
		for _, task := range tasks.Tasks {
			// A task of an older spec still running mid-update does not count.
			if task.Status.State == api.TaskStateRunning && !orchestrator.IsTaskDirty(service, task, nil) {
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
