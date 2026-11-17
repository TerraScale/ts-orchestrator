package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"encoding/json"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/scheduler"
	"io"
)

type ScalePolicy struct {
	Target autoscale.Target
	Bounds autoscale.Bounds
	Policy *autoscale.Policy
}

type ScaleResult struct {
	Replicas int
	Target   int
	Decision autoscale.Decision
	Readings []autoscale.Reading
	Reason   string
}

type scaleMemory struct {
	serviceID string
	task      *api.TaskSpec
	history   autoscale.History
	bounds    autoscale.Bounds
}

type Autoscaler struct {
	client   api.ControlClient
	nodeID   string
	source   autoscale.Source
	probe    func(context.Context, *api.Task) error
	mu       sync.Mutex
	term     uint64
	node     *Node
	policies []ScalePolicy
	history  map[autoscale.Target]scaleMemory
	last     map[autoscale.Target]ScaleResult
}

const LabelReplicaBounds = "terrascale.replica-bounds"

var replicaMetrics struct {
	sync.Mutex
	scaler *Autoscaler
}

func RunReplicaAutoscaler(ctx context.Context, node *Node, executor *Executor, address func(*api.Node) (string, error)) error {
	client, err := node.ControlClient(ctx)
	if err != nil {
		return err
	}
	source := &replicaSource{client: client, local: node.ID(), executor: executor, address: address}
	source.Reset()
	a := &Autoscaler{client: client, nodeID: node.ID(), node: node, source: source,
		history: make(map[autoscale.Target]scaleMemory), last: make(map[autoscale.Target]ScaleResult)}
	a.probe = func(ctx context.Context, task *api.Task) error {
		if task.NodeID == node.ID() {
			return ProbeLocalTask(ctx, task)
		}
		response, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(response.Node.Status.Addr)
		if err != nil {
			return err
		}
		return ProbeTask(ctx, task, ip)
	}
	replicaMetrics.Lock()
	replicaMetrics.scaler = a
	replicaMetrics.Unlock()
	defer func() {
		a.Reset()
		replicaMetrics.Lock()
		if replicaMetrics.scaler == a {
			replicaMetrics.scaler = nil
		}
		replicaMetrics.Unlock()
	}()
	return a.Run(ctx)
}

func WriteReplicaMetrics(w io.Writer) {
	replicaMetrics.Lock()
	a := replicaMetrics.scaler
	replicaMetrics.Unlock()
	if a == nil {
		return
	}
	for target, result := range a.Last() {
		observability.WriteGauge(w, observability.Series("ts_orch_service_replicas_current", "service", target.Role), float64(result.Replicas))
		observability.WriteGauge(w, observability.Series("ts_orch_service_replicas_desired", "service", target.Role), float64(result.Target))
		observability.WriteGauge(w, observability.Series("ts_orch_service_replica_decision", "service", target.Role, "reason", result.Reason), 1)
	}
}

func replicaPolicy() *autoscale.Policy {
	return &autoscale.Policy{Signals: []autoscale.Signal{
		{Name: autoscale.SignalCPUUtilization, Target: .7, MinSamples: 4},
		{Name: autoscale.SignalMemoryUtilization, Target: .8, MinSamples: 4},
		{Name: autoscale.SignalRequestRatePerReplica, Target: 100, MinSamples: 4},
	}, UpStabilizationSeconds: 20, DownStabilizationSeconds: 120, UpCooldownSeconds: 20,
		DownCooldownSeconds: 180, MaxStepUp: 2, MaxStepDown: 1, Tolerance: .1}
}

func (a *Autoscaler) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reset()
}

func (a *Autoscaler) reset() {
	a.term = 0
	clear(a.history)
	clear(a.last)
	if source, ok := a.source.(interface{ Reset() }); ok {
		source.Reset()
	}
}

func (a *Autoscaler) Last() map[autoscale.Target]ScaleResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	if term, err := a.node.upstream.Manager().ReplicaAuthority(); err != nil || term != a.term {
		return nil
	}
	results := maps.Clone(a.last)
	for target, result := range results {
		result.Readings = slices.Clone(result.Readings)
		result.Decision.History.Recommendations = slices.Clone(result.Decision.History.Recommendations)
		results[target] = result
	}
	return results
}

func (a *Autoscaler) Run(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if err := a.Tick(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.ErrorContext(ctx, "autoscaling service replicas", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (a *Autoscaler) Tick(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	term, err := a.node.upstream.Manager().ReplicaAuthority()
	if err != nil {
		a.reset()
		return nil
	}
	if a.term != term {
		a.reset()
		a.term = term
	}
	listed, err := a.client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return err
	}
	a.source.(*replicaSource).loads = nil
	a.policies = nil
	active := make(map[autoscale.Target]bool)
	serviceIDs := make(map[string]bool)
	for _, service := range listed.Services {
		encoded := service.Spec.Annotations.Labels[LabelReplicaBounds]
		if encoded == "" || service.Spec.GetReplicated() == nil {
			continue
		}
		var bounds autoscale.Bounds
		if err := json.Unmarshal([]byte(encoded), &bounds); err != nil {
			return err
		}
		if err := bounds.Validate(); err != nil {
			return err
		}
		target := autoscale.Target{Cell: a.node.admission.Region, Environment: service.Spec.Annotations.Labels[LabelEnvironment], Role: service.Spec.Annotations.Name}
		active[target] = true
		serviceIDs[service.ID] = true
		a.policies = append(a.policies, ScalePolicy{Target: target, Bounds: bounds, Policy: replicaPolicy()})
	}
	for target := range a.last {
		if !active[target] {
			delete(a.last, target)
			delete(a.history, target)
		}
	}
	for target := range a.history {
		if !active[target] {
			delete(a.history, target)
		}
	}
	a.source.(*replicaSource).retain(active, serviceIDs)
	var failures []error
	for _, policy := range a.policies {
		result, err := a.scale(ctx, policy, time.Now())
		if err != nil {
			delete(a.last, policy.Target)
			failures = append(failures, fmt.Errorf("autoscale %s/%s: %w", policy.Target.Environment, policy.Target.Role, err))
			if a.term == 0 {
				break
			}
			continue
		}
		a.last[policy.Target] = result
	}
	return errors.Join(failures...)
}

func (a *Autoscaler) scale(ctx context.Context, policy ScalePolicy, now time.Time) (ScaleResult, error) {
	result := ScaleResult{Reason: "awaiting-release"}
	services, err := a.client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{
		Names: []string{policy.Target.Role},
	}})
	if err != nil {
		return result, err
	}
	if len(services.Services) == 0 {
		delete(a.history, policy.Target)
		return result, nil
	}
	if len(services.Services) != 1 {
		return result, errors.New("regional service identity is ambiguous")
	}
	service := services.Services[0]
	if err := json.Unmarshal([]byte(service.Spec.Annotations.Labels[LabelReplicaBounds]), &policy.Bounds); err != nil {
		return result, err
	}
	if err := policy.Bounds.Validate(); err != nil {
		return result, err
	}
	replicated := service.Spec.GetReplicated()
	if replicated == nil || replicated.Replicas > autoscale.MaxReplicas {
		return result, errors.New("autoscaling requires a replicated service within the product replica limit")
	}
	result.Target = int(replicated.Replicas)
	tasks, err := a.client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
	if err != nil {
		return result, err
	}
	for _, task := range tasks.Tasks {
		if task.Status.State == api.TaskStateRunning {
			result.Replicas++
		}
	}
	if policy.Bounds.Min == policy.Bounds.Max && int(replicated.Replicas) == policy.Bounds.Min {
		result.Reason = "pinned"
		return result, nil
	}
	if service.UpdateStatus != nil && service.UpdateStatus.State != api.UpdateStatus_COMPLETED &&
		service.UpdateStatus.State != api.UpdateStatus_ROLLBACK_COMPLETED ||
		service.UpdateStatus == nil && service.PreviousSpec != nil && !proto.Equal(&service.PreviousSpec.Task, &service.Spec.Task) {
		delete(a.history, policy.Target)
		delete(a.source.(*replicaSource).warm, policy.Target)
		result.Reason = "release-in-progress"
		return result, nil
	}
	if replicated.Replicas > 0 && policy.Bounds != (autoscale.Bounds{}) {
		ready, err := ReadyService(ctx, a.client, service, a.probe)
		if err != nil {
			return result, err
		}
		if !ready {
			delete(a.history, policy.Target)
			delete(a.source.(*replicaSource).warm, policy.Target)
			result.Reason = "unready-replicas"
			return result, nil
		}
	}
	memory, exists := a.history[policy.Target]
	history := memory.history
	if !exists || memory.serviceID != service.ID || memory.bounds != policy.Bounds || !proto.Equal(memory.task, &service.Spec.Task) {
		history = autoscale.Reset(now)
	}
	var signalPolicy autoscale.Policy
	if policy.Policy != nil {
		signalPolicy = *policy.Policy
		if err := a.source.(*replicaSource).Observe(ctx, service, policy.Target, now); err != nil {
			result.Reason = "missing-metrics"
			delete(a.source.(*replicaSource).warm, policy.Target)
			delete(a.history, policy.Target)
			return result, nil
		}
		result.Readings = autoscale.Collect(ctx, a.source, policy.Target, signalPolicy, now)
	}
	decision := autoscale.Decide(signalPolicy, autoscale.Input{Current: int(replicated.Replicas), Bounds: policy.Bounds,
		Readings: result.Readings, Now: now}, history)
	result.Target, result.Decision, result.Reason = decision.To, decision, decision.Reason
	if decision.Changed() {
		if decision.To > decision.From {
			nodes, nodeErr := a.client.ListNodes(ctx, &api.ListNodesRequest{})
			tasks, taskErr := a.client.ListTasks(ctx, &api.ListTasksRequest{})
			if err := errors.Join(nodeErr, taskErr); err != nil {
				return result, err
			}
			capacity := scheduler.ReplicaCapacity(service, nodes.Nodes, tasks.Tasks, decision.To-decision.From)
			decision.To = min(decision.To, decision.From+capacity)
			result.Target = decision.To
			if decision.To == decision.From {
				result.Reason = "region-capacity"
				return result, nil
			}
		}
		if err := a.node.upstream.Manager().ScaleReplicas(ctx, a.term, service.ID, service.Meta.Version, uint64(decision.To)); err != nil {
			a.reset()
			return result, err
		}
		slog.InfoContext(ctx, "service replicas changed", "service", policy.Target.Role, "from", decision.From, "to", decision.To, "reason", decision.Reason)

	}
	a.history[policy.Target] = scaleMemory{serviceID: service.ID, task: service.Spec.Task.Copy(), history: decision.History, bounds: policy.Bounds}
	return result, nil
}
