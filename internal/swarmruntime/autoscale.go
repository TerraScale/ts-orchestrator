package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/moby/swarmkit/v2/api"
)

// ScalePolicy applies product replica bounds and signal policy to one service.
// Stateful member changes remain subject to their separate storage safety gate.
type ScalePolicy struct {
	Target autoscale.Target
	Bounds autoscale.Bounds
	Policy *autoscale.Policy
}

// ScaleResult describes desired replicas, not running task or placement state.
type ScaleResult struct {
	Replicas int
	Target   int
	Decision autoscale.Decision
	Readings []autoscale.Reading
	Reason   string
}

type scaleMemory struct {
	serviceID string
	history   autoscale.History
}

// Autoscaler changes only upstream service replica counts. SwarmKit owns all
// task creation, placement, rollout and convergence.
type Autoscaler struct {
	client   api.ControlClient
	nodeID   string
	source   autoscale.Source
	mu       sync.Mutex
	leader   bool
	policies []ScalePolicy
	history  map[autoscale.Target]scaleMemory
	last     map[autoscale.Target]ScaleResult
}

func NewAutoscaler(client api.ControlClient, nodeID string, source autoscale.Source, policies []ScalePolicy) (*Autoscaler, error) {
	if client == nil || nodeID == "" || source == nil {
		return nil, errors.New("autoscaling requires the local manager identity, control client and signal source")
	}
	a := &Autoscaler{client: client, nodeID: nodeID, source: source}
	if err := a.SetPolicies(policies); err != nil {
		return nil, err
	}
	return a, nil
}

// SetPolicies replaces signed service policy atomically with respect to ticks.
func (a *Autoscaler) SetPolicies(policies []ScalePolicy) error {
	policies = slices.Clone(policies)
	seen := make(map[autoscale.Target]bool, len(policies))
	for i, policy := range policies {
		if policy.Target.Cell == "" || policy.Target.Environment == "" || policy.Target.Role == "" || seen[policy.Target] {
			return errors.New("autoscaling requires unique regional service identities")
		}
		seen[policy.Target] = true
		if err := policy.Bounds.Validate(); err != nil {
			return err
		}
		if policy.Policy != nil {
			if err := policy.Policy.Validate(); err != nil {
				return err
			}
			copy := *policy.Policy
			copy.Signals = slices.Clone(copy.Signals)
			policies[i].Policy = &copy
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.policies = policies
	a.history = make(map[autoscale.Target]scaleMemory)
	a.last = make(map[autoscale.Target]ScaleResult)
	return nil
}

func (a *Autoscaler) Last() map[autoscale.Target]ScaleResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	results := maps.Clone(a.last)
	for target, result := range results {
		result.Readings = slices.Clone(result.Readings)
		result.Decision.History.Recommendations = slices.Clone(result.Decision.History.Recommendations)
		results[target] = result
	}
	return results
}

// Run evaluates policy every ten seconds and retries from fresh observations.
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

func (a *Autoscaler) leading(ctx context.Context) (bool, error) {
	node, err := a.client.GetNode(ctx, &api.GetNodeRequest{NodeID: a.nodeID})
	if err != nil {
		return false, err
	}
	return node.Node != nil && node.Node.ManagerStatus != nil && node.Node.ManagerStatus.Leader, nil
}

// Tick evaluates each policy once. CAS conflicts return to observation instead
// of retrying a decision calculated against an earlier release or replica count.
func (a *Autoscaler) Tick(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	leading, err := a.leading(ctx)
	if err != nil || !leading {
		a.leader = false
		clear(a.history)
		clear(a.last)
		return err
	}
	if !a.leader {
		if source, ok := a.source.(interface{ Reset() }); ok {
			source.Reset()
		}
		a.leader = true
	}
	var failures []error
	for _, policy := range a.policies {
		result, err := a.scale(ctx, policy, time.Now())
		if err != nil {
			delete(a.last, policy.Target)
			failures = append(failures, fmt.Errorf("autoscale %s/%s: %w", policy.Target.Environment, policy.Target.Role, err))
			continue
		}
		a.last[policy.Target] = result
	}
	return errors.Join(failures...)
}

func (a *Autoscaler) scale(ctx context.Context, policy ScalePolicy, now time.Time) (ScaleResult, error) {
	result := ScaleResult{Reason: "awaiting-release"}
	services, err := a.client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{
		Labels: map[string]string{LabelRegion: policy.Target.Cell, LabelEnvironment: policy.Target.Environment, LabelRole: policy.Target.Role},
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
	replicated := service.Spec.GetReplicated()
	if replicated == nil || replicated.Replicas > autoscale.MaxReplicas {
		return result, errors.New("autoscaling requires a replicated service within the product replica limit")
	}
	memory, exists := a.history[policy.Target]
	history := memory.history
	if !exists || memory.serviceID != service.ID {
		history = autoscale.Reset(now)
	}
	var signalPolicy autoscale.Policy
	if policy.Policy != nil {
		signalPolicy = *policy.Policy
		if service.UpdateStatus == nil || service.UpdateStatus.State == api.UpdateStatus_COMPLETED ||
			service.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED {
			result.Readings = autoscale.Collect(ctx, a.source, policy.Target, signalPolicy, now)
		}
	}
	decision := autoscale.Decide(signalPolicy, autoscale.Input{Current: int(replicated.Replicas), Bounds: policy.Bounds,
		Readings: result.Readings, Now: now}, history)
	result.Replicas, result.Target, result.Decision, result.Reason = decision.From, decision.To, decision, decision.Reason
	if decision.Changed() {
		leading, err := a.leading(ctx)
		if err != nil {
			return result, err
		}
		if !leading {
			a.leader = false
			clear(a.history)
			return result, errors.New("manager leadership changed before replica update")
		}
		spec := service.Spec.Copy()
		spec.GetReplicated().Replicas = uint64(decision.To)
		if _, err := a.client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID,
			ServiceVersion: &service.Meta.Version, Spec: spec}); err != nil {
			return result, err
		}
	}
	a.history[policy.Target] = scaleMemory{serviceID: service.ID, history: decision.History}
	return result, nil
}
