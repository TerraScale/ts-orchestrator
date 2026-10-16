package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"github.com/containerd/containerd/api/types"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

// BindStateful installs the production verifier; task metadata cannot install it.
func (e *Executor) BindStateful(source *execution.Source) error {
	if source == nil {
		return execution.ErrUnsafe
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stateful != nil {
		return errors.New("stateful admission authority is immutable")
	}
	e.stateful = source
	return nil
}

func decodeStateful(task *api.Task) (*api.ContainerSpec, error) {
	if task == nil || !execution.Stateful(task) {
		return nil, execution.ErrUnsafe
	}
	g := task.Spec.GetGeneric()
	if g == nil || g.Kind != execution.StatefulContainerKind || g.Payload == nil || g.Payload.TypeUrl != execution.StatefulContainerTypeURL {
		return nil, execution.ErrUnsafe
	}
	// Reuse every stateless structural restriction without relaxing its public guard.
	check := task.Copy()
	check.Spec.GetGeneric().Kind = ContainerKind
	check.Spec.GetGeneric().Payload.TypeUrl = containerTypeURL
	for _, labels := range []map[string]string{check.Annotations.Labels, check.ServiceAnnotations.Labels} {
		delete(labels, "terrascale.stateful")
		if labels[LabelRole] == "terrabase" {
			delete(labels, LabelRole)
		}
	}
	spec, err := DecodeContainer(check)
	if err != nil {
		return nil, err
	}
	if _, err := execution.TaskSHA256(task); err != nil {
		return nil, err
	}
	return spec, nil
}

type statefulController struct {
	*controller
	source *execution.Source
	hooks  *execution.Hooks
}

type statefulPinsKey struct{}

func (s *statefulController) effect(ctx context.Context, before func(context.Context, *api.Task) error, effect func(context.Context) error) error {
	return s.hooks.WithTaskEffect(ctx, s.task, func(ctx context.Context) error {
		if err := before(ctx, s.task); err != nil {
			return err
		}
		pins, err := s.source.ResolveRuntime(ctx, s.task)
		if err != nil {
			return err
		}
		witness, err := hostvolume.ObserveMount(pins.Volume)
		if err != nil {
			return err
		}
		defer witness.Close()
		ctx = context.WithValue(ctx, statefulPinsKey{}, pins)
		if err := effect(ctx); err != nil {
			return err
		}
		return witness.Recheck()
	})
}

func (s *statefulController) Prepare(ctx context.Context) error {
	return s.effect(ctx, s.hooks.BeforePrepare, s.controller.Prepare)
}
func (s *statefulController) Start(ctx context.Context) error {
	return s.effect(ctx, s.hooks.BeforeStart, s.controller.Start)
}
func (s *statefulController) Shutdown(ctx context.Context) error {
	return s.effect(ctx, s.hooks.BeforeShutdown, s.controller.Shutdown)
}
func (s *statefulController) Terminate(ctx context.Context) error {
	return s.effect(ctx, s.hooks.BeforeShutdown, s.controller.Terminate)
}
func (s *statefulController) Remove(ctx context.Context) error {
	return s.effect(ctx, s.hooks.BeforeRemove, s.controller.Remove)
}
func (s *statefulController) Update(_ context.Context, task *api.Task) error {
	digest, err := execution.TaskSHA256(task)
	if _, decodeErr := decodeStateful(task); err != nil || decodeErr != nil || digest != s.fingerprint {
		return swarmexec.ErrTaskUpdateRejected
	}
	return nil
}

func (s *statefulController) observe(ctx context.Context) error {
	pins, ok := ctx.Value(statefulPinsKey{}).(execution.RuntimePins)
	if !ok {
		return execution.ErrUnsafe
	}
	observation, err := (execution.RuntimeObserver{Client: s.executor.client}).Observe(ctx, pins)
	if err != nil {
		return err
	}
	return s.source.RecordRuntime(ctx, s.task, observation)
}

// Wait continuously checks the same concrete process and retained volume while
// upstream SwarmKit remains the task lifecycle owner.
func (s *statefulController) Wait(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var exited bool
		var result error
		err := s.effect(ctx, s.hooks.BeforeStart, func(ctx context.Context) error {
			task, err := s.controller.runtimeTask(ctx)
			if err != nil {
				return err
			}
			status, err := task.Status(runtimeContext(ctx))
			if err != nil {
				return err
			}
			if status.Status == containerd.Stopped {
				exited = true
				result = exitError(status.ExitStatus)
				return nil
			}
			return s.observe(ctx)
		})
		if err != nil {
			return fmt.Errorf("observe qualified stateful process: %w", err)
		}
		if exited {
			return result
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *statefulController) specOption(ctx context.Context) (oci.SpecOpts, error) {
	pins, ok := ctx.Value(statefulPinsKey{}).(execution.RuntimePins)
	if !ok {
		return nil, execution.ErrUnsafe
	}
	return func(_ context.Context, _ oci.Client, _ *containers.Container, spec *runtimespec.Spec) error {
		spec.Process = &pins.Process
		if spec.Linux == nil {
			return execution.ErrUnsafe
		}
		spec.Linux.Resources = &pins.Resources
		spec.Linux.CgroupsPath = "/terrascale/" + s.id
		spec.Mounts = pins.Mounts
		return nil
	}, nil
}

func (s *statefulController) verifySpec(ctx context.Context, ctr containerd.Container) error {
	pins, ok := ctx.Value(statefulPinsKey{}).(execution.RuntimePins)
	if !ok {
		return execution.ErrUnsafe
	}
	spec, err := ctr.Spec(ctx)
	if err != nil {
		return err
	}
	if spec.Linux == nil || !reflect.DeepEqual(spec.Process, &pins.Process) || !reflect.DeepEqual(spec.Linux.Resources, &pins.Resources) || !reflect.DeepEqual(spec.Mounts, pins.Mounts) {
		return errors.New("container specification differs from qualified stateful runtime")
	}
	return nil
}

func (s *statefulController) ContainerStatus(ctx context.Context) (*api.ContainerStatus, error) {
	var status *api.ContainerStatus
	err := s.effect(ctx, s.hooks.BeforeStart, func(ctx context.Context) error {
		var err error
		status, err = s.controller.ContainerStatus(ctx)
		return err
	})
	return status, err
}
func (s *statefulController) Metrics(ctx context.Context) (*types.Metric, error) {
	var metric *types.Metric
	err := s.effect(ctx, s.hooks.BeforeStart, func(ctx context.Context) error {
		var err error
		metric, err = s.controller.Metrics(ctx)
		return err
	})
	return metric, err
}
func (s *statefulController) Logs(ctx context.Context, publisher swarmexec.LogPublisher, options api.LogSubscriptionOptions) error {
	return s.effect(ctx, s.hooks.BeforeStart, func(ctx context.Context) error { return s.controller.Logs(ctx, publisher, options) })
}
