// Package execution retains database safety at the SwarmKit runtime boundary.
package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

var ErrUnsafe = errors.New("database execution lacks current safety evidence")

// Binding contains identities read from trusted admission, never task labels.
// AdmissionSHA256 binds retained release, disk/CPU compatibility, writer fencing,
// and member/volume identity evidence. It is not a caller assertion of safety.
type Binding struct {
	TaskSHA256, AdmissionSHA256 string
	Epoch                       uint64
	Volume                      oci.VolumeInitializationPins
	Member                      *memberstatus.Client
	DrainStore                  *memberstatus.FileStore
	Survivor                    memberstatus.Survivor
	OperationID                 string
}

// BindingSource is implemented by the production admission/host integration.
// VerifyTaskBinding must authenticate the exact task/node/member/volume mapping,
// current writer authority, release and disk/CPU evidence, and independent stop
// of any predecessor. The retained initializer must have prepared the mounted
// volume before admission; runtime hooks cannot consume a first-format grant.
// Container process binding must preserve host SO_PEERCRED
// identity; a container namespace PID cannot stand in for the host PID.
// VerifyRemoval additionally requires a retained final survivor drain receipt
// and independent observation that this task's exact writer process stopped.
// No production adapter exists yet: leaving Bindings nil deliberately denies it.
type BindingSource interface {
	VerifyTaskBinding(context.Context, *api.Task) (Binding, error)
	VerifyRemoval(context.Context, *api.Task, Binding) error
}

type Hooks struct {
	Authority authority.Fencer
	Volumes   oci.VolumeInitializationInspector
	Bindings  BindingSource
	Worker    *WorkerSession
}

type activeEffect interface {
	BeginActiveWorkloadEffect(context.Context, uint64, authority.WorkloadScope) (func(), error)
}

type heldKey struct{}
type heldEffect struct {
	hooks   *Hooks
	binding Binding
	active  atomic.Bool
}

// Stateful uses labels only to demand safety, never to prove it.
func Stateful(task *api.Task) bool {
	if task == nil {
		return false
	}
	for _, labels := range []map[string]string{task.Annotations.Labels, task.ServiceAnnotations.Labels} {
		if labels["terrascale.stateful"] == "true" || labels["terrascale.role"] == "terrabase" {
			return true
		}
	}
	return false
}

// TaskSHA256 binds the assignment and complete spec, including both label sets.
func TaskSHA256(task *api.Task) (string, error) {
	digest, err := executionwire.TaskSHA256(task)
	if err != nil {
		return "", errors.Join(ErrUnsafe, err)
	}
	return digest, nil
}

// WithTaskEffect holds the existing per-database authority gate through the
// synchronous runtime effect. Every executor mutation route must use it.
func (h *Hooks) WithTaskEffect(ctx context.Context, task *api.Task, effect func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || effect == nil || task == nil {
		return ErrUnsafe
	}
	if !Stateful(task) {
		return effect(ctx)
	}

	apply := func(ctx context.Context, expected *Binding) error {
		binding, err := h.resolve(ctx, task)
		if err != nil {
			return err
		}
		if expected != nil && binding != *expected {
			return ErrUnsafe
		}
		held := &heldEffect{hooks: h, binding: binding}
		held.active.Store(true)
		defer held.active.Store(false)
		ctx = context.WithValue(ctx, heldKey{}, held)
		if err := h.check(ctx, task); err != nil {
			return err
		}
		return effect(ctx)
	}
	if h != nil && h.Worker != nil {
		return h.Worker.WithTaskEffect(ctx, task, func(ctx context.Context) error { return apply(ctx, nil) })
	}
	binding, err := h.resolve(ctx, task)
	if err != nil {
		return err
	}
	gate, ok := h.Authority.(activeEffect)
	if !ok {
		return fmt.Errorf("%w: authority cannot hold workload effect", ErrUnsafe)
	}
	ctx = authority.WithActiveWorkloadEffectContext(ctx)
	release, err := gate.BeginActiveWorkloadEffect(ctx, binding.Epoch, authority.WorkloadScope{DatabaseID: binding.Volume.DatabaseID, PartitionID: binding.Volume.PartitionID})
	if err != nil {
		return err
	}
	defer release()
	return apply(ctx, &binding)
}

func (h *Hooks) resolve(ctx context.Context, task *api.Task) (Binding, error) {
	if h == nil || h.Bindings == nil {
		return Binding{}, ErrUnsafe
	}
	if h.Worker != nil {
		source, ok := h.Bindings.(*Source)
		if !ok || !h.Worker.ownsSource(source) {
			return Binding{}, ErrUnsafe
		}
	} else if h.Authority == nil || h.Volumes == nil {
		return Binding{}, ErrUnsafe
	}
	binding, err := h.Bindings.VerifyTaskBinding(ctx, task)
	if err != nil {
		return Binding{}, errors.Join(ErrUnsafe, err)
	}
	digest, err := TaskSHA256(task)
	if err != nil {
		return Binding{}, err
	}
	admission, err := hex.DecodeString(binding.AdmissionSHA256)
	if err != nil || len(admission) != sha256.Size || hex.EncodeToString(admission) != binding.AdmissionSHA256 ||
		binding.TaskSHA256 != digest || binding.Epoch == 0 || binding.Member == nil || binding.DrainStore == nil ||
		!entityid.Valid(binding.OperationID) || !entityid.Valid(binding.Volume.DatabaseID) || !entityid.Valid(binding.Volume.PartitionID) ||
		binding.Volume.InstanceID == "" || binding.Volume.HostCreateKey == "" || binding.Volume.VolumeID == "" ||
		binding.Volume.AttachmentID == "" || binding.Volume.AttachmentETag == "" || binding.Volume.Device == "" ||
		binding.Volume.FileSystemUUID == "" || binding.Volume.FileSystemType != "ext4" && binding.Volume.FileSystemType != "xfs" {
		return Binding{}, ErrUnsafe
	}
	if h.Worker != nil {
		return binding, nil
	}
	snapshot := h.Authority.Current()
	if !snapshot.CanMutate() || snapshot.Epoch != binding.Epoch {
		return Binding{}, authority.ErrFenced
	}
	if err := h.Authority.Guard(ctx, binding.Epoch); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

func (h *Hooks) check(ctx context.Context, task *api.Task) error {
	if ctx == nil || task == nil {
		return ErrUnsafe
	}
	held, ok := ctx.Value(heldKey{}).(*heldEffect)
	if !Stateful(task) && !ok {
		return nil
	}
	if !ok || held.hooks != h || !held.active.Load() {
		return ErrUnsafe
	}
	if h.Worker != nil {
		if err := h.Worker.CheckHeld(ctx, task); err != nil {
			return err
		}
	}
	binding, err := h.resolve(ctx, task)
	if err != nil {
		return err
	}
	if binding != held.binding {
		return fmt.Errorf("%w: binding changed during runtime effect", ErrUnsafe)
	}
	return nil
}

func (h *Hooks) volume(ctx context.Context, task *api.Task) error {
	if err := h.check(ctx, task); err != nil {
		return err
	}
	if !Stateful(task) {
		return nil
	}
	if h.Worker != nil {
		return h.check(ctx, task)
	}
	held := ctx.Value(heldKey{}).(*heldEffect)
	proof, err := h.Volumes.InspectVolumeInitialization(ctx, held.binding.Volume)
	if err != nil {
		return errors.Join(ErrUnsafe, err)
	}
	if proof.BootDescriptorSHA256 == "" || proof.AllowFormat {
		return ErrUnsafe
	}
	// The runtime never forwards a first-format grant. Inspect may consume one
	// if admission incorrectly supplied an uninitialized volume, which holds it.
	return h.check(ctx, task)
}

func (h *Hooks) BeforePrepare(ctx context.Context, task *api.Task) error { return h.volume(ctx, task) }
func (h *Hooks) BeforeStart(ctx context.Context, task *api.Task) error   { return h.volume(ctx, task) }

func (h *Hooks) BeforeShutdown(ctx context.Context, task *api.Task) error {
	if err := h.volume(ctx, task); err != nil {
		return err
	}
	if !Stateful(task) {
		return nil
	}
	binding := ctx.Value(heldKey{}).(*heldEffect).binding
	result, err := binding.Member.Drain(ctx, binding.Survivor, binding.OperationID, binding.DrainStore)
	if err != nil {
		return errors.Join(ErrUnsafe, err)
	}
	if result.State != "complete" || result.Receipt == nil {
		return memberstatus.ErrOutcomeUnknown
	}
	return h.check(ctx, task)
}

func (h *Hooks) BeforeRemove(ctx context.Context, task *api.Task) error {
	if err := h.volume(ctx, task); err != nil {
		return err
	}
	if !Stateful(task) {
		return nil
	}
	binding := ctx.Value(heldKey{}).(*heldEffect).binding
	if err := h.Bindings.VerifyRemoval(ctx, task, binding); err != nil {
		return errors.Join(ErrUnsafe, err)
	}
	return h.check(ctx, task)
}
