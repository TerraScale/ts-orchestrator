package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
)

type genericRuntimeConfig struct {
	Client        api.ControlClient
	ManagerID     string
	Authority     authority.Fencer
	Specs         *specRegistry
	Delivery      *delivery.Service
	Factory       *ociclient.Factory
	Evidence      func(context.Context, string, string) (io.ReadCloser, error)
	Probe         func(context.Context, *api.Task) error
	SessionGuard  func(context.Context) error
	RetainedFloor func(context.Context, string, string) (release.SequenceFloor, error)
}

type genericRuntime struct {
	config         genericRuntimeConfig
	scaler         *swarmruntime.Autoscaler
	mu             sync.Mutex
	epoch          uint64
	owned          map[string]bool
	policyRevision uint64
	policyWire     []byte
	policyRoot     string
	policyEpoch    uint64
	releases       map[string]string
}

func newGenericRuntime(config genericRuntimeConfig, signals autoscale.Source) (*genericRuntime, error) {
	if config.Client == nil || config.ManagerID == "" || config.Authority == nil || config.Specs == nil || config.Specs.kv == nil || config.Specs.roots == nil || config.Delivery == nil || config.Factory == nil || config.Evidence == nil || config.Probe == nil || config.RetainedFloor == nil || config.SessionGuard == nil {
		return nil, errors.New("generic runtime requires current signed service, release, manager and recipient authority")
	}
	runtime := &genericRuntime{config: config, owned: map[string]bool{}, releases: map[string]string{}}
	var err error
	runtime.scaler, err = swarmruntime.NewAutoscaler(genericScaleClient{ControlClient: config.Client, runtime: runtime}, config.ManagerID, signals, config.Probe, nil)
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

func (runtime *genericRuntime) owns(role string) bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.owned[role]
}

func (runtime *genericRuntime) apply(ctx context.Context, intent delivery.Intent) error {
	config := runtime.config
	epoch := config.Authority.Current().Epoch
	if err := config.Authority.Guard(ctx, epoch); err != nil {
		return err
	}
	entry, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return err
	}
	config.Specs.mu.Lock()
	revision := config.Specs.revision
	config.Specs.mu.Unlock()
	if revision != entry.Revision() {
		return containermaterial.ErrPending
	}
	roots, head := config.Specs.roots.current(), config.Specs.roots.reply("").Head
	proof, err := containermaterial.VerifyProfile(entry.Value(), roots, config.Specs.identity, intent)
	if err != nil {
		return err
	}
	claimEnvelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return err
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(claimEnvelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return err
	}
	expected, err := containermaterial.ServiceIntent(proof, claim.Architecture)
	if err != nil {
		return err
	}
	_, specs := config.Specs.effective()
	index := -1
	for i, spec := range specs {
		if spec.Role == intent.Role && spec.Environment == intent.Environment {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("container release requires a signed stateless service policy")
	}
	policy := specs[index]
	if policy.Kind != workload.KindStateless {
		return containermaterial.ErrPending
	}
	expected.Replicas = uint64(min(max(intent.DesiredReplicas, policy.Replicas.Min), policy.Replicas.Max))
	allocations, err := currentContainerAllocations(ctx, config.Factory, *intent.Container, roots, release.ContainerTarget{Cell: strings.ToUpper(intent.Cell), Environment: intent.Environment, Role: intent.Role, Architecture: expected.Architecture})
	if err != nil {
		return err
	}
	retained, err := config.RetainedFloor(ctx, intent.Role, intent.Environment)
	if err != nil {
		return err
	}
	if retained.Cell != strings.ToUpper(intent.Cell) {
		return errors.New("retained legacy floor names another region")
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	guard := func(ctx context.Context) error {
		latest, err := config.Specs.kv.Get(ctx, cellSpecKey)
		if err != nil {
			return err
		}
		config.Specs.mu.Lock()
		adopted := config.Specs.revision
		config.Specs.mu.Unlock()
		if adopted != revision || latest.Revision() != revision || !bytes.Equal(latest.Value(), entry.Value()) || config.Specs.roots.reply("").Head != head {
			return containermaterial.ErrPending
		}
		confirmed, err := config.Delivery.ContainerIntent(ctx, intent.OperationID)
		if err != nil {
			return err
		}
		current, err := confirmed.Fingerprint()
		if err != nil || current != fingerprint {
			return containermaterial.ErrPending
		}
		if err := config.SessionGuard(ctx); err != nil {
			return err
		}
		return config.Authority.Guard(ctx, epoch)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	identity := claim.Image + "/" + intent.ConfigDigest
	runtime.mu.Lock()
	changed := runtime.releases[intent.Role] != identity
	runtime.releases[intent.Role] = identity
	runtime.mu.Unlock()
	if changed {
		runtime.scaler.Reset()
	}
	_, err = swarmruntime.ApplySignedService(ctx, config.Client, expected, *intent.Container, roots, retained,
		func(ctx context.Context, digest string) (io.ReadCloser, error) {
			return config.Evidence(ctx, intent.Role, digest)
		}, config.Probe, allocations, guard)
	if err != nil {
		return err
	}
	return guard(ctx)
}

func (runtime *genericRuntime) refresh(ctx context.Context) error {
	config := runtime.config
	state := config.Authority.Current()
	if err := config.SessionGuard(ctx); err != nil {
		runtime.scaler.Reset()
		return err
	}
	if err := config.Authority.Guard(ctx, state.Epoch); err != nil {
		runtime.scaler.Reset()
		return err
	}
	entry, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		runtime.scaler.Reset()
		return err
	}
	config.Specs.mu.Lock()
	revision := config.Specs.revision
	config.Specs.mu.Unlock()
	if revision != entry.Revision() {
		runtime.scaler.Reset()
		return containermaterial.ErrPending
	}
	root := config.Specs.roots.reply("").Head
	floors, err := config.Client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Labels: map[string]string{
		swarmruntime.LabelRegion: catalog.OCIRegion(strings.ToUpper(config.Specs.cell)), swarmruntime.LabelEnvironment: config.Specs.identity.Environment,
	}}})
	if err != nil {
		return err
	}
	_, specs := config.Specs.effective()
	policies := make([]swarmruntime.ScalePolicy, 0, len(specs))
	runtime.mu.Lock()
	changedEpoch := runtime.epoch != state.Epoch
	runtime.epoch = state.Epoch
	for _, floor := range floors.Configs {
		if floor != nil && floor.Spec.Annotations.Labels[swarmruntime.LabelIntentGeneration] != "" {
			runtime.owned[floor.Spec.Annotations.Labels[swarmruntime.LabelRole]] = true
		}
	}
	for _, spec := range specs {
		if spec.Kind != workload.KindStateless {
			continue
		}
		runtime.owned[spec.Role] = true
		policies = append(policies, swarmruntime.ScalePolicy{Target: autoscale.Target{Cell: config.Specs.cell, Environment: spec.Environment, Role: spec.Role}, Bounds: autoscale.Bounds{Min: spec.Replicas.Min, Max: spec.Replicas.Max}, Policy: spec.Scaling})
	}
	runtime.policyRevision, runtime.policyWire, runtime.policyRoot, runtime.policyEpoch = revision, bytes.Clone(entry.Value()), root, state.Epoch
	runtime.mu.Unlock()
	if changedEpoch {
		runtime.scaler.Reset()
	}
	if err := runtime.scaler.SetPolicies(policies); err != nil {
		return err
	}
	if err := runtime.removeAbsent(ctx); err != nil {
		return err
	}
	return config.Authority.Guard(ctx, state.Epoch)
}

func (runtime *genericRuntime) removalReady(ctx context.Context, role string) error {
	config := runtime.config
	services, err := config.Client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Labels: map[string]string{
		swarmruntime.LabelRegion: catalog.OCIRegion(strings.ToUpper(config.Specs.cell)), swarmruntime.LabelEnvironment: config.Specs.identity.Environment, swarmruntime.LabelRole: role,
	}}})
	if err != nil {
		return err
	}
	for _, service := range services.Services {
		if service == nil || service.Spec.GetReplicated() == nil || service.Spec.GetReplicated().Replicas != 0 {
			return errors.New("manager service must drain to zero before removal")
		}
		if err := runtime.drained(ctx, service.ID); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *genericRuntime) drained(ctx context.Context, serviceID string) error {
	tasks, err := runtime.config.Client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{serviceID}}})
	if err != nil {
		return err
	}
	for _, task := range tasks.Tasks {
		if task == nil || task.DesiredState <= api.TaskStateRunning || task.Status.State <= api.TaskStateRunning {
			return errors.New("manager service still has live tasks")
		}
	}
	return nil
}

func (runtime *genericRuntime) removeAbsent(ctx context.Context) error {
	config := runtime.config
	epoch := config.Authority.Current().Epoch
	entry, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return err
	}
	config.Specs.mu.Lock()
	revision := config.Specs.revision
	config.Specs.mu.Unlock()
	head := config.Specs.roots.reply("").Head
	if revision != entry.Revision() {
		return containermaterial.ErrPending
	}
	_, specs := config.Specs.effective()
	services, err := config.Client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Labels: map[string]string{
		swarmruntime.LabelRegion: catalog.OCIRegion(strings.ToUpper(config.Specs.cell)), swarmruntime.LabelEnvironment: config.Specs.identity.Environment,
	}}})
	if err != nil {
		return err
	}
	for _, service := range services.Services {
		if service == nil || !runtime.owns(service.Spec.Annotations.Labels[swarmruntime.LabelRole]) {
			continue
		}
		kept := false
		for _, spec := range specs {
			if spec.Role == service.Spec.Annotations.Labels[swarmruntime.LabelRole] {
				kept = true
				break
			}
		}
		if kept {
			continue
		}
		if service.Spec.GetReplicated() == nil || service.Spec.GetReplicated().Replicas != 0 {
			return errors.New("removed manager service was not drained")
		}
		if err := runtime.drained(ctx, service.ID); err != nil {
			return err
		}
		latest, err := config.Specs.kv.Get(ctx, cellSpecKey)
		if err != nil {
			return err
		}
		if latest.Revision() != revision || !bytes.Equal(latest.Value(), entry.Value()) || config.Specs.roots.reply("").Head != head {
			return containermaterial.ErrPending
		}
		current, err := config.Client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
		if err != nil {
			return err
		}
		if current == nil || current.Service == nil || current.Service.Meta.Version != service.Meta.Version {
			return containermaterial.ErrPending
		}
		if err := config.SessionGuard(ctx); err != nil {
			return err
		}
		if err := config.Authority.Guard(ctx, epoch); err != nil {
			return err
		}
		if _, err := config.Client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: service.ID}); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *genericRuntime) Run(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if err := runtime.refresh(ctx); err != nil {
			if ctx.Err() == nil {
				slog.DebugContext(ctx, "generic service authority unavailable", "error", err)
			}
		} else if err := runtime.scaler.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "generic service scaling pending", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Only replica changes within the current signed bounds may pass this client.
type genericScaleClient struct {
	api.ControlClient
	runtime *genericRuntime
}

func (client genericScaleClient) UpdateService(ctx context.Context, request *api.UpdateServiceRequest, options ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	config := client.runtime.config
	client.runtime.mu.Lock()
	epoch, pinnedRevision, pinnedWire, pinnedRoot := client.runtime.policyEpoch, client.runtime.policyRevision, bytes.Clone(client.runtime.policyWire), client.runtime.policyRoot
	client.runtime.mu.Unlock()
	entry, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return nil, err
	}
	config.Specs.mu.Lock()
	revision := config.Specs.revision
	config.Specs.mu.Unlock()
	head := config.Specs.roots.reply("").Head
	if epoch == 0 || revision != pinnedRevision || !bytes.Equal(entry.Value(), pinnedWire) || head != pinnedRoot || entry.Revision() != revision || request == nil || request.Spec == nil || request.Rollback != api.UpdateServiceRequest_NONE {
		return nil, containermaterial.ErrPending
	}
	current, err := client.ControlClient.GetService(ctx, &api.GetServiceRequest{ServiceID: request.ServiceID})
	if err != nil {
		return nil, err
	}
	if current == nil || current.Service == nil || request.Spec.GetReplicated() == nil || !proto.Equal(&request.Spec.Task, &current.Service.Spec.Task) || !proto.Equal(&request.Spec.Annotations, &current.Service.Spec.Annotations) || !proto.Equal(request.Spec.Endpoint, current.Service.Spec.Endpoint) {
		return nil, containermaterial.ErrPending
	}
	_, specs := config.Specs.effective()
	allowed := false
	for _, spec := range specs {
		if spec.Role == request.Spec.Annotations.Labels[swarmruntime.LabelRole] && spec.Environment == request.Spec.Annotations.Labels[swarmruntime.LabelEnvironment] && spec.Kind == workload.KindStateless {
			count := request.Spec.GetReplicated().Replicas
			allowed = count >= uint64(spec.Replicas.Min) && count <= uint64(spec.Replicas.Max)
		}
	}
	latest, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return nil, err
	}
	if !allowed || latest.Revision() != revision || !bytes.Equal(latest.Value(), entry.Value()) || config.Specs.roots.reply("").Head != head {
		return nil, containermaterial.ErrPending
	}
	if err := config.Authority.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	if err := config.SessionGuard(ctx); err != nil {
		return nil, err
	}
	return client.ControlClient.UpdateService(ctx, request, options...)
}
