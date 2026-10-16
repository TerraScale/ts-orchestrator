package swarmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

const (
	FunctionWorkerRole    = "function-worker"
	LabelFunctionTenant   = "terrascale.function-tenant"
	LabelFunctionID       = "terrascale.function-id"
	LabelFunctionRevision = "terrascale.function-revision"
	LabelFunctionDigest   = "terrascale.function-digest"
	LabelFunctionProof    = "terrascale.function-proof"
	LabelFunctionSequence = "terrascale.function-sequence"
)

// CurrentFunctionIntent resolves signed bytes against the durable current head
// and its sequence floor. Task annotations never implement this authority.
type CurrentFunctionIntent interface {
	CurrentFunction(context.Context, string, string) (release.VerifiedFunction, error)
}

// FunctionServiceIntent identifies the independently admitted deployment target.
// Each tenant/function has one long-lived worker; SwarmKit chooses its host.
type FunctionServiceIntent struct {
	TenantID, FunctionID, Region, Environment, Architecture string
}

func (i FunctionServiceIntent) serviceSpec(function release.VerifiedFunction, worker release.VerifiedContainer) (*api.ServiceSpec, error) {
	if !function.Valid() || !worker.Valid(time.Now().UTC()) || !entityid.Valid(i.TenantID) || !intentName.MatchString(i.FunctionID) || !intentName.MatchString(i.Region) {
		return nil, errors.New("function service requires current signed function and qualified worker")
	}
	f, w := function.Claim(), worker.Claim()
	if f.TenantID != i.TenantID || f.FunctionID != i.FunctionID || f.Environment != i.Environment || catalog.OCIRegion(f.Cell) != i.Region || w.Role != FunctionWorkerRole || w.Environment != i.Environment || w.Cell != f.Cell || w.Architecture != i.Architecture {
		return nil, errors.New("function or qualified worker differs from admitted target")
	}
	base := ServiceIntent{
		ID:   entityid.Derive("function-service", i.Environment, i.Region, i.TenantID, i.FunctionID),
		Role: FunctionWorkerRole, Region: i.Region, Environment: i.Environment, Architecture: i.Architecture, Replicas: 1,
		Container:       &api.ContainerSpec{Image: w.Image, User: "65532:65532", Command: []string{"/usr/local/bin/terrascale-orchestrator"}, Args: []string{FunctionWorkerRole}},
		Resources:       &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 750_000_000, MemoryBytes: 256 << 20}},
		Ports:           []*api.PortConfig{{Name: "function-https", Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, TargetPort: 8080, PublishedPort: 8080}},
		releaseSequence: w.ReleaseSequence, releaseFingerprint: worker.ReleaseIdentity(),
	}
	spec, err := base.serviceSpec()
	if err != nil {
		return nil, err
	}
	spec.Task.Placement.Constraints = []string{
		"node.labels." + LabelRegion + "==" + i.Region,
		"node.labels." + LabelExecutionScope + "==tenant",
		"node.labels." + LabelHostRole + "==wasm",
	}
	spec.Task.Resources.Limits.Generic = []*api.GenericResource{genericresource.NewDiscrete(FunctionWorkerSlot, 1)}
	spec.Task.Resources.Reservations = spec.Task.Resources.Limits.Copy()
	labels := spec.Annotations.Labels
	labels[LabelFunctionTenant], labels[LabelFunctionID] = f.TenantID, f.FunctionID
	labels[LabelFunctionRevision], labels[LabelFunctionDigest] = f.Revision, f.Digest
	labels[LabelFunctionProof], labels[LabelFunctionSequence] = function.EnvelopeSHA256(), strconv.FormatUint(f.Sequence, 10)
	// Renewed proof material requires a new task even when module bytes match.
	fingerprint := sha256.Sum256([]byte(function.EnvelopeSHA256()))
	spec.Task.ForceUpdate = binary.BigEndian.Uint64(fingerprint[:8])
	if _, err := DecodeContainer(&api.Task{ID: "validation", ServiceID: "validation", Spec: spec.Task, ServiceAnnotations: spec.Annotations}); err != nil {
		return nil, err
	}
	return spec, nil
}

// VerifyTask compares actual manager state with the fixed qualified worker
// contract before a controller issues any task-bound material. The caller also
// verifies current intent, live qualification and admitted recipient identity.
func (i FunctionServiceIntent) VerifyTask(task *api.Task, service *api.Service, function release.VerifiedFunction, worker release.VerifiedContainer) error {
	if task == nil || service == nil || task.ServiceID != service.ID || service.PendingDelete || task.DesiredState != api.TaskStateRunning {
		return errors.New("function material requires a current assigned service task")
	}
	spec, err := i.serviceSpec(function, worker)
	if err != nil {
		return err
	}
	if !proto.Equal(&service.Spec, spec) || !proto.Equal(&task.Spec, &spec.Task) || !proto.Equal(&task.ServiceAnnotations, &spec.Annotations) {
		return errors.New("function task differs from the current fixed qualified service")
	}
	_, err = DecodeContainer(task)
	return err
}

// VerifyWorkerFloor denies material for an image superseded by the durable
// regional role floor. The caller first verifies live worker qualification.
func (i FunctionServiceIntent) VerifyWorkerFloor(ctx context.Context, client api.ControlClient, worker release.VerifiedContainer) error {
	claim := worker.Claim()
	workerIntent := ServiceIntent{ID: entityid.Derive("function-worker-release", i.Environment, i.Region), Role: FunctionWorkerRole, Region: i.Region, Environment: i.Environment, Architecture: i.Architecture}
	name, err := releaseFloorName(workerIntent, worker)
	if err != nil {
		return err
	}
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{name}}})
	if err != nil {
		return err
	}
	if listed == nil || len(listed.Configs) != 1 || listed.Configs[0] == nil {
		return errors.New("qualified worker has no unique durable release floor")
	}
	floor := listed.Configs[0]
	for key, value := range map[string]string{LabelIntentID: workerIntent.ID, LabelRole: FunctionWorkerRole, LabelRegion: i.Region, LabelEnvironment: i.Environment, labelReleaseArchitecture: i.Architecture} {
		if floor.Spec.Annotations.Labels[key] != value {
			return errors.New("worker release floor ownership or target mismatch")
		}
	}
	// The exact immutable migration must match the already verified worker proof;
	// mutable sequence labels alone cannot establish a release ordering namespace.
	migration, err := trust.DecodeEnvelope(floor.Spec.Data)
	if err != nil {
		return err
	}
	fingerprint, err := trust.Fingerprint(migration)
	if err != nil {
		return err
	}
	if fingerprint != claim.SequenceMigrationSHA256 || floor.Spec.Annotations.Labels[labelReleaseSequence] != strconv.FormatUint(claim.ReleaseSequence, 10) || floor.Spec.Annotations.Labels[labelReleaseFingerprint] != worker.ReleaseIdentity() {
		return errors.New("qualified worker release floor differs or was superseded")
	}
	if !worker.Valid(time.Now().UTC()) {
		return errors.New("worker authorization expired during release floor verification")
	}
	return ctx.Err()
}

// ApplyFunctionService admits the qualified OCI worker separately from its
// tenant function and waits for authenticated application readiness. Material
// delivery remains bound to the actual scheduled task by the executor provider.
func ApplyFunctionService(ctx context.Context, client api.ControlClient, intent FunctionServiceIntent, current CurrentFunctionIntent, bundle release.ContainerBundle, roots trust.Keyring, retained release.SequenceFloor, evidence func(context.Context, string) (io.ReadCloser, error), probe func(context.Context, *api.Task) error) (*api.Service, error) {
	if current == nil || probe == nil {
		return nil, errors.New("function service requires current intent authority and authenticated readiness")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	function, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if !function.Valid() || function.ExpiresAt().Before(deadline) {
		return nil, errors.New("function authority expires before rollout deadline")
	}
	region, knownRegion := catalog.CellForOCIRegion(intent.Region)
	if !knownRegion {
		return nil, errors.New("function service requires an admitted OCI region")
	}
	target := release.ContainerTarget{Cell: region.Cell, Environment: intent.Environment, Role: FunctionWorkerRole, Architecture: intent.Architecture}
	worker, err := release.VerifyContainerCurrent(ctx, bundle, roots, target, time.Now().UTC(), deadline, evidence)
	if err != nil {
		return nil, err
	}
	spec, err := intent.serviceSpec(function, worker)
	if err != nil {
		return nil, err
	}
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{spec.Annotations.Name}}})
	if err != nil {
		return nil, err
	}
	if len(listed.Services) > 1 {
		return nil, errors.New("ambiguous function service identity")
	}
	var existing *api.Service
	if len(listed.Services) == 1 {
		existing = listed.Services[0]
		for _, key := range []string{LabelIntentID, LabelRole, LabelRegion, LabelEnvironment, LabelFunctionTenant, LabelFunctionID} {
			if existing.Spec.Annotations.Labels[key] != spec.Annotations.Labels[key] {
				return nil, errors.New("function service ownership or target mismatch")
			}
		}
		if existing.PendingDelete || existing.Spec.GetReplicated() == nil || existing.Spec.GetReplicated().Replicas != 1 {
			return nil, errors.New("function service is deleting or has unsupported replication")
		}
		if existing.UpdateStatus != nil && existing.PreviousSpec != nil {
			switch existing.UpdateStatus.State {
			case api.UpdateStatus_ROLLBACK_STARTED, api.UpdateStatus_ROLLBACK_COMPLETED, api.UpdateStatus_ROLLBACK_PAUSED:
				if proto.Equal(&existing.PreviousSpec.Task, &spec.Task) && !proto.Equal(&existing.Spec.Task, &spec.Task) {
					return nil, errors.New("function revision already rolled back; a newer signed revision is required")
				}
			}
		}
	}
	// Worker ordering belongs to the regional role channel, independently of
	// tenant function ordering retained by the current intent authority.
	checkIntent := func() error {
		latest, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
		if err != nil {
			return err
		}
		if !latest.Valid() || latest.EnvelopeSHA256() != function.EnvelopeSHA256() {
			return errors.New("function intent changed during service admission")
		}
		return ctx.Err()
	}
	if err := checkIntent(); err != nil {
		return nil, err
	}
	workerIntent := ServiceIntent{ID: entityid.Derive("function-worker-release", intent.Environment, intent.Region), Role: FunctionWorkerRole, Region: intent.Region, Environment: intent.Environment, Architecture: intent.Architecture}
	_, err = reserveReleaseFloor(ctx, client, workerIntent, worker, roots, retained, 0)
	if err != nil {
		return nil, err
	}
	guard := func() error {
		if err := checkIntent(); err != nil {
			return err
		}
		return intent.VerifyWorkerFloor(ctx, client, worker)
	}
	if err := guard(); err != nil {
		return nil, err
	}
	var requested *api.Service
	if existing == nil {
		created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
		if err != nil {
			return nil, fmt.Errorf("create function service: %w", err)
		}
		requested = created.Service
	} else if proto.Equal(&existing.Spec, spec) {
		requested = existing
	} else {
		updated, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: existing.ID, ServiceVersion: &existing.Meta.Version, Spec: spec})
		if err != nil {
			return nil, fmt.Errorf("update function service: %w", err)
		}
		requested = updated.Service
	}
	ready, err := AwaitServiceReady(ctx, client, requested, probe)
	if err != nil {
		return ready, err
	}
	if err := guard(); err != nil {
		return nil, err
	}
	return ready, nil
}
