package swarmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const labelReleaseBaseline = "terrascale.release-baseline"
const labelReleaseArchitecture = "terrascale.release-architecture"
const labelReleaseMigration = "terrascale.release-migration"

// ApplySignedService admits a release and waits for actual application readiness.
// The probe must resolve each task through independently admitted node inventory.
func ApplySignedService(ctx context.Context, client api.ControlClient, intent ServiceIntent, bundle release.ContainerBundle, roots trust.Keyring, retained release.SequenceFloor, evidence func(context.Context, string) (io.ReadCloser, error), probe func(context.Context, *api.Task) error, allocations release.SequenceLocation, guard func(context.Context) error) (*api.Service, error) {
	if probe == nil || guard == nil || intent.Generation == 0 {
		return nil, errors.New("signed service rollout requires application readiness, current authority and delivery generation")
	}
	client = guardedServiceClient{ControlClient: client, guard: guard}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	requested, err := applySignedService(ctx, client, intent, bundle, roots, retained, evidence, allocations)
	if err != nil {
		return nil, err
	}
	ready, err := AwaitServiceReady(ctx, client, requested, probe)
	if currentErr := guard(ctx); currentErr != nil {
		return nil, currentErr
	}
	return ready, err
}

// AwaitServiceReady consumes an already admitted upstream service revision.
// Callers must validate its typed release and reserve its durable ordering floor before mutation.
func AwaitServiceReady(ctx context.Context, client api.ControlClient, requested *api.Service, probe func(context.Context, *api.Task) error) (*api.Service, error) {
	if requested == nil || requested.Spec.GetReplicated() == nil || probe == nil {
		return nil, errors.New("service rollout requires an admitted replicated revision and application probe")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var unhealthySince time.Time
	rolledBack := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("service readiness remains pending: %w", err)
		}
		response, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: requested.ID})
		if err != nil {
			return nil, err
		}
		current := response.Service
		matches := func(spec *api.ServiceSpec) bool {
			return spec != nil && proto.Equal(&current.Spec.Task, &spec.Task) && proto.Equal(&current.Spec.Annotations, &spec.Annotations) && proto.Equal(current.Spec.Endpoint, spec.Endpoint)
		}
		if !matches(&requested.Spec) {
			if current.UpdateStatus == nil || !matches(requested.PreviousSpec) || (current.UpdateStatus.State != api.UpdateStatus_ROLLBACK_STARTED && current.UpdateStatus.State != api.UpdateStatus_ROLLBACK_COMPLETED && current.UpdateStatus.State != api.UpdateStatus_ROLLBACK_PAUSED) {
				return nil, errors.New("a different service revision superseded readiness observation")
			}
			rolledBack = true
		}
		ready, failed, err := serviceReadiness(ctx, client, current, probe)
		if err != nil {
			return nil, err
		}
		complete := current.UpdateStatus == nil && (current.PreviousSpec == nil || proto.Equal(&current.PreviousSpec.Task, &current.Spec.Task))
		if current.UpdateStatus != nil {
			complete = current.UpdateStatus.State == api.UpdateStatus_COMPLETED || current.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED
		}
		if complete && ready {
			if rolledBack {
				return current, errors.New("signed service release rolled back; previous revision is application-ready")
			}
			return current, nil
		}
		if failed && !rolledBack {
			if unhealthySince.IsZero() {
				unhealthySince = time.Now()
			}
			if time.Since(unhealthySince) >= 30*time.Second {
				if err := ctx.Err(); err != nil {
					return nil, fmt.Errorf("service readiness remains pending: %w", err)
				}
				if current.PreviousSpec == nil {
					return current, errors.New("initial service revision is application-unhealthy; no previous revision exists")
				}
				_, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: current.ID, ServiceVersion: &current.Meta.Version, Spec: &current.Spec, Rollback: api.UpdateServiceRequest_PREVIOUS})
				if err != nil {
					return nil, fmt.Errorf("request application-readiness rollback: %w", err)
				}
				rolledBack = true
			}
		} else {
			unhealthySince = time.Time{}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("service readiness remains pending: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// applySignedService is the production service admission mutation. The caller
// supplies the target from admitted membership and its retained legacy floor,
// never from untrusted release metadata. OCI child images have their own signed
// contract; native binary/tarball artifact records cannot enter this path.
func applySignedService(ctx context.Context, client api.ControlClient, intent ServiceIntent, bundle release.ContainerBundle, roots trust.Keyring, retained release.SequenceFloor, evidence func(context.Context, string) (io.ReadCloser, error), allocations release.SequenceLocation) (*api.Service, error) {
	operation, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	deadline, _ := operation.Deadline()
	if _, err := intent.serviceSpec(); err != nil {
		return nil, err
	}
	region, ok := catalog.CellForOCIRegion(intent.Region)
	if !ok {
		return nil, errors.New("signed service requires canonical OCI region")
	}
	if !entityid.Valid(intent.OperationID) {
		return nil, errors.New("signed service requires durable delivery operation locator")
	}
	target := release.ContainerTarget{Cell: region.Cell, Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture}
	verified, err := release.VerifyContainerCurrent(operation, bundle, roots, target, time.Now().UTC(), deadline, evidence, allocations)
	if err != nil {
		return nil, err
	}
	claim := verified.Claim()
	intent, err = intent.withVerifiedRelease(verified)
	if err != nil {
		return nil, err
	}
	spec, _ := intent.serviceSpec()
	services, err := client.ListServices(operation, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{spec.Annotations.Name}}})
	if err != nil {
		return nil, err
	}
	var baseline uint64
	if len(services.Services) > 1 {
		return nil, errors.New("ambiguous service identity")
	}
	if len(services.Services) == 1 {
		baseline = services.Services[0].Meta.Version.Index
	}
	previousFloor, err := readReleaseFloorRecord(operation, client, intent, verified, roots)
	if err != nil {
		return nil, err
	}
	if len(services.Services) == 1 && previousFloor != nil && previousFloor.Spec.Annotations.Labels[labelReleaseSequence] == strconv.FormatUint(claim.ReleaseSequence, 10) {
		if err := checkReleaseRollback(services.Services[0], previousFloor, intent, verified); err != nil {
			return nil, err
		}
	}
	floor, err := reserveReleaseFloor(operation, client, intent, verified, roots, retained, baseline)
	if err != nil {
		return nil, err
	}
	guard := func(ctx context.Context) error {
		if !verified.Valid(time.Now().UTC()) {
			return errors.New("signed container authorization expired before service mutation")
		}
		current, err := client.GetConfig(ctx, &api.GetConfigRequest{ConfigID: floor.ID})
		if err != nil {
			return err
		}
		if current.Config.Spec.Annotations.Labels[labelReleaseSequence] != strconv.FormatUint(claim.ReleaseSequence, 10) || current.Config.Spec.Annotations.Labels[labelReleaseFingerprint] != verified.ReleaseIdentity() {
			return errors.New("a newer signed release superseded this operation")
		}
		if err := checkIntentGeneration(current.Config.Spec.Annotations.Labels, intent); err != nil {
			return err
		}
		if current.Config.Spec.Annotations.Labels[LabelIntentGeneration] != strconv.FormatUint(intent.Generation, 10) && intent.Generation != 0 {
			return errors.New("a newer intent superseded this operation")
		}
		if !verified.Valid(time.Now().UTC()) {
			return errors.New("signed container authorization expired before service mutation")
		}
		return nil
	}
	if len(services.Services) == 1 {
		if err := checkReleaseRollback(services.Services[0], floor, intent, verified); err != nil {
			return nil, err
		}
	}
	return applyServiceGuarded(operation, client, intent, guard)
}

func checkReleaseRollback(current *api.Service, floor *api.Config, intent ServiceIntent, verified release.VerifiedContainer) error {
	storedBaseline, err := strconv.ParseUint(floor.Spec.Annotations.Labels[labelReleaseBaseline], 10, 64)
	if err != nil {
		return errors.New("invalid durable release baseline")
	}
	if current.UpdateStatus != nil && (current.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED || current.UpdateStatus.State == api.UpdateStatus_ROLLBACK_STARTED || current.UpdateStatus.State == api.UpdateStatus_ROLLBACK_PAUSED) && current.Meta.Version.Index > storedBaseline && (current.Spec.Annotations.Labels[labelReleaseSequence] != strconv.FormatUint(verified.Claim().ReleaseSequence, 10) || current.Spec.Annotations.Labels[labelReleaseFingerprint] != verified.ReleaseIdentity() || intent.Generation != 0 && (current.Spec.Annotations.Labels[LabelIntentGeneration] != strconv.FormatUint(intent.Generation, 10) || current.Spec.Annotations.Labels[labelIntentFingerprint] != intent.intentFingerprint)) {
		return errors.New("signed release already rolled back; a newer signed release is required")
	}
	return nil
}

// The Raft config is release evidence, not a second task store. Its immutable
// data preserves the root-signed migration while CAS labels retain a high-water
// mark independently of SwarmKit's automatic previous-spec rollback.
func reserveReleaseFloor(ctx context.Context, client api.ControlClient, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring, retained release.SequenceFloor, baseline uint64) (*api.Config, error) {
	if verified.Claim().Role == "function-worker" {
		wire, err := verified.WorkerFamilyEvidence()
		if err != nil {
			return nil, err
		}
		if err := release.VerifyWorkerFamilyEvidence(wire, roots, verified); err != nil {
			return nil, err
		}
	}
	floor, err := reserveReleaseFloorRecord(ctx, client, intent, verified, roots, retained, baseline)
	if err != nil {
		return nil, err
	}
	// Family evidence cannot precede admission of the durable ordering floor.
	if verified.Claim().Role == "function-worker" {
		if err := reserveWorkerFamily(ctx, client, intent, verified, roots); err != nil {
			return nil, err
		}
	}
	return floor, nil
}

func reserveReleaseFloorRecord(ctx context.Context, client api.ControlClient, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring, retained release.SequenceFloor, baseline uint64) (*api.Config, error) {
	name, err := releaseFloorName(intent, verified)
	if err != nil {
		return nil, err
	}
	current, err := readReleaseFloorRecord(ctx, client, intent, verified, roots)
	if err != nil {
		return nil, err
	}
	claim := verified.Claim()
	if current == nil {
		if verified.Claim().Role == "function-worker" {
			legacyIdentity := sha256.Sum256([]byte(intent.Environment + "/" + intent.Region + "/" + intent.Role))
			legacy, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{fmt.Sprintf("ts-release-%x", legacyIdentity[:16])}}})
			if err != nil {
				return nil, err
			}
			if len(legacy.Configs) != 0 {
				return nil, errors.New("unpartitioned worker release floor requires root-authorized migration")
			}
		}
		migration, err := release.VerifySequenceMigrationCurrent(verified.MigrationEnvelope(), roots, intent.Role, intent.Environment, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		_, digestErr := hex.DecodeString(retained.EvidenceSHA256)
		if retained.Cell != claim.Cell || retained.RunNumber < 0 || retained.RunNumber == 0 && retained.IssuedAt.IsZero() || len(retained.EvidenceSHA256) != 64 || strings.ToLower(retained.EvidenceSHA256) != retained.EvidenceSHA256 || digestErr != nil || !migration.AdmitsLegacyFloor(retained.Cell, retained.RunNumber, retained.IssuedAt) {
			return nil, errors.New("signed migration does not cover retained local legacy release floor")
		}
		wire, err := trust.EncodeEnvelope(verified.MigrationEnvelope())
		if err != nil {
			return nil, err
		}
		labels := map[string]string{LabelIntentID: intent.ID, LabelRole: intent.Role, LabelRegion: intent.Region, LabelEnvironment: intent.Environment, labelReleaseSequence: strconv.FormatUint(claim.ReleaseSequence, 10), labelReleaseFingerprint: verified.ReleaseIdentity(), labelReleaseBaseline: strconv.FormatUint(baseline, 10), "terrascale.legacy-run": strconv.FormatInt(retained.RunNumber, 10), "terrascale.legacy-issued": retained.IssuedAt.UTC().Format(time.RFC3339Nano), "terrascale.legacy-evidence": retained.EvidenceSHA256}
		if intent.Generation != 0 {
			labels[LabelIntentGeneration] = strconv.FormatUint(intent.Generation, 10)
			labels[labelIntentFingerprint] = intent.intentFingerprint
			labels[LabelOperationID] = intent.OperationID
		}
		if claim.Role == "function-worker" {
			labels[labelReleaseArchitecture] = claim.Architecture
		}
		if !verified.Valid(time.Now().UTC()) {
			return nil, errors.New("signed container authorization expired before floor reservation")
		}
		created, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: name, Labels: labels}, Data: wire}})
		if err != nil {
			return nil, err
		}
		return created.Config, nil
	}
	labels := current.Spec.Annotations.Labels
	if err := checkIntentGeneration(labels, intent); err != nil {
		return nil, err
	}
	floor, _ := strconv.ParseUint(labels[labelReleaseSequence], 10, 64)
	if claim.ReleaseSequence < floor || claim.ReleaseSequence == floor && labels[labelReleaseFingerprint] != verified.ReleaseIdentity() {
		return nil, errors.New("stale or equivocating signed release")
	}
	if claim.ReleaseSequence == floor && (intent.Generation == 0 || labels[LabelIntentGeneration] == strconv.FormatUint(intent.Generation, 10)) {
		return current, nil
	}
	spec := current.Spec.Copy()
	spec.Annotations.Labels[labelReleaseSequence] = strconv.FormatUint(claim.ReleaseSequence, 10)
	spec.Annotations.Labels[labelReleaseFingerprint] = verified.ReleaseIdentity()
	if claim.ReleaseSequence > floor {
		spec.Annotations.Labels[labelReleaseBaseline] = strconv.FormatUint(baseline, 10)
	}
	if intent.Generation != 0 {
		spec.Annotations.Labels[LabelIntentGeneration] = strconv.FormatUint(intent.Generation, 10)
		spec.Annotations.Labels[labelIntentFingerprint] = intent.intentFingerprint
		spec.Annotations.Labels[LabelOperationID] = intent.OperationID
	}
	if !verified.Valid(time.Now().UTC()) {
		return nil, errors.New("signed container authorization expired before floor reservation")
	}
	updated, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: current.ID, ConfigVersion: &current.Meta.Version, Spec: spec})
	if err != nil {
		return nil, err
	}
	return updated.Config, nil
}

// Each generation retains its authenticated allocation independently of variant
// high-water marks, so advancing one architecture cannot revoke its sibling.
func reserveWorkerFamily(ctx context.Context, client api.ControlClient, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring) error {
	wire, err := verified.WorkerFamilyEvidence()
	if err != nil {
		return err
	}
	if err := release.VerifyWorkerFamilyEvidence(wire, roots, verified); err != nil {
		return err
	}
	claim := verified.Claim()
	identity := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s/%d", claim.SequenceMigrationSHA256, claim.Role, claim.Environment, claim.ReleaseSequence)))
	name := fmt.Sprintf("ts-worker-family-%x", identity[:16])
	for range 3 {
		listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{name}}})
		if err != nil {
			return err
		}
		if len(listed.Configs) == 1 {
			return release.VerifyWorkerFamilyEvidence(listed.Configs[0].Spec.Data, roots, verified)
		}
		if len(listed.Configs) != 0 {
			return errors.New("ambiguous durable worker release family")
		}
		if !verified.Valid(time.Now().UTC()) {
			return errors.New("worker authorization expired before family reservation")
		}
		_, err = client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: name, Labels: map[string]string{LabelIntentID: intent.ID, LabelRole: claim.Role, LabelRegion: intent.Region, LabelEnvironment: claim.Environment, labelReleaseSequence: strconv.FormatUint(claim.ReleaseSequence, 10), labelReleaseMigration: claim.SequenceMigrationSHA256}}, Data: wire}})
		if status.Code(err) != codes.AlreadyExists {
			return err
		}
	}
	return errors.New("worker release family changed concurrently")
}

// The worker artifact floor is shared by functions but independent per qualified architecture.
func releaseFloorName(intent ServiceIntent, verified release.VerifiedContainer) (string, error) {
	claim := verified.Claim()
	region, known := catalog.CellForOCIRegion(intent.Region)
	if !known || !verified.Valid(time.Now().UTC()) || claim.Cell != region.Cell || claim.Role != intent.Role || claim.Environment != intent.Environment || claim.Architecture != intent.Architecture {
		return "", errors.New("release floor requires current proof for admitted target")
	}
	scope := intent.Environment + "/" + intent.Region + "/" + intent.Role
	if claim.Role == "function-worker" {
		scope += "/" + claim.Architecture
	}
	identity := sha256.Sum256([]byte(scope))
	return fmt.Sprintf("ts-release-%x", identity[:16]), nil
}

// Every signed mutation rechecks the current APP authority after its evidence reads.
type guardedServiceClient struct {
	api.ControlClient
	guard func(context.Context) error
}

func (c guardedServiceClient) CreateConfig(ctx context.Context, request *api.CreateConfigRequest, options ...grpc.CallOption) (*api.CreateConfigResponse, error) {
	if err := c.guard(ctx); err != nil {
		return nil, err
	}
	return c.ControlClient.CreateConfig(ctx, request, options...)
}

func (c guardedServiceClient) UpdateConfig(ctx context.Context, request *api.UpdateConfigRequest, options ...grpc.CallOption) (*api.UpdateConfigResponse, error) {
	if err := c.guard(ctx); err != nil {
		return nil, err
	}
	return c.ControlClient.UpdateConfig(ctx, request, options...)
}

func (c guardedServiceClient) CreateService(ctx context.Context, request *api.CreateServiceRequest, options ...grpc.CallOption) (*api.CreateServiceResponse, error) {
	if err := c.guard(ctx); err != nil {
		return nil, err
	}
	return c.ControlClient.CreateService(ctx, request, options...)
}

func (c guardedServiceClient) UpdateService(ctx context.Context, request *api.UpdateServiceRequest, options ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	if err := c.guard(ctx); err != nil {
		return nil, err
	}
	return c.ControlClient.UpdateService(ctx, request, options...)
}

// Both mutation and task admission reconstruct the same authenticated revision.
func (intent ServiceIntent) withVerifiedRelease(verified release.VerifiedContainer) (ServiceIntent, error) {
	claim := verified.Claim()
	if !verified.Valid(time.Now().UTC()) || intent.Container == nil || claim.Image != intent.Container.Image {
		return ServiceIntent{}, errors.New("service image differs from current signed OCI child manifest")
	}
	intent.releaseSequence = claim.ReleaseSequence
	intent.releaseFingerprint = verified.ReleaseIdentity()
	spec, err := intent.serviceSpec()
	if err != nil {
		return ServiceIntent{}, err
	}
	if intent.Generation != 0 {
		intent.intentFingerprint, err = serviceIntentFingerprint(spec)
		if err != nil {
			return ServiceIntent{}, err
		}
	}
	return intent, nil
}
