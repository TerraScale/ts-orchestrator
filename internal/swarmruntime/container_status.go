package swarmruntime

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// VerifyCurrentContainerService authenticates the current complete revision and
// exact durable floor. Names and labels only locate manager-owned records.
func VerifyCurrentContainerService(ctx context.Context, client api.ControlClient, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring) (*api.Service, error) {
	if client == nil || !verified.Valid(time.Now().UTC()) {
		return nil, errors.New("current container release is pending")
	}
	intent, err := intent.withVerifiedRelease(verified)
	if err != nil {
		return nil, err
	}
	wanted, err := intent.serviceSpec()
	if err != nil {
		return nil, err
	}
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{wanted.Annotations.Name}}})
	if err != nil {
		return nil, err
	}
	if listed == nil || len(listed.Services) != 1 || listed.Services[0] == nil || listed.Services[0].ID == "" {
		return nil, errors.New("current container service is pending")
	}
	response, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: listed.Services[0].ID})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Service == nil {
		return nil, errors.New("current container service is unavailable")
	}
	service := response.Service
	if service.ID != listed.Services[0].ID || service.PendingDelete || service.Spec.GetReplicated() == nil {
		return nil, errors.New("current container service is deleting or unsupported")
	}
	// Scale and secret-version restarts are separately manager-owned state.
	wanted.GetReplicated().Replicas = service.Spec.GetReplicated().Replicas
	wanted.Task.ForceUpdate = service.Spec.Task.ForceUpdate
	if !proto.Equal(wanted, &service.Spec) {
		return nil, errors.New("current container service differs from exact admitted operation")
	}
	floorName, err := releaseFloorName(intent, verified)
	if err != nil {
		return nil, err
	}
	floors, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{floorName}}})
	if err != nil {
		return nil, err
	}
	if floors == nil || len(floors.Configs) != 1 || floors.Configs[0] == nil {
		return nil, errors.New("current container release floor is unavailable")
	}
	floor := floors.Configs[0]
	labels := floor.Spec.Annotations.Labels
	if floor.Spec.Annotations.Name != floorName || labels[LabelIntentID] != intent.ID || labels[LabelRole] != intent.Role || labels[LabelRegion] != intent.Region || labels[LabelEnvironment] != intent.Environment ||
		labels[labelReleaseSequence] != strconv.FormatUint(verified.Claim().ReleaseSequence, 10) || labels[labelReleaseFingerprint] != verified.ReleaseIdentity() {
		return nil, errors.New("current container release floor changed")
	}
	if err := authenticateReleaseFloor(ctx, client, intent, verified, roots, floor); err != nil {
		return nil, err
	}
	return service, ctx.Err()
}

// CurrentContainerOperation returns a locator only. The caller must reopen its
// authenticated intent before VerifyCurrentContainerService admits any status.
func CurrentContainerOperation(ctx context.Context, client api.ControlClient, intent ServiceIntent) (string, error) {
	if client == nil {
		return "", errors.New("current container manager is pending")
	}
	wanted, err := intent.serviceSpec()
	if err != nil {
		return "", err
	}
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{wanted.Annotations.Name}}})
	if err != nil {
		return "", err
	}
	if listed == nil || len(listed.Services) != 1 || listed.Services[0] == nil {
		return "", errors.New("current container operation is pending")
	}
	response, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: listed.Services[0].ID})
	if err != nil {
		return "", err
	}
	if response == nil || response.Service == nil || response.Service.PendingDelete {
		return "", errors.New("current container service is unavailable")
	}
	return response.Service.Spec.Annotations.Labels[LabelOperationID], nil
}
