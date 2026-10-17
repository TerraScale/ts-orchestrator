package swarmruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// VerifyRegistryTask binds current signed release authority to the manager's
// actual assignment and ordering floor. Operation labels are locators only.
func VerifyRegistryTask(ctx context.Context, client api.ControlClient, task *api.Task, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring) error {
	if client == nil || task == nil || task.ID == "" || task.ServiceID == "" || task.NodeID == "" || !verified.Valid(time.Now().UTC()) {
		return errors.New("registry requires current release and assigned task")
	}
	claim := verified.Claim()
	if intent.Container == nil || intent.Container.Image != claim.Image || intent.OperationID == "" {
		return errors.New("registry task differs from authenticated release operation")
	}
	floorName, err := releaseFloorName(intent, verified)
	if err != nil {
		return err
	}
	intent, err = intent.withVerifiedRelease(verified)
	if err != nil {
		return err
	}
	wanted, err := intent.serviceSpec()
	if err != nil {
		return err
	}
	assignment, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
	if err != nil {
		return err
	}
	if assignment.Task == nil || assignment.Task.ID != task.ID || assignment.Task.ServiceID != task.ServiceID || assignment.Task.NodeID != task.NodeID ||
		assignment.Task.DesiredState > api.TaskStateRunning || !proto.Equal(&assignment.Task.Spec, &task.Spec) ||
		!proto.Equal(&assignment.Task.ServiceAnnotations, &task.ServiceAnnotations) {
		return errors.New("registry task is not the current manager assignment")
	}
	// Vault-version renewal advances this manager-owned counter without changing
	// the independently authenticated executable profile.
	wanted.Task.ForceUpdate = assignment.Task.Spec.ForceUpdate
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		return err
	}
	if node.Node == nil || node.Node.ID != task.NodeID || node.Node.Spec.Membership != api.NodeMembershipAccepted ||
		node.Node.Spec.Annotations.Labels[LabelRegion] != intent.Region || node.Node.Spec.Annotations.Labels[LabelExecutionScope] != "platform" ||
		node.Node.Spec.Annotations.Labels[LabelInstanceID] == "" || node.Node.Description == nil || node.Node.Description.Platform == nil ||
		node.Node.Description.Platform.OS != "linux" || node.Node.Description.Platform.Architecture != intent.Architecture {
		return errors.New("registry task node differs from admitted region and architecture")
	}
	hostRole := node.Node.Spec.Annotations.Labels[LabelHostRole]
	if hostRole != "manager" && hostRole != "container" || (node.Node.Role == api.NodeRoleManager) != (hostRole == "manager") {
		return errors.New("registry task node differs from admitted certificate role")
	}
	service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
	if err != nil {
		return err
	}
	if service.Service == nil || service.Service.ID != task.ServiceID || service.Service.PendingDelete {
		return errors.New("registry task service is unavailable")
	}
	matches := func(spec *api.ServiceSpec) bool {
		return spec != nil && spec.GetReplicated() != nil && proto.Equal(&spec.Task, &wanted.Task) &&
			proto.Equal(&spec.Annotations, &wanted.Annotations) && proto.Equal(spec.Endpoint, wanted.Endpoint) &&
			proto.Equal(spec.Update, wanted.Update) && proto.Equal(spec.Rollback, wanted.Rollback) &&
			proto.Equal(&task.Spec, &spec.Task) && proto.Equal(&task.ServiceAnnotations, &spec.Annotations)
	}
	if !matches(&service.Service.Spec) && !matches(service.Service.PreviousSpec) {
		return errors.New("registry task differs from current and previous admitted service revisions")
	}
	floors, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{floorName}}})
	if err != nil {
		return err
	}
	if len(floors.Configs) != 1 || floors.Configs[0] == nil {
		return errors.New("registry requires one durable release floor")
	}
	floor := floors.Configs[0]
	labels := floor.Spec.Annotations.Labels
	if floor.Spec.Annotations.Name != floorName || labels[LabelIntentID] != intent.ID || labels[LabelRole] != intent.Role ||
		labels[LabelRegion] != intent.Region || labels[LabelEnvironment] != intent.Environment {
		return errors.New("registry release floor belongs to another service")
	}
	if claim.Role == "function-worker" && labels[labelReleaseArchitecture] != claim.Architecture {
		return errors.New("registry release floor differs from admitted worker architecture")
	}
	migration, err := trust.DecodeEnvelope(floor.Spec.Data)
	if err != nil {
		return err
	}
	if _, err := release.VerifySequenceMigrationHistorical(migration, roots, intent.Role, intent.Environment); err != nil {
		return err
	}
	fingerprint, err := trust.Fingerprint(migration)
	if err != nil || fingerprint != claim.SequenceMigrationSHA256 {
		return errors.New("registry release differs from durable ordering namespace")
	}
	sequence, err := strconv.ParseUint(labels[labelReleaseSequence], 10, 64)
	_, fingerprintErr := hex.DecodeString(labels[labelReleaseFingerprint])
	if err != nil || sequence == 0 || sequence < claim.ReleaseSequence || fingerprintErr != nil || len(labels[labelReleaseFingerprint]) != 64 ||
		strings.ToLower(labels[labelReleaseFingerprint]) != labels[labelReleaseFingerprint] ||
		sequence == claim.ReleaseSequence && labels[labelReleaseFingerprint] != verified.ReleaseIdentity() {
		return errors.New("registry release is not admitted by the durable ordering floor")
	}
	if !verified.Valid(time.Now().UTC()) {
		return errors.New("registry release authorization expired during assignment verification")
	}
	return nil
}
