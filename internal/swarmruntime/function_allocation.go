package swarmruntime

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
)

// VerifyFunctionTaskAllocation observes reserved resources only. Callers must
// independently verify current finite worker membership and OCI qualification;
// success grants no image pull, material, credential or execution authority.
func VerifyFunctionTaskAllocation(ctx context.Context, client api.ControlClient, task *api.Task, intent FunctionServiceIntent, current CurrentFunctionIntent, worker release.VerifiedContainer) error {
	if client == nil || current == nil || task == nil || task.ID == "" || task.ServiceID == "" || task.NodeID == "" || !functionAllocationState(task.Status.State) {
		return errors.New("function allocation requires an exact nonterminal manager assignment")
	}
	function, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return err
	}
	expected, err := intent.serviceSpec(function, worker)
	if err != nil {
		return err
	}
	ctx, cancelFunction := context.WithDeadline(ctx, function.ExpiresAt())
	defer cancelFunction()
	ctx, cancelWorker := context.WithDeadline(ctx, worker.ExpiresAt())
	defer cancelWorker()
	assignment, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
	if err != nil {
		return err
	}
	if assignment == nil || !proto.Equal(assignment.Task, task) {
		return errors.New("function allocation differs from the exact manager task")
	}
	service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
	if err != nil {
		return err
	}
	if service == nil || service.Service == nil || service.Service.ID != task.ServiceID ||
		(!proto.Equal(&service.Service.Spec, expected) && !proto.Equal(service.Service.PreviousSpec, expected)) ||
		!proto.Equal(&task.Spec, &expected.Task) || !proto.Equal(&task.ServiceAnnotations, &expected.Annotations) {
		return errors.New("function allocation lacks an exact signed current or previous recipe")
	}
	if _, err := DecodeContainer(task); err != nil {
		return err
	}
	if _, err := ContainerTaskFingerprint(task); err != nil {
		return err
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		return err
	}
	if node == nil || node.Node == nil || node.Node.ID != task.NodeID {
		return errors.New("function allocation recipient is unavailable")
	}
	if err := verifyFunctionAllocationRecipient(node.Node, intent); err != nil {
		return err
	}
	// A superseding image does not release an existing task's reservation.
	if err := intent.verifyRetainedWorkerFloor(ctx, client, worker); err != nil {
		return err
	}
	latest, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return err
	}
	if !latest.Valid() || latest.EnvelopeSHA256() != function.EnvelopeSHA256() || !worker.Valid(time.Now().UTC()) {
		return errors.New("function allocation signed authority changed during observation")
	}
	confirmedTask, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
	if err != nil {
		return err
	}
	confirmedService, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
	if err != nil {
		return err
	}
	confirmedNode, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		return err
	}
	if confirmedTask == nil || confirmedService == nil || confirmedNode == nil ||
		!proto.Equal(confirmedTask.Task, assignment.Task) || !proto.Equal(confirmedService.Service, service.Service) || !proto.Equal(confirmedNode.Node, node.Node) {
		return errors.New("function allocation manager state changed during observation")
	}
	if err := verifyFunctionAllocationRecipient(confirmedNode.Node, intent); err != nil {
		return err
	}
	if err := intent.verifyRetainedWorkerFloor(ctx, client, worker); err != nil {
		return err
	}
	if !function.Valid() || !latest.Valid() || !worker.Valid(time.Now().UTC()) {
		return errors.New("function allocation signed authority expired during observation")
	}
	return ctx.Err()
}

func functionAllocationState(state api.TaskState) bool {
	switch state {
	case api.TaskStateNew, api.TaskStatePending, api.TaskStateAssigned, api.TaskStateAccepted,
		api.TaskStatePreparing, api.TaskStateReady, api.TaskStateStarting, api.TaskStateRunning:
		return true
	default:
		return false
	}
}

func verifyFunctionAllocationRecipient(node *api.Node, intent FunctionServiceIntent) error {
	if node == nil || node.Spec.Membership != api.NodeMembershipAccepted || node.Role != api.NodeRoleWorker ||
		node.Certificate.Role != api.NodeRoleWorker || node.Certificate.CN != node.ID || node.Certificate.Status.State != api.IssuanceStateIssued ||
		!entityid.Valid(node.Spec.Annotations.Name) || node.Description == nil || node.Description.Hostname != node.Spec.Annotations.Name ||
		node.Description.Platform == nil || node.Description.Platform.OS != "linux" || node.Description.Platform.Architecture != intent.Architecture {
		return errors.New("function allocation recipient differs from the enrolled worker identity")
	}
	for key, value := range map[string]string{LabelRegion: intent.Region, LabelExecutionScope: "tenant", LabelHostRole: "wasm"} {
		if node.Spec.Annotations.Labels[key] != value {
			return errors.New("function allocation recipient differs from the signed placement")
		}
	}
	if node.Spec.Annotations.Labels[LabelInstanceID] == "" {
		return errors.New("function allocation recipient lacks its OCI instance")
	}
	block, _ := pem.Decode(node.Certificate.Certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("function allocation recipient certificate is unavailable")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	now := time.Now().UTC()
	if err != nil || certificate.Subject.CommonName != node.ID || !slices.Equal(certificate.Subject.OrganizationalUnit, []string{ca.WorkerRole}) ||
		now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("function allocation certificate does not identify the enrolled worker")
	}
	return nil
}
