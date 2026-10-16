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

// VerifyFunctionRegistryTask authorizes only the qualified worker image pull.
// PreviousSpec or the manager's current rollback recipe may retain a qualified
// worker image; this does not authorize stale function material or task startup.
func VerifyFunctionRegistryTask(ctx context.Context, client api.ControlClient, task *api.Task, intent FunctionServiceIntent, current CurrentFunctionIntent, worker release.VerifiedContainer) error {
	if client == nil || current == nil || task == nil || task.ID == "" || task.ServiceID == "" || task.NodeID == "" || task.DesiredState != api.TaskStateRunning {
		return errors.New("function registry requires current authority and an assigned task")
	}
	function, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return err
	}
	assignment, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
	if err != nil {
		return err
	}
	if assignment == nil || assignment.Task == nil || assignment.Task.ID != task.ID || assignment.Task.NodeID != task.NodeID || assignment.Task.ServiceID != task.ServiceID || assignment.Task.Status.State < api.TaskStateAssigned || assignment.Task.Status.State > api.TaskStateRunning || !proto.Equal(&assignment.Task.Spec, &task.Spec) || !proto.Equal(&assignment.Task.ServiceAnnotations, &task.ServiceAnnotations) {
		return errors.New("function registry task differs from the manager assignment")
	}
	wantedFingerprint, err := ContainerTaskFingerprint(task)
	if err != nil {
		return err
	}
	actualFingerprint, err := ContainerTaskFingerprint(assignment.Task)
	if err != nil || actualFingerprint != wantedFingerprint {
		return errors.New("function registry task fingerprint differs from the manager assignment")
	}
	service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
	if err != nil {
		return err
	}
	if service == nil || service.Service == nil || service.Service.ID != task.ServiceID || service.Service.PendingDelete {
		return errors.New("function registry requires an available current service")
	}
	previous := false
	if err := intent.VerifyTask(assignment.Task, service.Service, function, worker); err != nil {
		if service.Service.PreviousSpec == nil {
			return err
		}
		selected := service.Service.Copy()
		selected.Spec = *selected.PreviousSpec.Copy()
		if err := intent.VerifyTask(assignment.Task, selected, function, worker); err != nil {
			return err
		}
		previous = true
	}
	rollback := !previous && functionServiceRollback(service.Service)

	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		return err
	}
	if node == nil || node.Node == nil {
		return errors.New("function registry recipient node is unavailable")
	}
	recipient := node.Node
	if recipient.ID != task.NodeID || recipient.Spec.Membership != api.NodeMembershipAccepted || recipient.Spec.Availability != api.NodeAvailabilityActive || recipient.Status.State != api.NodeStatus_READY || recipient.Role != api.NodeRoleWorker || recipient.Certificate.Role != api.NodeRoleWorker || recipient.Certificate.CN != recipient.ID || recipient.Certificate.Status.State != api.IssuanceStateIssued || !entityid.Valid(recipient.Spec.Annotations.Name) || recipient.Description == nil || recipient.Description.Hostname != recipient.Spec.Annotations.Name || recipient.Description.Platform == nil || recipient.Description.Platform.OS != "linux" || recipient.Description.Platform.Architecture != intent.Architecture {
		return errors.New("function registry recipient differs from the admitted worker identity")
	}
	for key, value := range map[string]string{LabelRegion: intent.Region, LabelExecutionScope: "tenant", LabelHostRole: "wasm"} {
		if recipient.Spec.Annotations.Labels[key] != value {
			return errors.New("function registry recipient differs from the admitted worker placement")
		}
	}
	if recipient.Spec.Annotations.Labels[LabelInstanceID] == "" {
		return errors.New("function registry recipient has no admitted OCI instance")
	}
	block, _ := pem.Decode(recipient.Certificate.Certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("function registry recipient certificate is unavailable")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	now := time.Now().UTC()
	if err != nil || certificate.Subject.CommonName != recipient.ID || !slices.Equal(certificate.Subject.OrganizationalUnit, []string{ca.WorkerRole}) || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("function registry recipient certificate does not authorize this worker")
	}
	if previous || rollback {
		if err := intent.verifyRetainedWorkerFloor(ctx, client, worker); err != nil {
			return err
		}
	} else if err := intent.VerifyWorkerFloor(ctx, client, worker); err != nil {
		return err
	}
	latest, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return err
	}
	if !latest.Valid() || latest.EnvelopeSHA256() != function.EnvelopeSHA256() || !worker.Valid(time.Now().UTC()) {
		return errors.New("function registry authority changed during assignment verification")
	}
	return ctx.Err()
}
