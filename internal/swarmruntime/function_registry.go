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
	_, err := AdmitFunctionRegistryTask(ctx, client, task, intent, current, worker)
	return err
}

// FunctionRegistryTaskAdmission retains the exact manager observations checked
// against the current function and durable worker floor.
type FunctionRegistryTaskAdmission struct {
	client   api.ControlClient
	task     *api.Task
	service  *api.Service
	node     *api.Node
	intent   FunctionServiceIntent
	function release.VerifiedFunction
	worker   release.VerifiedContainer
}

// AdmitFunctionRegistryTask returns a receipt callers must recheck after any
// subsequent authority waits, immediately before delivering registry admission.
func AdmitFunctionRegistryTask(ctx context.Context, client api.ControlClient, task *api.Task, intent FunctionServiceIntent, current CurrentFunctionIntent, worker release.VerifiedContainer) (*FunctionRegistryTaskAdmission, error) {
	if client == nil || current == nil || task == nil || task.ID == "" || task.ServiceID == "" || task.NodeID == "" || task.DesiredState != api.TaskStateRunning {
		return nil, errors.New("function registry requires current authority and an assigned task")
	}
	function, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return nil, err
	}
	assignment, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
	if err != nil {
		return nil, err
	}
	if assignment == nil || assignment.Task == nil || assignment.Task.ID != task.ID || assignment.Task.NodeID != task.NodeID || assignment.Task.ServiceID != task.ServiceID || assignment.Task.DesiredState != api.TaskStateRunning || assignment.Task.Status.State < api.TaskStateAssigned || assignment.Task.Status.State > api.TaskStateRunning || !proto.Equal(&assignment.Task.Spec, &task.Spec) || !proto.Equal(&assignment.Task.ServiceAnnotations, &task.ServiceAnnotations) {
		return nil, errors.New("function registry task differs from the manager assignment")
	}
	wantedFingerprint, err := ContainerTaskFingerprint(task)
	if err != nil {
		return nil, err
	}
	actualFingerprint, err := ContainerTaskFingerprint(assignment.Task)
	if err != nil || actualFingerprint != wantedFingerprint {
		return nil, errors.New("function registry task fingerprint differs from the manager assignment")
	}
	service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
	if err != nil {
		return nil, err
	}
	if service == nil || service.Service == nil || service.Service.ID != task.ServiceID || service.Service.PendingDelete {
		return nil, errors.New("function registry requires an available current service")
	}
	previous := false
	if err := intent.VerifyTask(assignment.Task, service.Service, function, worker); err != nil {
		if service.Service.PreviousSpec == nil {
			return nil, err
		}
		selected := service.Service.Copy()
		selected.Spec = *selected.PreviousSpec.Copy()
		if err := intent.VerifyTask(assignment.Task, selected, function, worker); err != nil {
			return nil, err
		}
		previous = true
	}
	rollback := !previous && functionServiceRollback(service.Service)

	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		return nil, err
	}
	if node == nil || node.Node == nil || node.Node.ID != task.NodeID {
		return nil, errors.New("function registry recipient node is unavailable")
	}
	if err := verifyFunctionRegistryRecipient(node.Node, intent); err != nil {
		return nil, err
	}
	admission := &FunctionRegistryTaskAdmission{client: client, task: assignment.Task.Copy(), service: service.Service.Copy(), node: node.Node.Copy(), intent: intent, function: function, worker: worker}
	if previous || rollback {
		if err := intent.verifyRetainedWorkerFloor(ctx, client, worker); err != nil {
			return nil, err
		}
	} else if err := intent.VerifyWorkerFloor(ctx, client, worker); err != nil {
		return nil, err
	}
	latest, err := current.CurrentFunction(ctx, intent.TenantID, intent.FunctionID)
	if err != nil {
		return nil, err
	}
	if !latest.Valid() || latest.EnvelopeSHA256() != function.EnvelopeSHA256() {
		return nil, errors.New("function registry authority changed during assignment verification")
	}
	if err := admission.VerifyCurrent(ctx); err != nil {
		return nil, err
	}
	return admission, nil
}

// VerifyCurrent rereads manager state without repeating source, floor or OCI
// verification. Exact service equality preserves the admitted PreviousSpec path.
func (admission *FunctionRegistryTaskAdmission) VerifyCurrent(ctx context.Context) error {
	if admission == nil || admission.client == nil || admission.task == nil || admission.service == nil || admission.node == nil {
		return errors.New("function registry admission is unavailable")
	}
	service, err := admission.client.GetService(ctx, &api.GetServiceRequest{ServiceID: admission.service.ID})
	if err != nil {
		return err
	}
	if service == nil || !proto.Equal(service.Service, admission.service) {
		return errors.New("function registry service changed during admission")
	}
	node, err := admission.client.GetNode(ctx, &api.GetNodeRequest{NodeID: admission.node.ID})
	if err != nil {
		return err
	}
	if node == nil || !proto.Equal(node.Node, admission.node) {
		return errors.New("function registry recipient changed during admission")
	}
	task, err := admission.client.GetTask(ctx, &api.GetTaskRequest{TaskID: admission.task.ID})
	if err != nil {
		return err
	}
	if task == nil || !proto.Equal(task.Task, admission.task) {
		return errors.New("function registry task changed during admission")
	}
	if err := verifyFunctionRegistryRecipient(node.Node, admission.intent); err != nil {
		return err
	}
	if !admission.function.Valid() || !admission.worker.Valid(time.Now().UTC()) {
		return errors.New("function registry authority expired during admission")
	}
	return ctx.Err()
}

func verifyFunctionRegistryRecipient(recipient *api.Node, intent FunctionServiceIntent) error {
	if recipient == nil {
		return errors.New("function registry recipient node is unavailable")
	}
	if recipient.Spec.Membership != api.NodeMembershipAccepted || recipient.Spec.Availability != api.NodeAvailabilityActive || recipient.Status.State != api.NodeStatus_READY || recipient.Role != api.NodeRoleWorker || recipient.Certificate.Role != api.NodeRoleWorker || recipient.Certificate.CN != recipient.ID || recipient.Certificate.Status.State != api.IssuanceStateIssued || !entityid.Valid(recipient.Spec.Annotations.Name) || recipient.Description == nil || recipient.Description.Hostname != recipient.Spec.Annotations.Name || recipient.Description.Platform == nil || recipient.Description.Platform.OS != "linux" || recipient.Description.Platform.Architecture != intent.Architecture {
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
	return nil
}
