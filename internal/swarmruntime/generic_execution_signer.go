package swarmruntime

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

// SignGenericExecution is used only beside the actual root-owned manager.
// The ROOT operation independently derives host, lease and protected pool source;
// beforeSign rechecks those retained sources at key use and before delivery;
// this helper never exposes the private key or replaces those admission checks.
func (n *Node) SignGenericExecution(ctx context.Context, h drainwire.ExecutionHold, beforeSign func(context.Context) error) (drainwire.SignedHold, error) {
	var empty drainwire.SignedHold
	if os.Geteuid() != 0 || n == nil || n.upstream == nil || n.role != "manager" || ctx == nil || beforeSign == nil || h.Validate() != nil || h.IssuedAt.After(time.Now().UTC()) {
		return empty, ErrGenericExecutionPending
	}
	ctx, cancel := context.WithDeadline(ctx, h.ExpiresAt)
	defer cancel()
	deadline, _ := ctx.Deadline()
	control, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return empty, err
	}
	if err := VerifyGenericExecutionAssignment(ctx, control, h); err != nil {
		return empty, err
	}
	cluster, err := control.ClusterIdentity(ctx)
	if err != nil {
		return empty, err
	}
	key, chain, err := n.nodeSigningKey()
	if err != nil {
		return empty, err
	}
	wire, err := drainwire.HoldSigningBytes(h)
	if err != nil {
		return empty, err
	}
	digest := sha256.Sum256(wire)
	if err := beforeSign(ctx); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if !time.Now().Before(deadline) {
		return empty, context.DeadlineExceeded
	}
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return empty, err
	}
	signed := drainwire.SignedHold{Hold: h, CertificateChain: chain, Signature: signature}
	if err := verifyGenericExecutionManager(ctx, control, signed, cluster.ID, cluster.RootCACert); err != nil {
		return empty, err
	}
	if err := beforeSign(ctx); err != nil {
		return empty, err
	}
	if !time.Now().Before(deadline) {
		return empty, context.DeadlineExceeded
	}
	return signed, ctx.Err()
}

// VerifyGenericExecutionAssignment independently reads the actual manager task
// and accepted worker. It does not authenticate a host session or grant a hold.
func VerifyGenericExecutionAssignment(ctx context.Context, control api.ControlReader, h drainwire.ExecutionHold) error {
	if ctx == nil || control == nil || h.Validate() != nil {
		return ErrGenericExecutionPending
	}
	return verifyGenericExecutionAssignment(ctx, control, h)
}

func verifyGenericExecutionAssignment(ctx context.Context, control api.ControlReader, h drainwire.ExecutionHold) error {
	got, err := control.GetTask(ctx, &api.GetTaskRequest{TaskID: h.TaskID})
	if err != nil || got == nil || got.Task == nil {
		return errors.Join(errors.New("generic execution actual task unavailable"), err)
	}
	task := got.Task
	actual, err := executionwire.TaskSHA256(task)
	if err != nil || actual != h.TaskSHA256 || task.ID != h.TaskID || task.NodeID != h.NodeID || task.ServiceID != h.ServiceID ||
		task.DesiredState != api.TaskStateRunning || task.Status.State < api.TaskStateAssigned || task.Status.State > api.TaskStateRunning {
		return errors.New("generic execution task differs from current manager assignment")
	}
	fingerprint, err := ContainerTaskFingerprint(task)
	if err != nil || fingerprint != h.ExecutionSHA256 {
		return errors.Join(errors.New("generic execution task fingerprint changed"), err)
	}
	node, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil || node == nil || node.Node == nil {
		return errors.Join(errors.New("generic execution actual node unavailable"), err)
	}
	n := node.Node
	role, scope := "container", "platform"
	if task.ServiceAnnotations.Labels[LabelRole] == FunctionWorkerRole {
		role, scope = "wasm", "tenant"
	}
	labels := n.Spec.Annotations.Labels
	if n.ID != task.NodeID || n.Spec.Annotations.Name != h.RegistrationID || n.Role != api.NodeRoleWorker || n.Spec.DesiredRole != api.NodeRoleWorker ||
		n.Spec.Membership != api.NodeMembershipAccepted || n.Spec.Availability != api.NodeAvailabilityActive ||
		labels[LabelInstanceID] == "" || h.InstanceID != "" && labels[LabelInstanceID] != h.InstanceID || labels[LabelHostRole] != role || labels[LabelExecutionScope] != scope ||
		n.Certificate.CN != n.ID || n.Certificate.Role != api.NodeRoleWorker || len(n.Certificate.Certificate) == 0 {
		return errors.New("generic execution requires exact admitted ACTIVE worker")
	}
	return ctx.Err()
}

func verifyGenericExecutionManager(ctx context.Context, control api.ControlReader, signed drainwire.SignedHold, clusterID string, clusterCA []byte) error {
	if len(signed.CertificateChain) == 0 {
		return ErrGenericExecutionPending
	}
	leaf, err := x509.ParseCertificate(signed.CertificateChain[0])
	if err != nil {
		return err
	}
	node, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: leaf.Subject.CommonName})
	if err != nil || node == nil || node.Node == nil {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	n := node.Node
	if n.ID != leaf.Subject.CommonName || n.Role != api.NodeRoleManager || n.Spec.DesiredRole != api.NodeRoleManager ||
		n.Spec.Membership != api.NodeMembershipAccepted || n.Certificate.CN != n.ID || n.Certificate.Role != api.NodeRoleManager {
		return errors.New("generic execution signer is not the actual accepted manager")
	}
	if err := drainwire.VerifySignedHold(signed, n.Certificate.Certificate, clusterCA, clusterID, time.Now().UTC()); err != nil {
		return err
	}
	return ctx.Err()
}
