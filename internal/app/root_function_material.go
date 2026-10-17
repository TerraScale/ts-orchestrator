//go:build linux

package app

import (
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/jetstream"
)

// This admission and both broad signing keys remain inside the root service.
type rootFunctionAdmission struct {
	producer     *rootMaterialAdmission
	call         rootoci.Call
	original     context.Context
	issuer       bootstrapstart.RootFunctionIssuer
	controller   functionController
	credentials  containerMaterialConfig
	lease        *authority.LeaseAdmission
	node         *swarmruntime.Node
	membership   *hostenroll.WorkerMembershipSource
	member       swarmruntime.VerifiedWorkerMembership
	registration host.Registration
	binding      functionmaterial.Binding
	function     release.VerifiedFunction
	account      brokerauth.Claim
	rootChain    jetstream.KeyValueEntry
	accepted     string
	vault        vaultsecret.VaultClient
	target       vaultsecret.Target
	deadline     time.Time
	close        context.CancelFunc
}

func (service *rootWorkloadCredentials) IssueFunctionTaskMaterial(ctx context.Context, call rootoci.Call, request rootoci.FunctionTaskRequest) (rootoci.FunctionTaskMaterialReceipt, error) {
	if service == nil || service.admission == nil || call.Operation() != rootoci.OperationIssueFunctionTaskMaterial {
		return rootoci.FunctionTaskMaterialReceipt{}, rootoci.ErrUnauthorized
	}
	admitted, err := service.admission.function(ctx, call, request.TaskID)
	if err != nil {
		return rootoci.FunctionTaskMaterialReceipt{}, err
	}
	defer admitted.close()
	defer admitted.issuer.Issuer.Wipe()
	ctx = admitted.original
	reader := admitted.controller.config.Material.Reader
	reader.AuthorizeRecipient = func(ctx context.Context, binding functionmaterial.Binding) error {
		if binding != admitted.binding {
			return rootoci.ErrUnauthorized
		}
		return admitted.guard(ctx)
	}
	claim := admitted.function.Claim()
	value, err := reader.IssueRootTaskMaterial(ctx, admitted.issuer.Issuer, admitted.binding, claim.TenantID, claim.FunctionID, admitted.vault, admitted.target)
	if err != nil {
		return rootoci.FunctionTaskMaterialReceipt{}, err
	}
	if err := admitted.guard(ctx); err != nil {
		clear(value)
		return rootoci.FunctionTaskMaterialReceipt{}, err
	}
	return rootoci.FunctionTaskMaterialReceipt{Value: value, ExpiresAt: admitted.deadline}, nil
}

func (service *rootWorkloadCredentials) IssueFunctionObservationIdentity(ctx context.Context, call rootoci.Call, request rootoci.FunctionTaskRequest) (rootoci.FunctionObservationIdentityReceipt, error) {
	if service == nil || service.admission == nil || call.Operation() != rootoci.OperationIssueFunctionObservationIdentity {
		return rootoci.FunctionObservationIdentityReceipt{}, rootoci.ErrUnauthorized
	}
	admitted, err := service.admission.function(ctx, call, request.TaskID)
	if err != nil {
		return rootoci.FunctionObservationIdentityReceipt{}, err
	}
	defer admitted.close()
	defer admitted.issuer.Issuer.Wipe()
	if err := admitted.guard(admitted.original); err != nil {
		return rootoci.FunctionObservationIdentityReceipt{}, err
	}
	cert, key, ca, err := admitted.issuer.Issuer.IssueFunctionClientTLS(admitted.function)
	if err != nil {
		return rootoci.FunctionObservationIdentityReceipt{}, err
	}
	if err := admitted.guard(admitted.original); err != nil {
		clear(key)
		return rootoci.FunctionObservationIdentityReceipt{}, err
	}
	return rootoci.FunctionObservationIdentityReceipt{Certificate: cert, Key: key, CA: ca, ExpiresAt: admitted.deadline}, nil
}

func (producer *rootMaterialAdmission) function(ctx context.Context, call rootoci.Call, taskID string) (_ *rootFunctionAdmission, resultErr error) {
	if os.Geteuid() != 0 || ctx == nil || producer == nil || producer.ownhost == nil || call.Guard(ctx) != nil || len(taskID) != 25 {
		return nil, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer func() {
		if resultErr != nil {
			cancel()
		}
	}()
	controller, _, err := producer.readers(ctx, call)
	if err != nil {
		return nil, err
	}
	config := controller.config
	ctx = config.credentialContext
	producer.ownhost.mu.RLock()
	node, founder, accepted := producer.ownhost.node, producer.ownhost.reader, producer.ownhost.accepted.Clone()
	producer.ownhost.mu.RUnlock()
	if node == nil || founder == nil {
		return nil, rootoci.ErrUnauthorized
	}
	acceptance, err := accepted.AcceptanceSHA256()
	if err != nil {
		return nil, err
	}
	readerAcceptance, err := config.Accepted.AcceptanceSHA256()
	if err != nil || readerAcceptance != acceptance {
		return nil, rootoci.ErrUnauthorized
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return nil, err
	}
	issuer, err := founder.ReadRootFunctionIssuer(ctx, accepted, uid, gid)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			issuer.Issuer.Wipe()
		}
	}()
	lease, err := config.Mutations.AdmitRuntimeLease(ctx, accepted.DeploymentID, call.RuntimeID())
	if err != nil {
		return nil, err
	}
	deadline := earlier(call.Deadline(), earlier(lease.Deadline(), issuer.ExpiresAt()))
	if !config.releaseDeadline.IsZero() {
		deadline = earlier(deadline, config.releaseDeadline)
	}
	ctx, stop := context.WithDeadline(ctx, deadline)
	context.AfterFunc(config.credentialContext, stop)
	rootKV, err := config.JS.KeyValue(ctx, rootChainBucket)
	if err != nil {
		return nil, err
	}
	rootChain, err := rootKV.Get(ctx, rootChainKey)
	if err != nil || rootChain == nil || rootChain.Operation() != jetstream.KeyValuePut {
		return nil, rootoci.ErrUnauthorized
	}
	chain, err := trust.DecodeRootChain(rootChain.Value())
	if err != nil {
		return nil, err
	}
	roots, err := trust.VerifyRootChain(config.Specs.roots.genesis, config.Specs.roots.identity, chain)
	if err != nil || roots.Head != config.Specs.roots.reply("").Head || rootTrustChainCurrent(ctx, config.JS, rootChain) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil || cfg.NATS.Cell != strings.ToLower(accepted.Cell) || producer.factory.Region() != catalog.OCIRegion(accepted.Cell) {
		return nil, rootoci.ErrUnauthorized
	}
	template, err := bootstrap.VerifyBoundRegionalStartupTemplate(ctx, producer.factory, issuer.Startup.GrantWire(), config.Specs.roots.current(), issuer.Anchor, issuer.Startup.Manifest().Cell, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	address, err := template.SlotPrivateIP(accepted.Slot)
	if err != nil || cfg.NATS.URL != "tls://"+address+":4222" {
		return nil, rootoci.ErrUnauthorized
	}
	public, err := functionmaterial.NewStartupPublicTrust(ctx, issuer.Startup, issuer.OperatorJWT, issuer.BrokerCA, cfg.NATS.URL)
	if err != nil {
		return nil, err
	}
	accounts, err := brokerauth.OpenStore(ctx, config.JS, cfg.NATS.Cell, nil)
	if err != nil {
		return nil, err
	}
	management, bundles, err := automaticVaultClients(producer.factory)
	if err != nil {
		return nil, err
	}
	membership, err := hostenroll.OpenWorkerMembershipReader(ctx, config.Mutations, config.Registrations, config.JS, cfg.NATS.Cell, config.ResponsePublic)
	if err != nil {
		return nil, err
	}
	signedTarget := template.VaultTarget()
	admitted := &rootFunctionAdmission{close: cancel, vault: management, target: vaultsecret.Target{VaultID: signedTarget.VaultOCID, CompartmentID: signedTarget.CompartmentOCID, KeyID: signedTarget.KMSKeyOCID}, producer: producer, call: call, original: ctx, issuer: issuer, credentials: config, lease: lease, node: node, membership: membership, rootChain: rootChain, accepted: acceptance, deadline: deadline}
	management.HTTPClient = nativeCanaryDispatcher{next: management.HTTPClient, guard: admitted.sourceGuard}
	bundles.HTTPClient = nativeCanaryDispatcher{next: bundles.HTTPClient, guard: admitted.sourceGuard}
	admitted.controller.config = functionControllerConfig{ReadLease: lease, JS: config.JS, Startup: issuer.Startup, ReadClient: config.Client, Roots: config.Specs.roots, Factory: producer.factory,
		Cell: cfg.NATS.Cell, Environment: accepted.Environment,
		Material: functionmaterial.Controller{Reader: functionmaterial.Reader{Authority: config.Mutations, Artifacts: config.Delivery.Artifacts(), Roots: config.Specs.roots.current,
			Accounts: accounts, Bundles: bundles, VaultID: template.VaultTarget().VaultOCID, Trust: public}},
		Evidence: func(ctx context.Context, digest string) (io.ReadCloser, error) {
			return config.Evidence(ctx, swarmruntime.FunctionWorkerRole, digest)
		}}
	if err := admitted.selectTask(ctx, taskID); err != nil {
		return nil, err
	}
	leafDeadline := admitted.issuer.ExpiresAt()
	if !config.releaseDeadline.IsZero() {
		leafDeadline = earlier(leafDeadline, config.releaseDeadline)
	}
	account, err := jwt.DecodeAccountClaims(admitted.account.JWT)
	if err != nil {
		return nil, rootoci.ErrUnauthorized
	}
	if account.Expires != 0 {
		leafDeadline = earlier(leafDeadline, time.Unix(account.Expires, 0))
	}
	if err := admitted.issuer.Issuer.RestrictExpiry(leafDeadline); err != nil {
		return nil, err
	}
	admitted.deadline = earlier(admitted.deadline, earlier(admitted.member.Info().ExpiresAt, admitted.function.ExpiresAt()))
	ctx, taskStop := context.WithDeadline(ctx, admitted.deadline)
	context.AfterFunc(admitted.original, taskStop)
	admitted.original = ctx
	if err := admitted.guard(ctx); err != nil {
		return nil, err
	}
	return admitted, nil
}

func (admitted *rootFunctionAdmission) selectTask(ctx context.Context, taskID string) error {
	client := admitted.controller.config.ReadClient
	task, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: taskID})
	if err != nil || task == nil || task.Task == nil {
		return rootoci.ErrUnauthorized
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.Task.NodeID})
	if err != nil || node == nil || node.Node == nil {
		return rootoci.ErrUnauthorized
	}
	hosts, err := admitted.credentials.Hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(hosts, func(status host.HostStatus) bool {
		return status.Verified && !status.Retired && status.Registration.ID == node.Node.Spec.Annotations.Name
	})
	if index < 0 {
		return rootoci.ErrUnauthorized
	}
	registration := hosts[index].Registration
	member, err := admitted.node.ReadRootWorkerMembership(ctx, task.Task.NodeID, admitted.membership)
	if err != nil || member.Validate() != nil || member.RegistrationID() != registration.ID || member.Info().Generation != registration.Generation || member.Info().PublicKey != registration.PublicKey || member.Info().NATSUserPublicKey != registration.NATSUserPublicKey || member.Role() != "wasm" || member.Cell() != admitted.controller.config.Cell || member.OCIRegion() != catalog.OCIRegion(strings.ToUpper(member.Cell())) {
		return rootoci.ErrUnauthorized
	}
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task.Task)
	if err != nil {
		return err
	}
	binding := functionmaterial.Binding{TaskID: task.Task.ID, ServiceID: task.Task.ServiceID, NodeID: task.Task.NodeID, InstanceID: member.InstanceID(), Region: member.OCIRegion(), HostID: registration.ID, Fingerprint: fingerprint}
	proof, err := admitted.controller.recipient(ctx, registration, binding)
	if err != nil {
		return err
	}
	account, err := admitted.controller.config.Material.Reader.CurrentAccount(ctx, proof)
	if err != nil {
		return err
	}
	admitted.registration, admitted.member, admitted.binding, admitted.function, admitted.account = registration, member, binding, proof, account
	return nil
}

func (admitted *rootFunctionAdmission) sourceGuard(ctx context.Context) error {
	if admitted == nil || ctx == nil || admitted.original == nil || admitted.original.Err() != nil || ctx.Err() != nil || !time.Now().Before(admitted.deadline) ||
		admitted.call.Guard(ctx) != nil || admitted.credentials.credentialSource == nil || admitted.credentials.credentialSource.Guard(ctx) != nil || admitted.lease.Guard(ctx) != nil ||
		admitted.issuer.Guard(ctx) != nil || rootTrustChainCurrent(ctx, admitted.credentials.JS, admitted.rootChain) != nil {
		return rootoci.ErrUnauthorized
	}
	admitted.producer.ownhost.mu.RLock()
	accepted, node := admitted.producer.ownhost.accepted.Clone(), admitted.producer.ownhost.node
	admitted.producer.ownhost.mu.RUnlock()
	fingerprint, err := accepted.AcceptanceSHA256()
	if err != nil || fingerprint != admitted.accepted || node != admitted.node {
		return rootoci.ErrUnauthorized
	}
	return admitted.call.Guard(ctx)
}

func (admitted *rootFunctionAdmission) guard(ctx context.Context) error {
	if err := admitted.sourceGuard(ctx); err != nil {
		return err
	}
	if admitted.member.Validate() != nil {
		return rootoci.ErrUnauthorized
	}
	proof, err := admitted.controller.recipient(ctx, admitted.registration, admitted.binding)
	if err != nil || proof.EnvelopeSHA256() != admitted.function.EnvelopeSHA256() {
		return rootoci.ErrUnauthorized
	}
	account, err := admitted.controller.config.Material.Reader.CurrentAccount(ctx, proof)
	if err != nil || account.Sequence != admitted.account.Sequence || account.Hash != admitted.account.Hash {
		return rootoci.ErrUnauthorized
	}
	member, err := admitted.node.ReadRootWorkerMembership(ctx, admitted.binding.NodeID, admitted.membership)
	if err != nil || member.Validate() != nil {
		return rootoci.ErrUnauthorized
	}
	before, after := admitted.member.Info(), member.Info()
	before.ObservedAt, before.ExpiresAt, after.ObservedAt, after.ExpiresAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	if before != after {
		return rootoci.ErrUnauthorized
	}
	hosts, err := admitted.credentials.Hosts.ListHosts(ctx)
	if err != nil || !slices.ContainsFunc(hosts, func(status host.HostStatus) bool {
		current := status.Registration
		return status.Verified && !status.Retired && current.ID == admitted.registration.ID && current.Generation == admitted.registration.Generation && current.PublicKey == admitted.registration.PublicKey && current.NATSUserPublicKey == admitted.registration.NATSUserPublicKey
	}) {
		return rootoci.ErrUnauthorized
	}
	return admitted.sourceGuard(ctx)
}
