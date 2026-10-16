package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

// This document authorizes only a worker image pull, before task material exists.
type functionRegistrySnapshot struct {
	Function   release.FunctionClaim   `json:"function"`
	Envelope   []byte                  `json:"envelope"`
	Delegation []byte                  `json:"delegation"`
	Worker     release.ContainerBundle `json:"worker"`
	Chain      trust.RootChain         `json:"root_chain"`
}

func (controller functionController) registryAdmission(ctx context.Context, registration host.Registration, binding host.ContainerMaterialBinding) (host.RegistryAdmissionDocument, error) {
	config := controller.config
	if config.Authority == nil || config.Client == nil || config.Roots == nil || config.Factory == nil || config.Evidence == nil ||
		!entityid.Valid(registration.ID) || registration.ID != binding.HostID || registration.Cell != strings.ToLower(config.Cell) || registration.Environment != config.Environment {
		return host.RegistryAdmissionDocument{}, errors.New("function registry requires current authority and its admitted recipient")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	epoch := config.Authority.Current().Epoch
	if err := config.Authority.Guard(ctx, epoch); err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	response, err := config.Client.GetTask(ctx, &api.GetTaskRequest{TaskID: binding.TaskID})
	if err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	if response == nil || response.Task == nil || response.Task.ID != binding.TaskID || response.Task.ServiceID != binding.ServiceID || response.Task.NodeID != binding.NodeID {
		return host.RegistryAdmissionDocument{}, errors.New("function registry task differs from recipient binding")
	}
	task := response.Task
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil || fingerprint != binding.Fingerprint {
		return host.RegistryAdmissionDocument{}, errors.New("function registry task fingerprint differs from recipient binding")
	}
	node, err := config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	if node == nil || node.Node == nil || node.Node.Spec.Annotations.Name != registration.ID ||
		node.Node.Description == nil || node.Node.Description.Platform == nil ||
		node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != binding.InstanceID || binding.InstanceID == "" ||
		node.Node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != binding.Region {
		return host.RegistryAdmissionDocument{}, errors.New("function registry node differs from admitted host")
	}
	reader := config.Material.Reader
	reader.Authority = config.Authority
	current := functionIntentSource{reader: reader, authority: config.Authority, epoch: epoch}
	labels := task.ServiceAnnotations.Labels
	proof, err := current.CurrentFunction(ctx, labels[swarmruntime.LabelFunctionTenant], labels[swarmruntime.LabelFunctionID])
	if err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	claim := proof.Claim()
	if claim.Cell != strings.ToUpper(config.Cell) || claim.Environment != config.Environment || catalog.OCIRegion(claim.Cell) != binding.Region {
		return host.RegistryAdmissionDocument{}, release.ErrExpectationMismatch
	}
	intent := functionServiceTarget(proof, node.Node.Description.Platform.Architecture)
	bundle, err := intent.WorkerBundleForTask(ctx, config.Client, task)
	if err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	chain := config.Roots.reply("")
	deadline, _ := ctx.Deadline()
	target := release.ContainerTarget{Cell: claim.Cell, Environment: claim.Environment, Role: swarmruntime.FunctionWorkerRole, Architecture: intent.Architecture}
	allocations, err := currentContainerAllocations(ctx, config.Factory, bundle, config.Roots.current(), target)
	if err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	verified, err := release.VerifyContainerCurrent(ctx, bundle, config.Roots.current(), target, time.Now().UTC(), deadline, config.Evidence, allocations)
	if err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	if err := swarmruntime.VerifyFunctionRegistryTask(ctx, config.Client, task, intent, current, verified); err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	if err := config.Authority.Guard(ctx, epoch); err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	if config.Roots.reply("").Head != chain.Head {
		return host.RegistryAdmissionDocument{}, errors.New("function registry roots changed during assignment verification")
	}
	wire, err := protocol.EncodeJSON(functionRegistrySnapshot{Function: claim, Envelope: proof.Envelope(), Delegation: proof.Delegation(), Worker: bundle, Chain: chain.Chain})
	if err != nil || len(wire) > runtimeRegistrySourceBytes {
		return host.RegistryAdmissionDocument{}, errors.New("function registry source is oversized")
	}
	expires := time.Now().UTC().Add(2 * time.Minute)
	for _, limit := range []time.Time{proof.ExpiresAt(), verified.ExpiresAt()} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	return host.RegistryAdmissionDocument{Document: wire, ExpiresAt: expires}, nil
}

func functionRuntimeRegistryResolver(ctx context.Context, cfg Config, agent *host.Agent, accepted hostenroll.VerifiedSwarmWorker) (swarmruntime.RegistryResolver, error) {
	signed := accepted.Worker()
	if os.Geteuid() != 0 || agent == nil || signed.Role != "wasm" || len(accepted.Wire()) == 0 || signed.Validate(time.Now().UTC()) != nil {
		return nil, errors.New("function registry requires current signed wasm enrollment and live host agent")
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	if local.instanceID != signed.InstanceID || local.factory.Region() != signed.OCIRegion ||
		local.baked.Identity.DeploymentID != signed.DeploymentID || local.baked.Identity.Environment != signed.Environment ||
		!strings.EqualFold(string(local.baked.Identity.Cell), signed.Cell) || cfg.NATS.Cell != strings.ToLower(signed.Cell) {
		return nil, errors.New("function registry worker differs from root-owned OCI identity")
	}
	roots, err := newRootRegistry(local.baked.Genesis, local.baked.Identity.ChainIdentity(), local.baked.Chain, bootstrapstart.RootChainFile)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	return swarmruntime.NewOCIRegistryResolver(local.factory, func(ctx context.Context, task *api.Task) (*swarmruntime.RegistryAdmission, error) {
		mu.Lock()
		defer mu.Unlock()
		if task == nil || signed.Validate(time.Now().UTC()) != nil {
			return nil, errors.New("function registry requires a current enrolled recipient and task")
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
		if err != nil {
			return nil, err
		}
		binding := host.ContainerMaterialBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID,
			InstanceID: signed.InstanceID, Region: signed.OCIRegion, HostID: signed.RegistrationID, Fingerprint: fingerprint}
		document, err := agent.CurrentRegistryAdmission(ctx, binding)
		if err != nil {
			return nil, err
		}
		var snapshot functionRegistrySnapshot
		if err := protocol.DecodeStrict(document.Document, &snapshot, runtimeRegistrySourceBytes); err != nil {
			return nil, err
		}
		if err := roots.adopt(snapshot.Chain); err != nil {
			return nil, err
		}
		claim := snapshot.Function
		if claim.Validate() != nil || claim.Cell != strings.ToUpper(signed.Cell) || claim.Environment != signed.Environment || catalog.OCIRegion(claim.Cell) != signed.OCIRegion {
			return nil, release.ErrExpectationMismatch
		}
		receipt, err := release.VerifyFunctionReceiptCurrent(snapshot.Envelope, snapshot.Delegation, roots.current(), release.FunctionExpectation{
			Cell: strings.ToUpper(signed.Cell), Environment: signed.Environment, TenantID: claim.TenantID, FunctionID: claim.FunctionID,
			Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: claim.Sequence,
		}, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		claim = receipt.Claim()
		expected := swarmruntime.ServiceIntent{ID: entityid.Derive("function-service", signed.Environment, signed.OCIRegion, claim.TenantID, claim.FunctionID), Region: signed.OCIRegion, Environment: signed.Environment}
		for key, value := range map[string]string{
			swarmruntime.LabelIntentID: expected.ID, swarmruntime.LabelRole: swarmruntime.FunctionWorkerRole,
			swarmruntime.LabelRegion: signed.OCIRegion, swarmruntime.LabelEnvironment: signed.Environment,
			swarmruntime.LabelFunctionTenant: claim.TenantID, swarmruntime.LabelFunctionID: claim.FunctionID,
			swarmruntime.LabelFunctionRevision: claim.Revision, swarmruntime.LabelFunctionDigest: claim.Digest,
			swarmruntime.LabelFunctionProof: receipt.EnvelopeSHA256(), swarmruntime.LabelFunctionSequence: strconv.FormatUint(claim.Sequence, 10),
		} {
			if task.ServiceAnnotations.Labels[key] != value {
				return nil, errors.New("function registry task differs from current signed function receipt")
			}
		}
		location, err := instancePrincipalChannel(signed.OCIRegion, strings.ToUpper(signed.Cell)).get(ctx)
		if err != nil {
			return nil, err
		}
		deadline, _ := ctx.Deadline()
		target := release.ContainerTarget{
			Cell: strings.ToUpper(signed.Cell), Environment: signed.Environment, Role: swarmruntime.FunctionWorkerRole, Architecture: signed.Architecture,
		}
		allocations, err := currentContainerAllocations(ctx, local.factory, snapshot.Worker, roots.current(), target)
		if err != nil {
			return nil, err
		}
		verified, err := release.VerifyContainerCurrent(ctx, snapshot.Worker, roots.current(), target, time.Now().UTC(), deadline, func(ctx context.Context, digest string) (io.ReadCloser, error) {
			return releasechannel.ReadContainerEvidence(ctx, location, swarmruntime.FunctionWorkerRole, digest)
		}, allocations)
		if err != nil {
			return nil, err
		}
		spec, err := swarmruntime.DecodeContainer(task)
		if err != nil || spec.Image != verified.Claim().Image || task.ServiceAnnotations.Labels[swarmruntime.LabelFunctionWorkerBundle] != verified.BundleSHA256() {
			return nil, errors.New("function registry task differs from independently qualified worker image")
		}
		admission, err := runtimeRegistryPullAdmission(ctx, local.factory, task, expected, verified, roots)
		if err != nil {
			return nil, err
		}
		confirmed, err := agent.CurrentRegistryAdmission(ctx, binding)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(document.Document, confirmed.Document) || !time.Now().Before(document.ExpiresAt) || !time.Now().Before(confirmed.ExpiresAt) ||
			!receipt.Valid() || !verified.Valid(time.Now().UTC()) || signed.Validate(time.Now().UTC()) != nil {
			return nil, errors.New("function registry authority changed during credential admission")
		}
		return admission, nil
	})
}
