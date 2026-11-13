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
		ctx, stopEnrollment := context.WithDeadline(ctx, signed.ExpiresAt)
		defer stopEnrollment()
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
		ctx, stopDocument := context.WithDeadline(ctx, document.ExpiresAt)
		defer stopDocument()
		var snapshot functionRegistrySnapshot
		if err := protocol.DecodeStrict(document.Document, &snapshot, runtimeRegistrySourceBytes); err != nil {
			return nil, err
		}
		if err := roots.adopt(snapshot.Chain); err != nil {
			return nil, err
		}
		rootHead := roots.reply("").Head
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
		ctx, stopFunction := context.WithDeadline(ctx, receipt.ExpiresAt())
		defer stopFunction()
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
		ctx, stopWorker := context.WithDeadline(ctx, verified.ExpiresAt())
		defer stopWorker()
		spec, err := swarmruntime.DecodeContainer(task)
		if err != nil || spec.Image != verified.Claim().Image || task.ServiceAnnotations.Labels[swarmruntime.LabelFunctionWorkerBundle] != verified.BundleSHA256() {
			return nil, errors.New("function registry task differs from independently qualified worker image")
		}
		admission, err := runtimeRegistryPullAdmission(ctx, local.factory, task, expected, verified, roots)
		if err != nil {
			return nil, err
		}
		ctx, stopIssuer := context.WithDeadline(ctx, admission.Deadline)
		defer stopIssuer()
		issuerGuard := admission.VerifyCurrent
		confirmed, err := agent.CurrentRegistryAdmission(ctx, binding)
		if err != nil {
			return nil, err
		}
		ctx, stopConfirmed := context.WithDeadline(ctx, confirmed.ExpiresAt)
		defer stopConfirmed()
		if !bytes.Equal(document.Document, confirmed.Document) || !time.Now().Before(document.ExpiresAt) || !time.Now().Before(confirmed.ExpiresAt) ||
			!receipt.Valid() || !verified.Valid(time.Now().UTC()) || signed.Validate(time.Now().UTC()) != nil {
			return nil, errors.New("function registry authority changed during credential admission")
		}
		admissionDeadline, _ := ctx.Deadline()
		admission.Deadline = admissionDeadline
		admission.VerifyCurrent = func(ctx context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			if !time.Now().Before(admissionDeadline) {
				return errors.New("function registry original admission expired before Vault credential read")
			}
			if err := issuerGuard(ctx); err != nil {
				return err
			}
			current, err := agent.CurrentRegistryAdmission(ctx, binding)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			if !bytes.Equal(document.Document, current.Document) || !now.Before(admissionDeadline) || !now.Before(document.ExpiresAt) ||
				!now.Before(confirmed.ExpiresAt) || !now.Before(current.ExpiresAt) || !receipt.Valid() || !verified.Valid(now) ||
				signed.Validate(now) != nil || roots.reply("").Head != rootHead {
				return errors.New("function registry authority changed during Vault credential read")
			}
			return ctx.Err()
		}
		return admission, nil
	})
}
