package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

type CreateNodeProviderRequest struct {
	Context              ProviderOperationContext
	Parameters           CreateNodeProviderParameters
	Binding              CreateNodeReceiptBinding
	Receipt              CreateNodeHandoffReceipt
	RecoveryAuthority    CreateNodeRecoveryLookupAuthority
	InvocationCapability *CreateNodeAuthoritativeInvocationCapability
}
type CreateNodeProviderResponse struct {
	NodeId        ProviderResourceId
	WorkRequestId ProviderWorkRequestId
}
type CreateNodeReconciliationProof struct {
	Algorithm, KeyId string
	Binding          CreateNodeReceiptBinding
	NodeId           ProviderResourceId
	WorkRequestId    ProviderWorkRequestId
	Signature        string
}

func (p CreateNodeReconciliationProof) payload() []byte {
	return []byte(canonical("create-node-provider-proof-v2", p.Algorithm, p.KeyId, p.Binding.Digest(), p.NodeId.Value, p.WorkRequestId.Value))
}

type CreateNodeProviderProofSigner struct {
	key   *ecdsa.PrivateKey
	KeyId string
}

func NewCreateNodeProviderProofSigner(id string, key *ecdsa.PrivateKey) (*CreateNodeProviderProofSigner, error) {
	if strings.TrimSpace(id) == "" || key == nil || key.Curve != elliptic.P256() {
		return nil, &errs.Argument{Message: "provider proof signer requires P-256"}
	}
	return &CreateNodeProviderProofSigner{key, id}, nil
}
func (s *CreateNodeProviderProofSigner) Sign(binding CreateNodeReceiptBinding, response CreateNodeProviderResponse) (CreateNodeReconciliationProof, error) {
	p := CreateNodeReconciliationProof{ReceiptAlgorithm, s.KeyId, binding, response.NodeId, response.WorkRequestId, ""}
	h := sha256.Sum256(p.payload())
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return p, err
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return p, nil
}
func VerifyCreateNodeProviderProof(p CreateNodeReconciliationProof, resolver ReceiptKeyResolver, expected CreateNodeReceiptBinding) bool {
	if p.Algorithm != ReceiptAlgorithm || p.Binding != expected || p.Binding.Digest() != expected.Digest() {
		return false
	}
	return verifyPayload(p.KeyId, p.Algorithm, p.payload(), p.Signature, resolver)
}

type CreateNodeReconciliationStatus int

const (
	CreateNodeFound CreateNodeReconciliationStatus = iota + 1
	CreateNodeNotFound
	CreateNodeUnknown
)

type CreateNodeReconciliation struct {
	Status   CreateNodeReconciliationStatus
	Response *CreateNodeProviderResponse
	Proof    *CreateNodeReconciliationProof
}
type CreateNodeProvider interface {
	CreateNode(context.Context, CreateNodeProviderRequest) (CreateNodeProviderResponse, error)
	ReconcileCreateNode(context.Context, CreateNodeProviderRequest) (CreateNodeReconciliation, error)
}

// OciNodeLaunchSpec is the provider-bound result of resolving an admitted
// template and placement. No environment, credential, or implicit default is
// consulted by the provider; all launch material must be injected here.
type OciNodeLaunchSpec struct {
	CompartmentId, AvailabilityDomain, FaultDomain, SubnetId, ImageId string
	Shape                                                             string
	NetworkSecurityGroupIds                                           []string
	Ocpus, MemoryGB                                                   float64
	BootstrapBase64                                                   string
}

// OciNodeLaunchResolver is the explicit seam between opaque domain template /
// placement identities and OCI launch details.
type OciNodeLaunchResolver interface {
	Resolve(context.Context, ProviderTemplateId, ProviderPlacementId, ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error)
}

type OciNodeLaunchResolverFunc func(context.Context, ProviderTemplateId, ProviderPlacementId, ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error)

func (f OciNodeLaunchResolverFunc) Resolve(ctx context.Context, template ProviderTemplateId, placement ProviderPlacementId, digest ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error) {
	if f == nil {
		return OciNodeLaunchSpec{}, &InvalidOperationError{Message: "OCI node launch resolver is unavailable"}
	}
	return f(ctx, template, placement, digest)
}

// Compatibility aliases keep the provider-neutral wording available to
// integrations that call the resolved object a launch configuration.
type OciNodeLaunchConfiguration = OciNodeLaunchSpec
type OciNodeLaunchConfigurationResolver = OciNodeLaunchResolver

// CreateNodeJournal is the narrow durability seam needed by an external
// mutation provider. Implementations must atomically consume a capability.
type CreateNodeJournal interface {
	AuthoritativeDurable() bool
	ConsumeInvocationCapability(context.Context, CreateNodeAuthoritativeInvocationCapability, CreateNodeReceiptBinding, string, time.Time) error
	InvocationCapabilityConsumption(context.Context, CreateNodeAuthoritativeInvocationCapability, CreateNodeReceiptBinding) (CreateNodeInvocationConsumption, bool, error)
}

// CreateNodeInvocationConsumption is the durable authority for replaying one
// provider request after a controller restart. ProviderRequestDigest binds the
// exact authority, service, region, method, path, compartment, body, and
// caller-supplied retry token.
type CreateNodeInvocationConsumption struct {
	ConsumedAt            time.Time
	ProviderRequestDigest string
}
type DeterministicCreateNodeProvider struct {
	keys, recoveryKeys ReceiptKeyResolver
	proofSigner        *CreateNodeProviderProofSigner
	clock              func() time.Time
	mu                 sync.Mutex
	results            map[string]CreateNodeProviderResponse
	CreateCallCount    int
}

func NewDeterministicCreateNodeProvider(keys, recovery ReceiptKeyResolver, signer *CreateNodeProviderProofSigner, clock func() time.Time) (*DeterministicCreateNodeProvider, error) {
	if keys == nil || recovery == nil || signer == nil {
		return nil, &errs.Argument{Message: "deterministic provider dependencies are required"}
	}
	if clock == nil {
		clock = time.Now
	}
	return &DeterministicCreateNodeProvider{keys: keys, recoveryKeys: recovery, proofSigner: signer, clock: clock, results: map[string]CreateNodeProviderResponse{}}, nil
}
func validateCreateRequest(r CreateNodeProviderRequest, keys ReceiptKeyResolver, now time.Time) error {
	c := r.Context
	if c.Action != ActionCreateNode || c.ResourceKind != ResourceNode || c.Target == nil || c.ActionParameters == nil {
		return &InvalidOperationError{Message: "create-node request is not an exact authorized handoff"}
	}
	target, ok := c.Target.(IdempotentProviderCreate)
	p, okp := c.ActionParameters.(CreateNodeProviderParameters)
	if !ok || !okp || p != r.Parameters || target.Key.Value != r.Binding.CreateKey || c.OperationId.Value != r.Binding.OperationId || c.IdempotencyKey.Value != r.Binding.IdempotencyKey || c.CellId.Value != r.Binding.CellId || c.CompartmentId.Value != r.Binding.CompartmentId || c.ExpectedGeneration.Value != r.Binding.Generation || c.ControllerEpoch.Value != r.Binding.Epoch || p.TemplateId.Value != r.Binding.TemplateId || p.PlacementId.Value != r.Binding.PlacementId || p.BootstrapEnvelopeDigest.Sha256 != r.Binding.BootstrapEnvelopeDigest || c.fingerprint() != r.Binding.ProviderContextFingerprint || !VerifyCreateNodeHandoffReceipt(r.Receipt, keys, r.Binding, now) {
		return &InvalidOperationError{Message: "create-node request is not the exact signed authorized handoff"}
	}
	return nil
}
func validateRecovery(r CreateNodeProviderRequest, keys ReceiptKeyResolver, now time.Time) error {
	if !VerifyRecoveryLookupAuthority(r.RecoveryAuthority, keys, r.Binding, now) || r.Context.fingerprint() != r.Binding.ProviderContextFingerprint {
		return &InvalidOperationError{Message: "create-node recovery authority is invalid"}
	}
	return nil
}
func (p *DeterministicCreateNodeProvider) CreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeProviderResponse, error) {
	if ctx == nil {
		return CreateNodeProviderResponse{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if p == nil || p.keys == nil || p.clock == nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "deterministic provider is unavailable"}
	}
	if err := ctx.Err(); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if err := validateCreateRequest(r, p.keys, p.clock()); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.CreateCallCount++
	resp := CreateNodeProviderResponse{NodeId: ProviderResourceId{Value: "fake-node-" + r.Context.OperationId.Value}, WorkRequestId: ProviderWorkRequestId{Value: "fake-work-" + r.Context.OperationId.Value}}
	if _, exists := p.results[r.Binding.CreateKey]; exists {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "deterministic provider create key already used"}
	}
	p.results[r.Binding.CreateKey] = resp
	return resp, nil
}
func (p *DeterministicCreateNodeProvider) ReconcileCreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeReconciliation, error) {
	if ctx == nil {
		return CreateNodeReconciliation{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if p == nil || p.recoveryKeys == nil || p.proofSigner == nil || p.clock == nil {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "deterministic provider is unavailable"}
	}
	if err := ctx.Err(); err != nil {
		return CreateNodeReconciliation{}, err
	}
	if err := validateRecovery(r, p.recoveryKeys, p.clock()); err != nil {
		return CreateNodeReconciliation{}, err
	}
	p.mu.Lock()
	resp, ok := p.results[r.Binding.CreateKey]
	p.mu.Unlock()
	if !ok {
		return CreateNodeReconciliation{Status: CreateNodeNotFound}, nil
	}
	proof, err := p.proofSigner.Sign(r.Binding, resp)
	if err != nil {
		return CreateNodeReconciliation{}, err
	}
	return CreateNodeReconciliation{Status: CreateNodeFound, Response: &resp, Proof: &proof}, nil
}

type OciCreateNodeProviderOptions struct{ Enabled bool }
type OciCreateNodeClient interface {
	CreateNode(context.Context, CreateNodeProviderRequest) (CreateNodeProviderResponse, error)
	ReconcileCreateNode(context.Context, CreateNodeProviderRequest) (CreateNodeReconciliation, error)
}
type OciCreateNodeProvider struct {
	Enabled bool
	Client  OciCreateNodeClient
	// OCI is used to build the concrete HTTP client when Client is omitted.
	// Client remains available as a narrow seam for deterministic unit tests.
	OCI                                *OCIHTTPTransport
	ProofSigner                        *CreateNodeProviderProofSigner
	Keys, RecoveryKeys, InvocationKeys ReceiptKeyResolver
	Journal                            CreateNodeJournal
	Clock                              func() time.Time
	LaunchResolver                     OciNodeLaunchResolver
	Ownership                          DurableOwnershipEvidence
}

func (p *OciCreateNodeProvider) CreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeProviderResponse, error) {
	if p == nil || !p.Enabled {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode is disabled"}
	}
	if p.Journal == nil || p.Clock == nil || p.Keys == nil || p.InvocationKeys == nil || p.Ownership == nil || !p.Ownership.AuthoritativeDurable() {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode dependencies are incomplete"}
	}
	client := p.Client
	if client == nil && p.OCI != nil {
		client = &OCIComputeNodeClient{OCI: p.OCI, ProofSigner: p.ProofSigner, LaunchResolver: p.LaunchResolver, Ownership: p.Ownership}
	}
	if client == nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode client is unavailable"}
	}
	if ctx == nil {
		return CreateNodeProviderResponse{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := validateCreateRequest(r, p.Keys, p.Clock()); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if r.InvocationCapability == nil || !p.Journal.AuthoritativeDurable() || !VerifyInvocationCapability(*r.InvocationCapability, p.InvocationKeys, r.Binding, p.Clock()) {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode requires an unconsumed authoritative invocation capability"}
	}
	concrete, concreteClient := client.(*OCIComputeNodeClient)
	var launch ociNodeLaunchRequest
	providerRequestDigest := digestCanonical("create-node-client-seam-v1", r.Binding.Digest())
	if concreteClient {
		var err error
		launch, err = concrete.prepareNodeLaunch(ctx, r)
		if err != nil {
			return CreateNodeProviderResponse{}, err
		}
		providerRequestDigest = launch.digest()
	}
	if err := p.Journal.ConsumeInvocationCapability(ctx, *r.InvocationCapability, r.Binding, providerRequestDigest, p.Clock()); err != nil {
		if ctx.Err() != nil {
			return CreateNodeProviderResponse{}, ctx.Err()
		}
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode invocation capability was not consumed"}
	}
	var response CreateNodeProviderResponse
	var err error
	if concreteClient {
		response, err = concrete.executeNodeLaunch(ctx, launch)
	} else {
		response, err = client.CreateNode(ctx, r)
	}
	if err == nil {
		if recordErr := recordCreateNodeOwnership(ctx, p.Ownership, r, response.NodeId); recordErr != nil {
			if ctx.Err() != nil {
				return CreateNodeProviderResponse{}, ctx.Err()
			}
			return CreateNodeProviderResponse{}, &ProviderOutcomeUnknownError{Message: "OCI node was created but its ownership record is not durable"}
		}
		return response, nil
	}
	if ctx.Err() != nil {
		return CreateNodeProviderResponse{}, err
	}
	var unknown *ProviderOutcomeUnknownError
	if !concreteClient || !errors.As(err, &unknown) {
		return CreateNodeProviderResponse{}, err
	}
	var exhausted *ociResponseRetriesExhaustedError
	if errors.As(err, &exhausted) {
		return CreateNodeProviderResponse{}, err
	}
	// The invocation capability was validated and consumed before the first
	// POST. OCI defines opc-retry-token replay as the only authoritative way
	// to recover that mutation. Reuse the already-built request so the body,
	// caller headers, launch resolution, and token stay byte-identical.
	response, err = concrete.executeNodeLaunch(ctx, launch)
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if recordErr := recordCreateNodeOwnership(ctx, p.Ownership, r, response.NodeId); recordErr != nil {
		if ctx.Err() != nil {
			return CreateNodeProviderResponse{}, ctx.Err()
		}
		return CreateNodeProviderResponse{}, &ProviderOutcomeUnknownError{Message: "OCI node was recovered but its ownership record is not durable"}
	}
	return response, nil
}
func (p *OciCreateNodeProvider) ReconcileCreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeReconciliation, error) {
	if p == nil || !p.Enabled {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI CreateNode is disabled"}
	}
	if p.Clock == nil || p.RecoveryKeys == nil {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI CreateNode dependencies are incomplete"}
	}
	client := p.Client
	if client == nil && p.OCI != nil {
		client = &OCIComputeNodeClient{OCI: p.OCI, ProofSigner: p.ProofSigner, LaunchResolver: p.LaunchResolver, Ownership: p.Ownership}
	}
	if client == nil {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI CreateNode client is unavailable"}
	}
	if ctx == nil {
		return CreateNodeReconciliation{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	now := p.Clock()
	if err := validateRecovery(r, p.RecoveryKeys, now); err != nil {
		return CreateNodeReconciliation{}, err
	}
	if concrete, ok := client.(*OCIComputeNodeClient); ok {
		if concrete.ProofSigner == nil || p.Keys == nil || p.InvocationKeys == nil || p.Journal == nil || !p.Journal.AuthoritativeDurable() || p.Ownership == nil || !p.Ownership.AuthoritativeDurable() {
			return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI node mutation recovery dependencies are incomplete"}
		}
		if r.InvocationCapability == nil || !VerifyInvocationCapability(*r.InvocationCapability, p.InvocationKeys, r.Binding, r.InvocationCapability.IssuedAt) {
			return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
		}
		consumption, consumed, err := p.Journal.InvocationCapabilityConsumption(ctx, *r.InvocationCapability, r.Binding)
		if err != nil {
			return CreateNodeReconciliation{}, err
		}
		capability := *r.InvocationCapability
		if !consumed || consumption.ProviderRequestDigest == "" || consumption.ConsumedAt.Before(capability.IssuedAt) ||
			consumption.ConsumedAt.Before(r.Receipt.IssuedAt) || !consumption.ConsumedAt.Before(capability.ExpiresAt) ||
			!consumption.ConsumedAt.Before(capability.LeaseExpiresAt) || now.Before(consumption.ConsumedAt) ||
			!now.Before(consumption.ConsumedAt.Add(ociRetryTokenValidity)) {
			return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
		}
		if !createNodeReplayWindowValid(r, p.Keys, now) {
			return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
		}
		launch, err := concrete.prepareNodeLaunch(ctx, r)
		if err != nil {
			return CreateNodeReconciliation{}, err
		}
		if launch.digest() != consumption.ProviderRequestDigest {
			return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
		}
		response, err := concrete.executeNodeLaunch(ctx, launch)
		if err != nil {
			var unknown *ProviderOutcomeUnknownError
			if errors.As(err, &unknown) {
				return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
			}
			return CreateNodeReconciliation{}, err
		}
		if err := recordCreateNodeOwnership(ctx, p.Ownership, r, response.NodeId); err != nil {
			if ctx.Err() != nil {
				return CreateNodeReconciliation{}, ctx.Err()
			}
			return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
		}
		proof, err := concrete.ProofSigner.Sign(r.Binding, response)
		if err != nil {
			return CreateNodeReconciliation{}, err
		}
		return CreateNodeReconciliation{Status: CreateNodeFound, Response: &response, Proof: &proof}, nil
	}
	return client.ReconcileCreateNode(ctx, r)
}

const ociRetryTokenValidity = 24 * time.Hour

func createNodeReplayWindowValid(r CreateNodeProviderRequest, keys ReceiptKeyResolver, now time.Time) bool {
	issued := r.Receipt.IssuedAt
	if now.Before(issued) || !now.Before(issued.Add(ociRetryTokenValidity)) {
		return false
	}
	// Verify at the signed issue time because the short-lived handoff receipt
	// can expire before crash recovery. Its signed IssuedAt still proves a
	// conservative upper bound on the original OCI retry-token age.
	return VerifyCreateNodeHandoffReceipt(r.Receipt, keys, r.Binding, issued)
}

func recordCreateNodeOwnership(ctx context.Context, ownership DurableOwnershipEvidence, r CreateNodeProviderRequest, nodeID ProviderResourceId) error {
	if ownership == nil || !ownership.AuthoritativeDurable() {
		return &InvalidOperationError{Message: "OCI node ownership journal is unavailable"}
	}
	if !isOCID(nodeID.Value, "instance") || r.Context.CellId.Value == "" || r.Context.CellId.Value != r.Binding.CellId ||
		r.Context.CompartmentId.Value != r.Binding.CompartmentId || r.Context.ExpectedGeneration.Value != r.Binding.Generation {
		return &InvalidDataError{Message: "OCI node ownership binding is invalid"}
	}
	return ownership.Record(ctx, ProviderOwnershipRecord{
		ResourceId:    nodeID,
		CellId:        r.Context.CellId,
		CompartmentId: ProviderCompartmentId{Value: r.Binding.CompartmentId},
		Generation:    ProviderGeneration{Value: r.Binding.Generation},
	})
}
