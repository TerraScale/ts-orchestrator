package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
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

// OCINodeEstateBinding is an immutable network allowlist produced only by
// VerifyOCIEstateAndBind. Keeping its fields private prevents callers from
// manufacturing a binding from syntax-only configuration.
type OCINodeEstateBinding struct {
	vcnID                 string
	subnets               map[string]struct{}
	networkSecurityGroups map[string]struct{}
	digest                string
}

func (b *OCINodeEstateBinding) valid() bool {
	if b == nil || !isOCID(b.vcnID, "vcn") || len(b.subnets) == 0 || len(b.subnets) > 16 ||
		len(b.networkSecurityGroups) == 0 || len(b.networkSecurityGroups) > 16 || b.digest == "" {
		return false
	}
	for id := range b.subnets {
		if !isOCID(id, "subnet") {
			return false
		}
	}
	for id := range b.networkSecurityGroups {
		if !isOCID(id, "networksecuritygroup") {
			return false
		}
	}
	return true
}

func (b *OCINodeEstateBinding) allowsSubnet(id string) bool {
	if !b.valid() {
		return false
	}
	_, ok := b.subnets[id]
	return ok
}

func (b *OCINodeEstateBinding) allowsNetworkSecurityGroup(id string) bool {
	if !b.valid() {
		return false
	}
	_, ok := b.networkSecurityGroups[id]
	return ok
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
	ConsumeInvocationCapability(context.Context, CreateNodeAuthoritativeInvocationCapability, CreateNodeReceiptBinding, CreateNodeInvocationConsumption) error
	InvocationCapabilityConsumption(context.Context, CreateNodeAuthoritativeInvocationCapability, CreateNodeReceiptBinding) (CreateNodeInvocationConsumption, bool, error)
}

// CreateNodeProviderRequestProof is the exact OCI request authorized by one
// consumed invocation capability. Body is persisted so crash recovery never
// re-resolves launch configuration or silently changes provider bytes.
type CreateNodeProviderRequestProof struct {
	Authority, Region, Method, Path, CompartmentId, RetryToken string
	Service                                                    OCIService
	BindingDigest, OperationId, CreateKey, CellId              string
	Generation                                                 uint64
	Body                                                       []byte
	Digest                                                     string
}

func (p CreateNodeProviderRequestProof) calculatedDigest() string {
	return digestCanonical(
		"oci-create-node-request-v1", p.Authority, string(p.Service), p.Region,
		p.Method, p.Path, p.CompartmentId, p.RetryToken, p.BindingDigest,
		p.OperationId, p.CreateKey, p.CellId, p.Generation, string(p.Body),
	)
}

func (p CreateNodeProviderRequestProof) clone() CreateNodeProviderRequestProof {
	p.Body = append([]byte(nil), p.Body...)
	return p
}

func (p CreateNodeProviderRequestProof) structurallyValid(binding CreateNodeReceiptBinding) bool {
	return p.Digest != "" && p.Digest == p.calculatedDigest() && p.Authority != "" &&
		p.Service == OCIServiceCore && regionPattern.MatchString(p.Region) &&
		validOCIServiceHost(p.Service, p.Region, p.Authority) && p.Method == http.MethodPost &&
		p.Path == "/20160918/instances" && isOCID(p.CompartmentId, "compartment") &&
		p.CompartmentId == binding.CompartmentId && p.RetryToken == binding.IdempotencyKey &&
		p.BindingDigest == binding.Digest() && p.OperationId == binding.OperationId &&
		p.CreateKey == binding.CreateKey && p.CellId == binding.CellId &&
		p.Generation == binding.Generation && len(p.Body) > 0 && len(p.Body) <= 128<<10
}

// CreateNodeInvocationConsumption is the durable replay authority. It binds
// the exact provider request, operation/create ownership identity, signed
// receipt and lease windows, and the instant the first submission was
// committed by the journal.
type CreateNodeInvocationConsumption struct {
	BindingDigest, CapabilityDigest, ReceiptDigest          string
	OperationId, CreateKey, CellId, CompartmentId           string
	Generation                                              uint64
	ProviderRequest                                         CreateNodeProviderRequestProof
	ReceiptIssuedAt, ReceiptExpiresAt                       time.Time
	CapabilityIssuedAt, CapabilityExpiresAt, LeaseExpiresAt time.Time
	ConsumedAt, SubmissionCommittedAt                       time.Time
}

func invocationCapabilityDigest(capability CreateNodeAuthoritativeInvocationCapability) string {
	return digestCanonical("create-node-invocation-capability-v1", string(capability.payload()), capability.Signature)
}

func handoffReceiptDigest(receipt CreateNodeHandoffReceipt) string {
	return digestCanonical("create-node-handoff-receipt-v1", string(receipt.payload()), receipt.Signature)
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
	WorkRequests                       WorkRequestProvider
	EstateBinding                      *OCINodeEstateBinding
}

func (p *OciCreateNodeProvider) CreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeProviderResponse, error) {
	if p == nil || !p.Enabled {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode is disabled"}
	}
	if p.Journal == nil || p.Clock == nil || p.Keys == nil || p.InvocationKeys == nil || p.Ownership == nil || !p.Ownership.AuthoritativeDurable() {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode dependencies are incomplete"}
	}
	client, err := p.computeClient()
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if ctx == nil {
		return CreateNodeProviderResponse{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	now := p.Clock().UTC()
	if err := validateCreateRequest(r, p.Keys, now); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if r.InvocationCapability == nil || !p.Journal.AuthoritativeDurable() || !VerifyInvocationCapability(*r.InvocationCapability, p.InvocationKeys, r.Binding, now) {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode requires an unconsumed authoritative invocation capability"}
	}
	launch, err := client.prepareNodeLaunch(ctx, r)
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	consumption := newCreateNodeInvocationConsumption(r, *r.InvocationCapability, launch, now)
	if err := p.Journal.ConsumeInvocationCapability(ctx, *r.InvocationCapability, r.Binding, consumption); err != nil {
		if ctx.Err() != nil {
			return CreateNodeProviderResponse{}, ctx.Err()
		}
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode invocation capability was not consumed"}
	}
	response, err := client.executeNodeLaunch(ctx, launch)
	if err == nil {
		if err := waitOCIWorkRequest(ctx, p.WorkRequests, response.WorkRequestId.Value); err != nil {
			return CreateNodeProviderResponse{}, err
		}
		if recordErr := recordCreateNodeOwnership(ctx, p.Ownership, r, response.NodeId); recordErr != nil {
			return CreateNodeProviderResponse{}, createNodeOwnershipFailure(ctx, "OCI node was created but its ownership record is not durable", recordErr)
		}
		return response, nil
	}
	if ctx.Err() != nil {
		return CreateNodeProviderResponse{}, err
	}
	var unknown *ProviderOutcomeUnknownError
	var exhausted *ociResponseRetriesExhaustedError
	if !errors.As(err, &unknown) || errors.As(err, &exhausted) {
		return CreateNodeProviderResponse{}, err
	}
	// Read-only observation always precedes replay. OCI tags are deliberately
	// ignored by the observer, so they can never authorize adoption.
	if _, observeErr := client.ReconcileCreateNode(ctx, r); observeErr != nil {
		return CreateNodeProviderResponse{}, err
	}
	replay, authorized, loadErr := p.loadDurableReplay(ctx, client, r, now)
	if loadErr != nil {
		return CreateNodeProviderResponse{}, loadErr
	}
	if !authorized {
		return CreateNodeProviderResponse{}, err
	}
	response, err = client.executeNodeLaunch(ctx, replay)
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if err := waitOCIWorkRequest(ctx, p.WorkRequests, response.WorkRequestId.Value); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if recordErr := recordCreateNodeOwnership(ctx, p.Ownership, r, response.NodeId); recordErr != nil {
		return CreateNodeProviderResponse{}, createNodeOwnershipFailure(ctx, "OCI node was recovered but its ownership record is not durable", recordErr)
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
	client, err := p.computeClient()
	if err != nil {
		return CreateNodeReconciliation{}, err
	}
	if ctx == nil {
		return CreateNodeReconciliation{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	now := p.Clock().UTC()
	if err := validateRecovery(r, p.RecoveryKeys, now); err != nil {
		return CreateNodeReconciliation{}, err
	}
	observed, err := client.ReconcileCreateNode(ctx, r)
	if err != nil {
		return CreateNodeReconciliation{}, err
	}
	if observed.Status == CreateNodeFound {
		return observed, nil
	}
	if p.ProofSigner == nil || p.Keys == nil || p.InvocationKeys == nil || p.Journal == nil || !p.Journal.AuthoritativeDurable() || p.Ownership == nil || !p.Ownership.AuthoritativeDurable() || r.InvocationCapability == nil {
		return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
	}
	replay, authorized, err := p.loadDurableReplay(ctx, client, r, now)
	if err != nil {
		return CreateNodeReconciliation{}, err
	}
	if !authorized {
		return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
	}
	response, err := client.executeNodeLaunch(ctx, replay)
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
	proof, err := p.ProofSigner.Sign(r.Binding, response)
	if err != nil {
		return CreateNodeReconciliation{}, err
	}
	return CreateNodeReconciliation{Status: CreateNodeFound, Response: &response, Proof: &proof}, nil
}

const ociRetryTokenValidity = 24 * time.Hour

func (p *OciCreateNodeProvider) computeClient() (*OCIComputeNodeClient, error) {
	if p == nil {
		return nil, &InvalidOperationError{Message: "OCI CreateNode client is unavailable"}
	}
	if p.Client != nil {
		client, ok := p.Client.(*OCIComputeNodeClient)
		if !ok {
			return nil, &InvalidOperationError{Message: "OCI CreateNode requires the exact-request compute client"}
		}
		return client, nil
	}
	if p.OCI == nil {
		return nil, &InvalidOperationError{Message: "OCI CreateNode client is unavailable"}
	}
	return &OCIComputeNodeClient{OCI: p.OCI, ProofSigner: p.ProofSigner, LaunchResolver: p.LaunchResolver, Ownership: p.Ownership, WorkRequests: p.WorkRequests, EstateBinding: p.EstateBinding}, nil
}

func newCreateNodeInvocationConsumption(r CreateNodeProviderRequest, capability CreateNodeAuthoritativeInvocationCapability, launch ociNodeLaunchRequest, now time.Time) CreateNodeInvocationConsumption {
	now = now.UTC()
	return CreateNodeInvocationConsumption{
		BindingDigest: r.Binding.Digest(), CapabilityDigest: invocationCapabilityDigest(capability), ReceiptDigest: handoffReceiptDigest(r.Receipt),
		OperationId: r.Binding.OperationId, CreateKey: r.Binding.CreateKey, CellId: r.Binding.CellId,
		CompartmentId: r.Binding.CompartmentId, Generation: r.Binding.Generation, ProviderRequest: launch.request.clone(),
		ReceiptIssuedAt: r.Receipt.IssuedAt.UTC(), ReceiptExpiresAt: r.Receipt.ExpiresAt.UTC(),
		CapabilityIssuedAt: capability.IssuedAt.UTC(), CapabilityExpiresAt: capability.ExpiresAt.UTC(), LeaseExpiresAt: capability.LeaseExpiresAt.UTC(),
		ConsumedAt: now, SubmissionCommittedAt: now,
	}
}

func (p *OciCreateNodeProvider) loadDurableReplay(ctx context.Context, client *OCIComputeNodeClient, r CreateNodeProviderRequest, now time.Time) (ociNodeLaunchRequest, bool, error) {
	if r.InvocationCapability == nil {
		return ociNodeLaunchRequest{}, false, nil
	}
	consumption, found, err := p.Journal.InvocationCapabilityConsumption(ctx, *r.InvocationCapability, r.Binding)
	if err != nil {
		return ociNodeLaunchRequest{}, false, err
	}
	if !found || !validCreateNodeInvocationConsumption(consumption, r, *r.InvocationCapability, p.Keys, p.InvocationKeys, now) {
		return ociNodeLaunchRequest{}, false, nil
	}
	launch := ociNodeLaunchRequest{request: consumption.ProviderRequest.clone()}
	if err := client.validateNodeLaunchRequest(launch); err != nil {
		return ociNodeLaunchRequest{}, false, nil
	}
	return launch, true, nil
}

func validCreateNodeInvocationConsumption(consumption CreateNodeInvocationConsumption, r CreateNodeProviderRequest, capability CreateNodeAuthoritativeInvocationCapability, receiptKeys, invocationKeys ReceiptKeyResolver, now time.Time) bool {
	now = now.UTC()
	if consumption.BindingDigest != r.Binding.Digest() || consumption.CapabilityDigest != invocationCapabilityDigest(capability) ||
		consumption.ReceiptDigest != handoffReceiptDigest(r.Receipt) || consumption.OperationId != r.Binding.OperationId ||
		consumption.CreateKey != r.Binding.CreateKey || consumption.CellId != r.Binding.CellId || consumption.CompartmentId != r.Binding.CompartmentId ||
		consumption.Generation != r.Binding.Generation || !consumption.ProviderRequest.structurallyValid(r.Binding) ||
		!consumption.ReceiptIssuedAt.Equal(r.Receipt.IssuedAt) || !consumption.ReceiptExpiresAt.Equal(r.Receipt.ExpiresAt) ||
		!consumption.CapabilityIssuedAt.Equal(capability.IssuedAt) || !consumption.CapabilityExpiresAt.Equal(capability.ExpiresAt) ||
		!consumption.LeaseExpiresAt.Equal(capability.LeaseExpiresAt) || !VerifyInvocationCapability(capability, invocationKeys, r.Binding, capability.IssuedAt) ||
		!VerifyCreateNodeHandoffReceipt(r.Receipt, receiptKeys, r.Binding, r.Receipt.IssuedAt) {
		return false
	}
	consumed := consumption.ConsumedAt.UTC()
	submitted := consumption.SubmissionCommittedAt.UTC()
	return !consumed.Before(r.Receipt.IssuedAt) && !consumed.Before(capability.IssuedAt) && !submitted.Before(consumed) &&
		submitted.Before(r.Receipt.ExpiresAt) && submitted.Before(capability.ExpiresAt) && submitted.Before(capability.LeaseExpiresAt) &&
		!now.Before(submitted) && now.Before(submitted.Add(ociRetryTokenValidity)) &&
		!now.Before(r.Receipt.IssuedAt) && now.Before(r.Receipt.IssuedAt.Add(ociRetryTokenValidity))
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
		ResourceId: nodeID, CellId: r.Context.CellId,
		CompartmentId: ProviderCompartmentId{Value: r.Binding.CompartmentId}, Generation: ProviderGeneration{Value: r.Binding.Generation},
	})
}

func createNodeOwnershipFailure(ctx context.Context, message string, recordErr error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if recordErr == nil {
		return nil
	}
	return &ProviderOutcomeUnknownError{Message: message}
}
