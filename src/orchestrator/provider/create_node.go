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
	CompartmentId, AvailabilityDomain, FaultDomain, VcnId, SubnetId, ImageId string
	Shape                                                                    string
	NetworkSecurityGroupIds                                                  []string
	Ocpus, MemoryGB                                                          float64
	BootstrapBase64                                                          string
}

// OCINodeEstateBinding is the network portion of an estate after startup
// verification. The constructor copies the allowlists so a resolver cannot
// mutate the scope while a node request is being assembled.
type OCINodeEstateBinding struct {
	VCNID                   string
	SubnetIDs               []string
	NetworkSecurityGroupIDs []string
	vcnID                   string
	subnets                 map[string]struct{}
	networkSecurityGroups   map[string]struct{}
}

func NewOCINodeEstateBinding(vcnID string, subnetIDs, networkSecurityGroupIDs []string) (*OCINodeEstateBinding, error) {
	if !isOCID(vcnID, "vcn") || len(subnetIDs) < 1 || len(subnetIDs) > 16 || len(networkSecurityGroupIDs) < 1 || len(networkSecurityGroupIDs) > 16 {
		return nil, &InvalidDataError{Message: "OCI node estate binding is incomplete"}
	}
	if err := validateEstateIDs(subnetIDs, "subnet", networkSecurityGroupIDs, "networksecuritygroup"); err != nil {
		return nil, &InvalidDataError{Message: "OCI node estate binding contains invalid resource identities"}
	}
	binding := &OCINodeEstateBinding{
		VCNID:                   vcnID,
		SubnetIDs:               append([]string(nil), subnetIDs...),
		NetworkSecurityGroupIDs: append([]string(nil), networkSecurityGroupIDs...),
		vcnID:                   vcnID,
		subnets:                 make(map[string]struct{}, len(subnetIDs)),
		networkSecurityGroups:   make(map[string]struct{}, len(networkSecurityGroupIDs)),
	}
	if len(binding.subnets) != len(subnetIDs) || len(binding.networkSecurityGroups) != len(networkSecurityGroupIDs) {
		return nil, &InvalidDataError{Message: "OCI node estate binding contains duplicate resource identities"}
	}
	for _, id := range subnetIDs {
		binding.subnets[id] = struct{}{}
	}
	for _, id := range networkSecurityGroupIDs {
		binding.networkSecurityGroups[id] = struct{}{}
	}
	if err := binding.validate(); err != nil {
		return nil, err
	}
	return binding, nil
}

// NewOCINodeEstateBindingFromSpec extracts the network allowlists from a
// startup-verified estate specification. Call it only after VerifyOCIEstate
// succeeds; the spec validation here also protects callers that assemble the
// binding at a different composition boundary.
func NewOCINodeEstateBindingFromSpec(spec OCIEstateSpec) (*OCINodeEstateBinding, error) {
	if err := validateOCIEstateSpec(spec); err != nil {
		return nil, &InvalidDataError{Message: "OCI node estate specification is invalid"}
	}
	return NewOCINodeEstateBinding(spec.VCNID, spec.SubnetIDs, spec.NetworkSecurityGroupIDs)
}

func (b *OCINodeEstateBinding) validate() error {
	if b != nil && b.vcnID != "" {
		if !isOCID(b.vcnID, "vcn") || len(b.subnets) < 1 || len(b.subnets) > 16 || len(b.networkSecurityGroups) < 1 || len(b.networkSecurityGroups) > 16 {
			return &InvalidDataError{Message: "OCI node estate binding is incomplete"}
		}
		for id := range b.subnets {
			if !isOCID(id, "subnet") {
				return &InvalidDataError{Message: "OCI node estate binding contains invalid subnet identity"}
			}
		}
		for id := range b.networkSecurityGroups {
			if !isOCID(id, "networksecuritygroup") {
				return &InvalidDataError{Message: "OCI node estate binding contains invalid network group identity"}
			}
		}
		return nil
	}
	if b == nil || !isOCID(b.VCNID, "vcn") || len(b.SubnetIDs) < 1 || len(b.SubnetIDs) > 16 || len(b.NetworkSecurityGroupIDs) < 1 || len(b.NetworkSecurityGroupIDs) > 16 {
		return &InvalidDataError{Message: "OCI node estate binding is incomplete"}
	}
	if err := validateEstateIDs(b.SubnetIDs, "subnet", b.NetworkSecurityGroupIDs, "networksecuritygroup"); err != nil {
		return &InvalidDataError{Message: "OCI node estate binding contains invalid resource identities"}
	}
	return nil
}

func (b *OCINodeEstateBinding) allowsSubnet(id string) bool {
	if b != nil && b.subnets != nil {
		_, ok := b.subnets[id]
		return ok
	}
	for _, allowed := range b.SubnetIDs {
		if allowed == id {
			return true
		}
	}
	return false
}

func (b *OCINodeEstateBinding) vcn() string {
	if b != nil && b.vcnID != "" {
		return b.vcnID
	}
	return b.VCNID
}

func (b *OCINodeEstateBinding) allowsNetworkSecurityGroup(id string) bool {
	if b != nil && b.networkSecurityGroups != nil {
		_, ok := b.networkSecurityGroups[id]
		return ok
	}
	for _, allowed := range b.NetworkSecurityGroupIDs {
		if allowed == id {
			return true
		}
	}
	return false
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
	EstateBinding                      *OCINodeEstateBinding
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
	client := p.Client
	if client == nil && p.OCI != nil {
		if p.EstateBinding == nil {
			return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode requires a verified estate network binding"}
		}
		client = &OCIComputeNodeClient{OCI: p.OCI, ProofSigner: p.ProofSigner, LaunchResolver: p.LaunchResolver, EstateBinding: p.EstateBinding, Ownership: p.Ownership}
	}
	if client == nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode client is unavailable"}
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
		client = &OCIComputeNodeClient{OCI: p.OCI, ProofSigner: p.ProofSigner, LaunchResolver: p.LaunchResolver, EstateBinding: p.EstateBinding, Ownership: p.Ownership}
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
