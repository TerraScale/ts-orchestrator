package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"time"
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
		return nil, &ArgumentError{Message: "provider proof signer requires P-256"}
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

// CreateNodeJournal is the narrow durability seam needed by an external
// mutation provider. Implementations must atomically consume a capability.
type CreateNodeJournal interface {
	AuthoritativeDurable() bool
	ConsumeInvocationCapability(context.Context, CreateNodeAuthoritativeInvocationCapability, CreateNodeReceiptBinding, time.Time) error
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
		return nil, &ArgumentError{Message: "deterministic provider dependencies are required"}
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
		return CreateNodeProviderResponse{}, &ArgumentError{Param: "ctx", Message: "provider context is required"}
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
		return CreateNodeReconciliation{}, &ArgumentError{Param: "ctx", Message: "provider context is required"}
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
	Enabled                            bool
	Client                             OciCreateNodeClient
	Keys, RecoveryKeys, InvocationKeys ReceiptKeyResolver
	Journal                            CreateNodeJournal
	Clock                              func() time.Time
}

func (p *OciCreateNodeProvider) CreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeProviderResponse, error) {
	if p == nil || !p.Enabled {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode is disabled"}
	}
	if p.Client == nil || p.Journal == nil || p.Clock == nil || p.Keys == nil || p.InvocationKeys == nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode dependencies are incomplete"}
	}
	if ctx == nil {
		return CreateNodeProviderResponse{}, &ArgumentError{Param: "ctx", Message: "provider context is required"}
	}
	if err := validateCreateRequest(r, p.Keys, p.Clock()); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if r.InvocationCapability == nil || !p.Journal.AuthoritativeDurable() || !VerifyInvocationCapability(*r.InvocationCapability, p.InvocationKeys, r.Binding, p.Clock()) || p.Journal.ConsumeInvocationCapability(ctx, *r.InvocationCapability, r.Binding, p.Clock()) != nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI CreateNode requires an unconsumed authoritative invocation capability"}
	}
	return p.Client.CreateNode(ctx, r)
}
func (p *OciCreateNodeProvider) ReconcileCreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeReconciliation, error) {
	if p == nil || !p.Enabled {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI CreateNode is disabled"}
	}
	if p.Client == nil || p.Clock == nil || p.RecoveryKeys == nil {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI CreateNode dependencies are incomplete"}
	}
	if ctx == nil {
		return CreateNodeReconciliation{}, &ArgumentError{Param: "ctx", Message: "provider context is required"}
	}
	if err := validateRecovery(r, p.RecoveryKeys, p.Clock()); err != nil {
		return CreateNodeReconciliation{}, err
	}
	return p.Client.ReconcileCreateNode(ctx, r)
}
