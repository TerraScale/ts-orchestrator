package bootstrap

// This file is the greenfield OCI bootstrap boundary.  It deliberately owns
// no OCI or Cloudflare client: callers compose the individual provider ports
// below with the provider adapters appropriate to their estate.  Planning is
// pure, and execution is only possible with an authoritative durable journal
// and a short-lived credential lease.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	BootstrapRegionCode          = "GRU"
	BootstrapOCIRegion           = "sa-saopaulo-1"
	BootstrapPrimaryShape        = "VM.Standard.A1.Flex"
	BootstrapFallbackShape       = "VM.Standard.E5.Flex"
	BootstrapHostCount           = 2
	BootstrapOCPUs               = 2
	BootstrapMemoryGiB           = 12
	BootstrapDataVolumeGiB       = 200
	BootstrapDefaultCIDR         = "10.10.0.0/16"
	BootstrapDefaultSubnetCIDR   = "10.10.0.0/16"
	BootstrapDefaultNSG          = "terrascale-gru-members"
	BootstrapDefaultVCN          = "terrascale-gru"
	BootstrapDefaultCompartment  = "terrascale"
	BootstrapDefaultVault        = "terrascale-gru-vault"
	BootstrapDefaultKey          = "database-kek"
	BootstrapDefaultLedgerBucket = "terrascale-ledger-sa-saopaulo-1"
	BootstrapDefaultBackupBucket = "terrascale-backups-sa-saopaulo-1"
	BootstrapMaxSteps            = 128
)

var (
	ErrInvalidBootstrap       = errors.New("bootstrap configuration is invalid")
	ErrCredentialsUnavailable = errors.New("bootstrap credentials are unavailable")
	ErrJournalUnavailable     = errors.New("bootstrap requires an authoritative durable journal")
	ErrFingerprintMismatch    = errors.New("bootstrap journal fingerprint does not match the plan")
	ErrPlacementLocked        = errors.New("bootstrap placement lock was not acquired")
	ErrPreviouslyFailed       = errors.New("bootstrap step previously failed")
)

// BootstrapConfig contains only approved, non-secret bootstrap inputs.  OCI
// credentials are resolved at execution time through CredentialProvider and
// never appear in this value or a Plan.
type BootstrapConfig struct {
	TenancyID           string
	RegionCode          string
	OCIRegion           string
	CompartmentName     string
	VCNName             string
	VCNCIDR             string
	SubnetCIDR          string
	NSGName             string
	VaultName           string
	VaultKeyName        string
	Buckets             []BucketSpec
	ImageID             string
	AvailabilityDomains []string
	PrimaryShape        string
	FallbackShape       string
	OCPUs               float64
	MemoryGiB           float64
	DataVolumeGiB       uint64
	CloudInit           CloudInitConfig
	Edge                *EdgeBootstrapSpec
}

// DefaultBootstrapConfig is the closed GRU launch shape.  Image, AD, and
// signed ts-node artifact values remain explicit because they are tenancy- and
// release-specific; silently selecting any of them would be unsafe.
func DefaultBootstrapConfig() BootstrapConfig {
	return BootstrapConfig{
		RegionCode: BootstrapRegionCode, OCIRegion: BootstrapOCIRegion,
		CompartmentName: BootstrapDefaultCompartment, VCNName: BootstrapDefaultVCN,
		VCNCIDR: BootstrapDefaultCIDR, SubnetCIDR: BootstrapDefaultSubnetCIDR,
		NSGName: BootstrapDefaultNSG, VaultName: BootstrapDefaultVault,
		VaultKeyName: BootstrapDefaultKey,
		Buckets: []BucketSpec{
			{Name: BootstrapDefaultLedgerBucket, Purpose: "ledger", Versioning: true, LifecycleRules: []LifecycleRule{{Name: "ledger-archive", Action: "archive", AfterDays: 7}}},
			{Name: BootstrapDefaultBackupBucket, Purpose: "backup", Versioning: true, LifecycleRules: []LifecycleRule{{Name: "backup-infrequent", Action: "infrequent-access", AfterDays: 1}, {Name: "backup-archive", Action: "archive", AfterDays: 7}}},
		},
		PrimaryShape: BootstrapPrimaryShape, FallbackShape: BootstrapFallbackShape,
		OCPUs: BootstrapOCPUs, MemoryGiB: BootstrapMemoryGiB, DataVolumeGiB: BootstrapDataVolumeGiB,
	}
}

type BucketSpec struct {
	Name           string          `json:"name"`
	Purpose        string          `json:"purpose"`
	Versioning     bool            `json:"versioning"`
	LifecycleRules []LifecycleRule `json:"lifecycleRules,omitempty"`
}

type LifecycleRule struct {
	Name      string `json:"name"`
	Prefix    string `json:"prefix,omitempty"`
	Action    string `json:"action"`
	AfterDays uint16 `json:"afterDays"`
}

// CloudInitConfig describes one signed ts-node artifact and the regional NATS
// endpoint needed by the host agent. Cloud-init installs only this agent.
type CloudInitConfig struct {
	ArtifactURL        string
	SignatureURL       string
	SHA256             string
	SignaturePublicKey string
	NATSURL            string
}

type EdgeBootstrapSpec struct {
	Zone         string
	DNSRecords   []EdgeDNSRecord
	CacheRules   []EdgeCacheRule
	SnippetRules []EdgeSnippetRule
	WorkerRoutes []EdgeWorkerRoute
	KVNamespaces []string
	WAFRules     []EdgeRule
	RateRules    []EdgeRule
}

type EdgeDNSRecord struct {
	Name, Type, Content string
	Proxied             bool
	TTL                 uint32
}
type EdgeCacheRule struct {
	Name, Hostname, PathPrefix string
	Immutable                  bool
	SmartTiered                bool
}
type EdgeSnippetRule struct{ Name, Hostname, PathPrefix string }
type EdgeWorkerRoute struct{ Name, Hostname, PathPrefix, ScriptName string }
type EdgeRule struct{ Name, Expression, Action string }

func (c BootstrapConfig) Validate() error {
	if c.TenancyID == "" || strings.ContainsAny(c.TenancyID, "\r\n\x00") ||
		c.RegionCode != BootstrapRegionCode || c.OCIRegion == "" || strings.ContainsAny(c.OCIRegion, "\r\n\x00") {
		return ErrInvalidBootstrap
	}
	for _, value := range []string{c.CompartmentName, c.VCNName, c.NSGName, c.VaultName, c.VaultKeyName, c.ImageID} {
		if !validName(value) {
			return ErrInvalidBootstrap
		}
	}
	if !validCIDR(c.VCNCIDR) || !validCIDR(c.SubnetCIDR) {
		return ErrInvalidBootstrap
	}
	if len(c.Buckets) == 0 || len(c.Buckets) > 16 || len(c.AvailabilityDomains) == 0 || len(c.AvailabilityDomains) > 16 {
		return ErrInvalidBootstrap
	}
	if c.PrimaryShape != BootstrapPrimaryShape || c.FallbackShape != BootstrapFallbackShape || c.OCPUs <= 0 || c.MemoryGiB <= 0 || c.DataVolumeGiB == 0 {
		return ErrInvalidBootstrap
	}
	seen := map[string]bool{}
	for _, ad := range c.AvailabilityDomains {
		if ad == "" || strings.ContainsAny(ad, "\r\n\x00") || seen[ad] {
			return ErrInvalidBootstrap
		}
		seen[ad] = true
	}
	seen = map[string]bool{}
	for _, bucket := range c.Buckets {
		if !validName(bucket.Name) || !validName(bucket.Purpose) || seen[bucket.Name] {
			return ErrInvalidBootstrap
		}
		seen[bucket.Name] = true
		if len(bucket.LifecycleRules) > 32 {
			return ErrInvalidBootstrap
		}
		for _, rule := range bucket.LifecycleRules {
			if !validName(rule.Name) || !validName(rule.Action) || strings.ContainsAny(rule.Prefix, "\r\n\x00") {
				return ErrInvalidBootstrap
			}
		}
	}
	if err := validateCloudInit(c.CloudInit); err != nil {
		return err
	}
	if c.Edge != nil && c.Edge.Zone == "" {
		return ErrInvalidBootstrap
	}
	return nil
}

func validName(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func validCIDR(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.IsValid() && prefix == prefix.Masked()
}

func validateCloudInit(c CloudInitConfig) error {
	for _, value := range []string{c.ArtifactURL, c.SignatureURL, c.SHA256} {
		if value == "" || strings.ContainsAny(value, "\r\n\x00") || len(value) > 4096 {
			return ErrInvalidBootstrap
		}
	}
	for _, raw := range []string{c.ArtifactURL, c.SignatureURL} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return ErrInvalidBootstrap
		}
	}
	if len(c.SHA256) != 64 {
		return ErrInvalidBootstrap
	}
	if _, err := hex.DecodeString(c.SHA256); err != nil || strings.ToLower(c.SHA256) != c.SHA256 {
		return ErrInvalidBootstrap
	}
	if _, err := canonicalEd25519PublicKey(c.SignaturePublicKey); err != nil {
		return ErrInvalidBootstrap
	}
	if c.NATSURL != "" {
		if strings.ContainsAny(c.NATSURL, "\r\n\x00") || strings.ContainsFunc(c.NATSURL, func(r rune) bool { return r <= ' ' || r == 0x7f }) || len(c.NATSURL) > 4096 || strings.HasPrefix(c.NATSURL, "-") {
			return ErrInvalidBootstrap
		}
		parsed, err := url.Parse(c.NATSURL)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Scheme != "nats" && parsed.Scheme != "tls") || parsed.Host == "" {
			return ErrInvalidBootstrap
		}
	}
	return nil
}

// canonicalEd25519PublicKey accepts the release key as PKIX PEM, base64 raw
// key bytes, or lowercase hexadecimal raw key bytes. It always returns the
// canonical PKIX PEM form used by cloud-init. A digest alone is not an
// authentication mechanism, so an actual Ed25519 public key is mandatory.
func canonicalEd25519PublicKey(value string) (string, error) {
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, '\x00') {
		return "", errors.New("bootstrap release public key is missing")
	}
	var publicKey ed25519.PublicKey
	trimmed := strings.TrimSpace(value)
	if block, rest := pem.Decode([]byte(trimmed)); block != nil && strings.TrimSpace(string(rest)) == "" {
		if block.Type != "PUBLIC KEY" {
			return "", errors.New("bootstrap release public key must be an Ed25519 PKIX key")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", errors.New("bootstrap release public key is not valid PKIX")
		}
		var ok bool
		publicKey, ok = parsed.(ed25519.PublicKey)
		if !ok {
			return "", errors.New("bootstrap release public key is not Ed25519")
		}
	} else {
		var decoded []byte
		var err error
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			decoded, err = encoding.DecodeString(trimmed)
			if err == nil && len(decoded) == ed25519.PublicKeySize {
				break
			}
		}
		if len(decoded) != ed25519.PublicKeySize {
			decoded, err = hex.DecodeString(trimmed)
		}
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return "", errors.New("bootstrap release public key must contain 32 Ed25519 bytes")
		}
		publicKey = ed25519.PublicKey(decoded)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", errors.New("bootstrap release public key cannot be encoded")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

type ResourceKind string

const (
	ResourceCompartment ResourceKind = "compartment"
	ResourceVCN         ResourceKind = "vcn"
	ResourceNSG         ResourceKind = "nsg"
	ResourceVault       ResourceKind = "vault"
	ResourceBucket      ResourceKind = "bucket"
	ResourceHost        ResourceKind = "host"
	ResourceEdge        ResourceKind = "cloudflare"
)

type ShapeCandidate struct {
	AvailabilityDomain, Shape string
	OCPUs, MemoryGiB          float64
}
type NetworkRule struct {
	Direction, Protocol, Peer string
	PortMin, PortMax          uint16
}
type HostSpec struct {
	Name          string           `json:"name"`
	PlacementLock string           `json:"placementLock"`
	Candidates    []ShapeCandidate `json:"candidates"`
	ImageID       string           `json:"imageId"`
	SubnetCIDR    string           `json:"subnetCIDR"`
	NSGName       string           `json:"nsgName"`
	DataVolumeGiB uint64           `json:"dataVolumeGiB"`
	CloudInit     string           `json:"cloudInit"`
}

type Step struct {
	ID              string             `json:"id"`
	Kind            ResourceKind       `json:"kind"`
	Name            string             `json:"name"`
	DependsOn       []string           `json:"dependsOn,omitempty"`
	Compartment     string             `json:"compartment,omitempty"`
	VCN             string             `json:"vcn,omitempty"`
	CIDR            string             `json:"cidr,omitempty"`
	Rules           []NetworkRule      `json:"rules,omitempty"`
	VaultProtection string             `json:"vaultProtection,omitempty"`
	Bucket          *BucketSpec        `json:"bucket,omitempty"`
	VaultName       string             `json:"vaultName,omitempty"`
	VaultKeyName    string             `json:"vaultKeyName,omitempty"`
	Host            *HostSpec          `json:"host,omitempty"`
	Edge            *EdgeBootstrapSpec `json:"edge,omitempty"`
	IdempotencyKey  string             `json:"idempotencyKey"`
}

type Plan struct {
	Steps       []Step `json:"steps"`
	Fingerprint string `json:"fingerprint"`
}

func (p Plan) Validate() error {
	if len(p.Steps) == 0 || len(p.Steps) > BootstrapMaxSteps || p.Fingerprint == "" {
		return ErrInvalidBootstrap
	}
	without := p
	without.Fingerprint = ""
	raw, err := json.Marshal(without)
	if err != nil {
		return ErrInvalidBootstrap
	}
	hash := sha256.Sum256(raw)
	if p.Fingerprint != hex.EncodeToString(hash[:]) {
		return ErrFingerprintMismatch
	}
	seen := map[string]bool{}
	for _, step := range p.Steps {
		if step.ID == "" || step.IdempotencyKey == "" || seen[step.ID] {
			return ErrInvalidBootstrap
		}
		switch step.Kind {
		case ResourceCompartment, ResourceVCN, ResourceNSG, ResourceVault, ResourceBucket, ResourceHost, ResourceEdge:
		default:
			return ErrInvalidBootstrap
		}
		deps := map[string]bool{}
		for _, dependency := range step.DependsOn {
			if dependency == "" || deps[dependency] || !seen[dependency] {
				return ErrInvalidBootstrap
			}
			deps[dependency] = true
		}
		seen[step.ID] = true
	}
	return nil
}

func PlanBootstrap(c BootstrapConfig) (Plan, error) {
	if err := c.Validate(); err != nil {
		return Plan{}, err
	}
	steps := []Step{
		{ID: "compartment", Kind: ResourceCompartment, Name: c.CompartmentName},
		{ID: "vcn", Kind: ResourceVCN, Name: c.VCNName, DependsOn: []string{"compartment"}, Compartment: c.CompartmentName, CIDR: c.VCNCIDR},
		{ID: "nsg", Kind: ResourceNSG, Name: c.NSGName, DependsOn: []string{"vcn"}, VCN: c.VCNName, Rules: defaultNetworkRules(c.VCNCIDR)},
		{ID: "vault", Kind: ResourceVault, Name: c.VaultName, DependsOn: []string{"compartment"}, Compartment: c.CompartmentName, VaultName: c.VaultName, VaultKeyName: c.VaultKeyName, VaultProtection: "software"},
	}
	for i := range c.Buckets {
		bucket := c.Buckets[i]
		id := "bucket-" + bucket.Name
		steps = append(steps, Step{ID: id, Kind: ResourceBucket, Name: bucket.Name, DependsOn: []string{"compartment"}, Compartment: c.CompartmentName, Bucket: &bucket})
	}
	// Host user-data is supplied later by the admitted control seed. Keeping
	// this planning model free of a second renderer prevents stale bootstrap
	// instructions from reaching OCI.
	steps = append(steps,
		Step{ID: "host-1", Kind: ResourceHost, Name: "gru-member-1", DependsOn: []string{"vcn", "nsg", "vault"}, Compartment: c.CompartmentName, VCN: c.VCNName, Host: &HostSpec{Name: "gru-member-1", PlacementLock: "GRU/member/1", Candidates: hostCandidates(c), ImageID: c.ImageID, SubnetCIDR: c.SubnetCIDR, NSGName: c.NSGName, DataVolumeGiB: c.DataVolumeGiB}},
		Step{ID: "host-2", Kind: ResourceHost, Name: "gru-member-2", DependsOn: []string{"vcn", "nsg", "vault"}, Compartment: c.CompartmentName, VCN: c.VCNName, Host: &HostSpec{Name: "gru-member-2", PlacementLock: "GRU/member/2", Candidates: hostCandidates(c), ImageID: c.ImageID, SubnetCIDR: c.SubnetCIDR, NSGName: c.NSGName, DataVolumeGiB: c.DataVolumeGiB}},
	)
	if c.Edge != nil {
		edge := *c.Edge
		steps = append(steps, Step{ID: "cloudflare", Kind: ResourceEdge, Name: edge.Zone, DependsOn: []string{"host-1", "host-2"}, Edge: &edge})
	}
	for i := range steps {
		steps[i].IdempotencyKey = stableStepKey(c, steps[i])
	}
	plan := Plan{Steps: steps}
	without := plan
	without.Fingerprint = ""
	raw, _ := json.Marshal(without)
	sum := sha256.Sum256(raw)
	plan.Fingerprint = hex.EncodeToString(sum[:])
	return plan, nil
}

// DryRun is the side-effect-free bootstrap entry point.  It performs no
// credential resolution and makes no provider calls.
func DryRun(c BootstrapConfig) (Plan, error) { return PlanBootstrap(c) }

// RenderDryRun returns canonical JSON suitable for the bootstrap command's
// runbook output.  It is stable for identical inputs and contains no secrets.
func RenderDryRun(c BootstrapConfig) ([]byte, error) {
	plan, err := PlanBootstrap(c)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(plan, "", "  ")
}

// BootstrapPlan is an alias for callers that prefer noun-first naming.
func BootstrapPlan(c BootstrapConfig) (Plan, error) { return PlanBootstrap(c) }

func hostCandidates(c BootstrapConfig) []ShapeCandidate {
	out := make([]ShapeCandidate, 0, len(c.AvailabilityDomains)*2)
	for _, ad := range c.AvailabilityDomains {
		out = append(out, ShapeCandidate{ad, c.PrimaryShape, c.OCPUs, c.MemoryGiB}, ShapeCandidate{ad, c.FallbackShape, c.OCPUs, c.MemoryGiB})
	}
	return out
}
func defaultNetworkRules(cidr string) []NetworkRule {
	return []NetworkRule{{"ingress", "tcp", "0.0.0.0/0", 443, 443}, {"ingress", "tcp", cidr, 9090, 9091}, {"egress", "tcp", "0.0.0.0/0", 443, 443}}
}
func stableStepKey(c BootstrapConfig, step Step) string {
	raw, _ := json.Marshal(struct {
		Tenancy, Region string
		Step            Step
	}{c.TenancyID, c.OCIRegion, step})
	sum := sha256.Sum256(raw)
	return "bootstrap-" + hex.EncodeToString(sum[:])[:48]
}

// ResourceReceipt contains provider identity only.  Secret material is never
// accepted by the bootstrap journal.
type ResourceReceipt struct{ ID, ETag, WorkRequestID string }

type ProviderRequest struct {
	Step           Step
	IdempotencyKey string
	Credential     CredentialLease
}
type CompartmentProvider interface {
	EnsureCompartment(context.Context, ProviderRequest) (ResourceReceipt, error)
}
type NetworkProvider interface {
	EnsureVCN(context.Context, ProviderRequest) (ResourceReceipt, error)
	EnsureNSG(context.Context, ProviderRequest) (ResourceReceipt, error)
}
type VaultProvider interface {
	EnsureVault(context.Context, ProviderRequest) (ResourceReceipt, error)
}
type BucketProvider interface {
	EnsureBucket(context.Context, ProviderRequest) (ResourceReceipt, error)
}
type HostProvider interface {
	EnsureHost(context.Context, ProviderRequest) (ResourceReceipt, error)
}
type EdgeProvider interface {
	EnsureEdge(context.Context, ProviderRequest) (ResourceReceipt, error)
}

// PlacementProvider is separate from compute so a host cannot be launched
// merely because a provider happens to have capacity.  Its lock is the
// durable seat identity used by replacement and reconciliation.
type PlacementProvider interface {
	AcquirePlacement(context.Context, string, string) error
}

type Providers struct {
	Compartment CompartmentProvider
	Network     NetworkProvider
	Vault       VaultProvider
	Bucket      BucketProvider
	Host        HostProvider
	Placement   PlacementProvider
	Edge        EdgeProvider
}

type CredentialRequest struct{ TenancyID, RegionCode, OCIRegion string }
type CredentialLease struct {
	Token     string
	ExpiresAt time.Time
}
type CredentialProvider interface {
	Resolve(context.Context, CredentialRequest) (CredentialLease, error)
}

func validCredentialLease(lease CredentialLease, now time.Time) bool {
	return lease.Token != "" && len(lease.Token) <= 8192 && !strings.ContainsAny(lease.Token, "\r\n\x00") && lease.ExpiresAt.After(now)
}

type JournalState string

const (
	JournalPrepared  JournalState = "prepared"
	JournalSubmitted JournalState = "submitted"
	JournalSucceeded JournalState = "succeeded"
	JournalFailed    JournalState = "failed"
)

type JournalRecord struct {
	StepID, Fingerprint string
	State               JournalState
	Attempts            int
	Receipt             ResourceReceipt
	Failure             string
}
type DurableJournal interface {
	AuthoritativeDurable() bool
	Prepare(context.Context, string, string) (JournalRecord, error)
	MarkSubmitted(context.Context, string, string, int) (JournalRecord, error)
	MarkSucceeded(context.Context, string, string, ResourceReceipt) (JournalRecord, error)
	MarkFailed(context.Context, string, string, string) (JournalRecord, error)
}

type RetryPolicy struct {
	MaxAttempts int
	Backoff     func(context.Context, int) error
}

func (p RetryPolicy) Validate() error {
	if p.MaxAttempts < 1 || p.MaxAttempts > 16 {
		return errors.New("bootstrap retry attempts must be between 1 and 16")
	}
	return nil
}

type ExecutionResult struct {
	PlanFingerprint string
	Completed       []string
	Skipped         []string
	Attempts        map[string]int
	Canceled        bool
}
type Executor struct {
	Providers   Providers
	Journal     DurableJournal
	Credentials CredentialProvider
	Retry       RetryPolicy
	Now         func() time.Time
}

func NewExecutor(providers Providers, journal DurableJournal, credentials CredentialProvider, retry RetryPolicy) (*Executor, error) {
	if journal == nil || !journal.AuthoritativeDurable() {
		return nil, ErrJournalUnavailable
	}
	if credentials == nil {
		return nil, ErrCredentialsUnavailable
	}
	if err := retry.Validate(); err != nil {
		return nil, err
	}
	return &Executor{Providers: providers, Journal: journal, Credentials: credentials, Retry: retry, Now: time.Now}, nil
}

func (e *Executor) Execute(ctx context.Context, plan Plan, c BootstrapConfig) (ExecutionResult, error) {
	result := ExecutionResult{PlanFingerprint: plan.Fingerprint, Attempts: map[string]int{}}
	if e == nil || e.Journal == nil || !e.Journal.AuthoritativeDurable() || e.Credentials == nil {
		return result, ErrJournalUnavailable
	}
	if ctx == nil {
		return result, errors.New("bootstrap context is nil")
	}
	if err := plan.Validate(); err != nil {
		return result, err
	}
	if err := c.Validate(); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		result.Canceled = true
		return result, err
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	lease, err := e.Credentials.Resolve(ctx, CredentialRequest{c.TenancyID, c.RegionCode, c.OCIRegion})
	if err != nil || !validCredentialLease(lease, now) {
		return result, ErrCredentialsUnavailable
	}
	if err := validateDependencies(plan); err != nil {
		return result, err
	}
	for _, step := range plan.Steps {
		if err := ctx.Err(); err != nil {
			result.Canceled = true
			return result, err
		}
		checkNow := time.Now()
		if e.Now != nil {
			checkNow = e.Now()
		}
		if !validCredentialLease(lease, checkNow) {
			return result, ErrCredentialsUnavailable
		}
		record, err := e.Journal.Prepare(ctx, step.ID, step.IdempotencyKey)
		if err != nil {
			return result, err
		}
		if record.Fingerprint != "" && record.Fingerprint != step.IdempotencyKey {
			return result, ErrFingerprintMismatch
		}
		if record.State == JournalSucceeded {
			result.Skipped = append(result.Skipped, step.ID)
			continue
		}
		if record.State == JournalFailed {
			return result, ErrPreviouslyFailed
		}
		if record.State != "" && record.State != JournalPrepared && record.State != JournalSubmitted {
			return result, ErrInvalidBootstrap
		}
		if err := e.executeStep(ctx, step, lease, record, &result); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				result.Canceled = true
			}
			return result, err
		}
		result.Completed = append(result.Completed, step.ID)
	}
	return result, nil
}

func validateDependencies(plan Plan) error {
	known := map[string]bool{}
	for _, step := range plan.Steps {
		for _, dep := range step.DependsOn {
			if !known[dep] {
				return ErrInvalidBootstrap
			}
		}
		known[step.ID] = true
	}
	return nil
}

func (e *Executor) executeStep(ctx context.Context, step Step, lease CredentialLease, record JournalRecord, result *ExecutionResult) error {
	if step.Kind == ResourceHost && (e.Providers.Host == nil || e.Providers.Placement == nil || step.Host == nil) {
		return ErrInvalidBootstrap
	}
	attempt := record.Attempts
	if attempt < 0 {
		return ErrInvalidBootstrap
	}
	// A crash can leave the durable record at the attempt ceiling while the
	// provider outcome is unresolved.  Re-run that same idempotent request once
	// to reconcile it; never invent a replacement key.
	if attempt >= e.Retry.MaxAttempts {
		attempt = e.Retry.MaxAttempts - 1
	}
	for n := attempt; n < e.Retry.MaxAttempts; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if n == attempt && step.Kind == ResourceHost {
			if err := e.Providers.Placement.AcquirePlacement(ctx, step.Host.PlacementLock, step.ID); err != nil {
				return fmt.Errorf("%w: %v", ErrPlacementLocked, err)
			}
		}
		if _, err := e.Journal.MarkSubmitted(ctx, step.ID, step.IdempotencyKey, n+1); err != nil {
			return err
		}
		result.Attempts[step.ID] = n + 1
		receipt, err := e.callProvider(ctx, step, lease)
		if err == nil {
			_, err = e.Journal.MarkSucceeded(ctx, step.ID, step.IdempotencyKey, receipt)
			return err
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if !retryable(err) || n+1 >= e.Retry.MaxAttempts {
			_, markErr := e.Journal.MarkFailed(ctx, step.ID, step.IdempotencyKey, "provider-failed")
			if markErr != nil {
				return markErr
			}
			return err
		}
		if e.Retry.Backoff != nil {
			if waitErr := e.Retry.Backoff(ctx, n+1); waitErr != nil {
				return waitErr
			}
		}
	}
	return errors.New("bootstrap retry exhausted")
}

type permanentError interface{ Permanent() bool }

func retryable(err error) bool { var p permanentError; return !errors.As(err, &p) || !p.Permanent() }

func (e *Executor) callProvider(ctx context.Context, step Step, lease CredentialLease) (ResourceReceipt, error) {
	req := ProviderRequest{Step: step, IdempotencyKey: step.IdempotencyKey, Credential: lease}
	switch step.Kind {
	case ResourceCompartment:
		if e.Providers.Compartment == nil {
			return ResourceReceipt{}, ErrInvalidBootstrap
		}
		return e.Providers.Compartment.EnsureCompartment(ctx, req)
	case ResourceVCN, ResourceNSG:
		if e.Providers.Network == nil {
			return ResourceReceipt{}, ErrInvalidBootstrap
		}
		if step.Kind == ResourceVCN {
			return e.Providers.Network.EnsureVCN(ctx, req)
		}
		return e.Providers.Network.EnsureNSG(ctx, req)
	case ResourceVault:
		if e.Providers.Vault == nil {
			return ResourceReceipt{}, ErrInvalidBootstrap
		}
		return e.Providers.Vault.EnsureVault(ctx, req)
	case ResourceBucket:
		if e.Providers.Bucket == nil {
			return ResourceReceipt{}, ErrInvalidBootstrap
		}
		return e.Providers.Bucket.EnsureBucket(ctx, req)
	case ResourceHost:
		if e.Providers.Host == nil {
			return ResourceReceipt{}, ErrInvalidBootstrap
		}
		return e.Providers.Host.EnsureHost(ctx, req)
	case ResourceEdge:
		if e.Providers.Edge == nil {
			return ResourceReceipt{}, ErrInvalidBootstrap
		}
		return e.Providers.Edge.EnsureEdge(ctx, req)
	default:
		return ResourceReceipt{}, ErrInvalidBootstrap
	}
}

// FileJournal is a small durable reference implementation for recovery tests
// and the standalone bootstrap command.  Every mutation rewrites a bounded
// JSON file and calls Sync before returning.  Production may replace it with
// the JetStream-backed journal through DurableJournal.
type FileJournal struct {
	mu      sync.Mutex
	path    string
	records map[string]JournalRecord
}

func NewFileJournal(path string) (*FileJournal, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrJournalUnavailable
	}
	f := &FileJournal{path: path, records: map[string]JournalRecord{}}
	if raw, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(raw, &f.records) != nil {
			return nil, ErrJournalUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrJournalUnavailable
	}
	return f, nil
}
func (j *FileJournal) AuthoritativeDurable() bool { return j != nil && j.path != "" }
func (j *FileJournal) Prepare(ctx context.Context, id, fp string) (JournalRecord, error) {
	if ctx == nil {
		return JournalRecord{}, ErrJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return JournalRecord{}, err
	}
	if id == "" || fp == "" {
		return JournalRecord{}, ErrInvalidBootstrap
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if prior := j.records[id]; prior.Fingerprint != "" {
		if prior.Fingerprint != fp {
			return JournalRecord{}, ErrFingerprintMismatch
		}
		return prior, nil
	}
	next := JournalRecord{StepID: id, Fingerprint: fp, State: JournalPrepared}
	j.records[id] = next
	if err := j.sync(); err != nil {
		return JournalRecord{}, err
	}
	return next, nil
}
func (j *FileJournal) MarkSubmitted(ctx context.Context, id, fp string, n int) (JournalRecord, error) {
	return j.transition(ctx, id, fp, JournalSubmitted, n, ResourceReceipt{}, "")
}
func (j *FileJournal) MarkSucceeded(ctx context.Context, id, fp string, r ResourceReceipt) (JournalRecord, error) {
	return j.transition(ctx, id, fp, JournalSucceeded, 0, r, "")
}
func (j *FileJournal) MarkFailed(ctx context.Context, id, fp, reason string) (JournalRecord, error) {
	return j.transition(ctx, id, fp, JournalFailed, 0, ResourceReceipt{}, reason)
}
func (j *FileJournal) transition(ctx context.Context, id, fp string, state JournalState, attempt int, receipt ResourceReceipt, failure string) (JournalRecord, error) {
	if ctx == nil {
		return JournalRecord{}, ErrJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return JournalRecord{}, err
	}
	if id == "" || fp == "" {
		return JournalRecord{}, ErrInvalidBootstrap
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	prior := j.records[id]
	if prior.Fingerprint != "" && prior.Fingerprint != fp {
		return JournalRecord{}, ErrFingerprintMismatch
	}
	if prior.State == JournalSucceeded {
		return prior, nil
	}
	next := JournalRecord{StepID: id, Fingerprint: fp, State: state, Attempts: attempt, Receipt: receipt, Failure: failure}
	j.records[id] = next
	if err := j.sync(); err != nil {
		return JournalRecord{}, err
	}
	return next, nil
}
func (j *FileJournal) sync() error {
	raw, err := json.Marshal(j.records)
	if err != nil {
		return ErrJournalUnavailable
	}
	if len(raw) > 1<<20 {
		return ErrJournalUnavailable
	}
	dir := filepath.Dir(j.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ErrJournalUnavailable
	}
	tmp, err := os.CreateTemp(dir, ".bootstrap-journal-")
	if err != nil {
		return ErrJournalUnavailable
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return ErrJournalUnavailable
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return ErrJournalUnavailable
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return ErrJournalUnavailable
	}
	if err := tmp.Close(); err != nil {
		return ErrJournalUnavailable
	}
	if err := os.Rename(name, j.path); err != nil {
		return ErrJournalUnavailable
	}
	return nil
}

// Keep deterministic ordering available to callers rendering human dry-run
// output, regardless of how a provider stores bucket or edge declarations.
func SortSteps(steps []Step) []Step {
	out := append([]Step(nil), steps...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
