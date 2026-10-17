// Package principal creates only disposable image-qualification OCI identities.
// It is test infrastructure, never production FoundationGrant authority.
package principal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

const (
	ApprovalDomain    = "terrascale.test.image-qualification"
	PreparationSchema = "terrascale.test.image-qualification.principal.v1"
	GroupPlaceholder  = "PREPARED_GROUP"
	maxLifetime       = 72 * time.Hour
)

var (
	runPattern     = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
	hostPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
	identifier     = regexp.MustCompile(`^[a-zA-Z0-9._:/-]+$`)
	subjectPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
)

// HostSpec pins the same finite native hosts as the later host approval.
type HostSpec struct {
	Name               string  `json:"name"`
	Role               string  `json:"role"`
	AvailabilityDomain string  `json:"availability_domain"`
	FaultDomain        string  `json:"fault_domain"`
	Shape              string  `json:"shape"`
	OCPUs              float32 `json:"ocpus"`
	MemoryGB           float32 `json:"memory_gb"`
	BootGB             int64   `json:"boot_gb"`
}

type MaterialApproval struct {
	Scenario              string `json:"scenario"`
	SignedProfileSHA256   string `json:"signed_profile_sha256"`
	ContainerIntentSHA256 string `json:"container_intent_sha256"`
}

type ContainerArtifactApproval struct {
	Role          string `json:"role"`
	Image         string `json:"image"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

// Preparation is signed before any IAM write. Its envelope ends at CleanupUntil;
// ExpiresAt independently ends creation, so cleanup never renews create authority.
type Preparation struct {
	Schema                  string                               `json:"schema"`
	RunID                   string                               `json:"run_id"`
	Candidate               release.ProductionExpectation        `json:"candidate"`
	Tenancy                 string                               `json:"tenancy"`
	IssuerPrincipal         string                               `json:"issuer_principal"`
	IssuerFingerprint       string                               `json:"issuer_fingerprint"`
	OCIRegion               string                               `json:"oci_region"`
	IAMRegion               string                               `json:"iam_region"`
	PrincipalName           string                               `json:"principal_name"`
	GroupName               string                               `json:"group_name"`
	PolicyName              string                               `json:"policy_name"`
	PublicKeyPEM            string                               `json:"public_key_pem"`
	PublicKeyFingerprint    string                               `json:"public_key_fingerprint"`
	Compartment             string                               `json:"compartment"`
	Subnet                  string                               `json:"subnet"`
	Namespace               string                               `json:"namespace"`
	Bucket                  string                               `json:"bucket"`
	Object                  string                               `json:"object"`
	PolicyTemplate          []string                             `json:"policy_template"`
	ProductionDynamicGroups []confinement.ProductionDynamicGroup `json:"production_dynamic_groups"`
	ProfileIdentity         cellspec.Identity                    `json:"profile_identity"`
	ContainerArtifacts      []ContainerArtifactApproval          `json:"container_artifacts"`
	ClientSHA256            string                               `json:"client_sha256"`
	KernelRelease           string                               `json:"kernel_release"`
	MaterialFixtures        []MaterialApproval                   `json:"material_fixtures"`
	RunnerCIDR              string                               `json:"runner_cidr"`
	PeerCIDR                string                               `json:"peer_cidr"`
	VCNCIDR                 string                               `json:"vcn_cidr"`
	WorkloadImage           string                               `json:"workload_image"`
	WorkloadArchiveSHA256   string                               `json:"workload_archive_sha256"`
	ImageBytes              int64                                `json:"image_bytes"`
	MaxSpendMicros          int64                                `json:"max_spend_usd_micros"`
	Hosts                   []HostSpec                           `json:"hosts"`
	BinarySHA256            string                               `json:"binary_sha256"`
	KernelSHA256            string                               `json:"kernel_sha256"`
	ContainerdSHA256        string                               `json:"containerd_sha256"`
	RuncSHA256              string                               `json:"runc_sha256"`
	RunnerSHA256            string                               `json:"runner_sha256"`
	ExpiresAt               time.Time                            `json:"expires_at"`
	CleanupUntil            time.Time                            `json:"cleanup_until"`
}

func PreparationScope(runID string, c release.ProductionExpectation) trust.Scope {
	return trust.Scope{Domain: ApprovalDomain, DeploymentID: entityid.Derive("qualification", runID), Cell: c.Cell,
		Environment: "qualification", Role: "disposable-principal", Slot: c.Runtime + "/linux-" + c.Architecture}
}

// VerifiedPreparation retains the original authority for revalidation at every write.
type VerifiedPreparation struct {
	preparation      Preparation
	wire, delegation []byte
	roots            trust.Keyring
	digest           string
}

func (v VerifiedPreparation) Preparation() Preparation {
	p := v.preparation
	p.Hosts = slices.Clone(p.Hosts)
	p.PolicyTemplate = slices.Clone(p.PolicyTemplate)
	p.ProductionDynamicGroups = slices.Clone(p.ProductionDynamicGroups)
	p.ContainerArtifacts = slices.Clone(p.ContainerArtifacts)
	p.MaterialFixtures = slices.Clone(p.MaterialFixtures)
	return p
}

func (v VerifiedPreparation) SHA256() string { return v.digest }

func VerifyPreparation(wire, delegation []byte, roots trust.Keyring, runID string, now time.Time) (VerifiedPreparation, error) {
	var empty VerifiedPreparation
	e, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return empty, err
	}
	var p Preparation
	if err := protocol.DecodeStrict(e.Payload, &p, trust.MaxPayloadBytes); err != nil {
		return empty, err
	}
	if p.RunID != runID {
		return empty, errors.New("principal preparation run differs")
	}
	scope := PreparationScope(runID, p.Candidate)
	policy := trust.Policy{MaxLifetime: maxLifetime}
	var payload []byte
	if len(delegation) == 0 {
		payload, err = trust.VerifyCurrent(e, scope, roots, now, policy)
	} else {
		var de trust.Envelope
		de, err = trust.DecodeEnvelope(delegation)
		if err == nil {
			var verified trust.VerifiedDelegation
			verified, err = trust.VerifyDelegationCurrent(de, roots, now, policy)
			if err == nil {
				// The same original delegate must also be able to sign the exact host role.
				host := scope
				host.Role = "disposable-host"
				if !allows(verified.Capabilities(), host) {
					return empty, errors.New("qualifier delegation lacks exact disposable-host role")
				}
				payload, err = trust.VerifyDelegatedCurrent(e, scope, verified, now, policy)
			}
		}
	}
	if err != nil {
		return empty, err
	}
	if !bytes.Equal(payload, e.Payload) {
		return empty, errors.New("verified preparation payload differs")
	}
	if err := p.validate(e, now); err != nil {
		return empty, err
	}
	cloned := maps.Clone(roots)
	for key, value := range cloned {
		cloned[key] = slices.Clone(value)
	}
	return VerifiedPreparation{preparation: p, wire: slices.Clone(wire), delegation: slices.Clone(delegation), roots: cloned, digest: hash(wire)}, nil
}

func allows(capabilities []trust.Capability, s trust.Scope) bool {
	for _, c := range capabilities {
		if c.Domain == s.Domain && c.DeploymentID == s.DeploymentID && c.Cell == s.Cell && c.Environment == s.Environment && c.Role == s.Role && slices.Contains(c.Slots, s.Slot) && slices.Contains(c.Actions, "sign") {
			return true
		}
	}
	return false
}

func (p Preparation) scope(group string) confinement.Scope {
	names := make([]string, len(p.Hosts))
	for i, h := range p.Hosts {
		names[i] = h.Name
	}
	return confinement.Scope{RunID: p.RunID, Tenancy: p.Tenancy, Group: group, Compartment: p.Compartment, Subnet: p.Subnet,
		IAMRegion: p.IAMRegion, ProductionDynamicGroups: slices.Clone(p.ProductionDynamicGroups),
		Namespace: p.Namespace, Bucket: p.Bucket, Object: p.Object, RunnerCIDR: p.RunnerCIDR, PeerCIDR: p.PeerCIDR, VCNCIDR: p.VCNCIDR,
		HostNames: names, ExpiresAt: p.ExpiresAt, CleanupUntil: p.CleanupUntil}
}

// RequiredTemplate is canonical; only GroupPlaceholder may become an observed ID.
func RequiredTemplate(p Preparation) []string {
	return confinement.RequiredStatements(p.scope(GroupPlaceholder))
}

func (p Preparation) validate(e trust.Envelope, now time.Time) error {
	c := p.Candidate
	if p.Schema != PreparationSchema || !runPattern.MatchString(p.RunID) || !release.ValidSourceRevision(c.SourceRevision) ||
		!release.ValidEnvironment(c.Environment) ||
		(c.Architecture != "arm64" && c.Architecture != "amd64") || catalog.OCIRegion(c.Cell) != p.OCIRegion || !catalog.IsOCIRegion(p.IAMRegion) {
		return errors.New("invalid principal preparation candidate or region")
	}
	for _, digest := range []string{c.ArtifactSHA256, c.QualificationSHA256, p.BinarySHA256, p.KernelSHA256, p.ContainerdSHA256, p.RuncSHA256, p.RunnerSHA256} {
		if !validHash(digest) {
			return errors.New("exact qualification component hashes required")
		}
	}
	roles, err := p.validateRole()
	if err != nil {
		return err
	}
	if p.KernelRelease == "" || strings.ContainsAny(p.KernelRelease, "\r\n") {
		return errors.New("exact final kernel release required")
	}
	if !strings.HasPrefix(p.Tenancy, "ocid1.tenancy.") || !strings.HasPrefix(p.IssuerPrincipal, "ocid1.user.") || !strings.HasPrefix(p.Compartment, "ocid1.compartment.") || !strings.HasPrefix(p.Subnet, "ocid1.subnet.") {
		return errors.New("exact OCI tenancy, issuer and disposable resource IDs required")
	}
	for _, value := range []string{p.Tenancy, p.IssuerPrincipal, p.Compartment, p.Subnet, p.Namespace, p.Bucket, p.Object} {
		if !identifier.MatchString(value) {
			return errors.New("invalid principal preparation identifier")
		}
	}
	name := "ts-qualification-" + p.RunID
	if p.PrincipalName != name+"-user" || p.GroupName != name+"-group" || p.PolicyName != name+"-policy" || p.Object != "qualification/"+p.RunID+"/"+c.ArtifactSHA256+".qcow2" {
		return errors.New("disposable names or object differ from deterministic run identity")
	}
	if p.ImageBytes < 8 || p.ImageBytes > 64<<30 || p.MaxSpendMicros <= 0 || p.MaxSpendMicros > 100_000_000 || len(p.Hosts) != len(roles) {
		return errors.New("finite image, native HA hosts and spending bounds required")
	}
	seen := map[string]bool{}
	for i, h := range p.Hosts {
		if h.Role != roles[i] || c.Architecture == "arm64" && h.Shape != imageimport.A1Shape || !hostPattern.MatchString(h.Name) || seen[h.Name] || h.AvailabilityDomain == "" || h.FaultDomain == "" || h.Shape == "" || !(h.OCPUs > 0 && h.OCPUs <= 80) || !(h.MemoryGB > 0 && h.MemoryGB <= 1024) || h.BootGB < 50 || h.BootGB > 1024 {
			return errors.New("invalid disposable host bounds")
		}
		seen[h.Name] = true
	}
	if p.ExpiresAt.Location() != time.UTC || p.CleanupUntil.Location() != time.UTC || !p.ExpiresAt.After(e.IssuedAt) || p.ExpiresAt.Sub(e.IssuedAt) > 48*time.Hour || !p.CleanupUntil.Equal(e.ExpiresAt) || p.CleanupUntil.Before(p.ExpiresAt) || p.CleanupUntil.Sub(p.ExpiresAt) > 24*time.Hour || !now.Before(p.CleanupUntil) {
		return errors.New("finite signed creation and cleanup deadlines required")
	}
	for _, value := range []string{p.RunnerCIDR, p.PeerCIDR, p.VCNCIDR} {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix != prefix.Masked() || (value != p.VCNCIDR && prefix.Bits() < 24) {
			return errors.New("canonical private runner, peer and VCN prefixes required")
		}
	}
	vcn, _ := netip.ParsePrefix(p.VCNCIDR)
	runner, _ := netip.ParsePrefix(p.RunnerCIDR)
	peer, _ := netip.ParsePrefix(p.PeerCIDR)
	if !vcn.Contains(runner.Addr()) || !vcn.Contains(peer.Addr()) || vcn.Bits() > min(runner.Bits(), peer.Bits()) || runner.Overlaps(peer) {
		return errors.New("disjoint private subnets in isolated VCN required")
	}
	if !slices.Equal(p.PolicyTemplate, RequiredTemplate(p)) {
		return errors.New("principal policy differs from canonical finite operation template")
	}
	groups, names := map[string]bool{}, map[string]bool{}
	for _, profile := range p.ProductionDynamicGroups {
		if !strings.HasPrefix(profile.ID, "ocid1.dynamicgroup.") || !identifier.MatchString(profile.ID) || !subjectPattern.MatchString(profile.Name) || !strings.HasPrefix(profile.InstanceCompartment, "ocid1.compartment.") || !identifier.MatchString(profile.InstanceCompartment) || profile.InstanceCompartment == p.Compartment || groups[profile.ID] || names[strings.ToLower(profile.Name)] {
			return errors.New("invalid or overlapping signed production dynamic group")
		}
		groups[profile.ID] = true
		names[strings.ToLower(profile.Name)] = true
	}
	public, fingerprint, err := publicIdentity([]byte(p.PublicKeyPEM))
	if err != nil || public != p.PublicKeyPEM || fingerprint != p.PublicKeyFingerprint || fingerprint == p.IssuerFingerprint || !validFingerprint(p.IssuerFingerprint) {
		return errors.New("exact canonical public key and API fingerprints required")
	}
	return nil
}

func (p Preparation) validateRole() ([]string, error) {
	c := p.Candidate
	switch {
	case c.Role == "orchestrator" && c.Runtime == release.ProductionRuntime:
		if !entityid.Valid(p.ProfileIdentity.DeploymentID) || p.ProfileIdentity.Cell != c.Cell || p.ProfileIdentity.Environment != c.Environment {
			return nil, errors.New("signed production profile identity differs from candidate")
		}
		scenarios := []string{"ready", "after-loss", "after-partition", "unready", "failed-update"}
		if len(p.MaterialFixtures) != len(scenarios) || len(p.ContainerArtifacts) != 0 || p.ClientSHA256 != "" || !validHash(p.WorkloadArchiveSHA256) || !immutableImage(p.WorkloadImage) {
			return nil, errors.New("exact native material fixtures and immutable workload required")
		}
		for i, fixture := range p.MaterialFixtures {
			if fixture.Scenario != scenarios[i] || !validHash(fixture.SignedProfileSHA256) || !validHash(fixture.ContainerIntentSHA256) {
				return nil, errors.New("native material scenario or signed hashes differ")
			}
		}
		return []string{"manager", "manager", "manager", "worker"}, nil
	case c.Role == "netbird-manager" && c.Runtime == "netbird-containerd" && c.Cell == "GRU" && c.Architecture == "arm64":
		if len(p.MaterialFixtures) != 0 || p.ProfileIdentity != (cellspec.Identity{}) || p.WorkloadImage != "" || p.WorkloadArchiveSHA256 != "" || !validHash(p.ClientSHA256) || len(p.ContainerArtifacts) != 3 {
			return nil, errors.New("dedicated NetBird requires exact archives and native client")
		}
		for i, role := range []string{"server", "dashboard", "ingress"} {
			artifact := p.ContainerArtifacts[i]
			if artifact.Role != role || !immutableImage(artifact.Image) || !validHash(artifact.ArchiveSHA256) {
				return nil, errors.New("NetBird component role or immutable archive differs")
			}
		}
		return []string{"netbird-primary", "netbird-replacement"}, nil
	default:
		return nil, errors.New("unrecognized fixed native qualification role")
	}
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func immutableImage(value string) bool {
	parsed, err := reference.ParseNormalizedNamed(value)
	if err != nil || parsed.String() != value {
		return false
	}
	if _, tagged := parsed.(reference.Tagged); tagged {
		return false
	}
	canonical, ok := parsed.(reference.Canonical)
	return ok && canonical.Digest().Algorithm() == "sha256" && canonical.Digest().Validate() == nil
}

// Receipt contains public observed identities, without granting authority.
type Receipt struct {
	PreparationSHA256    string   `json:"preparation_sha256"`
	Principal            string   `json:"principal"`
	Group                string   `json:"group"`
	PolicyID             string   `json:"policy_id"`
	MembershipID         string   `json:"membership_id"`
	PublicKeyFingerprint string   `json:"public_key_fingerprint"`
	PolicyStatements     []string `json:"policy_statements"`
	Cleaned              bool     `json:"cleaned"`
}

// Result is sealed only after complete authenticated SDK preparation. Copying a
// public Receipt cannot manufacture the evidence required by the host signer.
type Result struct {
	receipt  Receipt
	factory  *ociclient.Factory
	prepared bool
}

func (r Result) Receipt() Receipt {
	receipt := r.receipt
	receipt.PolicyStatements = slices.Clone(receipt.PolicyStatements)
	return receipt
}
func (r Result) Prepared() bool               { return r.prepared && r.factory != nil }
func (r Result) MarshalJSON() ([]byte, error) { return json.Marshal(r.Receipt()) }

// CandidateFactory is for independent confinement observation before host execution.
func (r Result) CandidateFactory() *ociclient.Factory {
	if !r.Prepared() {
		return nil
	}
	return r.factory
}

// ValidatePreparation checks the sealed observed result against its original
// current finite authorization. Effective policy still requires confinement.
func (r Result) ValidatePreparation(v VerifiedPreparation, now time.Time) error {
	if !r.Prepared() || v.digest == "" {
		return errors.New("sealed SDK principal result and verified preparation required")
	}
	if _, err := VerifyPreparation(v.wire, v.delegation, v.roots, v.preparation.RunID, now); err != nil {
		return err
	}
	p := v.preparation
	receipt := r.receipt
	if !now.Before(p.ExpiresAt) || receipt.Cleaned || receipt.PreparationSHA256 != v.digest || receipt.PublicKeyFingerprint != p.PublicKeyFingerprint || !validID("user", receipt.Principal) || !validID("group", receipt.Group) || !validID("policy", receipt.PolicyID) || !validID("membership", receipt.MembershipID) || !slices.Equal(receipt.PolicyStatements, confinement.RequiredStatements(p.scope(receipt.Group))) {
		return errors.New("SDK principal result does not refine this exact finite preparation")
	}
	provider := r.factory.Provider()
	tenancy, err := provider.TenancyOCID()
	if err != nil {
		return err
	}
	user, err := provider.UserOCID()
	if err != nil {
		return err
	}
	fingerprint, err := provider.KeyFingerprint()
	if err != nil {
		return err
	}
	if tenancy != p.Tenancy || user != receipt.Principal || fingerprint != p.PublicKeyFingerprint || r.factory.Region() != p.OCIRegion {
		return errors.New("sealed candidate factory differs from observed result")
	}
	return nil
}

type Producer struct {
	issuer   *ociclient.Factory
	now      func() time.Time
	endpoint string // Package-local signed SDK HTTP fixtures only.
}

func New(issuer *ociclient.Factory) *Producer { return &Producer{issuer: issuer, now: time.Now} }

func (p *Producer) check(ctx context.Context, v VerifiedPreparation, cleanup bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.digest == "" {
		return errors.New("verified principal preparation required")
	}
	_, err := VerifyPreparation(v.wire, v.delegation, v.roots, v.preparation.RunID, p.now())
	if err != nil {
		return err
	}
	if !cleanup && !p.now().Before(v.preparation.ExpiresAt) {
		return errors.New("principal creation authority expired")
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if value, ok := os.LookupEnv(name); ok && value != "" {
			return errors.New("unsafe OCI SDK environment blocks principal operations")
		}
	}
	return nil
}

func hash(wire []byte) string { digest := sha256.Sum256(wire); return hex.EncodeToString(digest[:]) }
