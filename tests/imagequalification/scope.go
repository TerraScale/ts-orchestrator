// Package imagequalification prepares disposable final-image qualification.
// It is deliberately outside the production importer and launch paths.
package imagequalification

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

const (
	ApprovalDomain = "terrascale.test.image-qualification"
	ApprovalSchema = "terrascale.test.image-qualification.v1"
	maxRunLifetime = 72 * time.Hour
)

var runPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
var hostPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

// HostSpec is one exact, disposable host, never a desired production fleet.
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

// MaterialApproval pins existing signed production profile and intent bytes.
// The runner verifies their existing authority; these digests do not replace it.
type MaterialApproval struct {
	Scenario              string `json:"scenario"`
	SignedProfileSHA256   string `json:"signed_profile_sha256"`
	ContainerIntentSHA256 string `json:"container_intent_sha256"`
}

// ContainerArtifactApproval pins one offline component archive for NetBird.
type ContainerArtifactApproval struct {
	Role          string `json:"role"`
	Image         string `json:"image"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

// Approval is finite resource/spending authorization under existing trust roots.
// It does not establish effective IAM confinement or production qualification.
type Approval struct {
	Schema                  string                               `json:"schema"`
	RunID                   string                               `json:"run_id"`
	Candidate               release.ProductionExpectation        `json:"candidate"`
	IAMRegion               string                               `json:"iam_region"`
	OCIRegion               string                               `json:"oci_region"`
	Tenancy                 string                               `json:"tenancy"`
	Principal               string                               `json:"principal"`
	Compartment             string                               `json:"compartment"`
	Subnet                  string                               `json:"subnet"`
	Namespace               string                               `json:"namespace"`
	Bucket                  string                               `json:"bucket"`
	Group                   string                               `json:"group"`
	PolicyID                string                               `json:"policy_id"`
	ProductionDynamicGroups []confinement.ProductionDynamicGroup `json:"production_dynamic_groups"`
	ProfileIdentity         cellspec.Identity                    `json:"profile_identity"`
	ContainerArtifacts      []ContainerArtifactApproval          `json:"container_artifacts"`
	ClientSHA256            string                               `json:"client_sha256"`
	KernelRelease           string                               `json:"kernel_release"`
	MaterialFixtures        []MaterialApproval                   `json:"material_fixtures"`
	PolicyStatements        []string                             `json:"policy_statements"`
	RunnerCIDR              string                               `json:"runner_cidr"`
	PeerCIDR                string                               `json:"peer_cidr"`
	VCNCIDR                 string                               `json:"vcn_cidr"`
	WorkloadImage           string                               `json:"workload_image"`
	WorkloadArchiveSHA256   string                               `json:"workload_archive_sha256"`
	ImageBytes              int64                                `json:"image_bytes"`
	MaxSpendMicros          int64                                `json:"max_spend_usd_micros"`
	CleanupUntil            time.Time                            `json:"cleanup_until"`
	Hosts                   []HostSpec                           `json:"hosts"`
	BinarySHA256            string                               `json:"binary_sha256"`
	KernelSHA256            string                               `json:"kernel_sha256"`
	ContainerdSHA256        string                               `json:"containerd_sha256"`
	RuncSHA256              string                               `json:"runc_sha256"`
	RunnerSHA256            string                               `json:"runner_sha256"`
}

func ApprovalScope(runID string, candidate release.ProductionExpectation) trust.Scope {
	return trust.Scope{Domain: ApprovalDomain, DeploymentID: entityid.Derive("qualification", runID), Cell: candidate.Cell,
		Environment: "qualification", Role: "disposable-host", Slot: candidate.Runtime + "/linux-" + candidate.Architecture}
}

// Prepared binds locally verified inputs to their exact independently approved run.
// No exported execution entrypoint exists until OCI supplies authenticated,
// effective credential-policy confinement; an approval alone is insufficient.
type Prepared struct {
	approval       Approval
	issuedAt       time.Time
	expires        time.Time
	approvalSHA256 string
	approvalWire   []byte
	delegationWire []byte
	diskPath       string
}

func (p Prepared) Approval() Approval {
	a := p.approval
	a.Hosts = slices.Clone(a.Hosts)
	a.PolicyStatements = slices.Clone(a.PolicyStatements)
	a.ProductionDynamicGroups = slices.Clone(a.ProductionDynamicGroups)
	a.MaterialFixtures = slices.Clone(a.MaterialFixtures)
	a.ContainerArtifacts = slices.Clone(a.ContainerArtifacts)
	return a
}

func (p Prepared) ExpiresAt() time.Time { return p.expires }

// Prepare verifies scope, CI-manifest identity and the actual QCOW2 bytes before
// SDK construction. Accepted roots come from the caller's existing trust chain.
func Prepare(approvalWire, delegationWire []byte, roots trust.Keyring, expected release.ProductionExpectation,
	runID, diskPath, qualificationPath string, now time.Time) (Prepared, error) {
	var result Prepared
	envelope, err := trust.DecodeEnvelope(approvalWire)
	if err != nil {
		return result, err
	}
	policy := trust.Policy{MaxLifetime: maxRunLifetime}
	var payload []byte
	if len(delegationWire) == 0 {
		payload, err = trust.VerifyCurrent(envelope, ApprovalScope(runID, expected), roots, now, policy)
	} else {
		var delegationEnvelope trust.Envelope
		delegationEnvelope, err = trust.DecodeEnvelope(delegationWire)
		if err == nil {
			var delegation trust.VerifiedDelegation
			delegation, err = trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, policy)
			if err == nil {
				payload, err = trust.VerifyDelegatedCurrent(envelope, ApprovalScope(runID, expected), delegation, now, policy)
			}
		}
	}
	if err != nil {
		return result, fmt.Errorf("disposable run approval: %w", err)
	}
	var approval Approval
	if err := protocol.DecodeStrict(payload, &approval, trust.MaxPayloadBytes); err != nil {
		return result, err
	}
	if err := approval.validate(); err != nil {
		return result, err
	}
	if approval.RunID != runID || approval.Candidate != expected {
		return result, errors.New("approved run or candidate differs")
	}
	if approval.CleanupUntil.Before(envelope.ExpiresAt) || approval.CleanupUntil.After(envelope.ExpiresAt.Add(24*time.Hour)) {
		return result, errors.New("cleanup authority must end within 24 hours after run expiry")
	}
	qualificationWire, err := os.ReadFile(qualificationPath)
	if err != nil {
		return result, err
	}
	qualification, digest, err := release.DecodeQualification(qualificationWire)
	if err != nil {
		return result, err
	}
	if digest != expected.QualificationSHA256 || qualification.SourceRevision != expected.SourceRevision {
		return result, errors.New("retained CI qualification differs from approved source or digest")
	}
	for _, artifact := range qualification.Artifacts {
		if artifact.Architecture == expected.Architecture && artifact.SHA256 != approval.BinarySHA256 {
			return result, errors.New("approved binary differs from retained CI artifact")
		}
	}
	if err := verifyDisk(diskPath, approval); err != nil {
		return result, err
	}
	result = Prepared{approval: approval, issuedAt: envelope.IssuedAt, expires: envelope.ExpiresAt, approvalSHA256: hashBytes(approvalWire), approvalWire: bytes.Clone(approvalWire), delegationWire: bytes.Clone(delegationWire), diskPath: diskPath}
	if len(delegationWire) > 0 {
		delegation, _ := trust.DecodeEnvelope(delegationWire)
		if delegation.IssuedAt.After(result.issuedAt) {
			result.issuedAt = delegation.IssuedAt
		}
		if delegation.ExpiresAt.Before(result.expires) {
			result.expires = delegation.ExpiresAt
		}
	}
	return result, nil
}

func (a Approval) validate() error {
	c := a.Candidate
	if a.Schema != ApprovalSchema || !runPattern.MatchString(a.RunID) || !release.ValidSourceRevision(c.SourceRevision) ||
		!validHash(c.ArtifactSHA256) || !validHash(c.QualificationSHA256) || !release.ValidEnvironment(c.Environment) ||
		c.Architecture != "arm64" && c.Architecture != "amd64" ||
		catalog.OCIRegion(c.Cell) != a.OCIRegion || a.OCIRegion == "" {
		return errors.New("invalid disposable image candidate or regional scope")
	}
	for _, value := range []string{a.IAMRegion, a.Tenancy, a.Principal, a.Compartment, a.Subnet, a.Namespace, a.Bucket, a.Group, a.PolicyID} {
		if value == "" {
			return errors.New("disposable resource scope is incomplete")
		}
	}
	roles, err := a.validateRole()
	if err != nil {
		return err
	}
	for _, digest := range []string{a.BinarySHA256, a.KernelSHA256, a.ContainerdSHA256, a.RuncSHA256, a.RunnerSHA256} {
		if !validHash(digest) {
			return errors.New("exact native binary/runtime identities are required")
		}
	}
	if len(a.PolicyStatements) == 0 || len(a.PolicyStatements) > 32 || a.KernelRelease == "" || strings.ContainsAny(a.KernelRelease, "\r\n") {
		return errors.New("exact policy statements and immutable offline workload image are required")
	}
	for _, cidr := range []string{a.RunnerCIDR, a.PeerCIDR, a.VCNCIDR} {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix != prefix.Masked() {
			return errors.New("disposable network CIDRs must be canonical private IPv4 prefixes")
		}
	}
	vcn, _ := netip.ParsePrefix(a.VCNCIDR)
	for _, cidr := range []string{a.RunnerCIDR, a.PeerCIDR} {
		prefix, _ := netip.ParsePrefix(cidr)
		if prefix.Bits() < vcn.Bits() || !vcn.Contains(prefix.Addr()) {
			return errors.New("runner and peers must be inside the approved isolated VCN")
		}
	}
	if a.ImageBytes < 8 || a.ImageBytes > 64<<30 || a.MaxSpendMicros <= 0 || len(a.Hosts) != len(roles) {
		return errors.New("finite native HA host, image and spending bounds are required")
	}
	seen := map[string]bool{}
	for index, host := range a.Hosts {
		if !hostPattern.MatchString(host.Name) || seen[host.Name] || host.AvailabilityDomain == "" || host.FaultDomain == "" ||
			host.Shape == "" || !(host.OCPUs > 0 && host.OCPUs <= 80) || !(host.MemoryGB > 0 && host.MemoryGB <= 1024) || host.BootGB < 50 || host.BootGB > 1024 {
			return errors.New("invalid, repeated or unbounded disposable host")
		}
		if host.Role != roles[index] || a.Candidate.Architecture == "arm64" && host.Shape != imageimport.A1Shape {
			return errors.New("native qualification host topology or architecture shape differs")
		}
		seen[host.Name] = true
	}
	return nil
}

func (a Approval) validateRole() ([]string, error) {
	c := a.Candidate
	switch {
	case c.Role == "orchestrator" && c.Runtime == release.ProductionRuntime:
		if !entityid.Valid(a.ProfileIdentity.DeploymentID) || a.ProfileIdentity.Cell != c.Cell || a.ProfileIdentity.Environment != c.Environment {
			return nil, errors.New("signed production material profile identity differs from candidate")
		}
		scenarios := []string{"ready", "after-loss", "after-partition", "unready", "failed-update"}
		if len(a.MaterialFixtures) != len(scenarios) || len(a.ContainerArtifacts) != 0 || a.ClientSHA256 != "" || !validHash(a.WorkloadArchiveSHA256) || !immutableImage(a.WorkloadImage) {
			return nil, errors.New("all signed native material fixtures and immutable workload are required")
		}
		for index, fixture := range a.MaterialFixtures {
			if fixture.Scenario != scenarios[index] || !validHash(fixture.SignedProfileSHA256) || !validHash(fixture.ContainerIntentSHA256) {
				return nil, errors.New("native material fixture scenario or signed bytes differ")
			}
		}
		return []string{"manager", "manager", "manager", "worker"}, nil
	case c.Role == "netbird-manager" && c.Runtime == "netbird-containerd" && c.Cell == "GRU" && c.Architecture == "arm64":
		if len(a.MaterialFixtures) != 0 || a.ProfileIdentity != (cellspec.Identity{}) || a.WorkloadImage != "" || a.WorkloadArchiveSHA256 != "" || !validHash(a.ClientSHA256) || len(a.ContainerArtifacts) != 3 {
			return nil, errors.New("dedicated NetBird qualification requires exact component archives and native client")
		}
		for index, role := range []string{"server", "dashboard", "ingress"} {
			artifact := a.ContainerArtifacts[index]
			if artifact.Role != role || !immutableImage(artifact.Image) || !validHash(artifact.ArchiveSHA256) {
				return nil, errors.New("dedicated NetBird component role or immutable archive differs")
			}
		}
		return []string{"netbird-primary", "netbird-replacement"}, nil
	default:
		return nil, errors.New("unrecognized fixed native qualification role")
	}
}

func immutableImage(value string) bool {
	name, digest, found := strings.Cut(value, "@sha256:")
	return found && name != "" && !strings.ContainsAny(name, " \t\r\n@") && validHash(digest)
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func verifyDisk(path string, approval Approval) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != approval.ImageBytes {
		return errors.New("candidate image size or file type differs")
	}
	var header [8]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return err
	}
	if string(header[:4]) != "QFI\xfb" || (binary.BigEndian.Uint32(header[4:]) != 2 && binary.BigEndian.Uint32(header[4:]) != 3) {
		return errors.New("candidate is not a version 2 or 3 QCOW2 image")
	}
	digest := sha256.New()
	digest.Write(header[:])
	if _, err := io.Copy(digest, f); err != nil {
		return err
	}
	if hex.EncodeToString(digest.Sum(nil)) != approval.Candidate.ArtifactSHA256 {
		return errors.New("candidate QCOW2 bytes differ from approval")
	}
	return nil
}
