// Package qualification contains the existing finite disposable image authority.
// It never supplies production identity, spending authority or a trust root.
package qualification

import (
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"time"
)

// ProductionDynamicGroup is an independently approved exclusion from test IAM.
type ProductionDynamicGroup struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	InstanceCompartment string `json:"instance_compartment"`
}

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
	Purpose                 string                        `json:"purpose,omitempty"`
	Schema                  string                        `json:"schema"`
	RunID                   string                        `json:"run_id"`
	Candidate               release.ProductionExpectation `json:"candidate"`
	IAMRegion               string                        `json:"iam_region"`
	OCIRegion               string                        `json:"oci_region"`
	Tenancy                 string                        `json:"tenancy"`
	Principal               string                        `json:"principal"`
	Compartment             string                        `json:"compartment"`
	Subnet                  string                        `json:"subnet"`
	Namespace               string                        `json:"namespace"`
	Bucket                  string                        `json:"bucket"`
	Group                   string                        `json:"group"`
	PolicyID                string                        `json:"policy_id"`
	ProductionDynamicGroups []ProductionDynamicGroup      `json:"production_dynamic_groups"`
	ProfileIdentity         cellspec.Identity             `json:"profile_identity"`
	ContainerArtifacts      []ContainerArtifactApproval   `json:"container_artifacts"`
	ClientSHA256            string                        `json:"client_sha256"`
	KernelRelease           string                        `json:"kernel_release"`
	MaterialFixtures        []MaterialApproval            `json:"material_fixtures"`
	PolicyStatements        []string                      `json:"policy_statements"`
	RunnerCIDR              string                        `json:"runner_cidr"`
	PeerCIDR                string                        `json:"peer_cidr"`
	VCNCIDR                 string                        `json:"vcn_cidr"`
	WorkloadImage           string                        `json:"workload_image"`
	WorkloadArchiveSHA256   string                        `json:"workload_archive_sha256"`
	ImageBytes              int64                         `json:"image_bytes"`
	MaxSpendMicros          int64                         `json:"max_spend_usd_micros"`
	CleanupUntil            time.Time                     `json:"cleanup_until"`
	Hosts                   []HostSpec                    `json:"hosts"`
	BinarySHA256            string                        `json:"binary_sha256"`
	KernelSHA256            string                        `json:"kernel_sha256"`
	ContainerdSHA256        string                        `json:"containerd_sha256"`
	RuncSHA256              string                        `json:"runc_sha256"`
	RunnerSHA256            string                        `json:"runner_sha256"`
}

// Preparation is signed before any IAM write. Its envelope ends at CleanupUntil;
// ExpiresAt independently ends creation, so cleanup never renews create authority.
type Preparation struct {
	Purpose                 string                        `json:"purpose,omitempty"`
	Schema                  string                        `json:"schema"`
	RunID                   string                        `json:"run_id"`
	Candidate               release.ProductionExpectation `json:"candidate"`
	Tenancy                 string                        `json:"tenancy"`
	IssuerPrincipal         string                        `json:"issuer_principal"`
	IssuerFingerprint       string                        `json:"issuer_fingerprint"`
	OCIRegion               string                        `json:"oci_region"`
	IAMRegion               string                        `json:"iam_region"`
	PrincipalName           string                        `json:"principal_name"`
	GroupName               string                        `json:"group_name"`
	PolicyName              string                        `json:"policy_name"`
	PublicKeyPEM            string                        `json:"public_key_pem"`
	PublicKeyFingerprint    string                        `json:"public_key_fingerprint"`
	Compartment             string                        `json:"compartment"`
	Subnet                  string                        `json:"subnet"`
	Namespace               string                        `json:"namespace"`
	Bucket                  string                        `json:"bucket"`
	Object                  string                        `json:"object"`
	PolicyTemplate          []string                      `json:"policy_template"`
	ProductionDynamicGroups []ProductionDynamicGroup      `json:"production_dynamic_groups"`
	ProfileIdentity         cellspec.Identity             `json:"profile_identity"`
	ContainerArtifacts      []ContainerArtifactApproval   `json:"container_artifacts"`
	ClientSHA256            string                        `json:"client_sha256"`
	KernelRelease           string                        `json:"kernel_release"`
	MaterialFixtures        []MaterialApproval            `json:"material_fixtures"`
	RunnerCIDR              string                        `json:"runner_cidr"`
	PeerCIDR                string                        `json:"peer_cidr"`
	VCNCIDR                 string                        `json:"vcn_cidr"`
	WorkloadImage           string                        `json:"workload_image"`
	WorkloadArchiveSHA256   string                        `json:"workload_archive_sha256"`
	ImageBytes              int64                         `json:"image_bytes"`
	MaxSpendMicros          int64                         `json:"max_spend_usd_micros"`
	Hosts                   []HostSpec                    `json:"hosts"`
	BinarySHA256            string                        `json:"binary_sha256"`
	KernelSHA256            string                        `json:"kernel_sha256"`
	ContainerdSHA256        string                        `json:"containerd_sha256"`
	RuncSHA256              string                        `json:"runc_sha256"`
	RunnerSHA256            string                        `json:"runner_sha256"`
	ExpiresAt               time.Time                     `json:"expires_at"`
	CleanupUntil            time.Time                     `json:"cleanup_until"`
}
