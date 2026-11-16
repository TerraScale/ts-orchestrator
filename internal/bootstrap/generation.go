package bootstrap

import (
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// A material generation renews a running cell's bootstrap material in place
// (TS-568). The owner's root signs one per cell. It pins, by Vault reference,
// every renewable file: the CA bundle, the operator and account JWTs, the
// system credentials, the host TLS issuer and the online controller issuers.
// A generation's pin replaces the manifest's for the same target file. The
// cell then issues its own TLS leaves and NATS user JWTs under the
// generation's controller issuers, for at most IssuedLifetimeHours.
//
// Generations form a hash chain: each names its predecessor's fingerprint and
// keeps the NATS keys that brokers and hosts pin. A chain is verified by its
// links and by the newest generation's root signature alone, which covers the
// rest; so a chain stays valid when the roots that signed older generations
// are rotated, and a retired root cannot extend it.
//
// The v1 contract pins slot configurations, the role signer and interregion
// or link files, with controller issuers all or none.
const (
	MaterialGenerationSchemaVersion = 1
	MaxMaterialGenerationBytes      = 64 << 10
	// MaxMaterialGenerationLifetime covers a yearly CA with overlap.
	MaxMaterialGenerationLifetime = 400 * 24 * time.Hour
	MaxIssuedLifetime             = 90 * 24 * time.Hour
	// MaxMaterialGenerations bounds a chain; a yearly rollover never nears it.
	MaxMaterialGenerations   = 64
	materialGenerationDomain = "terrascale.bootstrap.material-generation"
	materialGenerationRole   = "material"
	materialGenerationSlot   = "generation"
	// SecretControllerIssuer is the online controller issuers' purpose: every
	// controller holds them, since any controller can lead.
	SecretControllerIssuer SecretPurpose = "controller-issuer"
	// SecretInterRegion is the leaf fabric's purpose (v1): the
	// interregion account JWT and CA, a child's leaf-<parent>.creds, and each
	// slot's leaf TLS, bound to that slot. interregion-ca.key and
	// child-<cell>.seed stay offline with the owner and are never pinned.
	// A link (TS-803) pins the same CA and leaf TLS, no account, and on a
	// spoke LinkCredentialsFile.
	SecretInterRegion SecretPurpose = "interregion"
	// LinkCredentialsFile is a spoke's link user, issued by the global link
	// signer for the home's cell account. One user links the region, so it is
	// shared by every slot, like a child's leaf-<parent>.creds.
	LinkCredentialsFile = "link.creds"
)

var ErrMaterialGenerationInvalid = errors.New("material generation is invalid")

// MaterialGenerationFiles returns the files a v1 generation pins, each
// exactly once, with the purpose its Vault secret carries. In v1, leaves
// and user credentials are issued by the cell; founder, response,
// ticket and route secrets and the host NATS issuer seed do not expire and
// keep their manifest pins. The v1 contract pins the controller-issuer files all or
// none, and may add the interregion files or offline-issued slot credentials.
func MaterialGenerationFiles() map[string]SecretPurpose {
	return map[string]SecretPurpose{
		"ca.pem": SecretRegionalShared, "operator.jwt": SecretRegionalShared, "system.jwt": SecretRegionalShared,
		"cell.jwt": SecretRegionalShared, "system.creds": SecretRegionalShared,
		"host-tls-issuer-cert.pem": SecretHostIssuer, "host-tls-issuer-key.pem": SecretHostIssuer,
		"controller-tls-issuer-cert.pem": SecretControllerIssuer, "controller-tls-issuer-key.pem": SecretControllerIssuer,
		"controller-account-signer.seed": SecretControllerIssuer,
	}
}

// MaterialGeneration is the signed payload.
type MaterialGeneration struct {
	SchemaVersion   int        `json:"schemaVersion"`
	DeploymentID    string     `json:"deploymentId"`
	Environment     string     `json:"environment"`
	ClusterID       string     `json:"clusterId"`
	Cell            oci.Region `json:"cell"`
	ControllerSlots []string   `json:"controllerSlots"`
	Generation      uint64     `json:"generation"`
	// Previous is the fingerprint of generation-1's envelope; empty for
	// generation 1.
	Previous string            `json:"previous,omitempty"`
	Secrets  []SecretReference `json:"secrets"`
	// Operator, SystemAccount, CellAccount and HostSigner (the host NATS
	// issuer's public key, whose scope the cell account JWT carries) never
	// change: brokers and hosts pin them.
	Operator      string `json:"operator"`
	SystemAccount string `json:"systemAccount"`
	CellAccount   string `json:"cellAccount"`
	HostSigner    string `json:"hostSigner"`
	// AccountSigner is the public key of controller-account-signer.seed, an
	// unscoped signing key of the cell account: controller user JWTs carry
	// their own grants, which a scoped key cannot sign. In v1 it and
	// IssuedLifetimeHours are zero when the controller issuers are not
	// pinned: the cell then issues nothing under the generation.
	AccountSigner       string `json:"accountSigner"`
	IssuedLifetimeHours int    `json:"issuedLifetimeHours"`
	// RoleSigner (v1) is the role signer's public key (TS-651), whose
	// scope cell.jwt carries. It derives from the host NATS issuer, so it
	// never changes either.
	RoleSigner string `json:"roleSigner,omitempty"`
	// ControllerConfigs (v1) pins every controller slot's new
	// controller config, in ControllerSlots order. Once a chain carries
	// them, every later generation does.
	ControllerConfigs []GenerationControllerConfig `json:"controllerConfigs,omitempty"`
}

// GenerationControllerConfig pins one slot's new controller config, bound to
// the slot's accepted manifest. The bytes travel beside the chain.
type GenerationControllerConfig struct {
	Slot             string `json:"slot"`
	AcceptanceSHA256 string `json:"acceptanceSha256"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
}

// InterRegionTLSFiles names a controller slot's interregion leaf certificate
// and key in a v1 generation.
func InterRegionTLSFiles(slot string) (cert, key string) {
	return "interregion-tls-" + slot + "-cert.pem", "interregion-tls-" + slot + "-key.pem"
}

// MaterialGenerationExpectation is the deployment a generation must name,
// taken from the controller's verified manifest.
type MaterialGenerationExpectation struct {
	DeploymentID    string
	Environment     string
	ClusterID       string
	Cell            oci.Region
	ControllerSlots []string
}

// VerifiedMaterialGeneration can only be built by verification.
type VerifiedMaterialGeneration struct {
	generation  MaterialGeneration
	fingerprint string
	expiresAt   time.Time
}
