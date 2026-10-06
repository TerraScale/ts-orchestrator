package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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
)

var ErrMaterialGenerationInvalid = errors.New("material generation is invalid")

// MaterialGenerationFiles returns the files a schema-1 generation pins, each
// exactly once, with the purpose its Vault secret carries. Leaves and user
// credentials are issued by the cell and never pinned; founder, response,
// ticket and route secrets and the host NATS issuer seed do not expire and
// keep their manifest pins. Interregion material is renewed separately.
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
	// their own grants, which a scoped key cannot sign.
	AccountSigner       string `json:"accountSigner"`
	IssuedLifetimeHours int    `json:"issuedLifetimeHours"`
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

func (verified VerifiedMaterialGeneration) Generation() MaterialGeneration {
	generation := verified.generation
	generation.ControllerSlots = slices.Clone(generation.ControllerSlots)
	generation.Secrets = slices.Clone(generation.Secrets)
	return generation
}

// Fingerprint is the digest the next generation names as Previous.
func (verified VerifiedMaterialGeneration) Fingerprint() string { return verified.fingerprint }

func (verified VerifiedMaterialGeneration) ExpiresAt() time.Time { return verified.expiresAt }

// MaterialGenerationPolicy bounds generation signatures.
func MaterialGenerationPolicy() trust.Policy {
	return trust.Policy{MaxLifetime: MaxMaterialGenerationLifetime, ClockSkew: ManifestClockSkew}
}

// Validate checks the payload's shape; bootstrapmaterial.CheckGenerationFiles
// checks the files it pins.
func (generation MaterialGeneration) Validate() error {
	if _, err := generation.Cell.OCIRegion(); err != nil || generation.SchemaVersion != MaterialGenerationSchemaVersion ||
		!deploymentRE.MatchString(generation.DeploymentID) || !clusterRE.MatchString(generation.ClusterID) ||
		generation.Environment != "production" && generation.Environment != "canary" ||
		len(generation.ControllerSlots) == 0 || len(generation.ControllerSlots) > 64 || generation.Generation == 0 ||
		generation.Generation > MaxMaterialGenerations ||
		generation.Generation == 1 && generation.Previous != "" ||
		generation.Generation > 1 && !sha256RE.MatchString(generation.Previous) ||
		!nkeys.IsValidPublicOperatorKey(generation.Operator) ||
		generation.IssuedLifetimeHours < 1 || generation.IssuedLifetimeHours > int(MaxIssuedLifetime.Hours()) {
		return fmt.Errorf("%w: identity, chain or issuance field", ErrMaterialGenerationInvalid)
	}
	accounts := []string{generation.SystemAccount, generation.CellAccount, generation.HostSigner, generation.AccountSigner}
	for index, account := range accounts {
		if !nkeys.IsValidPublicAccountKey(account) || slices.Contains(accounts[:index], account) {
			return fmt.Errorf("%w: account keys must be four distinct account keys", ErrMaterialGenerationInvalid)
		}
	}
	for index, slot := range generation.ControllerSlots {
		if !controllerSlotRE.MatchString(slot) || index > 0 && generation.ControllerSlots[index-1] >= slot {
			return fmt.Errorf("%w: controller slots must be sorted and distinct", ErrMaterialGenerationInvalid)
		}
	}
	files := MaterialGenerationFiles()
	seen := map[string]bool{}
	for _, secret := range generation.Secrets {
		purpose, renewable := files[secret.TargetFile]
		if !renewable || seen[secret.TargetFile] || secret.Purpose != purpose || secret.Slot != "" ||
			!isOCID(secret.SecretOCID, "vaultsecret") || secret.VersionNumber <= 0 || !sha256RE.MatchString(secret.SHA256) ||
			secret.MaxBytes <= 0 || secret.MaxBytes > MaxSecretBytes {
			return fmt.Errorf("%w: secret reference for %q", ErrMaterialGenerationInvalid, secret.TargetFile)
		}
		seen[secret.TargetFile] = true
	}
	if len(seen) != len(files) {
		return fmt.Errorf("%w: a generation pins every renewable file", ErrMaterialGenerationInvalid)
	}
	return nil
}

func (expected MaterialGenerationExpectation) matches(generation MaterialGeneration) bool {
	return generation.DeploymentID == expected.DeploymentID && generation.Environment == expected.Environment &&
		generation.ClusterID == expected.ClusterID && generation.Cell == expected.Cell &&
		slices.Equal(generation.ControllerSlots, expected.ControllerSlots)
}

func materialGenerationScope(deployment, cell, environment string) trust.Scope {
	return trust.Scope{Domain: materialGenerationDomain, DeploymentID: deployment, Cell: cell, Environment: environment,
		Role: materialGenerationRole, Slot: materialGenerationSlot}
}

// SignMaterialGeneration signs a generation under the offline root.
func SignMaterialGeneration(generation MaterialGeneration, issuedAt, expiresAt time.Time, rootPrivateKey ed25519.PrivateKey,
) (trust.Envelope, error) {
	if err := generation.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	payload, err := trust.EncodePayload(generation)
	if err != nil {
		return trust.Envelope{}, err
	}
	if len(payload) > MaxMaterialGenerationBytes {
		return trust.Envelope{}, fmt.Errorf("%w: generation exceeds its size limit", ErrMaterialGenerationInvalid)
	}
	if expiresAt.Sub(issuedAt) > MaxMaterialGenerationLifetime {
		return trust.Envelope{}, fmt.Errorf("%w: validity exceeds %s", ErrMaterialGenerationInvalid, MaxMaterialGenerationLifetime)
	}
	return trust.Sign(payload, materialGenerationScope(generation.DeploymentID, string(generation.Cell), generation.Environment),
		issuedAt, expiresAt, rootPrivateKey)
}

// VerifyMaterialGenerationChain verifies a chain, oldest first, for the
// expected deployment: every link and fixed key, and the newest generation's
// root signature as current at now. Use the current roots: a chain extended
// by a retired root is refused.
func VerifyMaterialGenerationChain(chain []trust.Envelope, roots trust.Keyring, expected MaterialGenerationExpectation,
	now time.Time,
) ([]VerifiedMaterialGeneration, error) {
	return verifyMaterialGenerationChain(chain, expected, func(envelope trust.Envelope, scope trust.Scope) ([]byte, error) {
		return trust.VerifyCurrent(envelope, scope, roots, now, MaterialGenerationPolicy())
	})
}

// VerifyAdoptedMaterialGenerationChain is VerifyMaterialGenerationChain
// without the current-time check, for a controller restarting on a chain it
// adopted; roots may include ones rotated out since.
func VerifyAdoptedMaterialGenerationChain(chain []trust.Envelope, roots trust.Keyring,
	expected MaterialGenerationExpectation,
) ([]VerifiedMaterialGeneration, error) {
	return verifyMaterialGenerationChain(chain, expected, func(envelope trust.Envelope, scope trust.Scope) ([]byte, error) {
		return trust.VerifyHistorical(envelope, scope, roots, MaterialGenerationPolicy())
	})
}

func verifyMaterialGenerationChain(chain []trust.Envelope, expected MaterialGenerationExpectation,
	verifyNewest func(trust.Envelope, trust.Scope) ([]byte, error),
) ([]VerifiedMaterialGeneration, error) {
	if len(chain) == 0 || len(chain) > MaxMaterialGenerations {
		return nil, fmt.Errorf("%w: chain length", ErrMaterialGenerationInvalid)
	}
	scope := materialGenerationScope(expected.DeploymentID, string(expected.Cell), expected.Environment)
	newest := chain[len(chain)-1]
	if _, err := verifyNewest(newest, scope); err != nil {
		return nil, fmt.Errorf("verify material generation signature: %w", err)
	}
	verified := make([]VerifiedMaterialGeneration, 0, len(chain))
	for index, envelope := range chain {
		if envelope.Scope != scope {
			return nil, fmt.Errorf("%w: generation scope", ErrMaterialGenerationInvalid)
		}
		var generation MaterialGeneration
		if err := protocol.DecodeStrict(envelope.Payload, &generation, MaxMaterialGenerationBytes); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMaterialGenerationInvalid, err)
		}
		if err := generation.Validate(); err != nil {
			return nil, err
		}
		if !expected.matches(generation) || generation.Generation != uint64(index+1) {
			return nil, fmt.Errorf("%w: generation %d does not belong at position %d of this deployment's chain",
				ErrMaterialGenerationInvalid, generation.Generation, index+1)
		}
		if index > 0 {
			previous := verified[index-1]
			if generation.Previous != previous.fingerprint || generation.Operator != previous.generation.Operator ||
				generation.SystemAccount != previous.generation.SystemAccount ||
				generation.CellAccount != previous.generation.CellAccount ||
				generation.HostSigner != previous.generation.HostSigner {
				return nil, fmt.Errorf("%w: generation %d does not extend generation %d", ErrMaterialGenerationInvalid,
					generation.Generation, previous.generation.Generation)
			}
		}
		fingerprint, err := trust.Fingerprint(envelope)
		if err != nil {
			return nil, err
		}
		verified = append(verified, VerifiedMaterialGeneration{generation: generation, fingerprint: fingerprint,
			expiresAt: envelope.ExpiresAt})
	}
	return verified, nil
}

// MaterialGenerationPayload decodes and validates a generation's payload
// without verifying its signature, for code whose caller verified the chain.
func MaterialGenerationPayload(envelope trust.Envelope) (MaterialGeneration, error) {
	var generation MaterialGeneration
	if err := protocol.DecodeStrict(envelope.Payload, &generation, MaxMaterialGenerationBytes); err != nil {
		return MaterialGeneration{}, fmt.Errorf("%w: %v", ErrMaterialGenerationInvalid, err)
	}
	if err := generation.Validate(); err != nil {
		return MaterialGeneration{}, err
	}
	return generation, nil
}

// EncodeMaterialGenerationChain emits a chain, oldest first, as one canonical
// JSON array of envelopes.
func EncodeMaterialGenerationChain(chain []trust.Envelope) ([]byte, error) {
	if len(chain) == 0 || len(chain) > MaxMaterialGenerations {
		return nil, fmt.Errorf("%w: chain length", ErrMaterialGenerationInvalid)
	}
	parts := make([]string, 0, len(chain))
	for _, envelope := range chain {
		encoded, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			return nil, err
		}
		parts = append(parts, string(encoded))
	}
	return []byte("[" + strings.Join(parts, ",") + "]"), nil
}

// DecodeMaterialGenerationChain strictly decodes a canonical chain.
func DecodeMaterialGenerationChain(wire []byte) ([]trust.Envelope, error) {
	var chain []trust.Envelope
	if err := protocol.DecodeStrict(wire, &chain, MaxMaterialGenerations*(MaxMaterialGenerationBytes+16<<10)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMaterialGenerationInvalid, err)
	}
	canonical, err := EncodeMaterialGenerationChain(chain)
	if err != nil {
		return nil, err
	}
	if string(canonical) != string(wire) {
		return nil, fmt.Errorf("%w: chain JSON is not canonical", ErrMaterialGenerationInvalid)
	}
	return chain, nil
}
