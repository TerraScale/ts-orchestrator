package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

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
//
// Schema 2 (TS-668) adds each controller slot's new controller config, by
// digest, the cell account's role signer and the interregion files, and pins
// the controller issuers all or none. A chain may move from schema 1 to 2,
// never back.
const (
	MaterialGenerationSchemaVersion = 2
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
	// SecretInterRegion is the leaf fabric's purpose (schema 2): the
	// interregion account JWT and CA, a child's leaf-<parent>.creds, and each
	// slot's leaf TLS, bound to that slot. interregion-ca.key and
	// child-<cell>.seed stay offline with the owner and are never pinned.
	SecretInterRegion SecretPurpose = "interregion"
)

var ErrMaterialGenerationInvalid = errors.New("material generation is invalid")

// MaterialGenerationFiles returns the files a schema-1 generation pins, each
// exactly once, with the purpose its Vault secret carries. Leaves and user
// credentials are issued by the cell and never pinned; founder, response,
// ticket and route secrets and the host NATS issuer seed do not expire and
// keep their manifest pins. Schema 2 pins the controller-issuer files all or
// none, and may add the interregion files.
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
	// their own grants, which a scoped key cannot sign. In schema 2 it and
	// IssuedLifetimeHours are zero when the controller issuers are not
	// pinned: the cell then issues nothing under the generation.
	AccountSigner       string `json:"accountSigner"`
	IssuedLifetimeHours int    `json:"issuedLifetimeHours"`
	// RoleSigner (schema 2) is the role signer's public key (TS-651), whose
	// scope cell.jwt carries. It derives from the host NATS issuer, so it
	// never changes either.
	RoleSigner string `json:"roleSigner,omitempty"`
	// ControllerConfigs (schema 2) pins every controller slot's new
	// controller config, in ControllerSlots order. Once a chain carries
	// them, every later generation does.
	ControllerConfigs []GenerationControllerConfig `json:"controllerConfigs,omitempty"`
}

// GenerationControllerConfig pins one slot's new controller config, bound to
// the slot's accepted manifest. The bytes travel beside the chain.
type GenerationControllerConfig struct {
	Slot           string `json:"slot"`
	ManifestSHA256 string `json:"manifestSha256"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
}

// InterRegionTLSFiles names a controller slot's interregion leaf certificate
// and key in a schema-2 generation.
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

func (verified VerifiedMaterialGeneration) Generation() MaterialGeneration {
	generation := verified.generation
	generation.ControllerSlots = slices.Clone(generation.ControllerSlots)
	generation.Secrets = slices.Clone(generation.Secrets)
	generation.ControllerConfigs = slices.Clone(generation.ControllerConfigs)
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
	v1 := generation.SchemaVersion == 1
	if _, err := generation.Cell.OCIRegion(); err != nil || generation.SchemaVersion < 1 ||
		generation.SchemaVersion > MaterialGenerationSchemaVersion ||
		v1 && (generation.RoleSigner != "" || len(generation.ControllerConfigs) != 0) ||
		!entityid.Valid(generation.DeploymentID) || !entityid.Valid(generation.ClusterID) ||
		generation.Environment != "production" && generation.Environment != "canary" ||
		len(generation.ControllerSlots) == 0 || len(generation.ControllerSlots) > 64 || generation.Generation == 0 ||
		generation.Generation > MaxMaterialGenerations ||
		generation.Generation == 1 && generation.Previous != "" ||
		generation.Generation > 1 && !sha256RE.MatchString(generation.Previous) ||
		!nkeys.IsValidPublicOperatorKey(generation.Operator) {
		return fmt.Errorf("%w: identity, schema or chain field", ErrMaterialGenerationInvalid)
	}
	accounts := []string{generation.SystemAccount, generation.CellAccount, generation.HostSigner}
	if v1 || generation.AccountSigner != "" {
		accounts = append(accounts, generation.AccountSigner)
	}
	if !v1 {
		accounts = append(accounts, generation.RoleSigner)
	}
	for index, account := range accounts {
		if !nkeys.IsValidPublicAccountKey(account) || slices.Contains(accounts[:index], account) {
			return fmt.Errorf("%w: account keys must be distinct account keys", ErrMaterialGenerationInvalid)
		}
	}
	for index, slot := range generation.ControllerSlots {
		if !controllerSlotRE.MatchString(slot) || index > 0 && generation.ControllerSlots[index-1] >= slot {
			return fmt.Errorf("%w: controller slots must be sorted and distinct", ErrMaterialGenerationInvalid)
		}
	}
	seen := map[string]bool{}
	interregion, leaves := 0, 0
	for _, secret := range generation.Secrets {
		purpose, slot, pinnable := generation.pinnable(secret.TargetFile)
		if !pinnable || seen[secret.TargetFile] || secret.Purpose != purpose || secret.Slot != slot ||
			!isOCID(secret.SecretOCID, "vaultsecret") || secret.VersionNumber <= 0 || !sha256RE.MatchString(secret.SHA256) ||
			secret.MaxBytes <= 0 || secret.MaxBytes > MaxSecretBytes {
			return fmt.Errorf("%w: secret reference for %q", ErrMaterialGenerationInvalid, secret.TargetFile)
		}
		seen[secret.TargetFile] = true
		if purpose == SecretInterRegion {
			interregion++
		}
		if strings.HasPrefix(secret.TargetFile, "leaf-") {
			leaves++
		}
	}
	issuers := 0
	for name, purpose := range MaterialGenerationFiles() {
		if purpose == SecretControllerIssuer && seen[name] {
			issuers++
		} else if !seen[name] && (v1 || purpose != SecretControllerIssuer) {
			return fmt.Errorf("%w: a generation pins every renewable file", ErrMaterialGenerationInvalid)
		}
	}
	// gru-1 and sfo-1 were founded without controller issuers (TS-668).
	issuing := issuers != 0
	if issuers != 0 && issuers != 3 || issuing != (generation.AccountSigner != "") ||
		issuing != (generation.IssuedLifetimeHours != 0) || generation.IssuedLifetimeHours < 0 ||
		generation.IssuedLifetimeHours > int(MaxIssuedLifetime.Hours()) {
		return fmt.Errorf("%w: the controller issuers, account signer and issued lifetime come all or none",
			ErrMaterialGenerationInvalid)
	}
	if interregion != 0 {
		complete := seen["interregion.jwt"] && seen["interregion-ca.pem"] && leaves <= 1 &&
			len(generation.ControllerConfigs) != 0
		for _, slot := range generation.ControllerSlots {
			cert, key := InterRegionTLSFiles(slot)
			complete = complete && seen[cert] && seen[key]
		}
		if !complete {
			return fmt.Errorf("%w: interregion files need the account, the CA, every slot's leaf TLS, "+
				"at most one parent's credentials and the controller configs", ErrMaterialGenerationInvalid)
		}
	}
	if len(generation.ControllerConfigs) != 0 && len(generation.ControllerConfigs) != len(generation.ControllerSlots) {
		return fmt.Errorf("%w: controller configs must pin every controller slot", ErrMaterialGenerationInvalid)
	}
	for index, config := range generation.ControllerConfigs {
		if config.Slot != generation.ControllerSlots[index] || !sha256RE.MatchString(config.ManifestSHA256) ||
			!sha256RE.MatchString(config.SHA256) || config.Size < 1 || config.Size > MaxControllerConfigBytes {
			return fmt.Errorf("%w: controller config %d must pin slot %s's config once, in slot order",
				ErrMaterialGenerationInvalid, index, generation.ControllerSlots[index])
		}
	}
	return nil
}

// pinnable returns the purpose and slot under which a generation may pin
// name. Schema 2 adds the interregion files; interregion-ca.key and
// child-<cell>.seed are never pinnable.
func (generation MaterialGeneration) pinnable(name string) (SecretPurpose, string, bool) {
	if purpose, renewable := MaterialGenerationFiles()[name]; renewable {
		return purpose, "", true
	}
	if generation.SchemaVersion < 2 {
		return "", "", false
	}
	parent, leaf := strings.CutPrefix(name, "leaf-")
	parent, creds := strings.CutSuffix(parent, ".creds")
	if name == "interregion.jwt" || name == "interregion-ca.pem" ||
		leaf && creds && clusterRE.MatchString(parent) && parent != strings.ToLower(string(generation.Cell)) {
		return SecretInterRegion, "", true
	}
	for _, slot := range generation.ControllerSlots {
		if cert, key := InterRegionTLSFiles(slot); name == cert || name == key {
			return SecretInterRegion, slot, true
		}
	}
	return "", "", false
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
			// Never back to schema 1, never without the role signer or the
			// configs once a generation carried them: controllers would
			// restart on configs the effective manifest no longer pins.
			if generation.Previous != previous.fingerprint || generation.Operator != previous.generation.Operator ||
				generation.SystemAccount != previous.generation.SystemAccount ||
				generation.CellAccount != previous.generation.CellAccount ||
				generation.HostSigner != previous.generation.HostSigner ||
				generation.SchemaVersion < previous.generation.SchemaVersion ||
				previous.generation.RoleSigner != "" && generation.RoleSigner != previous.generation.RoleSigner ||
				len(previous.generation.ControllerConfigs) != 0 && len(generation.ControllerConfigs) == 0 {
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

// ExtendsMaterialGenerationChain reports whether chain holds every
// generation of base, byte for byte, and at least one more.
func ExtendsMaterialGenerationChain(chain, base []trust.Envelope) bool {
	if len(chain) <= len(base) {
		return false
	}
	if len(base) == 0 {
		return true
	}
	prefix, err := EncodeMaterialGenerationChain(chain[:len(base)])
	held, heldErr := EncodeMaterialGenerationChain(base)
	return err == nil && heldErr == nil && string(prefix) == string(held)
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
