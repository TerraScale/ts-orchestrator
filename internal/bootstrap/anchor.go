package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const (
	BootstrapAnchorSchemaVersion   = 1
	MaxBootstrapAnchorBytes        = 64 << 10
	MaxInitialRegionIntentBytes    = 16 << 10
	MaxBootstrapAnchorSlots        = 64
	MaxBootstrapLedgerGrantBytes   = 16 << 10
	MaxBootstrapAnchorLifetime     = 365 * 24 * time.Hour
	DefaultBootstrapAnchorValidity = MaxBootstrapAnchorLifetime
	bootstrapAnchorDomain          = "terrascale.bootstrap.anchor"
	bootstrapAnchorRole            = "deployment-anchor"
	bootstrapAnchorSlot            = "region"
)

var ErrBootstrapAnchorInvalid = errors.New("bootstrap anchor is invalid")

// BootstrapAnchor is the root-authorized public identity and storage domain
// baked into one deployment's pre-import machine image. The exact canonical
// region-intent wire is base64-encoded by JSON and remains byte-for-byte pinned.
// Image identity is intentionally absent because the image receipt does not
// exist yet when this anchor is signed.
type BootstrapAnchor struct {
	SchemaVersion                 int           `json:"schemaVersion"`
	DeploymentID                  string        `json:"deploymentId"`
	Environment                   string        `json:"environment"`
	ClusterID                     string        `json:"clusterId"`
	Cell                          oci.Region    `json:"cell"`
	OCIRegion                     string        `json:"ociRegion"`
	StorageDomain                 StorageDomain `json:"storageDomain"`
	ControllerSlots               []string      `json:"controllerSlots"`
	LedgerDelegationWire          []byte        `json:"ledgerDelegationWire"`
	InitialRegionIntentGeneration uint64        `json:"initialRegionIntentGeneration"`
	InitialRegionIntentSHA256     string        `json:"initialRegionIntentSha256"`
	InitialRegionIntentWire       []byte        `json:"initialRegionIntentWire"`
}

// Validate verifies the immutable deployment scope, complete ledger domain,
// canonical intent bytes, and redundant generation and digest pins.
func (anchor BootstrapAnchor) Validate() error {
	ociRegion, err := anchor.Cell.OCIRegion()
	if err != nil || anchor.SchemaVersion != BootstrapAnchorSchemaVersion ||
		!entityid.Valid(anchor.DeploymentID) || !entityid.Valid(anchor.ClusterID) ||
		(anchor.Environment != "production" && anchor.Environment != "canary") || anchor.OCIRegion != ociRegion {
		return fmt.Errorf("%w: required identity or region binding", ErrBootstrapAnchorInvalid)
	}
	if err := anchor.StorageDomain.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrBootstrapAnchorInvalid, err)
	}
	if len(anchor.ControllerSlots) == 0 || len(anchor.ControllerSlots) > MaxBootstrapAnchorSlots ||
		hasDuplicate(anchor.ControllerSlots) || !slices.IsSorted(anchor.ControllerSlots) {
		return fmt.Errorf("%w: controller slot set is absent, oversized, duplicated, or not sorted", ErrBootstrapAnchorInvalid)
	}
	for _, slot := range anchor.ControllerSlots {
		if !controllerSlotRE.MatchString(slot) {
			return fmt.Errorf("%w: invalid controller slot %q", ErrBootstrapAnchorInvalid, slot)
		}
	}
	if len(anchor.LedgerDelegationWire) == 0 || len(anchor.LedgerDelegationWire) > MaxBootstrapLedgerGrantBytes {
		return fmt.Errorf("%w: ledger delegation wire is absent or exceeds %d bytes", ErrBootstrapAnchorInvalid, MaxBootstrapLedgerGrantBytes)
	}
	grantEnvelope, err := trust.DecodeEnvelope(anchor.LedgerDelegationWire)
	if err != nil {
		return fmt.Errorf("%w: decode ledger delegation wire: %v", ErrBootstrapAnchorInvalid, err)
	}
	grant, err := decodeBootstrapLedgerDelegation(grantEnvelope)
	if err != nil {
		return err
	}
	if err := validateBootstrapLedgerCapabilities(grant, anchor); err != nil {
		return err
	}
	if len(anchor.InitialRegionIntentWire) == 0 || len(anchor.InitialRegionIntentWire) > MaxInitialRegionIntentBytes ||
		anchor.InitialRegionIntentGeneration == 0 || !sha256RE.MatchString(anchor.InitialRegionIntentSHA256) {
		return fmt.Errorf("%w: initial region intent is absent or exceeds its size bound", ErrBootstrapAnchorInvalid)
	}
	intent, err := canonicalRegionIntent(anchor.InitialRegionIntentWire)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBootstrapAnchorInvalid, err)
	}
	if intent.Generation != anchor.InitialRegionIntentGeneration || digestBytes(anchor.InitialRegionIntentWire) != anchor.InitialRegionIntentSHA256 {
		return fmt.Errorf("%w: initial region-intent generation or exact-wire digest does not match", ErrBootstrapAnchorInvalid)
	}
	if !slices.ContainsFunc(intent.Regions, func(mapping oci.RegionMapping) bool {
		return mapping.Cell == anchor.Cell && mapping.OCIRegion == anchor.OCIRegion
	}) {
		return fmt.Errorf("%w: initial region intent does not admit anchor cell", ErrBootstrapAnchorInvalid)
	}
	payload, err := trust.EncodePayload(anchor)
	if err != nil {
		return fmt.Errorf("%w: encode anchor: %v", ErrBootstrapAnchorInvalid, err)
	}
	if len(payload) > MaxBootstrapAnchorBytes {
		return fmt.Errorf("%w: anchor exceeds %d bytes", ErrBootstrapAnchorInvalid, MaxBootstrapAnchorBytes)
	}
	return nil
}

// BootstrapAnchorExpectation is a local boot identity established outside the
// anchor and untrusted manifest transport. Cluster and storage values are
// obtained only after the root signature verifies.
type BootstrapAnchorExpectation struct {
	DeploymentID string
	Environment  string
	Cell         oci.Region
}

func (expected BootstrapAnchorExpectation) validate() error {
	if !entityid.Valid(expected.DeploymentID) ||
		(expected.Environment != "production" && expected.Environment != "canary") {
		return fmt.Errorf("%w: invalid expected deployment identity", ErrBootstrapAnchorInvalid)
	}
	if _, err := expected.Cell.OCIRegion(); err != nil {
		return fmt.Errorf("%w: unsupported expected cell", ErrBootstrapAnchorInvalid)
	}
	return nil
}

// VerifiedBootstrapAnchor is returned only after root signature, immutable
// local identity, intent bytes, and current validity checks succeed.
type VerifiedBootstrapAnchor struct {
	anchor           BootstrapAnchor
	intent           oci.RegionIntent
	ledgerDelegation trust.VerifiedDelegation
	wire             []byte
	digest           string
	issuedAt         time.Time
	expiresAt        time.Time
	verified         bool
}

// IsVerified reports whether this value came from VerifyBootstrapAnchor.
func (verified VerifiedBootstrapAnchor) IsVerified() bool { return verified.verified }

// Anchor returns a defensive value copy, including the exact intent bytes.
func (verified VerifiedBootstrapAnchor) Anchor() BootstrapAnchor {
	return cloneBootstrapAnchor(verified.anchor)
}

// InitialRegionIntent returns the validated region authorization pinned by the
// root-signed anchor.
func (verified VerifiedBootstrapAnchor) InitialRegionIntent() oci.RegionIntent {
	intent := verified.intent
	intent.Regions = slices.Clone(verified.intent.Regions)
	return intent
}

// StorageDomain returns the root-authorized immutable ledger and CAS-head
// storage domain.
func (verified VerifiedBootstrapAnchor) StorageDomain() StorageDomain {
	return verified.anchor.StorageDomain
}

// Wire returns the exact canonical root-signed envelope bytes. A caller can
// persist these bytes in an accepted-install marker for restart continuity.
func (verified VerifiedBootstrapAnchor) Wire() []byte { return bytes.Clone(verified.wire) }

// Digest returns the SHA-256 of the exact canonical root-signed envelope.
func (verified VerifiedBootstrapAnchor) Digest() string { return verified.digest }

// IssuedAt returns the root-signed anchor issuance time.
func (verified VerifiedBootstrapAnchor) IssuedAt() time.Time { return verified.issuedAt }

// ExpiresAt returns the root-signed anchor expiry, which bounds any manifest
// issued from this deployment identity.
func (verified VerifiedBootstrapAnchor) ExpiresAt() time.Time { return verified.expiresAt }

// LedgerDelegation returns the currently verified one-signer grant for all
// five exact slot-ledger record domains. It must be supplied to the ledger
// before opening signed records or performing a ledger action.
func (verified VerifiedBootstrapAnchor) LedgerDelegation() (trust.VerifiedDelegation, error) {
	if !verified.verified {
		return trust.VerifiedDelegation{}, fmt.Errorf("%w: anchor verification is absent", ErrBootstrapAnchorInvalid)
	}
	return verified.ledgerDelegation, nil
}

// ManifestExpectation derives trusted manifest scope and storage/intent pins
// from the anchor. The caller must supply the exact slot and image OCID from
// the independently verified signed bootstrap HEAD/Intent for that attempt.
func (verified VerifiedBootstrapAnchor) ManifestExpectation(slot, imageOCID string) (ManifestExpectation, error) {
	if !verified.verified {
		return ManifestExpectation{}, fmt.Errorf("%w: anchor verification is absent", ErrBootstrapAnchorInvalid)
	}
	if !slices.Contains(verified.anchor.ControllerSlots, slot) {
		return ManifestExpectation{}, fmt.Errorf("%w: manifest slot is not in the anchored controller slot set", ErrBootstrapAnchorInvalid)
	}
	expected := ManifestExpectation{
		DeploymentID: verified.anchor.DeploymentID, Environment: verified.anchor.Environment,
		ClusterID: verified.anchor.ClusterID, Cell: verified.anchor.Cell, Slot: slot,
		ImageOCID: imageOCID, StorageDomain: verified.anchor.StorageDomain,
		ControllerSlots:  slices.Clone(verified.anchor.ControllerSlots),
		IntentGeneration: verified.anchor.InitialRegionIntentGeneration,
		IntentSHA256:     verified.anchor.InitialRegionIntentSHA256,
	}
	if err := expected.validate(); err != nil {
		return ManifestExpectation{}, err
	}
	return expected, nil
}

// HistoricalBootstrapAnchor proves that an immutable anchor was valid at an
// accepted installation time. It conveys no present-day authorization.
type HistoricalBootstrapAnchor struct {
	anchor           BootstrapAnchor
	intent           oci.RegionIntent
	ledgerDelegation trust.VerifiedDelegation
	wire             []byte
	digest           string
	acceptedAt       time.Time
	verified         bool
}

// Anchor returns the historically verified anchor's defensive value copy.
func (verified HistoricalBootstrapAnchor) Anchor() BootstrapAnchor {
	return cloneBootstrapAnchor(verified.anchor)
}

// IsVerified reports whether this value came from VerifyHistoricalBootstrapAnchor.
func (verified HistoricalBootstrapAnchor) IsVerified() bool { return verified.verified }

// InitialRegionIntent returns the region authorization carried by this
// historical proof. It is evidence only and cannot authorize current actions.
func (verified HistoricalBootstrapAnchor) InitialRegionIntent() oci.RegionIntent {
	intent := verified.intent
	intent.Regions = slices.Clone(verified.intent.Regions)
	return intent
}

// Wire returns the exact canonical envelope bytes proven by the historical
// verification.
func (verified HistoricalBootstrapAnchor) Wire() []byte { return bytes.Clone(verified.wire) }

// Digest returns the historical envelope's canonical SHA-256 fingerprint.
func (verified HistoricalBootstrapAnchor) Digest() string { return verified.digest }

// AcceptedAt returns the caller-supplied accepted-install time covered by the
// anchor's signed interval.
func (verified HistoricalBootstrapAnchor) AcceptedAt() time.Time { return verified.acceptedAt }

// HistoricalLedgerDelegation returns grant evidence validated against the
// current root set and the accepted anchor interval. The result is for reading
// historical ledger records only; it does not authorize present-day actions.
func (verified HistoricalBootstrapAnchor) HistoricalLedgerDelegation() (trust.VerifiedDelegation, error) {
	if !verified.verified {
		return trust.VerifiedDelegation{}, fmt.Errorf("%w: historical anchor verification is absent", ErrBootstrapAnchorInvalid)
	}
	return verified.ledgerDelegation, nil
}

// BootstrapAnchorTrustPolicy is the shared current-verification policy for
// root-signed baked anchors.
func BootstrapAnchorTrustPolicy() trust.Policy {
	return trust.Policy{MaxLifetime: MaxBootstrapAnchorLifetime, ClockSkew: ManifestClockSkew}
}

// BootstrapLedgerCapabilityDomains returns the exact delegated signing domains
// required by schema-v1 anchors.
func BootstrapLedgerCapabilityDomains() []string {
	return []string{domainBootstrapHead, domainBootstrapIntent, domainBootstrapResult,
		domainBootstrapCandidate, domainBootstrapProgress}
}

// SignBootstrapAnchor canonicalizes and signs a valid immutable anchor with
// the offline root key.
func SignBootstrapAnchor(anchor BootstrapAnchor, issuedAt, expiresAt time.Time, rootPrivateKey ed25519.PrivateKey) (trust.Envelope, error) {
	if anchor.SchemaVersion != BootstrapAnchorSchemaVersion {
		return trust.Envelope{}, fmt.Errorf("%w: new anchors must use schema version %d", ErrBootstrapAnchorInvalid, BootstrapAnchorSchemaVersion)
	}
	if err := anchor.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	grantEnvelope, err := trust.DecodeEnvelope(anchor.LedgerDelegationWire)
	if err != nil {
		return trust.Envelope{}, fmt.Errorf("decode bootstrap ledger delegation: %w", err)
	}
	if err := validateBootstrapAnchorGrantInterval(issuedAt, expiresAt, grantEnvelope); err != nil {
		return trust.Envelope{}, err
	}
	payload, err := trust.EncodePayload(anchor)
	if err != nil {
		return trust.Envelope{}, fmt.Errorf("encode bootstrap anchor: %w", err)
	}
	if len(payload) > MaxBootstrapAnchorBytes {
		return trust.Envelope{}, fmt.Errorf("%w: anchor exceeds %d bytes", ErrBootstrapAnchorInvalid, MaxBootstrapAnchorBytes)
	}
	envelope, err := trust.Sign(payload, bootstrapAnchorScope(anchor.DeploymentID, string(anchor.Cell), anchor.Environment),
		issuedAt, expiresAt, rootPrivateKey)
	if err != nil {
		return trust.Envelope{}, err
	}
	if envelope.ExpiresAt.Sub(envelope.IssuedAt) > MaxBootstrapAnchorLifetime {
		return trust.Envelope{}, fmt.Errorf("%w: anchor validity exceeds %s", ErrBootstrapAnchorInvalid, MaxBootstrapAnchorLifetime)
	}
	if err := validateBootstrapAnchorEnvelopeSize(envelope); err != nil {
		return trust.Envelope{}, err
	}
	return envelope, nil
}

// VerifyBootstrapAnchor verifies the root signature before exposing any
// cluster, storage, or initial region-intent facts.
func VerifyBootstrapAnchor(envelope trust.Envelope, roots trust.Keyring, expected BootstrapAnchorExpectation,
	now time.Time, policy trust.Policy,
) (VerifiedBootstrapAnchor, error) {
	return verifyBootstrapAnchor(envelope, roots, expected, now, policy, false, time.Time{})
}

// VerifyHistoricalBootstrapAnchor proves an immutable anchor was root-signed
// for the expected local identity and covered acceptedAt. The result is
// historical evidence only; callers must separately establish accepted-install
// continuity and current action authority.
func VerifyHistoricalBootstrapAnchor(envelope trust.Envelope, roots trust.Keyring, expected BootstrapAnchorExpectation,
	acceptedAt time.Time, policy trust.Policy,
) (HistoricalBootstrapAnchor, error) {
	verified, err := verifyBootstrapAnchor(envelope, roots, expected, time.Time{}, policy, true, acceptedAt)
	if err != nil {
		return HistoricalBootstrapAnchor{}, err
	}
	return HistoricalBootstrapAnchor{
		anchor: verified.anchor, intent: verified.intent, ledgerDelegation: verified.ledgerDelegation,
		wire: verified.wire, digest: verified.digest,
		acceptedAt: acceptedAt.Round(0).UTC(), verified: true,
	}, nil
}

func verifyBootstrapAnchor(envelope trust.Envelope, roots trust.Keyring, expected BootstrapAnchorExpectation,
	now time.Time, policy trust.Policy, historical bool, acceptedAt time.Time,
) (VerifiedBootstrapAnchor, error) {
	if policy.MaxLifetime <= 0 || policy.MaxLifetime > MaxBootstrapAnchorLifetime || policy.ClockSkew < 0 ||
		envelope.ExpiresAt.Sub(envelope.IssuedAt) > MaxBootstrapAnchorLifetime {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("%w: invalid or overlong anchor verification policy", ErrBootstrapAnchorInvalid)
	}
	if err := validateBootstrapAnchorEnvelopeSize(envelope); err != nil {
		return VerifiedBootstrapAnchor{}, err
	}
	if err := expected.validate(); err != nil {
		return VerifiedBootstrapAnchor{}, err
	}
	scope := bootstrapAnchorScope(expected.DeploymentID, string(expected.Cell), expected.Environment)
	var payload []byte
	var err error
	if historical {
		payload, err = trust.VerifyHistorical(envelope, scope, roots, policy)
		if err == nil {
			acceptedAt = acceptedAt.Round(0).UTC()
			if acceptedAt.IsZero() || acceptedAt.Year() < 1 || acceptedAt.Year() > 9999 ||
				acceptedAt.Sub(envelope.IssuedAt) < -policy.ClockSkew || !acceptedAt.Before(envelope.ExpiresAt) {
				err = fmt.Errorf("%w: anchor did not cover accepted installation time", ErrBootstrapAnchorInvalid)
			}
		}
	} else {
		payload, err = trust.VerifyCurrent(envelope, scope, roots, now, policy)
	}
	if err != nil {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("verify bootstrap anchor signature: %w", err)
	}
	if len(payload) > MaxBootstrapAnchorBytes {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("%w: anchor exceeds %d bytes", ErrBootstrapAnchorInvalid, MaxBootstrapAnchorBytes)
	}
	var anchor BootstrapAnchor
	if err := protocol.DecodeStrict(payload, &anchor, MaxBootstrapAnchorBytes); err != nil {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("decode bootstrap anchor: %w", err)
	}
	if err := anchor.Validate(); err != nil {
		return VerifiedBootstrapAnchor{}, err
	}
	if anchor.DeploymentID != expected.DeploymentID || anchor.Environment != expected.Environment || anchor.Cell != expected.Cell {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("%w: anchor does not match fixed local boot identity", ErrBootstrapAnchorInvalid)
	}
	grantEnvelope, err := trust.DecodeEnvelope(anchor.LedgerDelegationWire)
	if err != nil {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("%w: decode ledger delegation wire: %v", ErrBootstrapAnchorInvalid, err)
	}
	var ledgerDelegation trust.VerifiedDelegation
	if historical {
		ledgerDelegation, err = trust.VerifyDelegationHistorical(grantEnvelope, roots, policy)
	} else {
		ledgerDelegation, err = trust.VerifyDelegationCurrent(grantEnvelope, roots, now, policy)
	}
	if err != nil {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("verify bootstrap ledger delegation: %w", err)
	}
	if err := validateBootstrapAnchorGrantInterval(envelope.IssuedAt, envelope.ExpiresAt, grantEnvelope); err != nil {
		return VerifiedBootstrapAnchor{}, err
	}
	if err := validateVerifiedBootstrapLedgerCapabilities(ledgerDelegation, anchor); err != nil {
		return VerifiedBootstrapAnchor{}, err
	}
	intent, err := canonicalRegionIntent(anchor.InitialRegionIntentWire)
	if err != nil {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("%w: %v", ErrBootstrapAnchorInvalid, err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return VerifiedBootstrapAnchor{}, fmt.Errorf("%w: encode verified envelope: %v", ErrBootstrapAnchorInvalid, err)
	}
	digest, err := trust.Fingerprint(envelope)
	if err != nil {
		return VerifiedBootstrapAnchor{}, err
	}
	return VerifiedBootstrapAnchor{
		anchor: cloneBootstrapAnchor(anchor), intent: cloneRegionIntent(intent), ledgerDelegation: ledgerDelegation,
		wire: bytes.Clone(wire), digest: digest, issuedAt: envelope.IssuedAt,
		expiresAt: envelope.ExpiresAt, verified: true,
	}, nil
}

func canonicalRegionIntent(wire []byte) (oci.RegionIntent, error) {
	if len(wire) == 0 || len(wire) > MaxInitialRegionIntentBytes {
		return oci.RegionIntent{}, fmt.Errorf("initial region intent must be between 1 and %d bytes", MaxInitialRegionIntentBytes)
	}
	intent, err := oci.ParseRegionIntent(wire)
	if err != nil {
		return oci.RegionIntent{}, fmt.Errorf("parse initial region intent: %w", err)
	}
	canonical, err := trust.EncodePayload(intent)
	if err != nil {
		return oci.RegionIntent{}, fmt.Errorf("encode canonical initial region intent: %w", err)
	}
	if !bytes.Equal(wire, canonical) {
		return oci.RegionIntent{}, errors.New("initial region intent is not canonical JSON")
	}
	return cloneRegionIntent(intent), nil
}

func decodeBootstrapLedgerDelegation(envelope trust.Envelope) (trust.Delegation, error) {
	expectedScope := trust.Scope{
		Domain: trust.DelegationDomain, DeploymentID: trust.DelegationDeploymentID, Cell: "global",
		Environment: "global", Role: "delegate", Slot: "capabilities",
	}
	if envelope.Scope != expectedScope {
		return trust.Delegation{}, fmt.Errorf("%w: ledger delegation is not root-scoped", ErrBootstrapAnchorInvalid)
	}
	var delegation trust.Delegation
	if err := protocol.DecodeStrict(envelope.Payload, &delegation, trust.MaxPayloadBytes); err != nil {
		return trust.Delegation{}, fmt.Errorf("%w: decode ledger delegation payload: %v", ErrBootstrapAnchorInvalid, err)
	}
	if err := delegation.Validate(); err != nil {
		return trust.Delegation{}, fmt.Errorf("%w: invalid ledger delegation: %v", ErrBootstrapAnchorInvalid, err)
	}
	canonical, err := trust.EncodePayload(delegation)
	if err != nil || !bytes.Equal(envelope.Payload, canonical) {
		return trust.Delegation{}, fmt.Errorf("%w: ledger delegation payload is not canonical JSON", ErrBootstrapAnchorInvalid)
	}
	return delegation, nil
}

func validateBootstrapLedgerCapabilities(delegation trust.Delegation, anchor BootstrapAnchor) error {
	return validateBootstrapLedgerCapabilitySet(delegation.Capabilities, anchor)
}

func validateVerifiedBootstrapLedgerCapabilities(delegation trust.VerifiedDelegation, anchor BootstrapAnchor) error {
	return validateBootstrapLedgerCapabilitySet(delegation.Capabilities(), anchor)
}

func validateBootstrapLedgerCapabilitySet(capabilities []trust.Capability, anchor BootstrapAnchor) error {
	wantDomains := BootstrapLedgerCapabilityDomains()
	if len(capabilities) != len(wantDomains) {
		return fmt.Errorf("%w: ledger grant must contain exactly %d capabilities", ErrBootstrapAnchorInvalid, len(wantDomains))
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if !slices.Contains(wantDomains, capability.Domain) {
			return fmt.Errorf("%w: ledger grant contains an unrecognized capability", ErrBootstrapAnchorInvalid)
		}
		if _, exists := seen[capability.Domain]; exists {
			return fmt.Errorf("%w: ledger grant duplicates a record capability", ErrBootstrapAnchorInvalid)
		}
		seen[capability.Domain] = struct{}{}
		if capability.DeploymentID != anchor.DeploymentID || capability.Cell != string(anchor.Cell) ||
			capability.Environment != anchor.Environment || capability.Role != roleController ||
			!sameStrings(capability.Slots, anchor.ControllerSlots) || !sameStrings(capability.Actions, []string{"sign"}) {
			return fmt.Errorf("%w: ledger grant exceeds or mismatches the anchored slot scope", ErrBootstrapAnchorInvalid)
		}
	}
	for _, domain := range wantDomains {
		if _, exists := seen[domain]; !exists {
			return fmt.Errorf("%w: ledger grant is missing %s capability", ErrBootstrapAnchorInvalid, domain)
		}
	}
	return nil
}

func validateBootstrapAnchorGrantInterval(anchorIssuedAt, anchorExpiresAt time.Time, grant trust.Envelope) error {
	if !anchorIssuedAt.Before(anchorExpiresAt) || anchorIssuedAt.Before(grant.IssuedAt) || anchorExpiresAt.After(grant.ExpiresAt) {
		return fmt.Errorf("%w: anchor validity is outside the ledger delegation interval", trust.ErrDelegationTime)
	}
	return nil
}

func validateBootstrapAnchorEnvelopeSize(envelope trust.Envelope) error {
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return fmt.Errorf("%w: invalid anchor envelope: %v", ErrBootstrapAnchorInvalid, err)
	}
	if len(encoded) > MaxBootstrapAnchorBytes {
		return fmt.Errorf("%w: signed anchor envelope exceeds its size limit", ErrBootstrapAnchorInvalid)
	}
	return nil
}

func bootstrapAnchorScope(deploymentID, cell, environment string) trust.Scope {
	return trust.Scope{
		Domain: bootstrapAnchorDomain, DeploymentID: deploymentID, Cell: cell,
		Environment: environment, Role: bootstrapAnchorRole, Slot: bootstrapAnchorSlot,
	}
}

func cloneBootstrapAnchor(anchor BootstrapAnchor) BootstrapAnchor {
	anchor.ControllerSlots = slices.Clone(anchor.ControllerSlots)
	anchor.LedgerDelegationWire = bytes.Clone(anchor.LedgerDelegationWire)
	anchor.InitialRegionIntentWire = bytes.Clone(anchor.InitialRegionIntentWire)
	return anchor
}

func cloneRegionIntent(intent oci.RegionIntent) oci.RegionIntent {
	intent.Regions = slices.Clone(intent.Regions)
	return intent
}
