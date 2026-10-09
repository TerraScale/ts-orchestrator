package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const (
	FounderPlanSchemaVersion = 1
	MaxFounderPlanBytes      = 64 << 10
	FounderPlanDomain        = "terrascale.bootstrap.founder-plan"
	founderPlanPeerCount     = 2
	founderMinBootVolumeGB   = 50
	founderMaxBootVolumeGB   = 32768
)

var (
	ErrFounderPlanInvalid       = errors.New("bootstrap founder plan is invalid")
	ErrFounderPlanAuthorization = errors.New("bootstrap founder plan is not authorized")
	ErrFounderPlanExpired       = errors.New("bootstrap founder plan authorization has expired")
	ErrFounderPlanRequired      = errors.New("managed bootstrap launch requires a founder plan")
	ErrFounderPeerAuthorization = errors.New("bootstrap founder peer authorization is invalid")
)

// FounderBootVolumeTier is the closed set of signed founder-plan boot-volume
// performance tiers supported by this version.
type FounderBootVolumeTier string

const FounderBootVolumeTierBalanced FounderBootVolumeTier = "balanced"

// VPUsPerGB returns the exact OCI boot-volume performance setting for a
// supported tier. Unknown labels are rejected instead of receiving a default.
func (tier FounderBootVolumeTier) VPUsPerGB() (uint32, bool) {
	switch tier {
	case FounderBootVolumeTierBalanced:
		return 10, true
	default:
		return 0, false
	}
}

// FounderPlan is the offline-root-signed authority for the two managed peers
// that join an already admitted seed. It contains references and launch pins,
// never secret bytes, private keys, or certificates.
type FounderPlan struct {
	SchemaVersion      int                   `json:"schemaVersion"`
	DeploymentID       string                `json:"deploymentId"`
	Cell               oci.Region            `json:"cell"`
	Environment        string                `json:"environment"`
	SeedSlot           string                `json:"seedSlot"`
	AnchorSHA256       string                `json:"anchorSha256"`
	ControllerSlots    []string              `json:"controllerSlots"`
	SeedManifestSHA256 string                `json:"seedManifestSha256"`
	SeedPrivateIP      string                `json:"seedPrivateIp"`
	Peers              []FounderPeerRow      `json:"peers"`
	Budget             FounderResourceBudget `json:"budget"`
	LaunchDeadline     time.Time             `json:"launchDeadline"`
}

// FounderPeerRow pins every region-specific input needed to launch one peer.
// Fields absent from Manifest remain authoritative here under the same offline
// root signature. Manifest-overlapping fields are compared during verification.
type FounderPeerRow struct {
	Slot           string `json:"slot"`
	ManifestSHA256 string `json:"manifestSha256"`
	ImageOCID      string `json:"imageOcid"`
	// ImageCompartmentOCID pins the compartment reported by OCI GetImage.
	ImageCompartmentOCID      string                    `json:"image_compartment_ocid"`
	CompartmentOCID           string                    `json:"compartmentOcid"`
	AvailabilityDomain        string                    `json:"availabilityDomain"`
	FaultDomain               string                    `json:"faultDomain"`
	SubnetOCID                string                    `json:"subnetOcid"`
	NetworkSecurityGroupOCIDs []string                  `json:"networkSecurityGroupOcids"`
	Shape                     string                    `json:"shape"`
	WholeOCPUs                uint32                    `json:"wholeOcpus"`
	MemoryInGB                uint32                    `json:"memoryInGb"`
	BootVolumeGB              uint32                    `json:"bootVolumeGb"`
	BootVolumeTier            FounderBootVolumeTier     `json:"bootVolumeTier"`
	PrivateIP                 string                    `json:"privateIp"`
	RouteEndpoints            []FounderEndpoint         `json:"routeEndpoints"`
	ClientEndpoints           []FounderEndpoint         `json:"clientEndpoints"`
	TLSMaterial               FounderTLSMaterialDigests `json:"tlsMaterial"`
}

// FounderEndpoint is a peer-to-peer endpoint pinned to one exact planned slot.
// Requiring literal private IPs rules out wildcard, CIDR, DNS, and cross-region
// route targets at this bootstrap boundary.
type FounderEndpoint struct {
	Slot      string `json:"slot"`
	PrivateIP string `json:"privateIp"`
	Port      uint16 `json:"port"`
}

// FounderTLSMaterialDigests references the six CA, leaf-certificate, and key
// materials already pinned by the slot manifest. No material is carried here.
type FounderTLSMaterialDigests struct {
	ClientCA          string `json:"clientCaSha256"`
	ClientCertificate string `json:"clientCertificateSha256"`
	ClientPrivateKey  string `json:"clientPrivateKeySha256"`
	RouteCA           string `json:"routeCaSha256"`
	RouteCertificate  string `json:"routeCertificateSha256"`
	RoutePrivateKey   string `json:"routePrivateKeySha256"`
}

// FounderResourceBudget is the exact sum authorized for the two peer rows.
// There are no unsigned service defaults: the root-signed plan chooses each
// value, and verification rejects overflow or any inconsistent total.
type FounderResourceBudget struct {
	WholeOCPUs   uint32 `json:"wholeOcpus"`
	MemoryInGB   uint32 `json:"memoryInGb"`
	BootVolumeGB uint32 `json:"bootVolumeGb"`
}

// VerifiedFounderPlan can only be constructed after its supplied root
// signature, anchor, and all three root-signed slot manifests verify under the
// current signature/time policy. It represents those exact captured bytes; it
// does not select or refresh the authoritative plan, anchor, or manifests.
type VerifiedFounderPlan struct {
	plan          FounderPlan
	envelope      trust.Envelope
	wire          []byte
	anchor        VerifiedBootstrapAnchor
	anchorWire    []byte
	manifestWires map[string][]byte
	manifests     map[string]VerifiedManifest
	digest        string
	verified      bool
}

// VerifiedCompletedFounderPlan carries only current signed identity for an
// already completed peer. It cannot authorize a launch, observation, or
// managed-peer repair, and its verification does not use LaunchDeadline as a
// restart-admission deadline.
type VerifiedCompletedFounderPlan struct {
	seedSlot       string
	peers          []FounderPeerRow
	launchDeadline time.Time
	digest         string
	verified       bool
}

// VerifiedFounderPeer is a short-lived, typed pre-quorum launch capability.
// Before each OCI effect and retry, callers must freshly read the currently
// selected plan, anchor, and manifests, verify that snapshot, and obtain a new
// ReadForLaunch token; then they call LaunchRequest with a fresh UTC clock.
type VerifiedFounderPeer struct {
	row            FounderPeerRow
	manifest       VerifiedManifest
	manifestWire   []byte
	launch         LaunchAuthorization
	recovery       *ManagedPeerRecoveryAuthorization
	planDigest     string
	rowDigest      string
	effectDeadline time.Time
	verified       bool
}

// FounderPeerLaunchRequest carries only the fields a pre-quorum OCI adapter
// needs. It deliberately does not expose or serialize the underlying Intent.
type FounderPeerLaunchRequest struct {
	DeploymentID      string
	Cell              oci.Region
	Environment       string
	Slot              string
	Node              string
	Attempt           uint64
	Generation        uint64
	IntentSHA256      string
	FounderPlanSHA256 string
	PeerRowSHA256     string
	ManifestSHA256    string
	ManifestWire      []byte
	CreateKey         string
	RetryToken        string
	HeadETag          string
	Row               FounderPeerRow
}

// FounderPeerObservationRequest carries the exact receipt-bound instance
// identity for the observation-only recovery path. Its Launch fields provide
// the pinned region, profile, and intent identity; this request does not grant
// permission to create or retry an instance.
type FounderPeerObservationRequest struct {
	Launch       FounderPeerLaunchRequest
	InstanceOCID string
}

// Validate checks the closed structural and resource-budget constraints.
// Signature, anchor, and manifest bindings are checked by VerifyFounderPlan.
func (plan FounderPlan) Validate() error {
	region, err := plan.Cell.OCIRegion()
	if err != nil || plan.SchemaVersion != FounderPlanSchemaVersion || !entityid.Valid(plan.DeploymentID) ||
		(plan.Environment != "production" && plan.Environment != "canary") || !controllerSlotRE.MatchString(plan.SeedSlot) ||
		!validDigest(plan.AnchorSHA256) || !validDigest(plan.SeedManifestSHA256) ||
		len(plan.ControllerSlots) != 3 || hasDuplicate(plan.ControllerSlots) || !slices.IsSorted(plan.ControllerSlots) ||
		!slices.Contains(plan.ControllerSlots, plan.SeedSlot) || len(plan.Peers) != founderPlanPeerCount ||
		!validPrivateIPv4(plan.SeedPrivateIP) || plan.LaunchDeadline.IsZero() || plan.LaunchDeadline.Location() != time.UTC {
		return fmt.Errorf("%w: required identity, exact three-slot topology, seed pin, or launch deadline", ErrFounderPlanInvalid)
	}
	if region == "" {
		return fmt.Errorf("%w: unsupported cell", ErrFounderPlanInvalid)
	}
	for _, slot := range plan.ControllerSlots {
		if !controllerSlotRE.MatchString(slot) {
			return fmt.Errorf("%w: invalid controller slot", ErrFounderPlanInvalid)
		}
	}

	ipBySlot := map[string]string{plan.SeedSlot: plan.SeedPrivateIP}
	peerSlots := make([]string, 0, founderPlanPeerCount)
	for _, slot := range plan.ControllerSlots {
		if slot != plan.SeedSlot {
			peerSlots = append(peerSlots, slot)
		}
	}
	if len(peerSlots) != founderPlanPeerCount || plan.Peers[0].Slot != peerSlots[0] || plan.Peers[1].Slot != peerSlots[1] {
		return fmt.Errorf("%w: peer rows must exactly follow the sorted non-seed controller slots", ErrFounderPlanInvalid)
	}
	for _, peer := range plan.Peers {
		if _, exists := ipBySlot[peer.Slot]; exists {
			return fmt.Errorf("%w: duplicate or seed peer slot", ErrFounderPlanInvalid)
		}
		if err := peer.validate(region); err != nil {
			return err
		}
		for _, other := range plan.Peers {
			if other.Slot != peer.Slot && peer.PrivateIP == other.PrivateIP {
				return fmt.Errorf("%w: duplicate peer private IP", ErrFounderPlanInvalid)
			}
		}
		if peer.PrivateIP == plan.SeedPrivateIP {
			return fmt.Errorf("%w: seed and peer private IPs must be distinct", ErrFounderPlanInvalid)
		}
		ipBySlot[peer.Slot] = peer.PrivateIP
	}
	if err := validateFounderEndpoints(plan, ipBySlot); err != nil {
		return err
	}
	if err := validateFounderBudget(plan); err != nil {
		return err
	}
	payload, err := trust.EncodePayload(plan)
	if err != nil || len(payload) > MaxFounderPlanBytes {
		return fmt.Errorf("%w: plan payload exceeds its size limit", ErrFounderPlanInvalid)
	}
	return nil
}

func (row FounderPeerRow) validate(region string) error {
	if !controllerSlotRE.MatchString(row.Slot) || !validDigest(row.ManifestSHA256) ||
		!localRegionOCID(row.ImageOCID, "image", region, false) ||
		!localRegionOCID(row.ImageCompartmentOCID, "compartment", region, true) ||
		!localRegionOCID(row.CompartmentOCID, "compartment", region, true) ||
		strings.TrimSpace(row.AvailabilityDomain) == "" || strings.ContainsAny(row.AvailabilityDomain, " \t\r\n") ||
		len(row.AvailabilityDomain) > 128 || !faultDomainRE.MatchString(row.FaultDomain) ||
		!localRegionOCID(row.SubnetOCID, "subnet", region, false) || !shapeRE.MatchString(row.Shape) ||
		row.WholeOCPUs == 0 || row.MemoryInGB == 0 ||
		row.BootVolumeGB < founderMinBootVolumeGB || row.BootVolumeGB > founderMaxBootVolumeGB ||
		!validFounderBootVolumeTier(row.BootVolumeTier) || !validPrivateIPv4(row.PrivateIP) ||
		len(row.NetworkSecurityGroupOCIDs) > 16 || hasDuplicate(row.NetworkSecurityGroupOCIDs) ||
		!slices.IsSorted(row.NetworkSecurityGroupOCIDs) {
		return fmt.Errorf("%w: peer row %q has an incomplete or out-of-region launch pin", ErrFounderPlanInvalid, row.Slot)
	}
	for _, nsg := range row.NetworkSecurityGroupOCIDs {
		if !localRegionOCID(nsg, "networksecuritygroup", region, false) {
			return fmt.Errorf("%w: peer row %q has a cross-region network security group", ErrFounderPlanInvalid, row.Slot)
		}
	}
	for _, digest := range row.TLSMaterial.digests() {
		if !validDigest(digest) {
			return fmt.Errorf("%w: peer row %q omits a TLS material digest", ErrFounderPlanInvalid, row.Slot)
		}
	}
	if len(row.RouteEndpoints) != founderPlanPeerCount || len(row.ClientEndpoints) != 1 {
		return fmt.Errorf("%w: peer row %q must pin two route peers and one client endpoint", ErrFounderPlanInvalid, row.Slot)
	}
	return nil
}

func validFounderBootVolumeTier(tier FounderBootVolumeTier) bool {
	_, supported := tier.VPUsPerGB()
	return supported
}

func validateFounderEndpoints(plan FounderPlan, ipBySlot map[string]string) error {
	routeBySlot := make(map[string]FounderEndpoint, len(plan.ControllerSlots))
	for _, row := range plan.Peers {
		wantRouteSlots := make([]string, 0, founderPlanPeerCount)
		for _, slot := range plan.ControllerSlots {
			if slot != row.Slot {
				wantRouteSlots = append(wantRouteSlots, slot)
			}
		}
		for index, endpoint := range row.RouteEndpoints {
			if endpoint.Slot != wantRouteSlots[index] || endpoint.Port == 0 || endpoint.PrivateIP != ipBySlot[endpoint.Slot] {
				return fmt.Errorf("%w: peer row %q route endpoint is broad, cross-region, duplicated, or out of order", ErrFounderPlanInvalid, row.Slot)
			}
			if prior, exists := routeBySlot[endpoint.Slot]; exists && prior != endpoint {
				return fmt.Errorf("%w: peer rows disagree about a route endpoint", ErrFounderPlanInvalid)
			}
			routeBySlot[endpoint.Slot] = endpoint
		}
		client := row.ClientEndpoints[0]
		if client.Slot != row.Slot || client.PrivateIP != row.PrivateIP || client.Port == 0 {
			return fmt.Errorf("%w: peer row %q client endpoint is not its exact private address", ErrFounderPlanInvalid, row.Slot)
		}
	}
	return nil
}

func validateFounderBudget(plan FounderPlan) error {
	var total FounderResourceBudget
	for _, row := range plan.Peers {
		var ok bool
		if total.WholeOCPUs, ok = addFounderBudget(total.WholeOCPUs, row.WholeOCPUs); !ok {
			return fmt.Errorf("%w: total whole OCPUs overflow", ErrFounderPlanInvalid)
		}
		if total.MemoryInGB, ok = addFounderBudget(total.MemoryInGB, row.MemoryInGB); !ok {
			return fmt.Errorf("%w: total memory overflow", ErrFounderPlanInvalid)
		}
		if total.BootVolumeGB, ok = addFounderBudget(total.BootVolumeGB, row.BootVolumeGB); !ok {
			return fmt.Errorf("%w: total boot volume overflow", ErrFounderPlanInvalid)
		}
	}
	if plan.Budget.WholeOCPUs == 0 || plan.Budget.MemoryInGB == 0 || plan.Budget.BootVolumeGB == 0 || plan.Budget != total {
		return fmt.Errorf("%w: declared two-peer resource budget does not equal its row totals", ErrFounderPlanInvalid)
	}
	return nil
}

func addFounderBudget(total, value uint32) (uint32, bool) {
	if ^uint32(0)-total < value {
		return 0, false
	}
	return total + value, true
}

func (material FounderTLSMaterialDigests) digests() [6]string {
	return [6]string{material.ClientCA, material.ClientCertificate, material.ClientPrivateKey,
		material.RouteCA, material.RouteCertificate, material.RoutePrivateKey}
}

// FounderPeerRowDigest hashes the deterministic JSON representation of one
// row. Managed intent v2 pins this digest together with the enclosing plan.
func FounderPeerRowDigest(row FounderPeerRow) (string, error) {
	wire, err := protocol.EncodeJSON(row)
	if err != nil {
		return "", fmt.Errorf("encode founder peer row: %w", err)
	}
	return digestBytes(wire), nil
}

// VerifyFounderPlan verifies a canonical current root-signed plan, the supplied
// current anchor, and exactly one current root-signed manifest per anchored
// controller slot. Manifest map keys are exact slot names.
func VerifyFounderPlan(
	wire []byte,
	roots trust.Keyring,
	anchorWire []byte,
	manifestWires map[string][]byte,
	now time.Time,
	policy trust.Policy,
) (VerifiedFounderPlan, error) {
	return verifyFounderPlan(wire, roots, anchorWire, manifestWires, now, policy, true)
}

// VerifyFounderPlanForCompletedPeerContinuation verifies the exact current
// root-signed plan, anchor, and manifests for read-only restart admission. A
// completed peer may restart after the launch deadline while all signatures
// and the selector remain current; launch APIs still use VerifyFounderPlan.
func VerifyFounderPlanForCompletedPeerContinuation(
	wire []byte,
	roots trust.Keyring,
	anchorWire []byte,
	manifestWires map[string][]byte,
	now time.Time,
	policy trust.Policy,
) (VerifiedCompletedFounderPlan, error) {
	current, err := verifyFounderPlan(wire, roots, anchorWire, manifestWires, now, policy, false)
	if err != nil {
		return VerifiedCompletedFounderPlan{}, err
	}
	return VerifiedCompletedFounderPlan{seedSlot: current.plan.SeedSlot,
		peers: cloneFounderPlan(current.plan).Peers, launchDeadline: current.plan.LaunchDeadline,
		digest: current.digest, verified: true}, nil
}

func verifyFounderPlan(
	wire []byte,
	roots trust.Keyring,
	anchorWire []byte,
	manifestWires map[string][]byte,
	now time.Time,
	policy trust.Policy,
	requireCurrentLaunch bool,
) (VerifiedFounderPlan, error) {
	if !validFounderNow(now) {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: current UTC verification time is required", ErrFounderPlanAuthorization)
	}
	if len(wire) == 0 || len(wire) > MaxFounderPlanBytes {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: founder-plan envelope exceeds its size limit", ErrFounderPlanInvalid)
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: decode canonical founder-plan envelope: %v", ErrFounderPlanInvalid, err)
	}
	scope := envelope.Scope
	if scope.Domain != FounderPlanDomain || scope.Role != roleController ||
		!entityid.Valid(scope.DeploymentID) || !controllerSlotRE.MatchString(scope.Slot) ||
		(scope.Environment != "production" && scope.Environment != "canary") {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: founder-plan signature scope is malformed", ErrFounderPlanAuthorization)
	}
	if _, err := oci.Region(scope.Cell).OCIRegion(); err != nil {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: founder-plan scope cell is unsupported", ErrFounderPlanAuthorization)
	}
	payload, err := trust.VerifyCurrent(envelope, scope, roots, now, policy)
	if err != nil {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: verify current root signature: %v", ErrFounderPlanAuthorization, err)
	}
	if len(payload) > MaxFounderPlanBytes {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: founder-plan payload exceeds its size limit", ErrFounderPlanInvalid)
	}
	var plan FounderPlan
	if err := decodeCanonicalPayload(payload, &plan); err != nil {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: decode canonical founder-plan payload: %v", ErrFounderPlanInvalid, err)
	}
	if err := plan.Validate(); err != nil {
		return VerifiedFounderPlan{}, err
	}
	if plan.DeploymentID != scope.DeploymentID || string(plan.Cell) != scope.Cell ||
		plan.Environment != scope.Environment || plan.SeedSlot != scope.Slot {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: founder-plan payload differs from its signed scope", ErrFounderPlanAuthorization)
	}
	if requireCurrentLaunch && !now.Before(plan.LaunchDeadline) || !plan.LaunchDeadline.After(envelope.IssuedAt) ||
		plan.LaunchDeadline.After(envelope.IssuedAt.Add(maxRetryAge)) || plan.LaunchDeadline.After(envelope.ExpiresAt) {
		return VerifiedFounderPlan{}, ErrFounderPlanExpired
	}
	if len(roots) == 0 {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: no configured root keys", ErrFounderPlanAuthorization)
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: decode current anchor wire: %v", ErrFounderPlanAuthorization, err)
	}
	anchor, err := VerifyBootstrapAnchor(anchorEnvelope, roots, BootstrapAnchorExpectation{
		DeploymentID: plan.DeploymentID, Environment: plan.Environment, Cell: plan.Cell,
	}, now, BootstrapAnchorTrustPolicy())
	if err != nil {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: verify current bootstrap anchor: %v", ErrFounderPlanAuthorization, err)
	}
	anchored := anchor.Anchor()
	if anchor.Digest() != plan.AnchorSHA256 || anchored.ClusterID == "" ||
		!slices.Equal(anchored.ControllerSlots, plan.ControllerSlots) || !now.Before(anchor.ExpiresAt()) ||
		!plan.LaunchDeadline.Before(anchor.ExpiresAt()) {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: founder plan does not match the current anchor and exact slot set", ErrFounderPlanAuthorization)
	}
	if len(manifestWires) != len(plan.ControllerSlots) {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: founder plan requires exactly one manifest per controller slot", ErrFounderPlanAuthorization)
	}
	verifiedManifests := make(map[string]VerifiedManifest, len(manifestWires))
	canonicalManifestWires := make(map[string][]byte, len(manifestWires))
	for _, slot := range plan.ControllerSlots {
		manifestWire, exists := manifestWires[slot]
		if !exists {
			return VerifiedFounderPlan{}, fmt.Errorf("%w: missing manifest for controller slot %q", ErrFounderPlanAuthorization, slot)
		}
		manifest, err := verifyFounderManifest(manifestWire, slot, roots, anchor, now)
		if err != nil {
			return VerifiedFounderPlan{}, err
		}
		verifiedManifests[slot] = manifest
		canonicalManifestWires[slot] = bytes.Clone(manifestWire)
	}
	seedManifest := verifiedManifests[plan.SeedSlot]
	seed := seedManifest.Manifest()
	if seedManifest.Digest() != plan.SeedManifestSHA256 ||
		seed.SeedSlot != plan.SeedSlot || !slices.Equal(seed.ControllerSlots, plan.ControllerSlots) {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: seed manifest digest or topology differs from founder plan", ErrFounderPlanAuthorization)
	}
	peerIPs := map[string]string{plan.SeedSlot: plan.SeedPrivateIP}
	for _, row := range plan.Peers {
		manifest, exists := verifiedManifests[row.Slot]
		if !exists || manifest.Digest() != row.ManifestSHA256 {
			return VerifiedFounderPlan{}, fmt.Errorf("%w: peer manifest digest differs for slot %q", ErrFounderPlanAuthorization, row.Slot)
		}
		manifestValue := manifest.Manifest()
		profile, ok := manifest.Profile(row.Slot)
		if manifestValue.SeedSlot != plan.SeedSlot || !slices.Equal(manifestValue.ControllerSlots, plan.ControllerSlots) ||
			manifestValue.Slot != row.Slot || manifestValue.ImageOCID != row.ImageOCID || !ok ||
			!founderRowMatchesProfile(row, profile) || !founderTLSReferencesExist(row, manifestValue.Secrets) {
			return VerifiedFounderPlan{}, fmt.Errorf("%w: peer row %q conflicts with its root-signed manifest or secret references", ErrFounderPlanAuthorization, row.Slot)
		}
		peerIPs[row.Slot] = row.PrivateIP
	}
	if err := validateFounderEndpoints(plan, peerIPs); err != nil {
		return VerifiedFounderPlan{}, err
	}
	digest, err := trust.Fingerprint(envelope)
	if err != nil {
		return VerifiedFounderPlan{}, fmt.Errorf("%w: fingerprint founder plan: %v", ErrFounderPlanInvalid, err)
	}
	return VerifiedFounderPlan{
		plan: cloneFounderPlan(plan), envelope: envelope, wire: bytes.Clone(wire), anchor: anchor,
		anchorWire: bytes.Clone(anchorWire), manifestWires: canonicalManifestWires,
		manifests: verifiedManifests, digest: digest, verified: true,
	}, nil
}

func (verified VerifiedCompletedFounderPlan) IsVerified() bool { return verified.verified }
func (verified VerifiedCompletedFounderPlan) Digest() string   { return verified.digest }
func (verified VerifiedCompletedFounderPlan) SeedSlot() string { return verified.seedSlot }

// StoredCompletionBeforeLaunchDeadline checks the latest possible instant
// represented by OCI's whole-second LastModified timestamps. It authorizes no
// new effect; delayed admission may use only proof completed before launch
// authority ended.
func (verified VerifiedCompletedFounderPlan) StoredCompletionBeforeLaunchDeadline(resultStored, headStored time.Time) bool {
	return verified.verified && !resultStored.IsZero() && !headStored.IsZero() &&
		resultStored.Location() == time.UTC && headStored.Location() == time.UTC &&
		!resultStored.Add(time.Second).After(verified.launchDeadline) &&
		!headStored.Add(time.Second).After(verified.launchDeadline)
}

func (verified VerifiedCompletedFounderPlan) PeerRow(slot string) (FounderPeerRow, bool) {
	if !verified.verified {
		return FounderPeerRow{}, false
	}
	for _, row := range verified.peers {
		if row.Slot == slot {
			return cloneFounderPeerRow(row), true
		}
	}
	return FounderPeerRow{}, false
}

func verifyFounderManifest(
	wire []byte,
	slot string,
	roots trust.Keyring,
	anchor VerifiedBootstrapAnchor,
	now time.Time,
) (VerifiedManifest, error) {
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedManifest{}, fmt.Errorf("%w: decode slot %q manifest: %v", ErrFounderPlanAuthorization, slot, err)
	}
	expectedScope := trust.Scope{
		Domain: manifestDomain, DeploymentID: anchor.anchor.DeploymentID, Cell: string(anchor.anchor.Cell),
		Environment: anchor.anchor.Environment, Role: roleController, Slot: slot,
	}
	if envelope.Scope != expectedScope {
		return VerifiedManifest{}, fmt.Errorf("%w: manifest scope differs for slot %q", ErrFounderPlanAuthorization, slot)
	}
	manifestPolicy := ManifestTrustPolicy()
	payload, err := trust.VerifyCurrent(envelope, expectedScope, roots, now, manifestPolicy)
	if err != nil {
		return VerifiedManifest{}, fmt.Errorf("%w: verify current manifest for slot %q: %v", ErrFounderPlanAuthorization, slot, err)
	}
	manifestValue, err := ManifestPayload(payload)
	if err != nil {
		return VerifiedManifest{}, fmt.Errorf("%w: decode manifest for slot %q: %v", ErrFounderPlanAuthorization, slot, err)
	}
	expected, err := anchor.ManifestExpectation(slot, manifestValue.ImageOCID)
	if err != nil {
		return VerifiedManifest{}, fmt.Errorf("%w: manifest is outside the current anchor: %v", ErrFounderPlanAuthorization, err)
	}
	verified, err := VerifyManifest(envelope, roots, expected, now, manifestPolicy)
	if err != nil {
		return VerifiedManifest{}, fmt.Errorf("%w: verify root-signed manifest for slot %q: %v", ErrFounderPlanAuthorization, slot, err)
	}
	if digestBytes(wire) != verified.Digest() {
		return VerifiedManifest{}, fmt.Errorf("%w: manifest wire digest differs for slot %q", ErrFounderPlanAuthorization, slot)
	}
	return verified, nil
}

func founderRowMatchesProfile(row FounderPeerRow, profile LaunchProfile) bool {
	return profile.Slot == row.Slot && profile.CompartmentOCID == row.CompartmentOCID &&
		profile.AvailabilityDomain == row.AvailabilityDomain && profile.FaultDomain == row.FaultDomain &&
		profile.SubnetOCID == row.SubnetOCID && slices.Equal(profile.NetworkSecurityGroupOCIDs, row.NetworkSecurityGroupOCIDs) &&
		profile.Shape == row.Shape
}

func founderTLSReferencesExist(row FounderPeerRow, secrets []SecretReference) bool {
	for _, digest := range row.TLSMaterial.digests() {
		if !slices.ContainsFunc(secrets, func(secret SecretReference) bool {
			return secret.SHA256 == digest && (secret.Purpose == SecretRegionalShared ||
				secret.Purpose == SecretController && secret.Slot == row.Slot)
		}) {
			return false
		}
	}
	return true
}

// IsVerified reports whether this value came from VerifyFounderPlan.
func (verified VerifiedFounderPlan) IsVerified() bool { return verified.verified }

// Plan returns a defensive copy of the root-signed plan.
func (verified VerifiedFounderPlan) Plan() FounderPlan { return cloneFounderPlan(verified.plan) }

// Digest returns the fingerprint of the exact canonical root-signed envelope.
func (verified VerifiedFounderPlan) Digest() string { return verified.digest }

// AuthorizePeer builds a typed pre-quorum token from the exact plan, anchor,
// manifests, and unforgeable ReadForLaunch token captured by its inputs. It
// re-verifies those supplied bytes using the supplied roots and fresh clock on
// every call, but does not fetch or select the currently authoritative plan,
// anchor, or manifests. Before every effect and retry, callers must freshly
// read that selected authority snapshot and obtain a new ReadForLaunch token,
// call VerifyFounderPlan with the fresh snapshot, then authorize the peer.
func (verified VerifiedFounderPlan) AuthorizePeer(
	slot string,
	launch LaunchAuthorization,
	roots trust.Keyring,
	now time.Time,
	policy trust.Policy,
) (VerifiedFounderPeer, error) {
	if !verified.verified {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: verified founder plan is absent", ErrFounderPeerAuthorization)
	}
	current, err := VerifyFounderPlan(verified.wire, roots, verified.anchorWire, verified.manifestWires, now, policy)
	if err != nil {
		return VerifiedFounderPeer{}, err
	}
	index := slices.IndexFunc(current.plan.Peers, func(row FounderPeerRow) bool { return row.Slot == slot })
	if index < 0 {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: slot %q is not a planned peer", ErrFounderPeerAuthorization, slot)
	}
	row := current.plan.Peers[index]
	rowDigest, err := FounderPeerRowDigest(row)
	if err != nil {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: hash peer row: %v", ErrFounderPeerAuthorization, err)
	}
	intent := launch.intent
	if intent.SchemaVersion != 2 {
		return VerifiedFounderPeer{}, ErrFounderPlanRequired
	}
	if !launch.ServerDate().IsZero() && now.Before(launch.ServerDate()) {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: founder-plan verification time predates the OCI launch read", ErrFounderPeerAuthorization)
	}
	if err := validateLaunchTokenBinding(launch, current, row, rowDigest); err != nil {
		return VerifiedFounderPeer{}, err
	}
	intentEnvelope, err := trust.DecodeEnvelope(launch.intentRecord.Bytes)
	if err != nil || !intentEnvelope.ExpiresAt.After(now) {
		return VerifiedFounderPeer{}, ErrFounderPlanExpired
	}
	retryDeadline := launch.intentRecord.LastModified.Add(maxRetryAge)
	if !now.Before(retryDeadline) {
		return VerifiedFounderPeer{}, ErrFounderPlanExpired
	}
	manifest := current.manifests[slot]
	deadline := earlierTime(current.plan.LaunchDeadline, current.envelope.ExpiresAt, current.anchor.ExpiresAt(),
		manifest.expiresAt, intentEnvelope.ExpiresAt, retryDeadline)
	if !now.Before(deadline) {
		return VerifiedFounderPeer{}, ErrFounderPlanExpired
	}
	return VerifiedFounderPeer{
		row: cloneFounderPeerRow(row), manifest: manifest, manifestWire: bytes.Clone(current.manifestWires[slot]), launch: launch,
		planDigest: current.digest, rowDigest: rowDigest, effectDeadline: deadline, verified: true,
	}, nil
}

// InitialManagedPeerIntent returns the attempt-one managed intent that
// reserves one planned peer slot. It pins exactly the plan row, manifest,
// release receipt, launch profile and anchor-pinned region intent that
// AuthorizePeerRecovery requires. The create key and OCI retry token derive
// from the plan digest, so every launch retry reuses the same OCI token.
func (verified VerifiedFounderPlan) InitialManagedPeerIntent(slot string, createdAt time.Time) (Intent, error) {
	if !verified.verified || !validFounderNow(createdAt) {
		return Intent{}, ErrFounderPeerAuthorization
	}
	index := slices.IndexFunc(verified.plan.Peers, func(row FounderPeerRow) bool { return row.Slot == slot })
	if index < 0 {
		return Intent{}, fmt.Errorf("%w: slot %q is not a planned peer", ErrFounderPeerAuthorization, slot)
	}
	row := verified.plan.Peers[index]
	rowDigest, err := FounderPeerRowDigest(row)
	if err != nil {
		return Intent{}, fmt.Errorf("%w: hash peer row: %v", ErrFounderPeerAuthorization, err)
	}
	manifest, ok := verified.manifests[slot]
	if !ok || manifest.Digest() != row.ManifestSHA256 {
		return Intent{}, fmt.Errorf("%w: peer manifest differs from its founder row", ErrFounderPeerAuthorization)
	}
	profileDigest, err := launchProfileDigest(LaunchProfile{
		Slot: row.Slot, CompartmentOCID: row.CompartmentOCID, AvailabilityDomain: row.AvailabilityDomain,
		FaultDomain: row.FaultDomain, SubnetOCID: row.SubnetOCID,
		NetworkSecurityGroupOCIDs: row.NetworkSecurityGroupOCIDs, Shape: row.Shape,
	})
	if err != nil {
		return Intent{}, err
	}
	anchor := verified.anchor.Anchor()
	token := "founder-" + slot + "-" + verified.digest[:24]
	return Intent{SchemaVersion: 2, Mode: IntentModeManaged, DeploymentID: verified.plan.DeploymentID,
		Cell: string(verified.plan.Cell), Environment: verified.plan.Environment, Role: roleController, Slot: slot,
		Attempt: 1, Generation: 1, ManifestDigest: row.ManifestSHA256,
		ReleaseReceiptDigest: manifest.Manifest().ReleaseReceiptSHA256, ImageOCID: row.ImageOCID,
		RegionIntentGeneration: anchor.InitialRegionIntentGeneration, RegionIntentDigest: anchor.InitialRegionIntentSHA256,
		LaunchRequestDigest: profileDigest, FounderPlanSHA256: verified.digest, PeerRowDigest: rowDigest,
		CreateKey: token, RetryToken: token, CreatedAt: createdAt, OCIRegion: anchor.OCIRegion,
		CompartmentOCID: row.CompartmentOCID, AvailabilityDomain: row.AvailabilityDomain, FaultDomain: row.FaultDomain,
		SubnetOCID: row.SubnetOCID, NetworkSecurityGroupIDs: slices.Clone(row.NetworkSecurityGroupOCIDs),
		Shape: row.Shape, Node: slot}, nil
}

// AuthorizePeerRecovery binds a freshly read ledger recovery state to this
// exact currently verified founder plan and its immutable intent pins. The
// returned capability is phase-limited: only clean and manifest-only phases
// can construct launch requests, while receipt-only provides an observation
// request for its persisted instance OCID.
func (verified VerifiedFounderPlan) AuthorizePeerRecovery(
	slot string,
	recovery ManagedPeerRecoveryAuthorization,
	roots trust.Keyring,
	now time.Time,
	selectorExpiresAt time.Time,
	policy trust.Policy,
) (VerifiedFounderPeer, error) {
	if !verified.verified || !recovery.verified || !validFounderNow(now) || !validFounderNow(selectorExpiresAt) {
		return VerifiedFounderPeer{}, ErrFounderPeerAuthorization
	}
	serverDate := recovery.ServerDate()
	authorizationTime := recovery.AuthorizationTime()
	if serverDate.IsZero() || authorizationTime.IsZero() {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: recovery token has no trusted OCI clock", ErrFounderPeerAuthorization)
	}
	// The OCI Date header is a conservative lower bound for checking not-before
	// times. The final successful read plus one-second header precision and
	// monotonic elapsed time is the conservative upper bound for expiry checks.
	// Never let a stale caller-supplied time move either bound backward.
	if now.After(authorizationTime) {
		authorizationTime = now
	}
	if !selectorExpiresAt.After(authorizationTime) {
		return VerifiedFounderPeer{}, ErrFounderPlanExpired
	}
	lowerBoundPlan, err := VerifyFounderPlan(verified.wire, roots, verified.anchorWire, verified.manifestWires, serverDate, policy)
	if err != nil {
		return VerifiedFounderPeer{}, err
	}
	current, err := VerifyFounderPlan(verified.wire, roots, verified.anchorWire, verified.manifestWires, authorizationTime, policy)
	if err != nil {
		return VerifiedFounderPeer{}, err
	}
	if current.digest != lowerBoundPlan.digest || current.anchor.Digest() != lowerBoundPlan.anchor.Digest() {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: root-authorized founder proof changed between trusted clock bounds", ErrFounderPeerAuthorization)
	}
	index := slices.IndexFunc(current.plan.Peers, func(row FounderPeerRow) bool { return row.Slot == slot })
	if index < 0 {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: slot %q is not a planned peer", ErrFounderPeerAuthorization, slot)
	}
	row := current.plan.Peers[index]
	rowDigest, err := FounderPeerRowDigest(row)
	if err != nil {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: hash peer row: %v", ErrFounderPeerAuthorization, err)
	}
	state := recovery.state
	intent := state.Intent
	if recovery.scope != (BootstrapScope{DeploymentID: current.plan.DeploymentID, Cell: string(current.plan.Cell), Slot: slot}) ||
		intent.Mode != IntentModeManaged || intent.SchemaVersion != 2 || intent.Attempt != state.Head.Attempt ||
		intent.Generation != state.Head.Generation || state.IntentRecord.SHA256 != state.Head.IntentDigest ||
		objectDigest(state.IntentRecord.Bytes) != state.IntentRecord.SHA256 ||
		state.Head.ResultDigest != "" && recovery.phase != ManagedPeerRecoveryComplete && recovery.phase != ManagedPeerRecoveryQuarantined ||
		state.Head.ResultDigest == "" && recovery.phase == ManagedPeerRecoveryComplete ||
		intent.FounderPlanSHA256 != current.digest || intent.PeerRowDigest != rowDigest ||
		intent.ManifestDigest != row.ManifestSHA256 || intent.ImageOCID != row.ImageOCID ||
		!sameProfile(launchProfileForIntent(intent), LaunchProfile{
			Slot: row.Slot, CompartmentOCID: row.CompartmentOCID, AvailabilityDomain: row.AvailabilityDomain,
			FaultDomain: row.FaultDomain, SubnetOCID: row.SubnetOCID,
			NetworkSecurityGroupOCIDs: row.NetworkSecurityGroupOCIDs, Shape: row.Shape,
		}) || recovery.serverDate.IsZero() {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: recovery state does not pin this exact founder plan row", ErrFounderPeerAuthorization)
	}
	manifest := current.manifests[slot]
	if manifest.Digest() != row.ManifestSHA256 {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: selected manifest digest differs from its founder row", ErrFounderPeerAuthorization)
	}
	if state.ManifestRecord != nil && (state.Manifest == nil || state.ManifestRecord.SHA256 != row.ManifestSHA256 ||
		objectDigest(state.ManifestRecord.Bytes) != state.ManifestRecord.SHA256) {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: persisted manifest differs from the selected founder row", ErrFounderPeerAuthorization)
	}
	if state.PeerReceiptRecord != nil && (state.PeerReceipt == nil ||
		state.PeerReceiptRecord.SHA256 == "" || objectDigest(state.PeerReceiptRecord.Bytes) != state.PeerReceiptRecord.SHA256 ||
		validatePeerReceiptForIntent(*state.PeerReceipt, intent, state.IntentRecord.SHA256) != nil) {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: persisted peer receipt differs from the current intent", ErrFounderPeerAuthorization)
	}
	if state.ResultRecord != nil && (state.Result == nil || state.PeerReceiptRecord == nil ||
		objectDigest(state.ResultRecord.Bytes) != state.ResultRecord.SHA256 ||
		validateResultForIntent(*state.Result, intent, state.IntentRecord.SHA256) != nil ||
		state.Result.PeerReceiptDigest != state.PeerReceiptRecord.SHA256) {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: persisted result differs from the current intent and receipt", ErrFounderPeerAuthorization)
	}
	if state.CandidateRecord != nil {
		if state.Candidate == nil || state.CandidateRecord.SHA256 == "" ||
			objectDigest(state.CandidateRecord.Bytes) != state.CandidateRecord.SHA256 ||
			validateManagedPeerCandidateForIntent(*state.Candidate, intent, state.IntentRecord.SHA256,
				current.digest, rowDigest, row.ManifestSHA256) != nil {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: persisted candidate differs from the exact current intent and founder row", ErrFounderPeerAuthorization)
		}
	}
	if state.ProgressRecord != nil {
		if state.Progress == nil || state.ProgressRecord.SHA256 == "" ||
			objectDigest(state.ProgressRecord.Bytes) != state.ProgressRecord.SHA256 || state.CandidateRecord == nil ||
			state.Progress.CandidateDigest != state.CandidateRecord.SHA256 ||
			state.Progress.Attempt != intent.Attempt || state.Progress.Generation != intent.Generation {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: persisted progress does not bind the verified candidate and current intent", ErrFounderPeerAuthorization)
		}
	}
	switch recovery.phase {
	case ManagedPeerRecoveryClean:
		if state.ManifestRecord != nil || state.PeerReceiptRecord != nil || state.ResultRecord != nil || state.CandidateRecord != nil ||
			state.ProgressRecord != nil || state.Head.ResultDigest != "" || state.Head.CandidateDigest != "" {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: clean recovery phase contains durable peer proofs", ErrFounderPeerAuthorization)
		}
	case ManagedPeerRecoveryManifestOnly:
		if state.ManifestRecord == nil || state.PeerReceiptRecord != nil || state.ResultRecord != nil || state.CandidateRecord != nil ||
			state.ProgressRecord != nil || state.Head.ResultDigest != "" || state.Head.CandidateDigest != "" {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: manifest-only recovery phase has inconsistent records", ErrFounderPeerAuthorization)
		}
	case ManagedPeerRecoveryCandidateOnly:
		if state.CandidateRecord == nil || state.PeerReceiptRecord != nil || state.ResultRecord != nil || state.Head.ResultDigest != "" ||
			state.Progress != nil && state.Progress.Phase != ManagedPeerProgressCandidate {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: candidate-only recovery phase has inconsistent records", ErrFounderPeerAuthorization)
		}
	case ManagedPeerRecoveryProofStaged:
		if state.CandidateRecord == nil || state.ProgressRecord == nil || state.Progress == nil ||
			state.Progress.Phase != ManagedPeerProgressReceipt && state.Progress.Phase != ManagedPeerProgressResult {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: proof-staged recovery phase has inconsistent progress", ErrFounderPeerAuthorization)
		}
	case ManagedPeerRecoveryQuarantined:
		if state.CandidateRecord == nil && state.PeerReceipt == nil && state.Result == nil {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: quarantined recovery state has no persisted instance identity", ErrFounderPeerAuthorization)
		}
	case ManagedPeerRecoveryReceiptOnly:
		if state.ManifestRecord == nil || state.PeerReceiptRecord == nil || state.CandidateRecord == nil ||
			state.ResultRecord != nil || state.Head.ResultDigest != "" {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: receipt-only recovery phase has inconsistent records", ErrFounderPeerAuthorization)
		}
	case ManagedPeerRecoveryResultReady:
		if state.ManifestRecord == nil || state.PeerReceiptRecord == nil || state.CandidateRecord == nil ||
			state.ResultRecord == nil || state.Head.ResultDigest != "" {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: result-ready recovery phase has inconsistent records", ErrFounderPeerAuthorization)
		}
	case ManagedPeerRecoveryComplete:
		if state.ManifestRecord == nil || state.PeerReceiptRecord == nil || state.CandidateRecord == nil || state.ResultRecord == nil ||
			state.Head.ResultDigest != state.ResultRecord.SHA256 || state.Head.CandidateDigest != state.CandidateRecord.SHA256 {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: complete recovery phase has inconsistent records", ErrFounderPeerAuthorization)
		}
	default:
		return VerifiedFounderPeer{}, fmt.Errorf("%w: recovery phase is malformed", ErrFounderPeerAuthorization)
	}
	deadline := earlierTime(current.plan.LaunchDeadline, current.envelope.ExpiresAt,
		current.anchor.ExpiresAt(), manifest.expiresAt, selectorExpiresAt)
	if recovery.phase == ManagedPeerRecoveryClean || recovery.phase == ManagedPeerRecoveryManifestOnly {
		intentEnvelope, decodeErr := trust.DecodeEnvelope(state.IntentRecord.Bytes)
		if decodeErr != nil || !intentEnvelope.ExpiresAt.After(authorizationTime) {
			return VerifiedFounderPeer{}, ErrFounderPlanExpired
		}
		if err := CheckRetryWindow(StoredRecord{
			LastModified: state.IntentRecord.LastModified,
			ServerDate:   authorizationTime,
		}); err != nil {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: original intent retry window is not current: %v", ErrFounderPlanExpired, err)
		}
		deadline = earlierTime(deadline, intentEnvelope.ExpiresAt, state.IntentRecord.LastModified.Add(maxRetryAge))
	}
	if !authorizationTime.Before(deadline) {
		return VerifiedFounderPeer{}, ErrFounderPlanExpired
	}
	launch := LaunchAuthorization{
		scope: recovery.scope, intent: intent, intentRecord: cloneStoredRecord(state.IntentRecord),
		head: state.Head, headRecord: cloneStoredRecord(state.HeadRecord),
	}
	recoveryCopy := recovery
	recoveryCopy.state = cloneSlotState(state)
	return VerifiedFounderPeer{
		row: cloneFounderPeerRow(row), manifest: manifest, manifestWire: bytes.Clone(current.manifestWires[slot]), launch: launch,
		recovery: &recoveryCopy, planDigest: current.digest, rowDigest: rowDigest,
		effectDeadline: deadline, verified: true,
	}, nil
}

func validateLaunchTokenBinding(launch LaunchAuthorization, plan VerifiedFounderPlan, row FounderPeerRow, rowDigest string) error {
	intent := launch.intent
	intentEnvelope, intentEnvelopeErr := trust.DecodeEnvelope(launch.intentRecord.Bytes)
	headEnvelope, headEnvelopeErr := trust.DecodeEnvelope(launch.headRecord.Bytes)
	var recordIntent Intent
	var recordHead SlotHead
	if intentEnvelopeErr == nil {
		intentEnvelopeErr = decodeCanonicalPayload(intentEnvelope.Payload, &recordIntent)
	}
	if headEnvelopeErr == nil {
		headEnvelopeErr = decodeCanonicalPayload(headEnvelope.Payload, &recordHead)
	}
	intentScope := trust.Scope{
		Domain: domainBootstrapIntent, DeploymentID: intent.DeploymentID, Cell: intent.Cell,
		Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot,
	}
	if launch.scope != (BootstrapScope{DeploymentID: plan.plan.DeploymentID, Cell: string(plan.plan.Cell), Slot: row.Slot}) ||
		intentEnvelopeErr != nil || headEnvelopeErr != nil || !sameIntent(recordIntent, intent) || !sameHead(recordHead, launch.head) ||
		launch.intentRecord.SHA256 == "" || digestBytes(launch.intentRecord.Bytes) != launch.intentRecord.SHA256 ||
		launch.headRecord.SHA256 == "" || digestBytes(launch.headRecord.Bytes) != launch.headRecord.SHA256 ||
		launch.head.ResultDigest != "" || launch.head.IntentDigest != launch.intentRecord.SHA256 ||
		launch.head.Attempt != intent.Attempt || launch.head.Generation != intent.Generation ||
		intentScope != (trust.Scope{
			Domain: domainBootstrapIntent, DeploymentID: plan.plan.DeploymentID, Cell: string(plan.plan.Cell),
			Environment: plan.plan.Environment, Role: roleController, Slot: row.Slot,
		}) || headEnvelope.Scope != (trust.Scope{
		Domain: domainBootstrapHead, DeploymentID: plan.plan.DeploymentID, Cell: string(plan.plan.Cell),
		Environment: plan.plan.Environment, Role: roleController, Slot: row.Slot,
	}) || intent.SchemaVersion != 2 || intent.Mode != IntentModeManaged ||
		intent.FounderPlanSHA256 != plan.digest || intent.PeerRowDigest != rowDigest ||
		intent.ManifestDigest != row.ManifestSHA256 || intent.ImageOCID != row.ImageOCID ||
		!sameProfile(launchProfileForIntent(intent), LaunchProfile{
			Slot: row.Slot, CompartmentOCID: row.CompartmentOCID, AvailabilityDomain: row.AvailabilityDomain,
			FaultDomain: row.FaultDomain, SubnetOCID: row.SubnetOCID,
			NetworkSecurityGroupOCIDs: row.NetworkSecurityGroupOCIDs, Shape: row.Shape,
		}) || !createTokenPattern.MatchString(intent.CreateKey) || !createTokenPattern.MatchString(intent.RetryToken) {
		return fmt.Errorf("%w: ReadForLaunch token does not pin this exact founder plan row", ErrFounderPeerAuthorization)
	}
	if err := CheckRetryWindow(launch.intentRecord); err != nil {
		return fmt.Errorf("%w: original intent retry window is not current: %v", ErrFounderPlanExpired, err)
	}
	return nil
}

// IsVerified reports whether this value came from VerifiedFounderPlan.AuthorizePeer.
func (verified VerifiedFounderPeer) IsVerified() bool { return verified.verified }

// EffectDeadline is the earliest signed-plan, anchor, or manifest deadline.
// Launchable recovery phases also include the original intent and OCI retry
// deadlines; observation and already-written-result recovery do not renew or
// depend on that retry window.
func (verified VerifiedFounderPeer) EffectDeadline() time.Time { return verified.effectDeadline }

// Manifest returns the exact current root-verified peer manifest.
func (verified VerifiedFounderPeer) Manifest() Manifest {
	if !verified.verified {
		return Manifest{}
	}
	return verified.manifest.Manifest()
}

// LaunchRequest returns a defensive request while the captured signed
// intervals and original OCI retry deadline remain current. It does not refresh
// authority or ledger state; callers must freshly read the selected authority
// snapshot and ledger immediately before every effect and retry.
func (verified VerifiedFounderPeer) LaunchRequest(now time.Time) (FounderPeerLaunchRequest, error) {
	if !verified.verified || !validFounderNow(now) {
		return FounderPeerLaunchRequest{}, ErrFounderPeerAuthorization
	}
	if verified.recovery != nil {
		authorizationTime := verified.recovery.AuthorizationTime()
		if authorizationTime.IsZero() {
			return FounderPeerLaunchRequest{}, ErrFounderPeerAuthorization
		}
		if now.Before(authorizationTime) {
			now = authorizationTime
		}
	}
	if !verified.launch.intentRecord.ServerDate.IsZero() && now.Before(verified.launch.intentRecord.ServerDate) {
		return FounderPeerLaunchRequest{}, fmt.Errorf("%w: request time predates the OCI launch read", ErrFounderPeerAuthorization)
	}
	if verified.recovery != nil && now.Before(verified.recovery.serverDate.Add(time.Second)) {
		return FounderPeerLaunchRequest{}, fmt.Errorf("%w: request time predates the final OCI recovery read", ErrFounderPeerAuthorization)
	}
	if !now.Before(verified.effectDeadline) {
		return FounderPeerLaunchRequest{}, ErrFounderPlanExpired
	}
	if verified.recovery != nil && verified.recovery.phase != ManagedPeerRecoveryClean &&
		verified.recovery.phase != ManagedPeerRecoveryManifestOnly {
		return FounderPeerLaunchRequest{}, fmt.Errorf("%w: recovery phase %q does not authorize an OCI launch", ErrFounderPeerAuthorization, verified.recovery.phase)
	}
	return verified.launchRequest(), nil
}

func (verified VerifiedFounderPeer) launchRequest() FounderPeerLaunchRequest {
	intent := verified.launch.intent
	return FounderPeerLaunchRequest{
		DeploymentID: intent.DeploymentID, Cell: oci.Region(intent.Cell), Environment: intent.Environment,
		Slot: intent.Slot, Node: intent.Node, Attempt: intent.Attempt, Generation: intent.Generation,
		IntentSHA256: verified.launch.intentRecord.SHA256, FounderPlanSHA256: verified.planDigest,
		PeerRowSHA256: verified.rowDigest, ManifestSHA256: verified.row.ManifestSHA256,
		ManifestWire: bytes.Clone(verified.manifestWire),
		CreateKey:    intent.CreateKey, RetryToken: intent.RetryToken, HeadETag: verified.launch.headRecord.ETag,
		Row: cloneFounderPeerRow(verified.row),
	}
}

// ObservationRequest authorizes observing only the exact instance already
// named by a persisted, verified peer receipt. Other recovery phases have no
// observation-only capability.
func (verified VerifiedFounderPeer) ObservationRequest(now time.Time) (FounderPeerObservationRequest, error) {
	if !verified.verified || verified.recovery == nil ||
		verified.recovery.phase != ManagedPeerRecoveryReceiptOnly &&
			verified.recovery.phase != ManagedPeerRecoveryCandidateOnly &&
			verified.recovery.phase != ManagedPeerRecoveryProofStaged &&
			verified.recovery.phase != ManagedPeerRecoveryQuarantined || !validFounderNow(now) {
		return FounderPeerObservationRequest{}, ErrFounderPeerAuthorization
	}
	authorizationTime := verified.recovery.AuthorizationTime()
	if authorizationTime.IsZero() {
		return FounderPeerObservationRequest{}, ErrFounderPeerAuthorization
	}
	if now.Before(authorizationTime) {
		now = authorizationTime
	}
	if now.Before(verified.recovery.serverDate.Add(time.Second)) {
		return FounderPeerObservationRequest{}, fmt.Errorf("%w: request time predates the OCI recovery read", ErrFounderPeerAuthorization)
	}
	if !now.Before(verified.effectDeadline) {
		return FounderPeerObservationRequest{}, ErrFounderPlanExpired
	}
	state := verified.recovery.state
	instanceOCID := ""
	if state.Candidate != nil {
		instanceOCID = state.Candidate.InstanceOCID
	} else if state.PeerReceipt != nil {
		instanceOCID = state.PeerReceipt.InstanceOCID
	} else if state.Result != nil {
		instanceOCID = state.Result.InstanceOCID
	}
	if !isOCID(instanceOCID, "instance") {
		return FounderPeerObservationRequest{}, fmt.Errorf("%w: recovery state has no verified instance identity", ErrFounderPeerAuthorization)
	}
	return FounderPeerObservationRequest{
		Launch: verified.launchRequest(), InstanceOCID: instanceOCID,
	}, nil
}

// validatePlanCurrentForEffect is used where time comes from an existing
// verified ledger clock. This package intentionally has no wall-clock fallback.
func validFounderNow(now time.Time) bool { return !now.IsZero() && now.Location() == time.UTC }

func earlierTime(values ...time.Time) time.Time {
	deadline := values[0]
	for _, value := range values[1:] {
		if value.Before(deadline) {
			deadline = value
		}
	}
	return deadline
}

func validPrivateIPv4(value string) bool {
	parsed := net.ParseIP(value)
	return parsed != nil && parsed.To4() != nil && parsed.String() == value && parsed.IsPrivate() &&
		!parsed.IsLoopback() && !parsed.IsUnspecified() && !parsed.IsMulticast() && !parsed.IsLinkLocalUnicast()
}

func localRegionOCID(value, kind, region string, allowGlobal bool) bool {
	if !isOCID(value, kind) {
		return false
	}
	parts := strings.Split(value, ".")
	return len(parts) == 5 && (parts[3] == region || allowGlobal && parts[3] == "")
}

func cloneFounderPlan(plan FounderPlan) FounderPlan {
	plan.ControllerSlots = slices.Clone(plan.ControllerSlots)
	plan.Peers = slices.Clone(plan.Peers)
	for index := range plan.Peers {
		plan.Peers[index] = cloneFounderPeerRow(plan.Peers[index])
	}
	return plan
}

func cloneFounderPeerRow(row FounderPeerRow) FounderPeerRow {
	row.NetworkSecurityGroupOCIDs = slices.Clone(row.NetworkSecurityGroupOCIDs)
	row.RouteEndpoints = slices.Clone(row.RouteEndpoints)
	row.ClientEndpoints = slices.Clone(row.ClientEndpoints)
	return row
}
