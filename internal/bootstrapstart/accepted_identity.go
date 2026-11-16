package bootstrapstart

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/nkeys"
)

// MaxAcceptedIdentityBytes permits complete public three-controller inventories.
const MaxAcceptedIdentityBytes = bootstrap.MaxAcceptedInstallBytes

var ErrAcceptedIdentity = errors.New("accepted installation identity is invalid")
var ErrAcceptancePredecessor = errors.New("accepted installation predecessor differs from root checkpoint")

// ControllerBinding records observed peers, not promises that intended peers exist.
type ControllerBinding struct {
	Slot             string                      `json:"slot"`
	InstanceOCID     string                      `json:"instanceOcid"`
	ImageOCID        string                      `json:"imageOcid"`
	PrimaryVNICOCID  string                      `json:"primaryVnicOcid"`
	PrimaryPrivateIP string                      `json:"primaryPrivateIp"`
	Binary           identityrekey.BinaryPin     `json:"binary"`
	Store            identityrekey.StoreIdentity `json:"store"`
}

// AcceptedIdentity is the root-owned local installation snapshot, not a signed
// checkpoint or current authorization to launch instances or mutate a cell.
type AcceptedIdentity struct {
	SchemaVersion            int                              `json:"schemaVersion"`
	Origin                   string                           `json:"origin"`
	OperationID              string                           `json:"operationId"`
	DeploymentID             string                           `json:"deploymentId"`
	ClusterID                string                           `json:"clusterId"`
	Environment              string                           `json:"environment"`
	Cell                     string                           `json:"cell"`
	Slot                     string                           `json:"slot"`
	SeedSlot                 string                           `json:"seedSlot"`
	ControllerSlots          []string                         `json:"controllerSlots"`
	ControllerBindings       []ControllerBinding              `json:"controllerBindings"`
	InstanceOCID             string                           `json:"instanceOcid"`
	ImageOCID                string                           `json:"imageOcid"`
	PrimaryVNICOCID          string                           `json:"primaryVnicOcid"`
	PrimaryPrivateIP         string                           `json:"primaryPrivateIp"`
	Binary                   identityrekey.BinaryPin          `json:"binary"`
	Broker                   identityrekey.BrokerIdentity     `json:"broker"`
	Store                    identityrekey.StoreIdentity      `json:"store"`
	ConfigSHA256             map[string]string                `json:"configSha256"`
	LaunchMaterialSHA256     map[string]string                `json:"launchMaterialSha256"`
	MaterialReferences       []bootstrap.SecretReference      `json:"materialReferences"`
	MaterialGenerationSHA256 string                           `json:"materialGenerationSha256"`
	ManagedMaterial          *bootstrap.ManagedMaterialDomain `json:"managedMaterial,omitempty"`
	AcceptedAt               time.Time                        `json:"acceptedAt"`
}

func (identity AcceptedIdentity) Clone() AcceptedIdentity {
	identity.ControllerSlots = slices.Clone(identity.ControllerSlots)
	identity.ControllerBindings = slices.Clone(identity.ControllerBindings)
	identity.ConfigSHA256 = maps.Clone(identity.ConfigSHA256)
	identity.LaunchMaterialSHA256 = maps.Clone(identity.LaunchMaterialSHA256)
	identity.MaterialReferences = slices.Clone(identity.MaterialReferences)
	if identity.ManagedMaterial != nil {
		identity.ManagedMaterial = new(*identity.ManagedMaterial)
	}
	return identity
}

func (identity AcceptedIdentity) localBinding() ControllerBinding {
	return ControllerBinding{Slot: identity.Slot, InstanceOCID: identity.InstanceOCID, ImageOCID: identity.ImageOCID,
		PrimaryVNICOCID: identity.PrimaryVNICOCID, PrimaryPrivateIP: identity.PrimaryPrivateIP,
		Binary: identity.Binary, Store: identity.Store}
}

func (identity AcceptedIdentity) Validate() error {
	if identity.SchemaVersion != 1 || !entityid.Valid(identity.OperationID) || !entityid.Valid(identity.DeploymentID) ||
		identity.Origin != identityrekey.AcceptanceOriginInitial && identity.Origin != identityrekey.AcceptanceOriginRekey ||
		!entityid.Valid(identity.ClusterID) || !release.ValidEnvironment(identity.Environment) || !catalog.IsCell(identity.Cell) ||
		!slices.Equal(identity.ControllerSlots, []string{"controller-a", "controller-b", "controller-c"}) ||
		!slices.Contains(identity.ControllerSlots, identity.Slot) || !slices.Contains(identity.ControllerSlots, identity.SeedSlot) ||
		len(identity.ControllerBindings) == 0 || len(identity.ControllerBindings) > 3 ||
		identity.AcceptedAt.IsZero() || identity.AcceptedAt.Location() != time.UTC ||
		identity.MaterialGenerationSHA256 != "" && !markerDigestRE.MatchString(identity.MaterialGenerationSHA256) ||
		identity.ManagedMaterial != nil && identity.ManagedMaterial.Validate() != nil {
		return ErrAcceptedIdentity
	}
	if err := validateAcceptedBroker(identity.Broker); err != nil {
		return err
	}
	localFound := false
	for i, binding := range identity.ControllerBindings {
		if !slices.Contains(identity.ControllerSlots, binding.Slot) || binding.validate(identity.Cell) != nil ||
			i > 0 && identity.ControllerBindings[i-1].Slot >= binding.Slot {
			return ErrAcceptedIdentity
		}
		if binding.Slot == identity.Slot {
			if binding != identity.localBinding() {
				return ErrAcceptedIdentity
			}
			localFound = true
		}
		for _, prior := range identity.ControllerBindings[:i] {
			if prior.InstanceOCID == binding.InstanceOCID || prior.PrimaryVNICOCID == binding.PrimaryVNICOCID ||
				prior.PrimaryPrivateIP == binding.PrimaryPrivateIP || prior.Store.ServerName == binding.Store.ServerName ||
				prior.Store.RaftNodeID == binding.Store.RaftNodeID {
				return ErrAcceptedIdentity
			}
		}
	}
	if !localFound || len(identity.ConfigSHA256) != 4 || !markerDigestRE.MatchString(identity.ConfigSHA256["controller.json"]) {
		return ErrAcceptedIdentity
	}
	for _, name := range bootstrap.ControllerConfigFileNames {
		if !markerDigestRE.MatchString(identity.ConfigSHA256[name]) {
			return ErrAcceptedIdentity
		}
	}
	if _, err := acceptedLaunchFileNames(identity.LaunchMaterialSHA256); err != nil {
		return ErrAcceptedIdentity
	}
	return validateAcceptedReferences(identity)
}

func validateAcceptedBroker(broker identityrekey.BrokerIdentity) error {
	if !nkeys.IsValidPublicOperatorKey(broker.Operator) {
		return ErrAcceptedIdentity
	}
	accounts := []string{broker.SystemAccount, broker.CellAccount, broker.HostSigner, broker.RoleSigner}
	for _, optional := range []string{broker.AccountSigner, broker.InterRegionAccount} {
		if optional != "" {
			accounts = append(accounts, optional)
		}
	}
	for i, key := range accounts {
		if !nkeys.IsValidPublicAccountKey(key) || slices.Contains(accounts[:i], key) {
			return ErrAcceptedIdentity
		}
	}
	return nil
}

func (binding ControllerBinding) validate(cell string) error {
	address, err := netip.ParseAddr(binding.PrimaryPrivateIP)
	store := binding.Store
	if !acceptedRegionalOCID(binding.InstanceOCID, "instance", cell) || !acceptedRegionalOCID(binding.PrimaryVNICOCID, "vnic", cell) ||
		!release.ValidOCIImageIDForRegion(binding.ImageOCID, cell) || err != nil || !address.Is4() || !address.IsPrivate() ||
		address.String() != binding.PrimaryPrivateIP || !markerDigestRE.MatchString(binding.Binary.SHA256) ||
		binding.Binary.Size <= 0 || binding.Binary.Size > release.MaxArtifactBytes ||
		binding.Binary.Architecture != "amd64" && binding.Binary.Architecture != "arm64" ||
		!filepath.IsAbs(store.Directory) || filepath.Clean(store.Directory) != store.Directory || store.Directory == "/" ||
		len(store.Directory) > 1024 || strings.ContainsAny(store.Directory, "\x00\r\n") ||
		!markerNameRE.MatchString(store.ServerName) || len(store.RaftNodeID) != 8 ||
		!markerDigestRE.MatchString(store.ServerNameSHA256) || !markerDigestRE.MatchString(store.NodeIdentitySHA256) {
		return ErrAcceptedIdentity
	}
	for _, char := range store.RaftNodeID {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z') {
			return ErrAcceptedIdentity
		}
	}
	return nil
}

func acceptedRegionalOCID(value, kind, cell string) bool {
	parts := strings.Split(value, ".")
	if len(value) > 255 || len(parts) != 5 || parts[0] != "ocid1" || parts[1] != kind ||
		parts[2] != "oc1" || parts[3] != catalog.OCIRegion(cell) || parts[4] == "" {
		return false
	}
	for _, char := range parts[4] {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
			return false
		}
	}
	return true
}

func validateAcceptedReferences(identity AcceptedIdentity) error {
	if len(identity.MaterialReferences) == 0 || len(identity.MaterialReferences) > 64 {
		return ErrAcceptedIdentity
	}
	allowed := bootstrap.MaterialGenerationFiles()
	for _, name := range []string{"route-password", "ticket.pub", "ticket.key", "membership.creds"} {
		allowed[name] = bootstrap.SecretRegionalShared
	}
	for _, name := range []string{"host-nats-issuer.seed", "terrabase-member-ca.pem", "terrabase-member-ca.key"} {
		allowed[name] = bootstrap.SecretHostIssuer
	}
	for _, suffix := range []string{".creds", "-tls-cert.pem", "-tls-key.pem", "-response.key"} {
		allowed[identity.Slot+suffix] = bootstrap.SecretController
	}
	if identity.Slot == identity.SeedSlot {
		allowed["founder-peer.key"] = bootstrap.SecretSeedFounder
		allowed["founder-ledger.key"] = bootstrap.SecretSeedLedgerSigner
	}
	allowed["interregion.jwt"], allowed["interregion-ca.pem"] = bootstrap.SecretInterRegion, bootstrap.SecretInterRegion
	allowed[bootstrap.LinkCredentialsFile] = bootstrap.SecretInterRegion
	cert, key := bootstrap.InterRegionTLSFiles(identity.Slot)
	allowed[cert], allowed[key] = bootstrap.SecretInterRegion, bootstrap.SecretInterRegion
	seen := make(map[string]bool, len(identity.MaterialReferences))
	for _, reference := range identity.MaterialReferences {
		purpose, known := allowed[reference.TargetFile]
		if strings.HasPrefix(reference.TargetFile, "leaf-") && strings.HasSuffix(reference.TargetFile, ".creds") {
			peer := strings.TrimSuffix(strings.TrimPrefix(reference.TargetFile, "leaf-"), ".creds")
			known, purpose = catalog.IsCell(strings.ToUpper(peer)) && peer == strings.ToLower(peer), bootstrap.SecretInterRegion
		}
		wantSlot := ""
		if purpose == bootstrap.SecretController || purpose == bootstrap.SecretSeedFounder || purpose == bootstrap.SecretSeedLedgerSigner ||
			reference.TargetFile == cert || reference.TargetFile == key {
			wantSlot = identity.Slot
		}
		if !known || reference.Purpose != purpose || reference.Slot != wantSlot || reference.ValidateIdentity() != nil ||
			!acceptedRegionalOCID(reference.SecretOCID, "vaultsecret", identity.Cell) || seen[reference.TargetFile] {
			return ErrAcceptedIdentity
		}
		seen[reference.TargetFile] = true
	}
	for _, name := range []string{"operator.jwt", "system.jwt", "cell.jwt", "system.creds", "ca.pem", "route-password",
		"ticket.pub", "ticket.key", "host-nats-issuer.seed", "host-tls-issuer-cert.pem", "host-tls-issuer-key.pem",
		identity.Slot + ".creds", identity.Slot + "-tls-cert.pem", identity.Slot + "-tls-key.pem", identity.Slot + "-response.key"} {
		if !seen[name] {
			return fmt.Errorf("%w: missing material %s", ErrAcceptedIdentity, name)
		}
	}
	if identity.ManagedMaterial != nil && (!seen["terrabase-member-ca.pem"] || !seen["terrabase-member-ca.key"]) {
		return ErrAcceptedIdentity
	}
	issuerCount := 0
	for name, purpose := range allowed {
		if purpose == bootstrap.SecretControllerIssuer && seen[name] {
			issuerCount++
		}
	}
	if issuerCount != 0 && issuerCount != 3 || (identity.Broker.AccountSigner != "") != (issuerCount == 3) {
		return ErrAcceptedIdentity
	}
	if identity.Broker.InterRegionAccount != "" && (!seen["interregion.jwt"] || !seen["interregion-ca.pem"] || !seen[cert] || !seen[key]) {
		return ErrAcceptedIdentity
	}
	return nil
}

// AcceptanceSHA256 matches the checkpoint's acyclic per-slot projection.
func (identity AcceptedIdentity) AcceptanceSHA256() (string, error) {
	if err := identity.Validate(); err != nil {
		return "", err
	}
	projection := struct {
		SchemaVersion int                          `json:"schemaVersion"`
		Origin        string                       `json:"origin"`
		OperationID   string                       `json:"operationId"`
		DeploymentID  string                       `json:"deploymentId"`
		ClusterID     string                       `json:"clusterId"`
		Environment   string                       `json:"environment"`
		Cell          string                       `json:"cell"`
		SeedSlot      string                       `json:"seedSlot"`
		Broker        identityrekey.BrokerIdentity `json:"broker"`
		Slot          string                       `json:"slot"`
		InstanceOCID  string                       `json:"instanceOcid"`
		ImageOCID     string                       `json:"imageOcid"`
		VNICOCID      string                       `json:"primaryVnicOcid"`
		PrivateIP     string                       `json:"primaryPrivateIp"`
		Binary        identityrekey.BinaryPin      `json:"binary"`
		Store         identityrekey.StoreIdentity  `json:"store"`
	}{identity.SchemaVersion, identity.Origin, identity.OperationID, identity.DeploymentID, identity.ClusterID, identity.Environment,
		identity.Cell, identity.SeedSlot, identity.Broker, identity.Slot, identity.InstanceOCID, identity.ImageOCID,
		identity.PrimaryVNICOCID, identity.PrimaryPrivateIP, identity.Binary, identity.Store}
	wire, err := protocol.EncodeJSON(projection)
	if err != nil {
		return "", err
	}
	return digest(append([]byte("terrascale.identity-rekey.slot-acceptance.v1\x00"), wire...)), nil
}

// InitialAcceptedIdentityInputs are current first-install proofs and independent
// physical/prepared broker facts. VerifyCurrent rechecks their common boundary.
type InitialAcceptedIdentityInputs struct {
	OperationID          string
	Manifest             bootstrap.StartupAuthority
	Receipt              bootstrap.VerifiedReceipt
	Image                release.VerifiedImage
	Observed             InstanceObservation
	Binary               RunningBinary
	Broker               identityrekey.BrokerIdentity
	Store                identityrekey.StoreIdentity
	LaunchMaterialSHA256 map[string]string
	ControllerBindings   []ControllerBinding
	AcceptedAt           time.Time
	VerifyCurrent        CurrentProofVerifier
}

// IdentityObservation must use the exact natscell preparation checks. Accepted
// pins or configuration declarations alone are not an independent observation.
type IdentityObservation func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error)
