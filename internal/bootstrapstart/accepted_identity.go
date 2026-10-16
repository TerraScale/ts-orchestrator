package bootstrapstart

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
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
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
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
	if identityrekey.ValidateLaunchMaterialPins(identity.LaunchMaterialSHA256) != nil {
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

func EncodeAcceptedIdentity(identity AcceptedIdentity) ([]byte, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(identity)
	if err != nil || len(wire) > MaxAcceptedIdentityBytes {
		return nil, ErrAcceptedIdentity
	}
	return wire, nil
}

func DecodeAcceptedIdentity(wire []byte) (AcceptedIdentity, error) {
	var identity AcceptedIdentity
	if err := protocol.DecodeStrict(wire, &identity, MaxAcceptedIdentityBytes); err != nil {
		return AcceptedIdentity{}, fmt.Errorf("%w: %v", ErrAcceptedIdentity, err)
	}
	canonical, err := EncodeAcceptedIdentity(identity)
	if err != nil || !bytes.Equal(wire, canonical) {
		return AcceptedIdentity{}, ErrAcceptedIdentity
	}
	return identity, nil
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

func AcceptedIdentityFromCheckpoint(verified identityrekey.VerifiedIdentityCheckpoint, slot string, acceptedAt time.Time) (AcceptedIdentity, error) {
	if !verified.IsVerified() || verified.Slot() != slot || acceptedAt.IsZero() || acceptedAt.Location() != time.UTC ||
		!acceptedAt.Before(verified.ExpiresAt()) {
		return AcceptedIdentity{}, ErrAcceptedIdentity
	}
	envelope, err := trust.DecodeEnvelope(verified.Wire())
	if err != nil || !coveredAt(envelope.IssuedAt, envelope.ExpiresAt, acceptedAt) {
		return AcceptedIdentity{}, ErrAcceptedIdentity
	}
	checkpoint := verified.Checkpoint()
	if err := checkpoint.Validate(); err != nil {
		return AcceptedIdentity{}, err
	}
	identity := AcceptedIdentity{SchemaVersion: 1, Origin: identityrekey.AcceptanceOriginRekey, OperationID: checkpoint.OperationID, DeploymentID: checkpoint.DeploymentID,
		ClusterID: checkpoint.ClusterID, Environment: checkpoint.Environment, Cell: checkpoint.Cell, Slot: slot,
		SeedSlot: checkpoint.SeedSlot, ControllerSlots: []string{"controller-a", "controller-b", "controller-c"},
		Broker: checkpoint.Broker, MaterialGenerationSHA256: checkpoint.MaterialGenerationSHA256,
		ManagedMaterial: checkpoint.ManagedMaterial, AcceptedAt: acceptedAt}
	for _, binding := range checkpoint.Slots {
		identity.ControllerBindings = append(identity.ControllerBindings, ControllerBinding{Slot: binding.Slot,
			InstanceOCID: binding.InstanceOCID, ImageOCID: binding.ImageOCID, PrimaryVNICOCID: binding.PrimaryVNICOCID,
			PrimaryPrivateIP: binding.PrimaryPrivateIP, Binary: binding.Binary, Store: binding.Store})
		if binding.Slot == slot {
			identity.InstanceOCID, identity.ImageOCID = binding.InstanceOCID, binding.ImageOCID
			identity.PrimaryVNICOCID, identity.PrimaryPrivateIP = binding.PrimaryVNICOCID, binding.PrimaryPrivateIP
			identity.Binary, identity.Store = binding.Binary, binding.Store
			identity.ConfigSHA256, identity.MaterialReferences = binding.ConfigSHA256, binding.MaterialReferences
			identity.LaunchMaterialSHA256 = binding.LaunchMaterialSHA256
		}
	}
	if err := identity.Validate(); err != nil {
		return AcceptedIdentity{}, err
	}
	return identity.Clone(), nil
}

// InitialAcceptedIdentityInputs are current first-install proofs and independent
// physical/prepared broker facts. VerifyCurrent rechecks their common boundary.
type InitialAcceptedIdentityInputs struct {
	OperationID          string
	Manifest             bootstrap.VerifiedManifest
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

func AcceptedIdentityFromInitial(inputs InitialAcceptedIdentityInputs) (AcceptedIdentity, error) {
	if inputs.VerifyCurrent == nil || !inputs.Image.IsVerified() || inputs.AcceptedAt.IsZero() ||
		inputs.AcceptedAt.Location() != time.UTC || !coveredAt(inputs.Image.IssuedAt(), inputs.Image.ExpiresAt(), inputs.AcceptedAt) {
		return AcceptedIdentity{}, ErrAcceptedIdentity
	}
	if err := inputs.VerifyCurrent(inputs.AcceptedAt); err != nil {
		return AcceptedIdentity{}, err
	}
	payload := inputs.Manifest.Manifest()
	wantReceipt, err := bootstrap.NewReceipt(inputs.Manifest, inputs.Observed.Facts)
	if err != nil || wantReceipt != inputs.Receipt.Receipt() || !inputs.Observed.PrimaryVNIC ||
		inputs.Observed.InstanceOCID != wantReceipt.InstanceOCID || inputs.Observed.ImageOCID != wantReceipt.ImageOCID ||
		payload.Slot != wantReceipt.Slot || inputs.Observed.LifecycleState != "RUNNING" {
		return AcceptedIdentity{}, ErrAcceptedIdentity
	}
	image := inputs.Image.Receipt()
	if image.OCIImageOCID != payload.ImageOCID || image.OCIRegion != string(payload.Cell) ||
		inputs.Binary.SHA256 != image.BinarySHA256 || inputs.Binary.Bytes != image.BinaryBytes ||
		inputs.Binary.Architecture != image.Architecture {
		return AcceptedIdentity{}, ErrAcceptedIdentity
	}
	identity := AcceptedIdentity{SchemaVersion: 1, Origin: identityrekey.AcceptanceOriginInitial, OperationID: inputs.OperationID, DeploymentID: payload.DeploymentID,
		ClusterID: payload.ClusterID, Environment: payload.Environment, Cell: string(payload.Cell), Slot: payload.Slot,
		SeedSlot: payload.SeedSlot, ControllerSlots: payload.ControllerSlots, ControllerBindings: inputs.ControllerBindings,
		InstanceOCID: inputs.Observed.InstanceOCID, ImageOCID: inputs.Observed.ImageOCID,
		PrimaryVNICOCID: inputs.Observed.PrimaryVNICOCID, PrimaryPrivateIP: inputs.Observed.PrimaryPrivateIP,
		Binary: identityrekey.BinaryPin{SHA256: inputs.Binary.SHA256, Size: inputs.Binary.Bytes, Architecture: inputs.Binary.Architecture},
		Broker: inputs.Broker, Store: inputs.Store, ConfigSHA256: map[string]string{"controller.json": payload.ControllerConfigSHA256},
		LaunchMaterialSHA256: inputs.LaunchMaterialSHA256, ManagedMaterial: payload.ManagedMaterial, AcceptedAt: inputs.AcceptedAt}
	identity = identity.Clone()
	for _, file := range payload.ControllerFiles {
		identity.ConfigSHA256[file.Name] = file.SHA256
	}
	for _, reference := range payload.Secrets {
		if reference.Slot == "" || reference.Slot == payload.Slot {
			identity.MaterialReferences = append(identity.MaterialReferences, reference)
		}
	}
	if !slices.ContainsFunc(identity.ControllerBindings, func(binding ControllerBinding) bool { return binding.Slot == identity.Slot }) {
		identity.ControllerBindings = append(identity.ControllerBindings, identity.localBinding())
	}
	slices.SortFunc(identity.ControllerBindings, func(a, b ControllerBinding) int { return strings.Compare(a.Slot, b.Slot) })
	if err := identity.Validate(); err != nil {
		return AcceptedIdentity{}, err
	}
	return identity, nil
}

// IdentityObservation must use the exact natscell preparation checks. Accepted
// pins or configuration declarations alone are not an independent observation.
type IdentityObservation func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error)

// VerifyAcceptedLocalIdentity refuses absent/changed stores before observation;
// observers must not initialize stores or replace broker identities.
func VerifyAcceptedLocalIdentity(identity AcceptedIdentity, observe IdentityObservation) error {
	if identity.Validate() != nil || observe == nil {
		return ErrAcceptedIdentity
	}
	if err := verifyAcceptedStoreFiles(identity.Store); err != nil {
		return err
	}
	broker, store, err := observe(identity.Clone())
	if err != nil {
		return err
	}
	if broker != identity.Broker || store != identity.Store {
		return ErrAcceptedIdentity
	}
	return verifyAcceptedStoreFiles(identity.Store)
}

func verifyAcceptedStoreFiles(store identityrekey.StoreIdentity) error {
	return verifyAcceptedStorePins(store, map[string]string{"server-name": store.ServerNameSHA256, "node-identity.json": store.NodeIdentitySHA256})
}

func verifyAcceptedStorePins(store identityrekey.StoreIdentity, pins map[string]string) error {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(store.Directory, "/"), "/") {
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return err
		}
		fd = next
	}
	defer unix.Close(fd)
	for name, want := range pins {
		fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fileFD), name)
		var stat unix.Stat_t
		if err := unix.Fstat(fileFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > 4096 {
			file.Close()
			return ErrAcceptedIdentity
		}
		wire, err := io.ReadAll(io.LimitReader(file, 4097))
		var current unix.Stat_t
		pathErr := unix.Fstatat(fd, name, &current, unix.AT_SYMLINK_NOFOLLOW)
		file.Close()
		if err != nil || len(wire) > 4096 || digest(wire) != want || pathErr != nil ||
			current.Dev != stat.Dev || current.Ino != stat.Ino || current.Mode != stat.Mode || current.Nlink != 1 || current.Size != stat.Size {
			return ErrAcceptedIdentity
		}
	}
	return nil
}

func (store MarkerStore) ReadIdentity() (AcceptedIdentity, error) {
	dir, err := store.openDirectory()
	if err != nil {
		return AcceptedIdentity{}, err
	}
	defer unix.Close(dir)
	wire, err := store.readIdentityBytes(dir, markerName)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	return DecodeAcceptedIdentity(wire)
}

func (store MarkerStore) readIdentityBytes(dir int, name string) ([]byte, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != store.ownerUID || store.ownerUID == 0 && stat.Gid != 0 || stat.Mode&0o7777 != 0o644 ||
		stat.Nlink != 1 || stat.Size <= 0 || stat.Size > MaxAcceptedIdentityBytes {
		return nil, ErrAcceptedIdentity
	}
	wire, err := io.ReadAll(io.LimitReader(file, MaxAcceptedIdentityBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > MaxAcceptedIdentityBytes {
		return nil, ErrAcceptedIdentity
	}
	return wire, nil
}

func (store MarkerStore) WriteNewIdentity(identity AcceptedIdentity, observe IdentityObservation) error {
	return store.publishIdentity(identity.Clone(), "", observe)
}

// ReplaceIdentity never interprets the predecessor as an identity document.
func (store MarkerStore) ReplaceIdentity(verified identityrekey.VerifiedIdentityCheckpoint, slot string,
	acceptedAt time.Time, observe IdentityObservation,
) error {
	identity, err := AcceptedIdentityFromCheckpoint(verified, slot, acceptedAt)
	if err != nil {
		return err
	}
	for _, binding := range verified.Checkpoint().Slots {
		if binding.Slot == slot {
			return store.publishIdentity(identity, binding.PreviousAcceptanceSHA256, observe)
		}
	}
	return ErrAcceptedIdentity
}

func (store MarkerStore) publishIdentity(identity AcceptedIdentity, predecessor string, observe IdentityObservation) error {
	return store.publishIdentityAt(identity, predecessor, observe, markerName)
}

func (store MarkerStore) publishIdentityAt(identity AcceptedIdentity, predecessor string, observe IdentityObservation, name string) error {
	wire, err := EncodeAcceptedIdentity(identity)
	if err != nil {
		return err
	}
	if err := VerifyAcceptedLocalIdentity(identity, observe); err != nil {
		return err
	}
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	lock, err := unix.Openat(dir, ".accepted-identity.lock", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o644)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		lock, err = unix.Openat(dir, ".accepted-identity.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return err
	}
	defer unix.Close(lock)
	var stat unix.Stat_t
	if err := unix.Fstat(lock, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != store.ownerUID || store.ownerUID == 0 && stat.Gid != 0 || stat.Nlink != 1 {
		return ErrAcceptedIdentity
	}
	if created {
		if err := unix.Fchmod(lock, 0o644); err != nil {
			return err
		}
	} else if stat.Mode&0o7777 != 0o644 {
		return ErrAcceptedIdentity
	}
	if err := unix.Flock(lock, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(lock, unix.LOCK_UN)
	if predecessor != "" {
		old, err := store.readIdentityBytes(dir, markerName)
		if err != nil {
			return err
		}
		if digest(old) != predecessor {
			return ErrAcceptancePredecessor
		}
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".accepted-install." + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	if err := unix.Fchmod(fd, 0o644); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != store.ownerUID || store.ownerUID == 0 && stat.Gid != 0 ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return ErrAcceptedIdentity
	}
	if count, err := file.Write(wire); err != nil {
		return err
	} else if count != len(wire) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := VerifyAcceptedLocalIdentity(identity, observe); err != nil {
		return err
	}
	if predecessor == "" {
		err = unix.Renameat2(dir, temporary, dir, name, unix.RENAME_NOREPLACE)
	} else {
		old, readErr := store.readIdentityBytes(dir, markerName)
		if readErr != nil {
			return readErr
		}
		if digest(old) != predecessor {
			return ErrAcceptancePredecessor
		}
		err = unix.Renameat(dir, temporary, dir, markerName)
	}
	if err != nil {
		return err
	}
	return unix.Fsync(dir)
}
