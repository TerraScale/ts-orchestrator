package region

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const foundationGrantDomain = "terrascale.foundation.scope"
const foundationGrantObject = "foundation-scope-v1.json"

// FoundationGrant is a separate root authorization. A bootstrap anchor, region
// subscription or permission to read OCI never authorizes foundation spending.
type FoundationGrant struct {
	InstallationID      string                     `json:"installationId"`
	SchemaVersion       int                        `json:"schemaVersion"`
	Generation          uint64                     `json:"generation"`
	TenancyID           string                     `json:"tenancyId"`
	ParentCompartmentID string                     `json:"parentCompartmentId"`
	SharedCompartmentID string                     `json:"sharedCompartmentId"`
	Currency            string                     `json:"currency"`
	MonthlyLimitMinor   int64                      `json:"monthlyLimitMinor"`
	CleanupOwner        string                     `json:"cleanupOwner"`
	Regions             []FoundationIntent         `json:"regions"`
	InfrastructureSpend *InfrastructureSpendIntent `json:"infrastructureSpend,omitempty"`
}

// BootstrapMaterialIntent explicitly authorizes credential generation. Its
// digest covers public generation inputs; secret output bytes are checkpointed
// separately by the existing immutable source producer.
type BootstrapMaterialIntent struct {
	InstallationID     string                               `json:"installationId"`
	PlanSHA256         string                               `json:"planSha256"`
	Config             bootstrapmaterial.Config             `json:"config"`
	SourceVaultTarget  bootstrapmaterial.VaultTarget        `json:"sourceVaultTarget"`
	Startup            *BootstrapStartupIntent              `json:"startup,omitempty"`
	SourceRegistration *bootstrap.InitialSourceRegistration `json:"sourceRegistration,omitempty"`
}

type BootstrapStartupIntent = bootstrap.StartupTemplate

type VerifiedBootstrapMaterial struct {
	intent          BootstrapMaterialIntent
	generation      uint64
	storage         bootstrap.StorageDomain
	expires         time.Time
	escrow          bootstrapmaterial.VaultTarget
	image           release.VerifiedImage
	grantWire       []byte
	ledgerPublicKey string
}

func (v VerifiedBootstrapMaterial) SourceRegistration() (bootstrap.InitialSourceRegistration, error) {
	if !v.IsVerified() || !time.Now().Before(v.expires) || v.intent.SourceRegistration == nil {
		return bootstrap.InitialSourceRegistration{}, errors.New("same signed grant has no current initial source registration authority")
	}
	return v.intent.SourceRegistration.Clone(), nil
}

// PinnedLedgerSignerPublicKey returns only an existing local anchor's verified
// ledger key. A new registration conveys no replacement authority.
func (v VerifiedBootstrapMaterial) PinnedLedgerSignerPublicKey() (string, error) {
	if !v.IsVerified() || !time.Now().Before(v.expires) || v.ledgerPublicKey == "" {
		return "", errors.New("same signed scope has no current pinned local ledger signer")
	}
	return v.ledgerPublicKey, nil
}

func (v VerifiedBootstrapMaterial) FoundationGrantWire() []byte { return bytes.Clone(v.grantWire) }

func (v VerifiedBootstrapMaterial) EscrowTarget() bootstrapmaterial.VaultTarget { return v.escrow }

func (v VerifiedBootstrapMaterial) Startup() (BootstrapStartupIntent, error) {
	if !v.IsVerified() || !time.Now().Before(v.expires) || v.intent.Startup == nil || !v.image.IsVerified() {
		return BootstrapStartupIntent{}, errors.New("signed bootstrap scope does not authorize initial controller startup")
	}
	return v.intent.Startup.Clone(), nil
}
func (v VerifiedBootstrapMaterial) Image() (release.VerifiedImage, error) {
	if _, err := v.Startup(); err != nil {
		return release.VerifiedImage{}, err
	}
	return v.image, nil
}

func (v VerifiedBootstrapMaterial) InstallationID() string                 { return v.intent.InstallationID }
func (v VerifiedBootstrapMaterial) Generation() uint64                     { return v.generation }
func (v VerifiedBootstrapMaterial) PlanDigest() string                     { return v.intent.PlanSHA256 }
func (v VerifiedBootstrapMaterial) StorageDomain() bootstrap.StorageDomain { return v.storage }
func (v VerifiedBootstrapMaterial) ExpiresAt() time.Time                   { return v.expires }
func (v VerifiedBootstrapMaterial) IsVerified() bool                       { return v.generation > 0 }
func (v VerifiedBootstrapMaterial) Config() bootstrapmaterial.Config {
	config := v.intent.Config
	config.Slots = slices.Clone(config.Slots)
	return config
}

func (s *SignedFootprint) AuthorizedBootstrapMaterial(ctx context.Context, cell string) (VerifiedBootstrapMaterial, error) {
	grantWire, err := s.readGrant(ctx)
	if err != nil {
		return VerifiedBootstrapMaterial{}, err
	}
	footprint, expires, err := s.verifyGrant(grantWire)
	if err != nil {
		return VerifiedBootstrapMaterial{}, err
	}
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != cell {
			continue
		}
		if intent.BootstrapMaterial == nil {
			break
		}
		material := *intent.BootstrapMaterial
		if material.SourceRegistration != nil {
			registration := material.SourceRegistration.Clone()
			slots := make([]string, len(material.Config.Slots))
			for i, slot := range material.Config.Slots {
				slots[i] = slot.Name
			}
			slices.Sort(slots)
			if registration.Validate() != nil || registration.InstallationID != material.InstallationID || registration.Generation != intent.Generation || registration.PlanSHA256 != material.PlanSHA256 || registration.DeploymentID != material.Config.DeploymentID || registration.Environment != material.Config.Environment || registration.ClusterID != material.Config.ClusterID || strings.ToLower(string(registration.Cell)) != material.Config.Cell || !slices.Equal(registration.ControllerSlots, slots) {
				return VerifiedBootstrapMaterial{}, errors.New("initial source registration differs from same signed material scope")
			}
			if material.Startup == nil || registration.SeedSlot != material.Startup.SeedSlot {
				return VerifiedBootstrapMaterial{}, errors.New("initial source registration lacks exact signed startup seed")
			}
			if registration.Cell == s.local.Cell {
				if s.local.InitialSourceRegistration == nil || len(s.local.LedgerDelegationWire) != 0 {
					return VerifiedBootstrapMaterial{}, errors.New("new source cannot replace existing pinned ledger authority")
				}
				localWire, _ := json.Marshal(s.local.InitialSourceRegistration, json.Deterministic(true))
				registrationWire, _ := json.Marshal(registration, json.Deterministic(true))
				if !bytes.Equal(localWire, registrationWire) {
					return VerifiedBootstrapMaterial{}, errors.New("new source registration differs from root anchor")
				}
			}
			material.SourceRegistration = &registration
		}
		config := material.Config
		wire, err := json.Marshal(config, json.Deterministic(true))
		digest := sha256.Sum256(wire)
		if err != nil || !entityid.Valid(material.InstallationID) || material.InstallationID != s.home.InstallationID || material.PlanSHA256 != hex.EncodeToString(digest[:]) ||
			config.Validate() != nil || config.Cell != strings.ToLower(cell) || config.Region != intent.Plan["region"] ||
			config.Environment != s.scope.Environment ||
			(config.Cell == strings.ToLower(string(s.local.Cell)) && (config.DeploymentID != s.local.DeploymentID || config.ClusterID != s.local.ClusterID)) {
			return VerifiedBootstrapMaterial{}, errors.New("bootstrap material intent differs from authenticated installation, region or digest")
		}
		escrow := material.SourceVaultTarget
		if escrow.Validate("sa-saopaulo-1") != nil || escrow.KMSKeyOCID != s.storage.HeadKMSKeyOCID {
			return VerifiedBootstrapMaterial{}, errors.New("bootstrap escrow differs from signed home Vault/KMS target")
		}
		owned := false
		for _, home := range footprint.Regions {
			if home.Plan["cell"] != "GRU" {
				continue
			}
			ids, _ := home.Plan["resource_ids"].(map[string]any)
			owned = ids["control_compartment"] == escrow.CompartmentOCID && ids["vault"] == escrow.VaultOCID && ids["key"] == escrow.KMSKeyOCID
		}
		if !owned {
			return VerifiedBootstrapMaterial{}, errors.New("bootstrap escrow is outside the signed owned home foundation")
		}
		var image release.VerifiedImage
		if material.Startup != nil {
			startup := material.Startup.Clone()
			image, err = s.verifyStartup(startup, config, intent.Plan)
			if err != nil {
				return VerifiedBootstrapMaterial{}, err
			}
			material.Startup = &startup
			if image.ExpiresAt().Before(expires) {
				expires = image.ExpiresAt()
			}
		}
		config.Slots = slices.Clone(config.Slots)
		material.Config = config
		var ledgerPublicKey string
		if config.Cell == strings.ToLower(string(s.local.Cell)) && len(s.local.LedgerDelegationWire) > 0 {
			envelope, err := trust.DecodeEnvelope(s.local.LedgerDelegationWire)
			if err != nil {
				return VerifiedBootstrapMaterial{}, err
			}
			if _, err := trust.VerifyDelegationCurrent(envelope, s.roots, time.Now(), bootstrap.BootstrapAnchorTrustPolicy()); err != nil {
				return VerifiedBootstrapMaterial{}, err
			}
			var delegation trust.Delegation
			if err := json.Unmarshal(envelope.Payload, &delegation, json.RejectUnknownMembers(true)); err != nil {
				return VerifiedBootstrapMaterial{}, err
			}
			key, err := base64.RawURLEncoding.Strict().DecodeString(delegation.SubjectPublicKey)
			if err != nil || len(key) != 32 {
				return VerifiedBootstrapMaterial{}, errors.New("pinned local ledger signer is invalid")
			}
			ledgerPublicKey = base64.StdEncoding.EncodeToString(key)
		}
		return VerifiedBootstrapMaterial{intent: material, generation: intent.Generation, storage: s.storage, expires: expires, escrow: escrow, image: image, grantWire: bytes.Clone(grantWire), ledgerPublicKey: ledgerPublicKey}, nil
	}
	return VerifiedBootstrapMaterial{}, errors.New("signed foundation scope does not authorize regional credential generation")
}

func (s *SignedFootprint) verifyStartup(startup BootstrapStartupIntent, config bootstrapmaterial.Config, plan map[string]any) (release.VerifiedImage, error) {
	if err := startup.Validate(); err != nil {
		return release.VerifiedImage{}, err
	}
	if config.Cell == strings.ToLower(string(s.local.Cell)) && !bytes.Equal(startup.ControllerFiles[0].Bytes, s.local.InitialRegionIntentWire) {
		return release.VerifiedImage{}, errors.New("startup sidecar differs from exact root-anchored initial region intent")
	}
	slots := map[string]bool{}
	for _, slot := range config.Slots {
		slots[slot.Name] = true
	}
	if !slots[startup.SeedSlot] || len(startup.Profiles) != len(slots) || len(startup.TrustedSigners) == 0 {
		return release.VerifiedImage{}, errors.New("startup lacks exact signed slot profiles or operator authority")
	}
	ids, _ := plan["resource_ids"].(map[string]any)
	seen := map[string]bool{}
	for _, profile := range startup.Profiles {
		if !slots[profile.Slot] || seen[profile.Slot] || profile.CompartmentOCID != ids["control_compartment"] || profile.SubnetOCID != ids["subnet"] || profile.CompartmentOCID == "" || profile.SubnetOCID == "" || profile.AvailabilityDomain == "" || len(profile.AvailabilityDomain) > 255 || profile.FaultDomain == "" || len(profile.FaultDomain) > 255 || profile.Shape == "" || len(profile.Shape) > 128 || len(profile.NetworkSecurityGroupOCIDs) != 1 || profile.NetworkSecurityGroupOCIDs[0] != ids["network_security_group"] || profile.NetworkSecurityGroupOCIDs[0] == "" {
			return release.VerifiedImage{}, errors.New("startup profile differs from signed owned regional foundation")
		}
		seen[profile.Slot] = true
	}
	var signers []struct {
		Actor        string                    `json:"actor"`
		PublicKey    string                    `json:"public_key"`
		Roles        []string                  `json:"roles"`
		Environments []string                  `json:"environments"`
		Remaining    map[string]jsontext.Value `json:",unknown"`
	}
	if err := json.Unmarshal(startup.TrustedSigners, &signers); err != nil || len(signers) == 0 || len(signers) > 64 {
		return release.VerifiedImage{}, errors.New("startup operator grants invalid")
	}
	actors := map[string]bool{}
	for _, signer := range signers {
		key, err := base64.StdEncoding.Strict().DecodeString(signer.PublicKey)
		if signer.Actor == "" || len(signer.Actor) > 128 || actors[signer.Actor] || err != nil || len(key) != 32 || len(signer.Roles) == 0 || !slices.Contains(signer.Environments, config.Environment) {
			return release.VerifiedImage{}, errors.New("startup operator authority is absent, ambiguous or outside environment")
		}
		actors[signer.Actor] = true
	}
	architecture := strings.TrimPrefix(startup.ImageArchitecture, "linux-")
	if architecture != "amd64" && architecture != "arm64" {
		return release.VerifiedImage{}, errors.New("startup architecture is invalid")
	}
	image, err := release.VerifyImageCurrent(startup.ReleaseImageReceiptWire, startup.ReleaseDelegationWire, s.roots, release.ImageExpectation{Environment: config.Environment, LogicalRegion: strings.ToUpper(config.Cell), OCIImageOCID: startup.ImageOCID, Architecture: architecture}, time.Now())
	if err != nil {
		return release.VerifiedImage{}, err
	}
	return image, nil
}

// SignedFootprint reads the exact root-authorized home object; it cannot list,
// create or install a grant. Its trust/storage identity comes from a currently
// verified controller bootstrap anchor.
type SignedFootprint struct {
	client  FoundationObjects
	storage bootstrap.StorageDomain
	scope   trust.Scope
	expires time.Time
	roots   trust.Keyring
	tenancy string
	home    bootstrap.FoundationScope
	local   bootstrap.BootstrapAnchor
}

func NewSignedFootprint(client FoundationObjects, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, tenancy string) (*SignedFootprint, error) {
	if client == nil || !anchor.IsVerified() || len(roots) == 0 {
		return nil, errors.New("foundation scope requires verified bootstrap identity and roots")
	}
	home, err := anchor.FoundationScope()
	if err != nil {
		return nil, err
	}
	if tenancy != home.TenancyID {
		return nil, errors.New("authenticated tenancy differs from signed home reference")
	}
	identity := anchor.Anchor()
	return &SignedFootprint{client: client, storage: home.StorageDomain, expires: anchor.ExpiresAt(), home: home, local: identity,
		scope: trust.Scope{Domain: foundationGrantDomain, DeploymentID: home.DeploymentID, Cell: "GRU", Environment: identity.Environment, Role: "foundation", Slot: home.ClusterID}, roots: maps.Clone(roots), tenancy: tenancy}, nil
}

func (s *SignedFootprint) AuthorizedRegions(ctx context.Context) (ApprovedFootprint, error) {
	footprint, _, err := s.authorizedRegions(ctx)
	return footprint, err
}

func (s *SignedFootprint) authorizedRegions(ctx context.Context) (ApprovedFootprint, time.Time, error) {
	wire, err := s.readGrant(ctx)
	if err != nil {
		return ApprovedFootprint{}, time.Time{}, err
	}
	return s.verifyGrant(wire)
}

func (s *SignedFootprint) readGrant(ctx context.Context) ([]byte, error) {
	if !time.Now().Before(s.expires) {
		return nil, errors.New("foundation bootstrap authority expired")
	}
	domain := s.storage
	name := strings.TrimSuffix(domain.Prefix, "/") + "/" + foundationGrantObject
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := s.client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(name)})
	if err != nil {
		return nil, errors.New("authenticated foundation scope unavailable; initial tenancy authorization is required")
	}
	if response.Content == nil {
		return nil, errors.New("foundation scope object has no content")
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, foundationRecordLimit+1))
	if err != nil || len(wire) > foundationRecordLimit {
		return nil, errors.New("foundation scope object unreadable or oversized")
	}
	return wire, nil
}

func (s *SignedFootprint) verifyGrant(wire []byte) (ApprovedFootprint, time.Time, error) {
	if !time.Now().Before(s.expires) {
		return ApprovedFootprint{}, time.Time{}, errors.New("foundation bootstrap authority expired")
	}
	digest := sha256.Sum256(wire)
	if hex.EncodeToString(digest[:]) != s.home.GrantSHA256 {
		return ApprovedFootprint{}, time.Time{}, errors.New("foundation grant differs from root-pinned exact wire")
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return ApprovedFootprint{}, time.Time{}, err
	}
	payload, err := trust.VerifyCurrent(envelope, s.scope, s.roots, time.Now(), bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return ApprovedFootprint{}, time.Time{}, err
	}
	if envelope.ExpiresAt.After(s.expires) {
		return ApprovedFootprint{}, time.Time{}, errors.New("foundation scope outlives bootstrap authority")
	}
	var grant FoundationGrant
	if err := json.Unmarshal(payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return ApprovedFootprint{}, time.Time{}, errors.New("foundation scope schema invalid")
	}
	if grant.InstallationID != s.home.InstallationID || grant.SchemaVersion != 1 || grant.Generation != s.home.GrantGeneration || grant.TenancyID != s.tenancy || grant.MonthlyLimitMinor <= 0 ||
		(grant.Currency != "USD" && grant.Currency != "BRL") || grant.CleanupOwner == "" || len(grant.CleanupOwner) > 128 {
		return ApprovedFootprint{}, time.Time{}, errors.New("foundation scope lacks matching tenancy, numerical spend authority or cleanup owner")
	}
	footprint := ApprovedFootprint{TenancyID: grant.TenancyID, ParentCompartmentID: grant.ParentCompartmentID,
		SharedCompartmentID: grant.SharedCompartmentID, Regions: grant.Regions}
	for _, intent := range footprint.Regions {
		if intent.Generation != grant.Generation {
			return ApprovedFootprint{}, time.Time{}, errors.New("foundation intent generation differs from signed grant")
		}
	}
	return footprint, envelope.ExpiresAt, validateFootprint(footprint)
}

// NewFoundationDiscovery supplies a concrete pre-overlay record reader using
// instance-principal clients and the existing verified bootstrap trust/storage
// scope. Missing grants remain blocked; this constructor performs no writes.
func NewFoundationDiscovery(factory *ociclient.Factory, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring) (FoundationResolver, error) {
	if factory == nil || !anchor.IsVerified() || factory.Region() != anchor.Anchor().OCIRegion {
		return FoundationResolver{}, errors.New("foundation discovery requires the verified local-region OCI client")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return FoundationResolver{}, err
	}
	home, err := anchor.FoundationScope()
	if err != nil {
		return FoundationResolver{}, err
	}
	homeFactory, err := factory.ForRegion(home.OCIRegion)
	if err != nil {
		return FoundationResolver{}, err
	}
	client, err := homeFactory.ObjectStorage()
	if err != nil {
		return FoundationResolver{}, err
	}
	footprint, err := NewSignedFootprint(&client, anchor, roots, tenancy)
	if err != nil {
		return FoundationResolver{}, err
	}
	domain := home.StorageDomain
	store, err := NewObjectFoundationStore(&client, domain.Namespace, domain.HeadBucket)
	if err != nil {
		return FoundationResolver{}, err
	}
	return FoundationResolver{Footprint: footprint, Store: store}, nil
}
