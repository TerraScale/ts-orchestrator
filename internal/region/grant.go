package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const foundationGrantDomain = "terrascale.foundation.scope"
const foundationGrantObject = "foundation-scope-v1.json"

// FoundationGrant is a separate root authorization. A bootstrap anchor, region
// subscription or permission to read OCI never authorizes foundation spending.
type FoundationGrant struct {
	InstallationID      string             `json:"installationId"`
	SchemaVersion       int                `json:"schemaVersion"`
	Generation          uint64             `json:"generation"`
	TenancyID           string             `json:"tenancyId"`
	ParentCompartmentID string             `json:"parentCompartmentId"`
	SharedCompartmentID string             `json:"sharedCompartmentId"`
	Currency            string             `json:"currency"`
	MonthlyLimitMinor   int64              `json:"monthlyLimitMinor"`
	CleanupOwner        string             `json:"cleanupOwner"`
	Regions             []FoundationIntent `json:"regions"`
}

// BootstrapMaterialIntent explicitly authorizes credential generation. Its
// digest covers public generation inputs; secret output bytes are checkpointed
// separately by the existing immutable source producer.
type BootstrapMaterialIntent struct {
	InstallationID    string                        `json:"installationId"`
	PlanSHA256        string                        `json:"planSha256"`
	Config            bootstrapmaterial.Config      `json:"config"`
	SourceVaultTarget bootstrapmaterial.VaultTarget `json:"sourceVaultTarget"`
}

type VerifiedBootstrapMaterial struct {
	intent     BootstrapMaterialIntent
	generation uint64
	storage    bootstrap.StorageDomain
	expires    time.Time
	escrow     bootstrapmaterial.VaultTarget
}

func (v VerifiedBootstrapMaterial) EscrowTarget() bootstrapmaterial.VaultTarget { return v.escrow }

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
	footprint, expires, err := s.authorizedRegions(ctx)
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
		config := material.Config
		wire, err := json.Marshal(config, json.Deterministic(true))
		digest := sha256.Sum256(wire)
		if err != nil || !entityid.Valid(material.InstallationID) || material.PlanSHA256 != hex.EncodeToString(digest[:]) ||
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
		config.Slots = slices.Clone(config.Slots)
		material.Config = config
		return VerifiedBootstrapMaterial{intent: material, generation: intent.Generation, storage: s.storage, expires: expires, escrow: escrow}, nil
	}
	return VerifiedBootstrapMaterial{}, errors.New("signed foundation scope does not authorize regional credential generation")
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
	if !time.Now().Before(s.expires) {
		return ApprovedFootprint{}, time.Time{}, errors.New("foundation bootstrap authority expired")
	}
	domain := s.storage
	name := strings.TrimSuffix(domain.Prefix, "/") + "/" + foundationGrantObject
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := s.client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(name)})
	if err != nil {
		return ApprovedFootprint{}, time.Time{}, errors.New("authenticated foundation scope unavailable; initial tenancy authorization is required")
	}
	if response.Content == nil {
		return ApprovedFootprint{}, time.Time{}, errors.New("foundation scope object has no content")
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, foundationRecordLimit+1))
	if err != nil || len(wire) > foundationRecordLimit {
		return ApprovedFootprint{}, time.Time{}, errors.New("foundation scope object unreadable or oversized")
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
