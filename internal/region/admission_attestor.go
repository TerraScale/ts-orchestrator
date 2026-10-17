package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var ErrAdmissionAttestorHold = errors.New("original admission attestor producer or protected source selection is unavailable")

func foundationAdmissionAttestor(grant FoundationGrant, home bootstrap.StorageDomain, regional FoundationIntent) (release.AdmissionAttestorAuthorization, error) {
	deny := func() (release.AdmissionAttestorAuthorization, error) {
		return release.AdmissionAttestorAuthorization{}, ErrAdmissionAttestorHold
	}
	material := regional.BootstrapMaterial
	if grant.SchemaVersion != 3 || home.Validate() != nil || material == nil || material.SourceRegistration == nil || material.SourceRegistration.Validate() != nil || material.Config.Validate() != nil || regional.Generation != grant.Generation || material.InstallationID != grant.InstallationID {
		return deny()
	}
	registration, config := material.SourceRegistration.Clone(), material.Config
	configWire, err := json.Marshal(config, json.Deterministic(true))
	slots := []string{"controller-a", "controller-b", "controller-c"}
	cell := strings.ToUpper(config.Cell)
	if err != nil || material.PlanSHA256 != preparationDigest(configWire) || registration.PlanSHA256 != material.PlanSHA256 || registration.InstallationID != grant.InstallationID || registration.Generation != grant.Generation || registration.DeploymentID != config.DeploymentID || registration.ClusterID != config.ClusterID || registration.Environment != config.Environment || string(registration.Cell) != cell || regional.Plan["cell"] != cell || regional.Plan["region"] != config.Region || registration.StorageDomain != home || !slices.Equal(registration.ControllerSlots, slots) || material.Startup == nil || registration.SeedSlot != material.Startup.SeedSlot {
		return deny()
	}
	var origins []release.WorkloadGenesis
	for _, origin := range grant.WorkloadGenesis {
		if origin.Cell == cell {
			if origin.Validate() != nil || origin.TenancyID != grant.TenancyID || origin.InstallationID != grant.InstallationID || origin.DeploymentID != config.DeploymentID || origin.ClusterID != config.ClusterID || origin.Environment != config.Environment || origin.Namespace != home.Namespace || origin.Bucket != home.HeadBucket {
				return deny()
			}
			origins = append(origins, origin)
		}
	}
	slices.SortFunc(origins, func(a, b release.WorkloadGenesis) int { return strings.Compare(a.Role, b.Role) })
	if len(origins) != 3 || origins[0].Role != "function-worker" || origins[1].Role != "terrabase" || origins[2].Role != "ts-auth" {
		return deny()
	}
	genesisWire, err := json.Marshal(origins, json.Deterministic(true))
	if err != nil {
		return deny()
	}
	registrationWire, err := json.Marshal(registration, json.Deterministic(true))
	if err != nil {
		return deny()
	}
	authorization := release.AdmissionAttestorAuthorization{Schema: release.AdmissionAttestorAuthorizationSchema, Domain: "terrascale.release.container-admission", Action: "reserve", SourceBinding: "original-source-inventory.v1",
		TenancyID: grant.TenancyID, InstallationID: grant.InstallationID, DeploymentID: config.DeploymentID, ClusterID: config.ClusterID, Cell: cell, Environment: config.Environment, Generation: grant.Generation,
		ControllerSlots: [3]string{"controller-a", "controller-b", "controller-c"}, Roles: [3]string{"function-worker", "terrabase", "ts-auth"}, PlanSHA256: material.PlanSHA256,
		WorkloadGenesisSHA256: preparationDigest(genesisWire), SourceRegistrationSHA256: preparationDigest(registrationWire), SourceNamespace: home.Namespace, SourceBucket: home.HeadBucket,
		SourceObject: home.Prefix + "/bootstrap/v2/material-source/" + preparationDigest([]byte(grant.InstallationID+"\x00"+config.Cell)) + ".json"}
	return authorization, authorization.Validate()
}

func validateFoundationAdmissionAttestors(grant FoundationGrant, home bootstrap.StorageDomain) error {
	if grant.SchemaVersion != 3 {
		for _, regional := range grant.Regions {
			if regional.BootstrapMaterial != nil && regional.BootstrapMaterial.AdmissionAttestor != nil {
				return ErrAdmissionAttestorHold
			}
		}
		return nil
	}
	if len(grant.Regions) != 3 {
		return ErrAdmissionAttestorHold
	}
	seen := map[string]bool{}
	for _, regional := range grant.Regions {
		expected, err := foundationAdmissionAttestor(grant, home, regional)
		if err != nil || regional.BootstrapMaterial.AdmissionAttestor == nil || *regional.BootstrapMaterial.AdmissionAttestor != expected || seen[expected.Cell] {
			return ErrAdmissionAttestorHold
		}
		seen[expected.Cell] = true
	}
	return nil
}

// VerifiedAdmissionAttestor is original-document producer permission only. It
// cannot serve as VerifiedBootstrapMaterial, startup or admission authority.
type VerifiedAdmissionAttestor struct {
	source        *SignedFootprint
	cell          string
	wire          []byte
	config        bootstrapmaterial.Config
	authorization release.AdmissionAttestorAuthorization
}

func (v VerifiedAdmissionAttestor) IsVerified() bool { return v.source != nil && len(v.wire) > 0 }
func (v VerifiedAdmissionAttestor) Authorization() release.AdmissionAttestorAuthorization {
	return v.authorization
}

func (s *SignedFootprint) AdmissionAttestor(ctx context.Context, cell string) (VerifiedAdmissionAttestor, error) {
	if s == nil || ctx.Err() != nil {
		return VerifiedAdmissionAttestor{}, ErrAdmissionAttestorHold
	}
	wire, err := s.readGrant(ctx)
	if err != nil {
		return VerifiedAdmissionAttestor{}, err
	}
	grant, _, err := s.verifyOriginalDocument(wire)
	if err != nil {
		return VerifiedAdmissionAttestor{}, err
	}
	if grant.SchemaVersion != 3 {
		return VerifiedAdmissionAttestor{}, nil
	}
	for _, regional := range grant.Regions {
		if regional.Plan["cell"] == cell && regional.BootstrapMaterial != nil && regional.BootstrapMaterial.AdmissionAttestor != nil {
			cfg := regional.BootstrapMaterial.Config
			cfg.Slots = slices.Clone(cfg.Slots)
			return VerifiedAdmissionAttestor{source: s, cell: cell, wire: bytes.Clone(wire), config: cfg, authorization: *regional.BootstrapMaterial.AdmissionAttestor}, nil
		}
	}
	return VerifiedAdmissionAttestor{}, ErrAdmissionAttestorHold
}

func (v VerifiedBootstrapMaterial) AdmissionAttestor(ctx context.Context) (VerifiedAdmissionAttestor, error) {
	if !v.IsVerified() || v.source == nil || !time.Now().Before(v.expires) {
		return VerifiedAdmissionAttestor{}, ErrAdmissionAttestorHold
	}
	proof, err := v.source.AdmissionAttestor(ctx, v.cell)
	if err != nil || proof.IsVerified() && !bytes.Equal(v.grantWire, proof.wire) {
		return VerifiedAdmissionAttestor{}, ErrAdmissionAttestorHold
	}
	return proof, nil
}

func (v VerifiedAdmissionAttestor) Revalidate(ctx context.Context) error {
	if !v.IsVerified() {
		return ErrAdmissionAttestorHold
	}
	current, err := v.source.AdmissionAttestor(ctx, v.cell)
	if err != nil || !current.IsVerified() || current.authorization != v.authorization || !bytes.Equal(current.wire, v.wire) || !sameAdmissionConfig(current.config, v.config) {
		return ErrAdmissionAttestorHold
	}
	return ctx.Err()
}

func sameAdmissionConfig(a, b bootstrapmaterial.Config) bool {
	aWire, aErr := json.Marshal(a, json.Deterministic(true))
	bWire, bErr := json.Marshal(b, json.Deterministic(true))
	return aErr == nil && bErr == nil && bytes.Equal(aWire, bWire)
}

// Generate emits an unpublished candidate. A genuine actor and protected CAS
// selection are independently required before escrow or accepted binding.
func (v VerifiedAdmissionAttestor) Generate(ctx context.Context, directory string, now time.Time) (bootstrapmaterial.Record, error) {
	if err := v.Revalidate(ctx); err != nil {
		return bootstrapmaterial.Record{}, err
	}
	return bootstrapmaterial.GenerateAdmissionCandidate(directory, v.config, v.authorization, now)
}

type VerifiedAdmissionAttestorBinding struct {
	original VerifiedAdmissionAttestor
	binding  release.AdmissionAttestorBinding
}

func (v VerifiedAdmissionAttestorBinding) IsVerified() bool {
	return v.original.IsVerified() && v.binding.SourceSHA256 != ""
}
func (v VerifiedAdmissionAttestorBinding) Binding() release.AdmissionAttestorBinding {
	return v.binding
}

// OriginalBinding never accepts caller-selected inventory bytes or public keys.
// SourceFounder's current schema3 refusal intentionally keeps this path HOLD.
func (v VerifiedAdmissionAttestor) OriginalBinding(ctx context.Context, actor *SourceFounder) (VerifiedAdmissionAttestorBinding, error) {
	deny := func() (VerifiedAdmissionAttestorBinding, error) {
		return VerifiedAdmissionAttestorBinding{}, ErrAdmissionAttestorHold
	}
	if v.Revalidate(ctx) != nil || actor == nil || actor.Guard(ctx) != nil || actor.GrantDigest() != preparationDigest(v.wire) || actor.SourceStorageDomain() != v.source.storage || actor.cell != v.cell {
		return deny()
	}
	a := v.authorization
	journal, _, err := actor.resolver.Store.Load(ctx, v.cell)
	if err != nil {
		return deny()
	}
	policy, ok := journal.SourcePolicyIDs[sourcePolicyKey(a.SourceNamespace, a.SourceBucket, a.SourceObject)]
	if !ok || policy.PolicyID == "" || policy.InstanceID != actor.InstanceID() || policy.GrantDigest != actor.GrantDigest() || policy.TemplateDigest != actor.TemplateDigest() || policy.InstallationID != a.InstallationID || policy.GrantGeneration != a.Generation || actor.verifyPolicy(ctx, policy) != nil {
		return deny()
	}
	response, err := actor.authority.objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(a.SourceNamespace), BucketName: new(a.SourceBucket), ObjectName: new(a.SourceObject)})
	if err != nil || response.Content == nil {
		return deny()
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, 2<<20))
	if err != nil || len(wire) >= 2<<20 || response.ETag == nil || *response.ETag == "" {
		return deny()
	}
	var state struct {
		SchemaVersion                int                            `json:"schemaVersion"`
		Kind                         string                         `json:"kind"`
		InstallationID               string                         `json:"installationId"`
		Cell                         string                         `json:"cell"`
		Generation                   uint64                         `json:"generation"`
		PlanSHA256                   string                         `json:"planSha256"`
		AdmissionAuthorizationSHA256 string                         `json:"admissionAuthorizationSha256"`
		Actor                        bootstrap.SourceInventoryActor `json:"actor"`
		Target                       bootstrapmaterial.VaultTarget  `json:"target"`
		Reference                    struct {
			SecretOCID string `json:"secretOcid"`
			SHA256     string `json:"sha256"`
			MaxBytes   int64  `json:"maxBytes"`
		} `json:"reference"`
		Inventory                  []byte `json:"inventory"`
		OriginalAdmissionInventory []byte `json:"originalAdmissionInventory"`
	}
	authDigest, _ := a.Digest()
	if json.Unmarshal(wire, &state) != nil || state.SchemaVersion != 1 || state.Kind != "" || state.InstallationID != a.InstallationID || state.Cell != strings.ToLower(a.Cell) || state.Generation != a.Generation || state.PlanSHA256 != a.PlanSHA256 || state.AdmissionAuthorizationSHA256 != authDigest || state.Actor.InstanceID != policy.InstanceID || state.Actor.GrantDigest != policy.GrantDigest || state.Actor.TemplateDigest != policy.TemplateDigest || state.Target != bootstrapmaterial.VaultTarget(policy.Escrow) || !strings.HasPrefix(state.Reference.SecretOCID, "ocid1.vaultsecret.") || !sourceDigest(state.Reference.SHA256) || state.Reference.MaxBytes <= 0 || state.Reference.MaxBytes > 25<<10 || len(state.OriginalAdmissionInventory) == 0 || len(state.OriginalAdmissionInventory) > bootstrap.MaxManifestBytes || len(state.Inventory) == 0 || len(state.Inventory) > bootstrap.MaxManifestBytes {
		return deny()
	}
	var selected bootstrap.RegionalSourceInventory
	var selectedRecord bootstrapmaterial.Record
	for index, inventory := range [][]byte{state.OriginalAdmissionInventory, state.Inventory} {
		envelope, err := trust.DecodeEnvelope(inventory)
		if err != nil {
			return deny()
		}
		var binding bootstrap.RegionalSourceInventory
		var record bootstrapmaterial.Record
		if json.Unmarshal(envelope.Payload, &binding, json.RejectUnknownMembers(true)) != nil || binding.SchemaVersion != 1 || binding.Actor != state.Actor || binding.PlanSHA256 != a.PlanSHA256 || binding.SourceSHA256 != state.Reference.SHA256 || index == 0 && binding.GrantSHA256 != preparationDigest(v.wire) || json.Unmarshal(binding.MaterialRecord, &record, json.RejectUnknownMembers(true)) != nil || !sameAdmissionConfig(record.Config, v.config) || bootstrapmaterial.ValidateAdmissionInventory(record) != nil || record.Public.AdmissionAttestor.AuthorizationSHA256 != authDigest {
			return deny()
		}
		key, err := base64.StdEncoding.Strict().DecodeString(record.Public.LedgerSignerPublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return deny()
		}
		id, _ := trust.KeyID(key)
		scope := trust.Scope{Domain: "terrascale.bootstrap.source-inventory", DeploymentID: a.DeploymentID, Cell: a.Cell, Environment: a.Environment, Role: "source", Slot: a.InstallationID}
		if _, err := trust.VerifyHistorical(envelope, scope, trust.Keyring{id: key}, bootstrap.ManifestTrustPolicy()); err != nil {
			return deny()
		}
		if index == 0 {
			selected, selectedRecord = binding, record
		} else if !bytes.Equal(selected.MaterialRecord, binding.MaterialRecord) {
			return deny()
		}
	}
	if actor.Guard(ctx) != nil || ctx.Err() != nil {
		return deny()
	}
	return VerifiedAdmissionAttestorBinding{original: v, binding: release.AdmissionAttestorBinding{Material: selectedRecord.Public.AdmissionAttestor, SourceSHA256: state.Reference.SHA256, OriginalInventorySHA256: preparationDigest(state.OriginalAdmissionInventory)}}, nil
}
