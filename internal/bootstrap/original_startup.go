package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// OriginalLaunchIdentity is signed DATA about an already-created original actor.
// It does not turn an observed tag, caller identity or ordinary founder into birth.
type OriginalLaunchIdentity struct {
	ActorOperationID string                           `json:"actorOperationId"`
	InstanceOCID     string                           `json:"instanceOcid"`
	Create           foundationbinding.CreateIdentity `json:"createIdentity"`
	EvidenceSHA256   string                           `json:"evidenceSha256"`
}

func (identity OriginalLaunchIdentity) validate() error {
	if !entityid.Valid(identity.ActorOperationID) || !isOCID(identity.InstanceOCID, "instance") || identity.Create.Validate() != nil || identity.Create.Key != "controller-a" || !validDigest(identity.Create.RequestDigest) || !validDigest(identity.Create.RetryToken) || !validDigest(identity.EvidenceSHA256) {
		return ErrManifestInvalid
	}
	if !strings.HasPrefix(identity.InstanceOCID, "ocid1.instance.oc1."+identity.Create.Region+".") {
		return ErrManifestInvalid
	}
	return nil
}

// OriginalLaunchCreateKey binds the real protected create identity; the separately
// signed evidence digest pins the grant and installation without inventing an OCI tag.
func OriginalLaunchCreateKey(identity OriginalLaunchIdentity) (string, error) {
	if identity.validate() != nil {
		return "", ErrManifestInvalid
	}
	wire, err := json.Marshal(struct {
		Purpose          string                           `json:"purpose"`
		ActorOperationID string                           `json:"actorOperationId"`
		InstanceOCID     string                           `json:"instanceOcid"`
		Create           foundationbinding.CreateIdentity `json:"createIdentity"`
	}{"original-seed/v1", identity.ActorOperationID, identity.InstanceOCID, identity.Create}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestBytes(wire), nil
}

// OriginalSourceBinding commits to the canonical schema-3 source before its
// recursive startup and seed-completion fields are attached.
type OriginalSourceBinding struct {
	StateSHA256 string `json:"stateSha256"`
}

// ErrOriginalSourcePending identifies a strict original CAS whose monotone
// publication has not completed; it never returns a verified source proof.
var ErrOriginalSourcePending = errors.New("original source publication is pending")

type originalSourceReference struct {
	SecretOCID string `json:"secretOcid"`
	SHA256     string `json:"sha256"`
	MaxBytes   int64  `json:"maxBytes"`
}
type originalSourceCandidate struct {
	SHA256       string `json:"sha256"`
	MaxBytes     int64  `json:"maxBytes"`
	CreateSHA256 string `json:"createSha256"`
}
type originalPublicationScope struct {
	Target         StartupVaultTarget `json:"target"`
	PolicyID       string             `json:"policyId"`
	PolicyETag     string             `json:"policyEtag"`
	PolicySHA256   string             `json:"policySha256"`
	ReadbackSHA256 string             `json:"readbackSha256"`
}
type originalPublicReference struct {
	SecretName string          `json:"secretName"`
	Reference  SecretReference `json:"reference"`
}
type originalPublicationResult struct {
	SchemaVersion  int                       `json:"schemaVersion"`
	Target         StartupVaultTarget        `json:"target"`
	MaterialSHA256 string                    `json:"materialSha256"`
	References     []originalPublicReference `json:"references"`
}
type originalPublicationState struct {
	Scope   originalPublicationScope   `json:"scope"`
	Journal []byte                     `json:"journal,omitempty"`
	Result  *originalPublicationResult `json:"result,omitempty"`
}
type originalSourceState struct {
	SchemaVersion                int                       `json:"schemaVersion"`
	Kind                         string                    `json:"kind"`
	Scope                        jsontext.Value            `json:"scope"`
	IntentSHA256                 string                    `json:"intentSha256"`
	AdmissionAuthorizationSHA256 string                    `json:"admissionAuthorizationSha256"`
	Target                       StartupVaultTarget        `json:"target"`
	SecretName                   string                    `json:"secretName"`
	RetryToken                   string                    `json:"retryToken"`
	StartedAt                    time.Time                 `json:"startedAt"`
	Candidate                    originalSourceCandidate   `json:"candidate"`
	Reference                    originalSourceReference   `json:"reference"`
	OriginalAdmissionInventory   []byte                    `json:"originalAdmissionInventory,omitempty"`
	Publication                  *originalPublicationState `json:"publication,omitempty"`
	Startup                      map[string][]byte         `json:"startup,omitempty"`
	SeedCompletion               []byte                    `json:"seedCompletion,omitempty"`
}

func decodeOriginalSource(wire []byte) (originalSourceState, error) {
	var state originalSourceState
	if len(wire) == 0 || len(wire) > 2<<20 || json.Unmarshal(wire, &state, json.RejectUnknownMembers(true)) != nil || state.SchemaVersion != 3 || state.Kind != "original-source-archive/v1" {
		return state, ErrManifestInvalid
	}
	canonical, err := json.Marshal(state, json.Deterministic(true))
	if err != nil || !bytes.Equal(wire, canonical) {
		return originalSourceState{}, ErrManifestInvalid
	}
	return state, nil
}

// OriginalSourceBindingFor makes public DATA only; the verifier separately reads
// the fixed live CAS and authenticates every source and publication component.
func OriginalSourceBindingFor(wire []byte) (OriginalSourceBinding, error) {
	state, err := decodeOriginalSource(wire)
	if err != nil {
		return OriginalSourceBinding{}, err
	}
	state.Startup, state.SeedCompletion = nil, nil
	canonical, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		return OriginalSourceBinding{}, err
	}
	return OriginalSourceBinding{StateSHA256: digestBytes(canonical)}, nil
}

type originalStartupProof struct {
	factory         *ociclient.Factory
	genesis         trust.Keyring
	rootChainWire   []byte
	resources       foundationbinding.OriginalStartupResources
	retentionRuleID string
}

func (template VerifiedStartupTemplate) StartupIdentity() BootstrapAnchor {
	return template.startupIdentity()
}
func (template VerifiedStartupTemplate) OriginAnchor() VerifiedBootstrapAnchor {
	return template.anchor
}
func (template VerifiedStartupTemplate) Roots() trust.Keyring {
	return cloneOriginalRoots(template.roots)
}
func (template VerifiedStartupTemplate) OriginRootChainWire() []byte {
	if template.bindings == nil || template.bindings.original == nil {
		return nil
	}
	return bytes.Clone(template.bindings.original.rootChainWire)
}
func cloneOriginalRoots(roots trust.Keyring) trust.Keyring {
	cloned := make(trust.Keyring, len(roots))
	for id, key := range roots {
		cloned[id] = bytes.Clone(key)
	}
	return cloned
}
func (template VerifiedStartupTemplate) OriginalLaunch() (OriginalLaunchIdentity, error) {
	if !template.IsVerified() || template.bindings == nil || template.bindings.original == nil {
		return OriginalLaunchIdentity{}, ErrManifestInvalid
	}
	data := template.bindings.original.resources
	identity := OriginalLaunchIdentity{data.ActorOperationID, data.InstanceOCID, data.Create, data.EvidenceSHA256}
	return identity, identity.validate()
}
func (template VerifiedStartupTemplate) OriginalLaunchRequest() (core.LaunchInstanceDetails, error) {
	if _, err := template.OriginalLaunch(); err != nil {
		return core.LaunchInstanceDetails{}, err
	}
	var request core.LaunchInstanceDetails
	if err := json.Unmarshal(template.bindings.original.resources.LaunchRequest, &request); err != nil {
		return core.LaunchInstanceDetails{}, err
	}
	return request, nil
}
func (authority DerivedStartupAuthority) Template() VerifiedStartupTemplate {
	return authority.template
}
func (authority DerivedStartupAuthority) OriginalLaunch() (OriginalLaunchIdentity, error) {
	expected, err := authority.template.OriginalLaunch()
	if err != nil || !authority.IsVerified() || authority.binding.SchemaVersion != 2 || authority.binding.OriginalLaunch == nil || *authority.binding.OriginalLaunch != expected || authority.binding.OriginalSource == nil {
		return OriginalLaunchIdentity{}, ErrManifestInvalid
	}
	return expected, nil
}

// OriginalSourceObject derives its locator from the same signed producer purpose.
func OriginalSourceObject(template VerifiedStartupTemplate) (StorageDomain, string, error) {
	if _, err := template.OriginalLaunch(); err != nil {
		return StorageDomain{}, "", err
	}
	home, err := template.anchor.FoundationScope()
	if err != nil {
		return StorageDomain{}, "", err
	}
	key := template.bindings.original.resources.SourceObject
	if key == "" || strings.ContainsAny(key, "\\\r\n\x00") || strings.HasPrefix(key, "/") {
		return StorageDomain{}, "", ErrManifestInvalid
	}
	return home.StorageDomain, key, nil
}

// VerifyBoundOriginalStartupTemplate verifies an explicitly supplied independent
// genesis against the actual HOME chain. Production callers use DiscoveryGenesis.
// The original GRU anchor remains genuine; the regional identity is signed DATA.
func VerifyBoundOriginalStartupTemplate(ctx context.Context, factory *ociclient.Factory, wire []byte, genesis trust.Keyring, anchor VerifiedBootstrapAnchor, requestedCell oci.Region, now time.Time) (VerifiedStartupTemplate, error) {
	if factory == nil || ctx == nil || ctx.Err() != nil || !anchor.IsVerified() || anchor.Anchor().Cell != oci.RegionGRU || len(genesis) == 0 || now.IsZero() {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	local := anchor.Anchor()
	home, err := anchor.FoundationScope()
	if err != nil || home.OCIRegion != "sa-saopaulo-1" || home.StorageDomain.HeadBucket != "gru-1-head" || home.DeploymentID != local.DeploymentID || home.ClusterID != local.ClusterID || home.GrantSHA256 != digestBytes(wire) || home.GrantGeneration != 1 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	regional, err := factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	objects, err := regional.ObjectStorage()
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	currentAnchor, err := readOriginalObject(ctx, &objects, home.StorageDomain, "orchestrator/foundation/v1/anchor.json", MaxBootstrapAnchorBytes)
	if err != nil || !bytes.Equal(currentAnchor, anchor.Wire()) {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	chainWire, err := readOriginalObject(ctx, &objects, home.StorageDomain, "orchestrator/foundation/v1/root-chain.json", trust.MaxRootChainBytes)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	current, err := trust.VerifyRootChain(genesis, trust.ChainIdentity{DeploymentID: home.DeploymentID, Cell: "gru", Environment: local.Environment}, chain)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	anchor, err = VerifyBootstrapAnchor(anchorEnvelope, current.Current, BootstrapAnchorExpectation{DeploymentID: home.DeploymentID, Cell: oci.RegionGRU, Environment: local.Environment}, now, BootstrapAnchorTrustPolicy())
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	identity, admission, err := originalStartupIdentity(wire, current.Current, anchor, requestedCell, now)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	auth := foundationbinding.Authority{Scope: trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: home.DeploymentID, Cell: "GRU", Environment: local.Environment, Role: "foundation", Slot: home.ClusterID}, Roots: current.Current, Policy: BootstrapAnchorTrustPolicy(), GrantSHA256: home.GrantSHA256, Generation: home.GrantGeneration, InstallationID: home.InstallationID, TenancyID: home.TenancyID, Namespace: home.StorageDomain.Namespace, Bucket: home.StorageDomain.HeadBucket, Prefix: home.StorageDomain.Prefix, Cell: string(requestedCell)}
	resources, err := foundationbinding.ResolveOriginalStartup(ctx, factory, auth, wire, anchor.ExpiresAt())
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	if resources.ProducerIntentSHA256 != admission.ProducerIntentSHA256 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	if err := verifyOriginalLedgerRetention(ctx, &objects, home.StorageDomain, admission.LedgerRetentionRuleID, now); err != nil {
		return VerifiedStartupTemplate{}, err
	}
	proof := &originalStartupProof{factory: factory, genesis: cloneOriginalRoots(genesis), rootChainWire: bytes.Clone(chainWire), resources: resources, retentionRuleID: admission.LedgerRetentionRuleID}
	bindings := &startupBindings{factory: factory, original: proof}
	return verifyStartupTemplateForIdentityBindings(wire, current.Current, anchor, identity, bindings, now)
}

func originalStartupIdentity(wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, cell oci.Region, now time.Time) (BootstrapAnchor, OriginalStartupAdmissionIntent, error) {
	var zero BootstrapAnchor
	var admission OriginalStartupAdmissionIntent
	home, err := anchor.FoundationScope()
	if err != nil {
		return zero, admission, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return zero, admission, err
	}
	payload, err := trust.VerifyCurrent(envelope, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: home.DeploymentID, Cell: "GRU", Environment: anchor.Anchor().Environment, Role: "foundation", Slot: home.ClusterID}, roots, now, BootstrapAnchorTrustPolicy())
	if err != nil || envelope.ExpiresAt.After(anchor.ExpiresAt()) {
		return zero, admission, ErrManifestInvalid
	}
	var grant struct {
		SchemaVersion  int    `json:"schemaVersion"`
		InstallationID string `json:"installationId"`
		Generation     uint64 `json:"generation"`
		TenancyID      string `json:"tenancyId"`
		Regions        []struct {
			Generation uint64 `json:"generation"`
			Plan       struct {
				Cell   string `json:"cell"`
				Region string `json:"region"`
			} `json:"plan"`
			BootstrapMaterial *struct {
				InstallationID           string                          `json:"installationId"`
				PlanSHA256               string                          `json:"planSha256"`
				Startup                  *StartupTemplate                `json:"startup"`
				SourceRegistration       *InitialSourceRegistration      `json:"sourceRegistration"`
				OriginalStartupAdmission *OriginalStartupAdmissionIntent `json:"originalStartupAdmission"`
			} `json:"bootstrapMaterial"`
		} `json:"regions"`
	}
	if json.Unmarshal(payload, &grant) != nil || grant.SchemaVersion != 3 || grant.Generation != 1 || grant.Generation != home.GrantGeneration || grant.InstallationID != home.InstallationID || grant.TenancyID != home.TenancyID || len(grant.Regions) != 3 {
		return zero, admission, ErrManifestInvalid
	}
	regionName, err := cell.OCIRegion()
	if err != nil {
		return zero, admission, err
	}
	selected := false
	for _, regional := range grant.Regions {
		if regional.Plan.Cell != string(cell) {
			continue
		}
		m := regional.BootstrapMaterial
		if selected || regional.Generation != grant.Generation || regional.Plan.Region != regionName || m == nil || m.Startup == nil || m.Startup.ValidateFoundation(string(cell)) != nil || m.Startup.ControllerConfigDerivation != ControllerConfigDerivationV2 || m.SourceRegistration == nil || m.SourceRegistration.Validate() != nil || m.OriginalStartupAdmission == nil || m.OriginalStartupAdmission.Purpose != OriginalStartupAdmissionPurpose || !validDigest(m.OriginalStartupAdmission.ProducerIntentSHA256) || m.OriginalStartupAdmission.LedgerRetentionRuleID == "" {
			return zero, admission, ErrManifestInvalid
		}
		selected = true
		registration := m.SourceRegistration.Clone()
		if registration.InstallationID != home.InstallationID || registration.Generation != grant.Generation || registration.Environment != anchor.Anchor().Environment || registration.Cell != cell || registration.PlanSHA256 != m.PlanSHA256 || registration.SeedSlot != m.Startup.SeedSlot || m.InstallationID != home.InstallationID {
			return zero, admission, ErrManifestInvalid
		}
		if registration.StorageDomain != home.StorageDomain || cell == oci.RegionGRU && (registration.DeploymentID != home.DeploymentID || registration.ClusterID != home.ClusterID) {
			return zero, admission, ErrManifestInvalid
		}
		intentWire := m.Startup.ControllerFiles[0].Bytes
		intent, err := canonicalRegionIntent(intentWire)
		if err != nil {
			return zero, admission, err
		}
		zero = BootstrapAnchor{SchemaVersion: BootstrapAnchorSchemaVersion, DeploymentID: registration.DeploymentID, Environment: registration.Environment, ClusterID: registration.ClusterID, Cell: cell, OCIRegion: regionName, StorageDomain: registration.StorageDomain, FoundationScope: new(home), InitialSourceRegistration: new(registration), ControllerSlots: slices.Clone(registration.ControllerSlots), InitialRegionIntentGeneration: intent.Generation, InitialRegionIntentSHA256: digestBytes(intentWire), InitialRegionIntentWire: bytes.Clone(intentWire)}
		admission = *m.OriginalStartupAdmission
	}
	if !selected || zero.Validate() != nil {
		return BootstrapAnchor{}, admission, ErrManifestInvalid
	}
	return zero, admission, nil
}

func (proof originalStartupProof) current(ctx context.Context, template VerifiedStartupTemplate, now time.Time) error {
	current, err := VerifyBoundOriginalStartupTemplate(ctx, proof.factory, template.grantWire, proof.genesis, template.anchor, template.identity.Cell, now)
	if err != nil {
		return err
	}
	original, err := template.OriginalLaunch()
	if err != nil {
		return err
	}
	actual, err := current.OriginalLaunch()
	if err != nil || original != actual || current.templateDigest != template.templateDigest || current.planDigest != template.planDigest || !bytes.Equal(current.OriginRootChainWire(), proof.rootChainWire) || !maps.Equal(current.bindings.original.resources.ResourceIDs, proof.resources.ResourceIDs) {
		return ErrManifestInvalid
	}
	return ctx.Err()
}

func readOriginalObject(ctx context.Context, client ObjectStorageClient, domain StorageDomain, key string, limit int) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.GetObject(ociclient.RequestContext(bounded), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(key)})
	if err != nil {
		return nil, err
	}
	if response.Content == nil {
		return nil, ErrManifestInvalid
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, int64(limit)+1))
	if err != nil || len(wire) > limit || response.ETag == nil || *response.ETag == "" {
		return nil, ErrManifestInvalid
	}
	return wire, nil
}

// LoadBoundOriginalStartupTemplate locates only the authenticated tenancy's fixed
// public GRU anchor, chain and grant. Metadata supplies hashes, never object paths.
func LoadBoundOriginalStartupTemplate(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, cell oci.Region, expectedGrantSHA256, expectedHomeAnchorSHA256 string, now time.Time) (VerifiedStartupTemplate, error) {
	if factory == nil || !validDigest(expectedGrantSHA256) || !validDigest(expectedHomeAnchorSHA256) {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	homeFactory, err := factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	objects, err := homeFactory.ObjectStorage()
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	response, err := objects.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{})
	if err != nil || response.Value == nil || *response.Value == "" || strings.ContainsAny(*response.Value, "/\\\r\n") {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	domain := StorageDomain{Namespace: *response.Value, HeadBucket: "gru-1-head"}
	anchorWire, err := readOriginalObject(ctx, &objects, domain, "orchestrator/foundation/v1/anchor.json", MaxBootstrapAnchorBytes)
	if err != nil || digestBytes(anchorWire) != expectedHomeAnchorSHA256 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	envelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	chainWire, err := readOriginalObject(ctx, &objects, domain, "orchestrator/foundation/v1/root-chain.json", trust.MaxRootChainBytes)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	roots, err := trust.VerifyRootChain(genesis, trust.ChainIdentity{DeploymentID: envelope.Scope.DeploymentID, Cell: "gru", Environment: "production"}, chain)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	anchor, err := VerifyBootstrapAnchor(envelope, roots.Current, BootstrapAnchorExpectation{DeploymentID: envelope.Scope.DeploymentID, Cell: oci.RegionGRU, Environment: "production"}, now, BootstrapAnchorTrustPolicy())
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	home, err := anchor.FoundationScope()
	tenancy, tenancyErr := factory.Provider().TenancyOCID()
	if err != nil || tenancyErr != nil || home.TenancyID != tenancy || home.StorageDomain.Namespace != domain.Namespace || home.StorageDomain.HeadBucket != domain.HeadBucket || home.GrantSHA256 != expectedGrantSHA256 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	wire, err := readOriginalObject(ctx, &objects, home.StorageDomain, home.StorageDomain.Prefix+"/foundation-scope-v1.json", 256<<10)
	if err != nil || digestBytes(wire) != expectedGrantSHA256 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	return VerifyBoundOriginalStartupTemplate(ctx, factory, wire, genesis, anchor, cell, now)
}

func RestoreBoundOriginalDerivedStartupAuthority(ctx context.Context, factory *ociclient.Factory, grantWire []byte, genesis trust.Keyring, homeAnchor VerifiedBootstrapAnchor, cell oci.Region, client ObjectStorageClient, wire []byte, now time.Time) (DerivedStartupAuthority, error) {
	template, err := VerifyBoundOriginalStartupTemplate(ctx, factory, grantWire, genesis, homeAnchor, cell, now)
	if err != nil {
		return DerivedStartupAuthority{}, err
	}
	return VerifyDerivedStartupAuthority(ctx, template, client, wire, now)
}

func verifyOriginalLedgerRetention(ctx context.Context, objects *objectstorage.ObjectStorageClient, domain StorageDomain, ruleID string, now time.Time) error {
	if ruleID == "" || len(ruleID) > 512 || strings.ContainsAny(ruleID, "/\\\r\n\x00 ") {
		return ErrManifestInvalid
	}
	bucket, err := objects.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.LedgerBucket)})
	if err != nil {
		return err
	}
	if bucket.Name == nil || *bucket.Name != domain.LedgerBucket || bucket.Namespace == nil || *bucket.Namespace != domain.Namespace || bucket.KmsKeyId == nil || *bucket.KmsKeyId != domain.LedgerKMSKeyOCID || bucket.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess || bucket.Versioning != objectstorage.BucketVersioningDisabled {
		return ErrManifestInvalid
	}
	// Preparation discovers an unambiguous rule; runtime rechecks its signed ID.
	// Other rules cannot shorten this locked indefinite retention.
	response, err := objects.GetRetentionRule(ociclient.RequestContext(ctx), objectstorage.GetRetentionRuleRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.LedgerBucket), RetentionRuleId: new(ruleID)})
	if err != nil {
		return err
	}
	rule := response.RetentionRule
	if rule.Id == nil || *rule.Id != ruleID || rule.Etag == nil || *rule.Etag == "" || len(*rule.Etag) > 1024 || strings.ContainsAny(*rule.Etag, "\r\n\x00") || rule.Duration != nil || rule.TimeRuleLocked == nil || rule.TimeRuleLocked.Time.After(now) || rule.DisplayName == nil || *rule.DisplayName == "" || rule.TimeCreated == nil || rule.TimeModified == nil || rule.TimeCreated.Time.After(now) || rule.TimeModified.Time.After(now) {
		return ErrManifestInvalid
	}
	return ctx.Err()
}

func loadOriginalSourceState(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, now time.Time) (originalSourceState, []byte, error) {
	domain, key, err := OriginalSourceObject(template)
	if err != nil {
		return originalSourceState{}, nil, err
	}
	wire, err := readOriginalObject(ctx, client, domain, key, 2<<20)
	if err != nil {
		return originalSourceState{}, nil, err
	}
	state, err := validateOriginalSourceState(template, wire, now)
	return state, wire, err
}

func validateOriginalSourceState(template VerifiedStartupTemplate, wire []byte, now time.Time) (originalSourceState, error) {
	state, err := decodeOriginalSource(wire)
	if err != nil {
		return state, err
	}
	proof := template.bindings.original
	scope := proof.resources
	token, tokenErr := uuid.Parse(state.RetryToken)
	if !scope.MatchesScope(state.Scope) || state.IntentSHA256 != scope.ProducerIntentSHA256 || state.AdmissionAuthorizationSHA256 != scope.AdmissionAuthorizationSHA256 || state.Target != template.escrow || state.SecretName != scope.SourceSecretName || tokenErr != nil || token.String() != state.RetryToken || state.StartedAt.IsZero() || state.StartedAt.After(now) || !state.StartedAt.Before(template.ExpiresAt()) || len(state.OriginalAdmissionInventory) > MaxManifestBytes {
		return state, ErrManifestInvalid
	}
	pending := func() (originalSourceState, error) {
		if len(state.Startup) != 0 || len(state.SeedCompletion) != 0 {
			return state, ErrManifestInvalid
		}
		return state, ErrOriginalSourcePending
	}
	if state.Candidate == (originalSourceCandidate{}) {
		if state.Reference != (originalSourceReference{}) || len(state.OriginalAdmissionInventory) != 0 || state.Publication != nil {
			return state, ErrManifestInvalid
		}
		return pending()
	}
	if !validDigest(state.Candidate.SHA256) || !validDigest(state.Candidate.CreateSHA256) || state.Candidate.MaxBytes <= 0 || state.Candidate.MaxBytes > 25<<10 {
		return state, ErrManifestInvalid
	}
	if state.Reference == (originalSourceReference{}) {
		if len(state.OriginalAdmissionInventory) != 0 || state.Publication != nil {
			return state, ErrManifestInvalid
		}
		return pending()
	}
	if state.Reference.SHA256 != state.Candidate.SHA256 || state.Reference.MaxBytes != state.Candidate.MaxBytes || !strings.HasPrefix(state.Reference.SecretOCID, "ocid1.vaultsecret.oc1.sa-saopaulo-1.") {
		return state, ErrManifestInvalid
	}
	if len(state.OriginalAdmissionInventory) == 0 {
		if state.Publication != nil {
			return state, ErrManifestInvalid
		}
		return pending()
	}
	if _, err := verifyOriginalInventory(template, nil, state, now); err != nil {
		return state, err
	}
	if state.Publication == nil {
		return pending()
	}
	if state.Publication.Result == nil {
		if err := validateOriginalPendingPublication(template, state, now); err != nil {
			return state, err
		}
		return pending()
	}
	if err := validateOriginalPublication(template, state, now); err != nil {
		return state, err
	}
	return state, nil
}

func originalPublicationSecretName(template VerifiedStartupTemplate, file string, purpose SecretPurpose, slot string) string {
	if slot == "" {
		slot = "shared"
	}
	identity := template.identity
	suffix := digestBytes([]byte(identity.DeploymentID + "\x00" + identity.ClusterID))[:16]
	return "ts-" + identity.Environment + "-" + identity.OCIRegion + "-" + strings.ReplaceAll(identity.DeploymentID, ":", "-") + "-" + suffix + "-" + string(purpose) + "-" + slot + "-" + strings.ReplaceAll(file, ".", "-")
}

func validateOriginalPendingPublication(template VerifiedStartupTemplate, state originalSourceState, now time.Time) error {
	p := state.Publication
	wire, err := json.Marshal(p.Scope, json.Deterministic(true))
	if err != nil || !bytes.Equal(wire, template.bindings.original.resources.PublicationScope) {
		return ErrManifestInvalid
	}
	if len(p.Journal) == 0 {
		return nil
	}
	var inventory RegionalSourceInventory
	envelope, err := trust.DecodeEnvelope(state.OriginalAdmissionInventory)
	if err != nil || json.Unmarshal(envelope.Payload, &inventory, json.RejectUnknownMembers(true)) != nil {
		return ErrManifestInvalid
	}
	var record struct {
		Files []struct {
			Name    string        `json:"name"`
			Purpose SecretPurpose `json:"purpose"`
			Slot    string        `json:"slot"`
		} `json:"files"`
	}
	if json.Unmarshal(inventory.MaterialRecord, &record) != nil {
		return ErrManifestInvalid
	}
	names := map[string]string{}
	for _, file := range record.Files {
		if file.Purpose != "owner-only" {
			if _, exists := names[file.Name]; exists {
				return ErrManifestInvalid
			}
			names[file.Name] = originalPublicationSecretName(template, file.Name, file.Purpose, file.Slot)
		}
	}
	if len(names) != 33 {
		return ErrManifestInvalid
	}
	var journal struct {
		SchemaVersion  int                `json:"schemaVersion"`
		Target         StartupVaultTarget `json:"target"`
		MaterialSHA256 string             `json:"materialSha256"`
		Entries        []struct {
			Name       string    `json:"name"`
			FileName   string    `json:"fileName"`
			RetryToken string    `json:"retryToken"`
			SentAt     time.Time `json:"sentAt"`
			SecretOCID string    `json:"secretOcid,omitempty"`
			Verified   bool      `json:"verified"`
		} `json:"entries"`
	}
	if json.Unmarshal(p.Journal, &journal, json.RejectUnknownMembers(true)) != nil || journal.SchemaVersion != 1 || journal.Target != template.VaultTarget() || journal.MaterialSHA256 != digestBytes(inventory.MaterialRecord) || len(journal.Entries) != 33 {
		return ErrManifestInvalid
	}
	ids := map[string]bool{}
	for i, entry := range journal.Entries {
		token, err := uuid.Parse(entry.RetryToken)
		if err != nil || token.String() != entry.RetryToken || names[entry.FileName] != entry.Name || entry.Name == "" || i > 0 && journal.Entries[i-1].FileName >= entry.FileName || entry.Verified != (entry.SecretOCID != "") || entry.Verified && entry.SentAt.IsZero() || !entry.SentAt.IsZero() && (entry.SentAt.Before(state.StartedAt) || entry.SentAt.After(now)) {
			return ErrManifestInvalid
		}
		if entry.SecretOCID != "" {
			if ids[entry.SecretOCID] || !strings.HasPrefix(entry.SecretOCID, "ocid1.vaultsecret.oc1."+template.identity.OCIRegion+".") {
				return ErrManifestInvalid
			}
			ids[entry.SecretOCID] = true
		}
	}
	return nil
}

func validateOriginalPublication(template VerifiedStartupTemplate, state originalSourceState, now time.Time) error {
	p := state.Publication
	result := p.Result
	target := template.VaultTarget()
	scopeWire, scopeErr := json.Marshal(p.Scope, json.Deterministic(true))
	if scopeErr != nil || !bytes.Equal(scopeWire, template.bindings.original.resources.PublicationScope) {
		return ErrManifestInvalid
	}
	if p.Scope.Target != target || !isOCID(p.Scope.PolicyID, "policy") || p.Scope.PolicyETag == "" || !validDigest(p.Scope.PolicySHA256) || !validDigest(p.Scope.ReadbackSHA256) || result.SchemaVersion != 1 || result.Target != target || len(result.References) != 33 {
		return ErrManifestInvalid
	}
	var inventory RegionalSourceInventory
	envelope, err := trust.DecodeEnvelope(state.OriginalAdmissionInventory)
	if err != nil || json.Unmarshal(envelope.Payload, &inventory, json.RejectUnknownMembers(true)) != nil {
		return ErrManifestInvalid
	}
	var journal struct {
		SchemaVersion  int                `json:"schemaVersion"`
		Target         StartupVaultTarget `json:"target"`
		MaterialSHA256 string             `json:"materialSha256"`
		Entries        []struct {
			Name       string    `json:"name"`
			FileName   string    `json:"fileName"`
			RetryToken string    `json:"retryToken"`
			SentAt     time.Time `json:"sentAt"`
			SecretOCID string    `json:"secretOcid,omitempty"`
			Verified   bool      `json:"verified"`
		} `json:"entries"`
	}
	if json.Unmarshal(p.Journal, &journal, json.RejectUnknownMembers(true)) != nil || journal.SchemaVersion != 1 || journal.Target != target || journal.MaterialSHA256 != digestBytes(inventory.MaterialRecord) || result.MaterialSHA256 != journal.MaterialSHA256 || len(journal.Entries) != 33 {
		return ErrManifestInvalid
	}
	var record struct {
		Files []struct {
			Name     string        `json:"name"`
			Purpose  SecretPurpose `json:"purpose"`
			Slot     string        `json:"slot"`
			SHA256   string        `json:"sha256"`
			MaxBytes int64         `json:"maxBytes"`
		} `json:"files"`
	}
	if json.Unmarshal(inventory.MaterialRecord, &record) != nil {
		return ErrManifestInvalid
	}
	files := map[string]SecretReference{}
	for _, file := range record.Files {
		if file.Purpose == "owner-only" {
			continue
		}
		if _, exists := files[file.Name]; exists {
			return ErrManifestInvalid
		}
		files[file.Name] = SecretReference{Purpose: file.Purpose, Slot: file.Slot, TargetFile: file.Name, SHA256: file.SHA256, MaxBytes: file.MaxBytes, VersionNumber: 1}
	}
	if len(files) != 33 {
		return ErrManifestInvalid
	}
	ids := map[string]bool{}
	for index, entry := range journal.Entries {
		token, err := uuid.Parse(entry.RetryToken)
		file, ok := files[entry.FileName]
		ref := result.References[index]
		if !ok || entry.Name != originalPublicationSecretName(template, file.TargetFile, file.Purpose, file.Slot) || err != nil || token.String() != entry.RetryToken || !entry.Verified || entry.SentAt.IsZero() || entry.SentAt.Before(state.StartedAt) || entry.SentAt.After(now) || index > 0 && journal.Entries[index-1].FileName >= entry.FileName || ref.SecretName != entry.Name || ref.Reference.SecretOCID != entry.SecretOCID || ids[entry.SecretOCID] || !strings.HasPrefix(entry.SecretOCID, "ocid1.vaultsecret.oc1."+template.identity.OCIRegion+".") {
			return ErrManifestInvalid
		}
		file.SecretOCID = entry.SecretOCID
		if ref.Reference != file {
			return ErrManifestInvalid
		}
		ids[entry.SecretOCID] = true
	}
	return nil
}

func validateOriginalIntentForAuthority(intent Intent, authority *DerivedStartupAuthority) error {
	if intent.SchemaVersion == 1 {
		if intent.OriginalLaunch != nil {
			return ErrRecordAuthorization
		}
		if authority != nil && intent.Mode == IntentModeExternalSeed {
			if _, err := authority.OriginalLaunch(); err == nil {
				return ErrRecordAuthorization
			}
		}
		return nil
	}
	if intent.SchemaVersion != 2 || intent.Mode != IntentModeExternalSeed || intent.OriginalLaunch == nil || authority == nil {
		return ErrRecordAuthorization
	}
	identity, err := authority.OriginalLaunch()
	if err != nil || *intent.OriginalLaunch != identity || intent.Slot != authority.Manifest().SeedSlot {
		return ErrRecordAuthorization
	}
	key, err := OriginalLaunchCreateKey(identity)
	if err != nil || intent.CreateKey != key {
		return ErrRecordAuthorization
	}
	return nil
}

// OriginalStartupLinkLocator returns DATA selectors; the verifier authenticates
// their domain and installation against the retained original grant separately.
func OriginalStartupLinkLocator(domain StorageDomain, installationID string, cell oci.Region) (string, string, error) {
	if !entityid.Valid(installationID) || domain.Prefix == "" || strings.ContainsAny(domain.Prefix, "\\\r\n\x00") {
		return "", "", ErrManifestInvalid
	}
	if _, err := cell.OCIRegion(); err != nil {
		return "", "", ErrManifestInvalid
	}
	suffix := digestBytes([]byte(installationID + "\x00" + strings.ToLower(string(cell)) + "\x00original-startup-link/v1"))
	return domain.Prefix + "/bootstrap/v3/original-startup/link-" + suffix + ".json", "ts-bootstrap-source-link-" + suffix[:32], nil
}

func validDerivedBindingVersion(template VerifiedStartupTemplate, binding DerivedStartupBinding) bool {
	if template.bindings == nil || template.bindings.original == nil {
		return binding.SchemaVersion == 1 && binding.OriginalLaunch == nil && binding.OriginalSource == nil
	}
	identity, err := template.OriginalLaunch()
	return err == nil && binding.SchemaVersion == 2 && binding.OriginalLaunch != nil && *binding.OriginalLaunch == identity && binding.OriginalSource != nil && validDigest(binding.OriginalSource.StateSHA256) && binding.Link != nil
}

func loadOriginalRegionalSource(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, now time.Time) (VerifiedRegionalSource, error) {
	if client == nil || ctx.Err() != nil || template.VerifyCurrentContext(ctx, now) != nil {
		return VerifiedRegionalSource{}, ErrManifestInvalid
	}
	state, _, err := loadOriginalSourceState(ctx, template, client, now)
	if err != nil {
		return VerifiedRegionalSource{}, err
	}
	return verifyOriginalInventory(template, client, state, now)
}

func verifyOriginalInventory(template VerifiedStartupTemplate, client ObjectStorageClient, state originalSourceState, now time.Time) (VerifiedRegionalSource, error) {
	deny := func() (VerifiedRegionalSource, error) { return VerifiedRegionalSource{}, ErrManifestInvalid }
	launch, err := template.OriginalLaunch()
	if err != nil {
		return deny()
	}
	envelope, err := trust.DecodeEnvelope(state.OriginalAdmissionInventory)
	if err != nil {
		return deny()
	}
	var binding RegionalSourceInventory
	actor := SourceInventoryActor{InstanceID: launch.InstanceOCID, GrantDigest: template.GrantDigest(), TemplateDigest: template.TemplateDigest()}
	if json.Unmarshal(envelope.Payload, &binding, json.RejectUnknownMembers(true)) != nil || binding.SchemaVersion != 1 || binding.Actor != actor || binding.GrantSHA256 != template.GrantDigest() || binding.PlanSHA256 != template.PlanDigest() || binding.SourceSHA256 != state.Reference.SHA256 {
		return deny()
	}
	var record struct {
		Config    jsontext.Value `json:"config"`
		IssuedAt  time.Time      `json:"issuedAt"`
		ExpiresAt time.Time      `json:"expiresAt"`
		Public    struct {
			LedgerSignerPublicKey string `json:"ledgerSignerPublicKey"`
			PeerSignerPublicKey   string `json:"peerSignerPublicKey"`
		} `json:"public"`
	}
	if json.Unmarshal(binding.MaterialRecord, &record) != nil || digestBytes(record.Config) != template.PlanDigest() || record.IssuedAt.IsZero() || now.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) {
		return deny()
	}
	key, err := base64.StdEncoding.Strict().DecodeString(record.Public.LedgerSignerPublicKey)
	peer, peerErr := base64.StdEncoding.Strict().DecodeString(record.Public.PeerSignerPublicKey)
	if err != nil || peerErr != nil || len(key) != ed25519.PublicKeySize || len(peer) != ed25519.PublicKeySize {
		return deny()
	}
	id, _ := trust.KeyID(key)
	if _, err := trust.VerifyCurrent(envelope, RegionalSourceInventoryScope(template), trust.Keyring{id: key}, now, ManifestTrustPolicy()); err != nil || envelope.IssuedAt.Before(template.IssuedAt()) || envelope.IssuedAt.Before(record.IssuedAt) || envelope.ExpiresAt.After(template.ExpiresAt()) || envelope.ExpiresAt.After(record.ExpiresAt) {
		return deny()
	}
	return VerifiedRegionalSource{template: template, client: client, binding: binding, wire: bytes.Clone(state.OriginalAdmissionInventory), ledgerKey: bytes.Clone(key), expiresAt: envelope.ExpiresAt}, nil
}

func verifyOriginalDerivedSource(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, wire, stateWire []byte, envelope trust.Envelope, binding DerivedStartupBinding, ledgerKey, peerKey ed25519.PublicKey, now time.Time) (DerivedStartupAuthority, error) {
	deny := func() (DerivedStartupAuthority, error) { return DerivedStartupAuthority{}, ErrManifestInvalid }
	state, err := validateOriginalSourceState(template, stateWire, now)
	if err != nil {
		return deny()
	}
	source, err := verifyOriginalInventory(template, client, state, now)
	if err != nil || !bytes.Equal(source.MaterialRecord(), binding.MaterialRecord) || state.Reference.SHA256 != binding.SourceSHA256 || !bytes.Equal(source.ledgerKey, ledgerKey) {
		return deny()
	}
	original, err := OriginalSourceBindingFor(stateWire)
	if err != nil || original != *binding.OriginalSource || len(state.Startup) != len(template.identity.ControllerSlots) || !bytes.Equal(state.Startup[binding.Manifest.Slot], wire) {
		return deny()
	}
	ownRefs, err := json.Marshal(binding.Manifest.Secrets, json.Deterministic(true))
	if err != nil {
		return deny()
	}
	ownLink, err := json.Marshal(binding.Link, json.Deterministic(true))
	if err != nil {
		return deny()
	}
	keyID, _ := trust.KeyID(ledgerKey)
	for _, slot := range template.identity.ControllerSlots {
		siblingEnvelope, err := trust.DecodeEnvelope(state.Startup[slot])
		if err != nil {
			return deny()
		}
		var sibling DerivedStartupBinding
		if json.Unmarshal(siblingEnvelope.Payload, &sibling, json.RejectUnknownMembers(true)) != nil || !validDerivedBindingVersion(template, sibling) || sibling.GrantSHA256 != binding.GrantSHA256 || sibling.TemplateSHA256 != binding.TemplateSHA256 || sibling.SourceSHA256 != binding.SourceSHA256 || !bytes.Equal(sibling.MaterialRecord, binding.MaterialRecord) || *sibling.OriginalSource != original || sibling.Manifest.Slot != slot || template.ValidateProjection(sibling.Manifest) != nil || !siblingEnvelope.IssuedAt.Equal(envelope.IssuedAt) || !siblingEnvelope.ExpiresAt.Equal(envelope.ExpiresAt) {
			return deny()
		}
		refs, err := json.Marshal(sibling.Manifest.Secrets, json.Deterministic(true))
		if err != nil || !bytes.Equal(refs, ownRefs) {
			return deny()
		}
		link, err := json.Marshal(sibling.Link, json.Deterministic(true))
		if err != nil || !bytes.Equal(link, ownLink) {
			return deny()
		}
		if _, err := trust.VerifyCurrent(siblingEnvelope, DerivedStartupScope(sibling.Manifest), trust.Keyring{keyID: ledgerKey}, now, ManifestTrustPolicy()); err != nil {
			return deny()
		}
	}
	expected := make(map[string]SecretReference, 33+len(binding.Link.References))
	for _, reference := range state.Publication.Result.References {
		expected[reference.Reference.TargetFile] = reference.Reference
	}
	for _, reference := range binding.Link.References {
		if _, exists := expected[reference.TargetFile]; exists && (reference.TargetFile != "cell.jwt" || template.identity.Cell != oci.RegionGRU) {
			return deny()
		}
		expected[reference.TargetFile] = reference
	}
	if len(binding.Manifest.Secrets) != len(expected) {
		return deny()
	}
	for _, reference := range binding.Manifest.Secrets {
		if expected[reference.TargetFile] != reference {
			return deny()
		}
		delete(expected, reference.TargetFile)
	}
	if len(expected) != 0 {
		return deny()
	}
	return DerivedStartupAuthority{template: template, binding: binding, client: client, wire: bytes.Clone(wire), digest: digestBytes(wire), envelope: envelope, ledgerKey: bytes.Clone(ledgerKey), peerKey: bytes.Clone(peerKey)}, ctx.Err()
}

func verifyOriginalLinkRecipient(ctx context.Context, regional, home VerifiedRegionalSource, now time.Time) (LinkRecipient, error) {
	rt, ht := regional.template, home.template
	if rt.bindings == nil || rt.bindings.original == nil || ht.bindings == nil || ht.bindings.original == nil || ht.identity.Cell != oci.RegionGRU || rt.InstallationID() != ht.InstallationID() || rt.Generation() != ht.Generation() || rt.GrantDigest() != ht.GrantDigest() || rt.anchor.Digest() != ht.anchor.Digest() || !bytes.Equal(rt.OriginRootChainWire(), ht.OriginRootChainWire()) || regional.StorageDomain() != home.StorageDomain() || rt.identity.Environment != ht.identity.Environment {
		return LinkRecipient{}, ErrManifestInvalid
	}
	regionalState, regionalWire, err := loadOriginalSourceState(ctx, rt, regional.client, now)
	if err != nil {
		return LinkRecipient{}, err
	}
	homeState, homeWire, err := loadOriginalSourceState(ctx, ht, home.client, now)
	if err != nil {
		return LinkRecipient{}, err
	}
	if !bytes.Equal(regionalState.OriginalAdmissionInventory, regional.wire) || !bytes.Equal(homeState.OriginalAdmissionInventory, home.wire) {
		return LinkRecipient{}, ErrManifestInvalid
	}
	r, err := OriginalSourceBindingFor(regionalWire)
	if err != nil {
		return LinkRecipient{}, err
	}
	h, err := OriginalSourceBindingFor(homeWire)
	if err != nil {
		return LinkRecipient{}, err
	}
	wire, err := json.Marshal([]string{"original-startup-link/v1", rt.InstallationID(), strings.ToLower(string(rt.identity.Cell)), rt.GrantDigest(), r.StateSHA256, h.StateSHA256}, json.Deterministic(true))
	if err != nil {
		return LinkRecipient{}, err
	}
	key, _, err := OriginalStartupLinkLocator(home.StorageDomain(), rt.InstallationID(), rt.identity.Cell)
	if err != nil {
		return LinkRecipient{}, err
	}
	return LinkRecipient{regional: regional, home: home, sourceSHA256: digestBytes(regional.MaterialRecord()), homeSHA256: digestBytes(home.MaterialRecord()), bindingSHA256: digestBytes(wire), key: key}, nil
}

type originalStartupLinkState struct {
	SchemaVersion  int                        `json:"schemaVersion"`
	Kind           string                     `json:"kind"`
	InstallationID string                     `json:"installationId"`
	Generation     uint64                     `json:"generation"`
	Cell           string                     `json:"cell"`
	GrantSHA256    string                     `json:"grantSha256"`
	BindingSHA256  string                     `json:"bindingSha256"`
	RegionalSource OriginalSourceBinding      `json:"regionalSource"`
	HomeSource     OriginalSourceBinding      `json:"homeSource"`
	HomeLinkSHA256 string                     `json:"homeLinkSha256,omitempty"`
	Target         StartupVaultTarget         `json:"target"`
	SecretName     string                     `json:"secretName"`
	RetryToken     string                     `json:"retryToken"`
	StartedAt      time.Time                  `json:"startedAt"`
	Candidate      originalSourceCandidate    `json:"candidate"`
	Reference      originalSourceReference    `json:"reference"`
	Journal        []byte                     `json:"journal,omitempty"`
	Publication    *originalPublicationResult `json:"publication,omitempty"`
	Delivery       []byte                     `json:"delivery,omitempty"`
}

func verifyOriginalStartupLink(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, evidence RegionalLinkEvidence, now time.Time) (VerifiedStartupLink, error) {
	deny := func() (VerifiedStartupLink, error) { return VerifiedStartupLink{}, ErrManifestInvalid }
	if ctx.Err() != nil || client == nil || template.VerifyCurrentContext(ctx, now) != nil || !validDigest(evidence.SourceSHA256) || len(evidence.MaterialRecord) == 0 || len(evidence.MaterialRecord) > 48<<10 || len(evidence.Journal) == 0 || len(evidence.Journal) > 64<<10 || len(evidence.Delivery) == 0 {
		return deny()
	}
	regional, err := LoadRegionalSource(ctx, template, client, now)
	if err != nil {
		return deny()
	}
	homeTemplate, err := template.ForCell(ctx, oci.RegionGRU, now)
	if err != nil {
		return deny()
	}
	home, err := LoadRegionalSource(ctx, homeTemplate, client, now)
	if err != nil {
		return deny()
	}
	recipient, err := VerifyLinkRecipient(ctx, regional, home, now)
	if err != nil {
		return deny()
	}
	payload, err := VerifyLinkDelivery(ctx, recipient, evidence.Delivery, now)
	expected, encodeErr := LinkDeliveryPayload(evidence)
	if err != nil || encodeErr != nil || !bytes.Equal(payload, expected) || evidence.SourceObjectKey != recipient.LinkObjectKey() || evidence.Actor != home.OriginalActor() {
		return deny()
	}
	domain := home.StorageDomain()
	wire, err := readOriginalObject(ctx, client, domain, recipient.LinkObjectKey(), 2<<20)
	if err != nil {
		return VerifiedStartupLink{}, err
	}
	var state originalStartupLinkState
	if json.Unmarshal(wire, &state, json.RejectUnknownMembers(true)) != nil {
		return deny()
	}
	canonical, err := json.Marshal(state, json.Deterministic(true))
	if err != nil || !bytes.Equal(wire, canonical) {
		return deny()
	}
	_, secretName, err := OriginalStartupLinkLocator(domain, template.InstallationID(), template.identity.Cell)
	if err != nil {
		return deny()
	}
	regionalState, regionalWire, err := loadOriginalSourceState(ctx, template, client, now)
	if err != nil {
		return deny()
	}
	_ = regionalState
	_, homeWire, err := loadOriginalSourceState(ctx, homeTemplate, client, now)
	if err != nil {
		return deny()
	}
	r, err := OriginalSourceBindingFor(regionalWire)
	if err != nil {
		return deny()
	}
	h, err := OriginalSourceBindingFor(homeWire)
	if err != nil {
		return deny()
	}
	token, tokenErr := uuid.Parse(state.RetryToken)
	if state.SchemaVersion != 3 || state.Kind != "original-startup-link/v1" || state.InstallationID != template.InstallationID() || state.Generation != template.Generation() || state.Cell != strings.ToLower(string(template.identity.Cell)) || state.GrantSHA256 != template.GrantDigest() || state.BindingSHA256 != recipient.BindingSHA256() || state.RegionalSource != r || state.HomeSource != h || state.Target != homeTemplate.escrow || state.SecretName != secretName || tokenErr != nil || token.String() != state.RetryToken || state.StartedAt.IsZero() || state.StartedAt.After(now) || !state.StartedAt.Before(recipient.ExpiresAt()) || !validDigest(state.Candidate.CreateSHA256) || state.Candidate.SHA256 != evidence.SourceSHA256 || state.Candidate.MaxBytes <= 0 || state.Candidate.MaxBytes > 25<<10 || state.Reference.SHA256 != state.Candidate.SHA256 || state.Reference.MaxBytes != state.Candidate.MaxBytes || !strings.HasPrefix(state.Reference.SecretOCID, "ocid1.vaultsecret.oc1.sa-saopaulo-1.") || !bytes.Equal(state.Journal, evidence.Journal) || !bytes.Equal(state.Delivery, evidence.Delivery) || state.Publication == nil {
		return deny()
	}
	var record struct {
		HomeLinkSHA256 string `json:"homeLinkSha256"`
	}
	if json.Unmarshal(evidence.MaterialRecord, &record) != nil || record.HomeLinkSHA256 != state.HomeLinkSHA256 {
		return deny()
	}
	publication := state.Publication
	if publication.SchemaVersion != 1 || publication.Target != template.VaultTarget() || publication.MaterialSHA256 != digestBytes(evidence.MaterialRecord) || len(publication.References) != len(evidence.References) {
		return deny()
	}
	for i, ref := range publication.References {
		if template.identity.Cell == oci.RegionGRU && ref.Reference.TargetFile == "link-cell.jwt" {
			ref.Reference.TargetFile = "cell.jwt"
		}
		if ref.SecretName == "" || ref.Reference != evidence.References[i] {
			return deny()
		}
	}
	return verifyStartupLinkContents(template, client, evidence, regional, home, template.identity.Cell == oci.RegionGRU, now)
}
