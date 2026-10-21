package region

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const originalSourceProducerPurpose = "original-source-archive/v1"

var ErrOriginalSourceProducerHold = errors.New("original source producer purpose or complete original birth is unavailable; HOLD")

// OriginalSourceProducerIntent reserves the existing seed slot for a prospective
// archive producer. Profile and ResourceSelectionsSHA256 bind signed selections,
// including unresolved foundation references: they prove no physical provenance.
// The selections digest covers the existing regional plan and its parent scopes.
// No parent-intent, grant or retained-bundle hash is an input to this purpose.
// Actor, launch, IAM and archive authority require separately verified originals.
type OriginalSourceProducerIntent struct {
	Purpose                             string                        `json:"purpose"`
	TenancyID                           string                        `json:"tenancyId"`
	InstallationID                      string                        `json:"installationId"`
	DeploymentID                        string                        `json:"deploymentId"`
	ClusterID                           string                        `json:"clusterId"`
	Environment                         string                        `json:"environment"`
	Cell                                string                        `json:"cell"`
	OCIRegion                           string                        `json:"ociRegion"`
	Generation                          uint64                        `json:"generation"`
	OriginalUserID                      string                        `json:"originalUserId"`
	OperationID                         string                        `json:"operationId"`
	Allocation                          BootstrapSlotIntent           `json:"allocation"`
	Profile                             bootstrap.LaunchProfile       `json:"profile"`
	ResourceSelectionsSHA256            string                        `json:"resourceSelectionsSha256"`
	ImageOCID                           string                        `json:"imageOcid"`
	ImageReceiptSHA256                  string                        `json:"imageReceiptSha256"`
	ImageDelegationSHA256               string                        `json:"imageDelegationSha256"`
	WriterQualificationSHA256           string                        `json:"writerQualificationSha256"`
	WriterQualificationDelegationSHA256 string                        `json:"writerQualificationDelegationSha256"`
	LaunchDeadline                      time.Time                     `json:"launchDeadline"`
	PlanSHA256                          string                        `json:"planSha256"`
	SourceRegistrationSHA256            string                        `json:"sourceRegistrationSha256"`
	AdmissionAuthorizationSHA256        string                        `json:"admissionAuthorizationSha256"`
	Home                                bootstrap.StorageDomain       `json:"home"`
	JournalObject                       string                        `json:"journalObject"`
	SourceObject                        string                        `json:"sourceObject"`
	SourceSecretName                    string                        `json:"sourceSecretName"`
	Escrow                              bootstrapmaterial.VaultTarget `json:"escrow"`
}

func originalSourceProducerIntent(grant FoundationGrant, home bootstrap.StorageDomain, regional FoundationIntent) (OriginalSourceProducerIntent, error) {
	var purpose OriginalSourceProducerIntent
	material := regional.BootstrapMaterial
	if grant.SchemaVersion != 3 || grant.Generation != 1 || material == nil || material.Startup == nil || material.Startup.FounderResources == nil ||
		material.SourceRegistration == nil || material.AdmissionAttestor == nil || grant.InfrastructureSpend == nil || grant.InfrastructureSpend.Bootstrap == nil {
		return purpose, ErrOriginalSourceProducerHold
	}
	attestor, err := foundationAdmissionAttestor(grant, home, regional)
	if err != nil || attestor != *material.AdmissionAttestor {
		return purpose, ErrOriginalSourceProducerHold
	}
	var user string
	for _, region := range grant.Regions {
		if region.Plan["cell"] == "GRU" && region.NetBirdManager != nil && region.NetBirdManager.Material != nil {
			user = region.NetBirdManager.Material.Context.ProducerUserID
		}
	}
	startup := material.Startup
	profileIndex := slices.IndexFunc(startup.Profiles, func(p bootstrap.LaunchProfile) bool { return p.Slot == startup.SeedSlot })
	if !netBirdMaterialUser(user) || profileIndex < 0 || startup.SeedSlot != "controller-a" {
		return purpose, ErrOriginalSourceProducerHold
	}
	profile := startup.Profiles[profileIndex]
	profile.NetworkSecurityGroupOCIDs = slices.Clone(profile.NetworkSecurityGroupOCIDs)
	profileDigest, err := ControllerBootstrapProfileDigest(profile)
	if err != nil {
		return purpose, err
	}
	recipeDigest, err := ControllerBootstrapRecipeDigest(*startup)
	if err != nil {
		return purpose, err
	}
	var allocation BootstrapSlotIntent
	matches := 0
	for _, slot := range grant.InfrastructureSpend.Bootstrap.Slots {
		if slot.Cell == attestor.Cell && slot.Role == "controller" {
			allocation = slot
			matches++
		}
	}
	if matches != 1 || allocation.Slot != startup.SeedSlot || allocation.SlotID != BootstrapSlotID(grant.InstallationID, attestor.Cell, "controller", startup.SeedSlot) ||
		allocation.ProfileSHA256 != profileDigest || allocation.RecipeSHA256 != recipeDigest || allocation.CompartmentID != profile.CompartmentOCID || allocation.Shape != profile.Shape ||
		allocation.MonthlyLimitMinor <= 0 || !positiveBootstrapDimension(allocation.OCPUs) || !positiveBootstrapDimension(allocation.MemoryGB) || !positiveBootstrapDimension(allocation.BootGB) || startup.FounderResources.LaunchDeadline.IsZero() {
		return purpose, ErrOriginalSourceProducerHold
	}
	imageEnvelope, err := trust.DecodeEnvelope(startup.ReleaseImageReceiptWire)
	if err != nil {
		return purpose, err
	}
	var image release.ImageReceipt
	if err := json.Unmarshal(imageEnvelope.Payload, &image, json.RejectUnknownMembers(true)); err != nil {
		return purpose, err
	}
	// Pin the existing independent writer proof without claiming its later
	// physical image/binary/evidence verification has already happened.
	writer := image.HostProduction[release.FoundationWriterRole]
	if image.OCIImageOCID != startup.ImageOCID || len(writer.Qualification) == 0 {
		return purpose, ErrOriginalSourceProducerHold
	}
	resources, ok := regional.Plan["resource_ids"].(map[string]any)
	if !ok || len(resources) == 0 {
		return purpose, ErrOriginalSourceProducerHold
	}
	resourceWire, err := json.Marshal(struct {
		ParentCompartmentID string         `json:"parentCompartmentId"`
		SharedCompartmentID string         `json:"sharedCompartmentId"`
		Plan                map[string]any `json:"plan"`
	}{grant.ParentCompartmentID, grant.SharedCompartmentID, regional.Plan}, json.Deterministic(true))
	if err != nil {
		return purpose, err
	}
	registrationWire, err := json.Marshal(material.SourceRegistration, json.Deterministic(true))
	if err != nil {
		return purpose, err
	}
	attestorWire, err := json.Marshal(attestor, json.Deterministic(true))
	if err != nil {
		return purpose, err
	}
	sourceScope := sha256.Sum256([]byte(grant.InstallationID + "\x00" + material.Config.Cell))
	purpose = OriginalSourceProducerIntent{Purpose: originalSourceProducerPurpose, TenancyID: grant.TenancyID, InstallationID: grant.InstallationID,
		DeploymentID: material.Config.DeploymentID, ClusterID: material.Config.ClusterID, Environment: material.Config.Environment, Cell: attestor.Cell, OCIRegion: material.Config.Region,
		Generation: grant.Generation, OriginalUserID: user, OperationID: BootstrapOperationID(grant.InstallationID, allocation.SlotID), Allocation: allocation, Profile: profile,
		ResourceSelectionsSHA256: preparationDigest(resourceWire), ImageOCID: startup.ImageOCID, ImageReceiptSHA256: preparationDigest(startup.ReleaseImageReceiptWire),
		ImageDelegationSHA256: preparationDigest(startup.ReleaseDelegationWire), WriterQualificationSHA256: preparationDigest(writer.Qualification), WriterQualificationDelegationSHA256: preparationDigest(writer.Delegation),
		LaunchDeadline: startup.FounderResources.LaunchDeadline, PlanSHA256: material.PlanSHA256, SourceRegistrationSHA256: preparationDigest(registrationWire), AdmissionAuthorizationSHA256: preparationDigest(attestorWire),
		Home: home, JournalObject: foundationObjectPrefix + "GRU.json", SourceObject: attestor.SourceObject, SourceSecretName: "ts-bootstrap-source-" + hex.EncodeToString(sourceScope[:16]), Escrow: material.SourceVaultTarget}
	return purpose, nil
}

// Absence on an already signed schema3 document never acquires purpose. Partial
// or altered purposes are invalid even when another original consumer reads it.
func validateOriginalSourceProducerPurposes(grant FoundationGrant, home bootstrap.StorageDomain) error {
	present := 0
	for _, regional := range grant.Regions {
		if regional.BootstrapMaterial != nil && regional.BootstrapMaterial.OriginalSourceProducer != nil {
			present++
			if grant.SchemaVersion != 3 {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	if present == 0 {
		return nil
	}
	if present != 3 || len(grant.Regions) != 3 {
		return ErrOriginalSourceProducerHold
	}
	seen := map[string]bool{}
	for _, regional := range grant.Regions {
		expected, err := originalSourceProducerIntent(grant, home, regional)
		if err != nil || seen[expected.Cell] || !sameOriginalSourceValue(expected, regional.BootstrapMaterial.OriginalSourceProducer) {
			return ErrOriginalSourceProducerHold
		}
		seen[expected.Cell] = true
	}
	return nil
}

func requireOriginalSourceProducerPurposes(grant FoundationGrant) error {
	var home bootstrap.StorageDomain
	for _, regional := range grant.Regions {
		if regional.BootstrapMaterial == nil || regional.BootstrapMaterial.OriginalSourceProducer == nil {
			return ErrOriginalSourceProducerHold
		}
		if regional.Plan["cell"] == "GRU" && regional.BootstrapMaterial.SourceRegistration != nil {
			home = regional.BootstrapMaterial.SourceRegistration.StorageDomain
		}
	}
	if grant.SchemaVersion != 3 || len(grant.Regions) != 3 {
		return ErrOriginalSourceProducerHold
	}
	return validateOriginalSourceProducerPurposes(grant, home)
}

func sameOriginalSourceValue(a, b any) bool {
	x, err := json.Marshal(a, json.Deterministic(true))
	y, other := json.Marshal(b, json.Deterministic(true))
	return err == nil && other == nil && bytes.Equal(x, y)
}

// VerifiedOriginalSourceProducerScope authenticates document purpose only. It
// has no actor, physical binding, archive or current-runtime authority.
type VerifiedOriginalSourceProducerScope struct {
	source *SignedFootprint
	wire   []byte
	intent OriginalSourceProducerIntent
}

func (v VerifiedOriginalSourceProducerScope) IsVerified() bool {
	return v.source != nil && len(v.wire) != 0
}
func (v VerifiedOriginalSourceProducerScope) Intent() OriginalSourceProducerIntent {
	intent := v.intent
	intent.Profile.NetworkSecurityGroupOCIDs = slices.Clone(intent.Profile.NetworkSecurityGroupOCIDs)
	return intent
}

func (s *SignedFootprint) OriginalSourceProducer(ctx context.Context, cell string) (VerifiedOriginalSourceProducerScope, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return VerifiedOriginalSourceProducerScope{}, ErrOriginalSourceProducerHold
	}
	wire, err := s.readGrant(ctx)
	if err != nil {
		return VerifiedOriginalSourceProducerScope{}, err
	}
	grant, _, err := s.verifyOriginalDocument(wire)
	if err != nil {
		return VerifiedOriginalSourceProducerScope{}, err
	}
	if err := requireOriginalSourceProducerPurposes(grant); err != nil {
		return VerifiedOriginalSourceProducerScope{}, err
	}
	attestor, err := s.AdmissionAttestor(ctx, cell)
	if err != nil || !attestor.IsVerified() || !bytes.Equal(attestor.wire, wire) {
		return VerifiedOriginalSourceProducerScope{}, ErrOriginalSourceProducerHold
	}
	for _, regional := range grant.Regions {
		if regional.Plan["cell"] == cell {
			return VerifiedOriginalSourceProducerScope{source: s, wire: bytes.Clone(wire), intent: *regional.BootstrapMaterial.OriginalSourceProducer}, nil
		}
	}
	return VerifiedOriginalSourceProducerScope{}, ErrOriginalSourceProducerHold
}

// OriginalSourceProducerBirth is immutable metadata, separate from any future
// launch/request/result journal. It reserves no paid resource or actor identity.
type OriginalSourceProducerBirth struct {
	Intent                  OriginalSourceProducerIntent `json:"intent"`
	IntentSHA256            string                       `json:"intentSha256"`
	OriginalGrantSHA256     string                       `json:"originalGrantSha256"`
	OriginalBundleSHA256    string                       `json:"originalBundleSha256"`
	OriginalGRUIntentSHA256 string                       `json:"originalGruIntentSha256"`
	OriginalGeneration      uint64                       `json:"originalGeneration"`
	OriginalOperationID     string                       `json:"originalOperationId"`
	BornAt                  time.Time                    `json:"bornAt"`
	HeadBucketID            string                       `json:"headBucketId"`
	LedgerBucketID          string                       `json:"ledgerBucketId"`
	OriginObjects           [9]string                    `json:"originObjects"`
}

func (operator *foundationOperator) originalSourceProducerBirth(grant FoundationGrant) ([3]OriginalSourceProducerBirth, error) {
	if err := requireOriginalSourceProducerPurposes(grant); err != nil {
		return [3]OriginalSourceProducerBirth{}, err
	}
	return operator.originalSourceProducerBirthFromPreparedGrant(grant)
}

// The caller must have required the complete original producer purposes on
// this same local grant. This assembles immutable values without authority I/O.
func (operator *foundationOperator) originalSourceProducerBirthFromPreparedGrant(grant FoundationGrant) ([3]OriginalSourceProducerBirth, error) {
	var births [3]OriginalSourceProducerBirth
	bundleWire, err := json.Marshal(operator.bundle, json.Deterministic(true))
	if err != nil {
		return births, err
	}
	var homeIntent FoundationIntent
	for _, regional := range grant.Regions {
		if regional.Plan["cell"] == "GRU" {
			homeIntent = regional
		}
	}
	homeDigest, err := FoundationIntentDigest(homeIntent)
	if err != nil {
		return births, err
	}
	var origins [9]string
	if len(grant.WorkloadGenesis) != len(origins) {
		return births, ErrOriginalSourceProducerHold
	}
	for index, origin := range grant.WorkloadGenesis {
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			return births, err
		}
		origins[index] = name
	}
	slices.Sort(origins[:])
	for index, cell := range []string{"GRU", "SJC", "FRA"} {
		for _, regional := range grant.Regions {
			if regional.Plan["cell"] != cell {
				continue
			}
			intent := *regional.BootstrapMaterial.OriginalSourceProducer
			if intent.OriginalUserID != operator.id || intent.TenancyID != operator.bundle.TenancyID || intent.Home != operator.domain {
				return births, ErrOriginalSourceProducerHold
			}
			wire, err := json.Marshal(intent, json.Deterministic(true))
			if err != nil {
				return births, err
			}
			births[index] = OriginalSourceProducerBirth{Intent: intent, IntentSHA256: preparationDigest(wire), OriginalGrantSHA256: preparationDigest(operator.bundle.GrantWire),
				OriginalBundleSHA256: preparationDigest(bundleWire), OriginalGRUIntentSHA256: homeDigest, OriginalGeneration: homeIntent.Generation,
				OriginalOperationID: entityid.Derive("regional-foundation", grant.TenancyID, "GRU", fmt.Sprint(homeIntent.Generation)),
				HeadBucketID:        operator.buckets["head_bucket"], LedgerBucketID: operator.buckets["ledger_bucket"], OriginObjects: origins}
		}
	}
	return births, nil
}

func (r FoundationRecord) validateOriginalSourceProducers() error {
	if r.OriginalSourceProducers == nil {
		if r.NetBirdMaterial != nil {
			return ErrOriginalSourceProducerHold
		}
		return nil
	}
	if r.Cell != "GRU" || r.NetBirdMaterial == nil {
		return ErrOriginalSourceProducerHold
	}
	for index, birth := range r.OriginalSourceProducers {
		intent := birth.Intent
		wire, err := json.Marshal(intent, json.Deterministic(true))
		if err != nil || birth.IntentSHA256 != preparationDigest(wire) || intent.Purpose != originalSourceProducerPurpose || intent.Cell != [3]string{"GRU", "SJC", "FRA"}[index] ||
			intent.TenancyID != r.TenancyID || intent.Generation != birth.OriginalGeneration || intent.OriginalUserID != r.NetBirdMaterial.Authority.Context.ProducerUserID ||
			intent.InstallationID != r.NetBirdMaterial.Authority.Context.InstallationID || intent.Home.Validate() != nil || intent.Escrow != r.NetBirdMaterial.Authority.Context.Target ||
			birth.OriginalGrantSHA256 != r.NetBirdMaterial.OriginalGrantSHA256 || birth.OriginalBundleSHA256 != r.NetBirdMaterial.OriginalBundleSHA256 ||
			!validFoundationDigest(birth.OriginalGRUIntentSHA256) || birth.OriginalGeneration == 0 || !entityid.Valid(birth.OriginalOperationID) ||
			birth.BornAt.IsZero() || !birth.BornAt.Equal(r.NetBirdMaterial.BornAt) || birth.HeadBucketID != r.AuxiliaryIDs["head_bucket"] || birth.LedgerBucketID != r.AuxiliaryIDs["ledger_bucket"] ||
			!validAuxiliaryID("head_bucket", birth.HeadBucketID, foundationHomeRegion) || !validAuxiliaryID("ledger_bucket", birth.LedgerBucketID, foundationHomeRegion) {
			return ErrOriginalSourceProducerHold
		}
		first := (*r.OriginalSourceProducers)[0]
		if birth.OriginalGrantSHA256 != first.OriginalGrantSHA256 || birth.OriginalBundleSHA256 != first.OriginalBundleSHA256 || birth.OriginalGRUIntentSHA256 != first.OriginalGRUIntentSHA256 ||
			birth.OriginalGeneration != first.OriginalGeneration || birth.OriginalOperationID != first.OriginalOperationID || birth.OriginObjects != first.OriginObjects ||
			birth.Intent.Home != first.Intent.Home || birth.Intent.JournalObject != foundationObjectPrefix+"GRU.json" {
			return ErrOriginalSourceProducerHold
		}
		if r.Generation == birth.OriginalGeneration && (r.IntentDigest != birth.OriginalGRUIntentSHA256 || r.OperationID != birth.OriginalOperationID || r.GrantSHA256 != birth.OriginalGrantSHA256) {
			return ErrOriginalSourceProducerHold
		}
		var expected [9]string
		position := 0
		for _, cell := range []string{"GRU", "SJC", "FRA"} {
			for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
				name, err := release.WorkloadGenesisObject(intent.TenancyID, cell, intent.Environment, role)
				if err != nil {
					return err
				}
				expected[position] = name
				position++
			}
		}
		slices.Sort(expected[:])
		if birth.OriginObjects != expected {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}

func (next FoundationRecord) retainOriginalSourceProducers(previous FoundationRecord) error {
	if !sameOriginalSourceValue(previous.OriginalSourceProducers, next.OriginalSourceProducers) {
		return errors.New("original source producer birth cannot be appended, removed or replaced; HOLD")
	}
	return nil
}

func (authority *HomeIAMAuthority) checkOriginalSourceProducerBirth(ctx context.Context) error {
	grant, err := authority.originalMaterialGrant()
	if err != nil || grant.SchemaVersion != 3 {
		return err
	}
	if err := requireOriginalSourceProducerPurposes(grant); err != nil {
		return err
	}
	return authority.checkOriginalSourceProducerBirthFromPreparedGrant(ctx, grant)
}

// The same local grant has already passed requireOriginalSourceProducerPurposes.
// Birth authority is still read independently from the protected store each time.
func (authority *HomeIAMAuthority) checkOriginalSourceProducerBirthFromPreparedGrant(ctx context.Context, grant FoundationGrant) error {
	expected, err := authority.operator.originalSourceProducerBirthFromPreparedGrant(grant)
	if err != nil {
		return err
	}
	record, _, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil || record.OriginalSourceProducers == nil || record.NetBirdMaterial == nil {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	for index := range expected {
		expected[index].BornAt = record.NetBirdMaterial.BornAt
	}
	if !sameOriginalSourceValue(expected, record.OriginalSourceProducers) {
		return ErrOriginalSourceProducerHold
	}
	return nil
}
