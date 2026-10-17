package region

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const RootOperationJournalRecordLimit = 256 << 10

const rootOperationJournalPurpose = "own-cell-root-node-first-acceptance-v1"
const rootOperationJournalPrefix = "orchestrator/root-operations/v1/"

// RootOperationJournalPurpose prepares NODE first-acceptance intent only.
// Actual signed identity, physical protection and writer proofs remain required.
type RootOperationJournalPurpose struct {
	Purpose                  string                  `json:"purpose"`
	InstallationID           string                  `json:"installationId"`
	TenancyID                string                  `json:"tenancyId"`
	Generation               uint64                  `json:"generation"`
	Cell                     string                  `json:"cell"`
	DeploymentID             string                  `json:"deploymentId"`
	ClusterID                string                  `json:"clusterId"`
	Environment              string                  `json:"environment"`
	SourcePlanSHA256         string                  `json:"sourcePlanSha256"`
	Storage                  bootstrap.StorageDomain `json:"storage"`
	BucketRole               string                  `json:"bucketRole"`
	Access                   string                  `json:"access"`
	OperationKind            string                  `json:"operationKind"`
	Identity                 string                  `json:"identity"`
	WriterSlotID             string                  `json:"writerSlotId"`
	WriterOperation          string                  `json:"writerOperation"`
	WriterProfile            string                  `json:"writerProfile"`
	WriterRecipe             string                  `json:"writerRecipe"`
	ObjectPrefix             string                  `json:"objectPrefix"`
	RecordLimit              int                     `json:"recordLimit"`
	ExpiresAt                time.Time               `json:"expiresAt"`
	LedgerBucketID           string                  `json:"ledgerBucketId"`
	RetentionRuleID          string                  `json:"retentionRuleId"`
	RetentionLockedAt        time.Time               `json:"retentionLockedAt"`
	RetentionDurationSeconds int64                   `json:"retentionDurationSeconds"`
}

func preparedRootOperationJournals(grant FoundationGrant, expires time.Time) ([]RootOperationJournalPurpose, error) {
	fail := func() ([]RootOperationJournalPurpose, error) {
		return nil, errors.New("root node purpose requires the exact original three signed controller allocations")
	}
	if !entityid.Valid(grant.InstallationID) || grant.Generation == 0 || grant.InfrastructureSpend == nil ||
		grant.InfrastructureSpend.Bootstrap == nil || len(grant.Regions) != 3 || expires.IsZero() {
		return fail()
	}
	var result []RootOperationJournalPurpose
	seen := map[string]bool{}
	for _, regional := range grant.Regions {
		cell, _ := regional.Plan["cell"].(string)
		material := regional.BootstrapMaterial
		if !capacityJournalCell(cell) || seen[cell] || regional.Generation != grant.Generation || material == nil ||
			material.InstallationID != grant.InstallationID || material.Startup == nil || material.SourceRegistration == nil {
			return fail()
		}
		seen[cell] = true
		startup, source := material.Startup, material.SourceRegistration
		configWire, err := json.Marshal(material.Config, json.Deterministic(true))
		if err != nil || material.Config.Validate() != nil || preparationDigest(configWire) != material.PlanSHA256 ||
			source.Validate() != nil || source.InstallationID != grant.InstallationID || source.Generation != grant.Generation ||
			string(source.Cell) != cell || source.PlanSHA256 != material.PlanSHA256 || source.DeploymentID != material.Config.DeploymentID ||
			source.ClusterID != material.Config.ClusterID || source.Environment != material.Config.Environment ||
			source.SeedSlot != startup.SeedSlot || startup.SeedSlot != "controller-a" || startup.FounderResources == nil {
			return fail()
		}
		deadline := expires
		if startup.FounderResources.LaunchDeadline.Before(deadline) {
			deadline = startup.FounderResources.LaunchDeadline
		}
		for _, wire := range [][]byte{startup.ReleaseImageReceiptWire, startup.ReleaseDelegationWire} {
			envelope, err := trust.DecodeEnvelope(wire)
			if err != nil {
				return nil, err
			}
			if envelope.ExpiresAt.Before(deadline) {
				deadline = envelope.ExpiresAt
			}
		}
		if deadline.IsZero() {
			return fail()
		}
		var profile bootstrap.LaunchProfile
		profiles := 0
		for _, candidate := range startup.Profiles {
			if candidate.Slot == startup.SeedSlot {
				profile, profiles = candidate, profiles+1
			}
		}
		profileDigest, err := ControllerBootstrapProfileDigest(profile)
		if err != nil || profiles != 1 {
			return fail()
		}
		recipeDigest, err := ControllerBootstrapRecipeDigest(*startup)
		if err != nil {
			return nil, err
		}
		slotID := BootstrapSlotID(grant.InstallationID, cell, "controller", startup.SeedSlot)
		allocations := 0
		for _, allocation := range grant.InfrastructureSpend.Bootstrap.Slots {
			if allocation.SlotID == slotID {
				if allocation.Cell != cell || allocation.Role != "controller" || allocation.Slot != startup.SeedSlot ||
					allocation.ProfileSHA256 != profileDigest || allocation.RecipeSHA256 != recipeDigest {
					return fail()
				}
				allocations++
			}
		}
		if allocations != 1 {
			return fail()
		}
		result = append(result, RootOperationJournalPurpose{Purpose: rootOperationJournalPurpose,
			InstallationID: grant.InstallationID, TenancyID: grant.TenancyID, Generation: grant.Generation, Cell: cell,
			DeploymentID: source.DeploymentID, ClusterID: source.ClusterID, Environment: source.Environment,
			SourcePlanSHA256: material.PlanSHA256, Storage: source.StorageDomain, BucketRole: "immutable-ledger",
			Access: "conditional-create-exact-read-no-overwrite-delete-list-or-phase-v1", WriterSlotID: slotID,
			OperationKind:   "node.submit",
			Identity:        "ulid-milliseconds-equal-signed-issued-at-v1",
			WriterOperation: BootstrapOperationID(grant.InstallationID, slotID), WriterProfile: profileDigest, WriterRecipe: recipeDigest,
			ObjectPrefix: rootOperationJournalPrefix + grant.InstallationID + "/" + cell + "/", RecordLimit: RootOperationJournalRecordLimit, ExpiresAt: deadline})
	}
	return result, nil
}

func validateRootOperationJournalIntents(grant FoundationGrant, envelopeExpiry time.Time) error {
	// Historical grants remain readable but cannot produce this purpose witness.
	if len(grant.RootOperationJournals) == 0 {
		return nil
	}
	if len(grant.RootOperationJournals) != 3 {
		return ErrFoundationFenced
	}
	seen := map[string]bool{}
	for _, purpose := range grant.RootOperationJournals {
		if seen[purpose.Cell] || !time.Now().Before(purpose.ExpiresAt) ||
			!envelopeExpiry.IsZero() && purpose.ExpiresAt.After(envelopeExpiry) {
			return ErrFoundationFenced
		}
		seen[purpose.Cell] = true
		expected, err := preparedRootOperationJournals(grant, purpose.ExpiresAt)
		if err != nil {
			return err
		}
		matched := false
		for _, candidate := range expected {
			// Physical descriptions are independently observed by SDK preparation.
			candidate.LedgerBucketID, candidate.RetentionRuleID = purpose.LedgerBucketID, purpose.RetentionRuleID
			candidate.RetentionLockedAt, candidate.RetentionDurationSeconds = purpose.RetentionLockedAt, purpose.RetentionDurationSeconds
			if candidate == purpose {
				matched = true
			}
		}
		if !matched {
			return ErrFoundationFenced
		}
	}
	return nil
}

func validateRootOperationJournals(grant FoundationGrant, envelopeExpiry time.Time) error {
	if err := validateRootOperationJournalIntents(grant, envelopeExpiry); err != nil {
		return err
	}
	var original *RootOperationJournalPurpose
	for _, purpose := range grant.RootOperationJournals {
		if !validAuxiliaryID("ledger_bucket", purpose.LedgerBucketID, foundationHomeRegion) || purpose.RetentionRuleID == "" ||
			len(purpose.RetentionRuleID) > 255 || strings.ContainsAny(purpose.RetentionRuleID, " /\\\t\r\n?#") ||
			purpose.RetentionLockedAt.IsZero() || purpose.RetentionLockedAt.After(time.Now()) || purpose.RetentionDurationSeconds < 31*60 {
			return errors.New("root node purpose lacks actual effective locked ledger protection")
		}
		if original != nil && (purpose.LedgerBucketID != original.LedgerBucketID || purpose.RetentionRuleID != original.RetentionRuleID ||
			!purpose.RetentionLockedAt.Equal(original.RetentionLockedAt) || purpose.RetentionDurationSeconds != original.RetentionDurationSeconds) {
			return errors.New("root node purposes differ from the one original protected home ledger")
		}
		original = new(purpose)
	}
	return nil
}
