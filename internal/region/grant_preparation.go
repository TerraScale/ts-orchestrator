package region

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// FoundationHostApproval is a finite permission for one initial A1 host.
// Region, role, address, image and placement are derived by the producer.
type FoundationHostApproval struct {
	OCPUs             float64 `json:"ocpus"`
	MemoryGB          float64 `json:"memoryGb"`
	BootGB            int64   `json:"bootGb"`
	MonthlyLimitMinor int64   `json:"monthlyLimitMinor"`
}

func validatePreparedReleaseAuthorities(authorities []ContainerReleaseAuthorityIntent) error {
	for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
		covered := false
		for _, authority := range authorities {
			if authority.Role == role && authority.Environment == "production" &&
				slices.Contains(authority.Cells, "GRU") && slices.Contains(authority.Cells, "SJC") && slices.Contains(authority.Cells, "FRA") &&
				slices.Contains(authority.Architectures, "arm64") && slices.Contains(authority.Architectures, "amd64") {
				covered = true
			}
		}
		if !covered {
			return fmt.Errorf("initial approval lacks the complete explicitly approved %s production release authority", role)
		}
	}
	return nil
}

func preparationDigest(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

func preparationResource(plan map[string]any, cell, key string) (string, error) {
	ids, _ := plan["resource_ids"].(map[string]any)
	if value, ok := ids[key].(string); ok && value != "" {
		return value, nil
	}
	return FoundationResourceReference(cell, key)
}

// ControllerBootstrapProfileDigest binds the signed logical launch profile;
// resource projection must preserve this original authorization digest.
func ControllerBootstrapProfileDigest(profile bootstrap.LaunchProfile) (string, error) {
	return bootstrap.ControllerBootstrapProfileDigest(profile)
}

// ControllerBootstrapRecipeDigest binds all public startup inputs, including
// the release proof, sidecars, operator grants and logical resource references.
func ControllerBootstrapRecipeDigest(startup bootstrap.StartupTemplate) (string, error) {
	return bootstrap.ControllerBootstrapRecipeDigest(startup)
}

func controllerBootstrapSlot(installation, cell string, startup bootstrap.StartupTemplate, host FoundationHostApproval) (BootstrapSlotIntent, error) {
	profileIndex := slices.IndexFunc(startup.Profiles, func(profile bootstrap.LaunchProfile) bool { return profile.Slot == startup.SeedSlot })
	if profileIndex < 0 || startup.SeedSlot != "controller-a" {
		return BootstrapSlotIntent{}, errors.New("initial controller allocation requires the exact controller-a seed profile")
	}
	profile := startup.Profiles[profileIndex]
	profileDigest, err := ControllerBootstrapProfileDigest(profile)
	if err != nil {
		return BootstrapSlotIntent{}, err
	}
	recipeDigest, err := ControllerBootstrapRecipeDigest(startup)
	if err != nil {
		return BootstrapSlotIntent{}, err
	}
	return BootstrapSlotIntent{SlotID: BootstrapSlotID(installation, cell, "controller", startup.SeedSlot), Cell: cell, Role: "controller", Slot: startup.SeedSlot,
		CompartmentID: profile.CompartmentOCID, ProfileSHA256: profileDigest, RecipeSHA256: recipeDigest, Shape: profile.Shape,
		OCPUs: host.OCPUs, MemoryGB: host.MemoryGB, BootGB: float64(host.BootGB), MonthlyLimitMinor: host.MonthlyLimitMinor}, nil
}

// ValidatePreparedFoundation prevents the ceremony from signing spending
// hashes unrelated to the recipes its launch consumers actually enforce.
func ValidatePreparedFoundation(grant FoundationGrant) error {
	if grant.SchemaVersion == 3 {
		if err := requireOriginalSourceProducerPurposes(grant); err != nil {
			return err
		}
	}
	if err := validateFoundationNetBirdMaterial(grant); err != nil {
		return err
	}
	var home bootstrap.StorageDomain
	for _, regional := range grant.Regions {
		if regional.Plan["cell"] == "GRU" && regional.BootstrapMaterial != nil && regional.BootstrapMaterial.SourceRegistration != nil {
			home = regional.BootstrapMaterial.SourceRegistration.StorageDomain
		}
	}
	if err := validateOriginalAdmissionReadIntents(grant, home); err != nil {
		return err
	}
	if err := validateOriginalFoundationPublicationIntent(grant, home); err != nil {
		return err
	}
	if err := validateOriginalMaterialIAMIntents(grant, home); err != nil {
		return err
	}
	if err := validateOriginalStartupAdmissions(grant); err != nil {
		return err
	}
	if err := validateNetBirdComponentIdentities(grant, home); err != nil {
		return err
	}
	if err := validateFoundationNetBirdAccount(grant); err != nil {
		return err
	}
	if err := validateFoundationNetBirdBackup(grant); err != nil {
		return err
	}
	if err := validateFoundationWorkloadGenesis(grant, home); err != nil {
		return err
	}
	if err := validateFoundationAdmissionAttestors(grant, home); err != nil {
		return err
	}
	if err := validatePreparedReleaseAuthorities(grant.ReleaseAuthorities); err != nil {
		return err
	}
	if err := ValidateBootstrapSpending(grant); err != nil {
		return err
	}
	if (grant.SchemaVersion != 2 && grant.SchemaVersion != 3) || grant.Generation != 1 || grant.InfrastructureSpend == nil || grant.InfrastructureSpend.Bootstrap == nil || len(grant.InfrastructureSpend.Bootstrap.Slots) != 4 || len(grant.Regions) != 3 {
		return errors.New("prepared foundation requires exactly three controller allocations and one dedicated GRU manager")
	}
	slots := make(map[string]BootstrapSlotIntent, 4)
	for _, slot := range grant.InfrastructureSpend.Bootstrap.Slots {
		key := slot.Cell + "/" + slot.Role
		if _, exists := slots[key]; exists || slot.Slot != "controller-a" && slot.Role == "controller" {
			return errors.New("prepared foundation repeats a bootstrap role or funds a non-seed controller")
		}
		slots[key] = slot
	}
	seen := map[string]bool{}
	for _, regional := range grant.Regions {
		cell, _ := regional.Plan["cell"].(string)
		if !slices.Contains([]string{"GRU", "SJC", "FRA"}, cell) || seen[cell] || regional.BootstrapMaterial == nil || regional.BootstrapMaterial.Startup == nil {
			return errors.New("prepared foundation differs from the fixed bootstrap footprint")
		}
		seen[cell] = true
		material := regional.BootstrapMaterial
		startup := *material.Startup
		configWire, err := json.Marshal(material.Config, json.Deterministic(true))
		if err != nil || material.Config.Validate() != nil || startup.ValidateFoundation(cell) != nil || material.InstallationID != grant.InstallationID ||
			material.Config.Cell != strings.ToLower(cell) || material.Config.Region != regional.Plan["region"] || material.PlanSHA256 != preparationDigest(configWire) || regional.Generation != grant.Generation ||
			material.SourceRegistration == nil || material.SourceRegistration.Validate() != nil || material.SourceRegistration.InstallationID != grant.InstallationID || material.SourceRegistration.PlanSHA256 != material.PlanSHA256 ||
			material.SourceRegistration.DeploymentID != material.Config.DeploymentID || material.SourceRegistration.ClusterID != material.Config.ClusterID || material.SourceRegistration.Generation != grant.Generation ||
			material.SourceRegistration.Cell != oci.Region(cell) || material.SourceRegistration.Environment != material.Config.Environment || material.SourceRegistration.SeedSlot != startup.SeedSlot {
			return errors.New("prepared material differs from its exact config, source registration or startup recipe")
		}
		var hosts []struct {
			Slot     string  `json:"slot"`
			Shape    string  `json:"shape"`
			OCPUs    float64 `json:"ocpus"`
			MemoryGB float64 `json:"memory_gb"`
			BootGB   int64   `json:"boot_gb"`
		}
		hostWire, err := json.Marshal(regional.Plan["hosts"])
		if err != nil || json.Unmarshal(hostWire, &hosts) != nil || len(hosts) != 1 || hosts[0].Slot != startup.SeedSlot || hosts[0].Shape != "VM.Standard.A1.Flex" {
			return errors.New("prepared plan must contain exactly its funded initial controller")
		}
		slot, exists := slots[cell+"/controller"]
		expected, err := controllerBootstrapSlot(grant.InstallationID, cell, startup, FoundationHostApproval{OCPUs: hosts[0].OCPUs, MemoryGB: hosts[0].MemoryGB, BootGB: hosts[0].BootGB, MonthlyLimitMinor: slot.MonthlyLimitMinor})
		if !exists || err != nil || expected != slot {
			return errors.New("controller allocation differs from its exact signed logical profile, geometry or startup recipe")
		}
		if startup.FounderResources == nil {
			return errors.New("controller startup lacks exact signed founder resources")
		}
		for _, resources := range startup.FounderResources.Slots {
			if float64(resources.WholeOCPUs) != slot.OCPUs || float64(resources.MemoryInGB) != slot.MemoryGB || float64(resources.BootVolumeGB) != slot.BootGB {
				return errors.New("controller founder resources differ from the finite host allocation")
			}
		}
		if cell != "GRU" {
			if regional.NetBirdManager != nil {
				return errors.New("dedicated NetBird manager is confined to GRU")
			}
			continue
		}
		manager := regional.NetBirdManager
		if manager == nil || manager.validate() != nil {
			return errors.New("prepared GRU foundation lacks the dedicated qualified NetBird manager")
		}
		managerSlot, exists := slots["GRU/"+NetBirdManagerRole]
		profileDigest, err := NetBirdManagerProfileDigest(manager.Profile)
		if !exists || err != nil || managerSlot.ProfileSHA256 != profileDigest || managerSlot.Shape != manager.Profile.Shape || managerSlot.OCPUs != float64(manager.Profile.OCPUs) || managerSlot.MemoryGB != float64(manager.Profile.MemoryGB) || managerSlot.BootGB != float64(manager.Profile.BootVolumeGB) {
			return errors.New("NetBird allocation differs from its exact signed logical profile or geometry")
		}
		envelope, err := trust.DecodeEnvelope(manager.ImageReceiptWire)
		if err != nil {
			return err
		}
		var receipt release.ImageReceipt
		if err := json.Unmarshal(envelope.Payload, &receipt, json.RejectUnknownMembers(true)); err != nil || receipt.Validate() != nil || receipt.OCIImageOCID != manager.ImageOCID || receipt.Architecture != manager.Architecture || receipt.OCIRegion != "GRU" {
			return errors.New("NetBird recipe differs from its exact image receipt")
		}
		recipeDigest, err := NetBirdManagerRecipeDigest(*manager, receipt.ImageSHA256)
		if err != nil || managerSlot.RecipeSHA256 != recipeDigest {
			return errors.New("NetBird allocation differs from its exact signed startup recipe")
		}
	}
	return nil
}
