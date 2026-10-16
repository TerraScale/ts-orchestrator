package bootstrap

import (
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// InitialSourceRegistration authorizes exactly one new source-key binding in
// the signed installation's conditional source record. It never replaces an
// existing pinned ledger signer or grants a second founder authority.
type InitialSourceRegistration struct {
	InstallationID      string        `json:"installationId"`
	DeploymentID        string        `json:"deploymentId"`
	Environment         string        `json:"environment"`
	ClusterID           string        `json:"clusterId"`
	Cell                oci.Region    `json:"cell"`
	Generation          uint64        `json:"generation"`
	PlanSHA256          string        `json:"planSha256"`
	SeedSlot            string        `json:"seedSlot"`
	ControllerSlots     []string      `json:"controllerSlots"`
	StorageDomain       StorageDomain `json:"storageDomain"`
	LedgerRecordDomains []string      `json:"ledgerRecordDomains"`
}

func (registration InitialSourceRegistration) Clone() InitialSourceRegistration {
	registration.ControllerSlots = slices.Clone(registration.ControllerSlots)
	registration.LedgerRecordDomains = slices.Clone(registration.LedgerRecordDomains)
	return registration
}

func (registration InitialSourceRegistration) Validate() error {
	_, regionErr := registration.Cell.OCIRegion()
	if !entityid.Valid(registration.InstallationID) || !entityid.Valid(registration.DeploymentID) || !entityid.Valid(registration.ClusterID) ||
		registration.Environment != "production" && registration.Environment != "canary" || regionErr != nil || registration.Generation == 0 ||
		!sha256RE.MatchString(registration.PlanSHA256) || registration.StorageDomain.Validate() != nil || !controllerSlotRE.MatchString(registration.SeedSlot) ||
		!slices.Contains(registration.ControllerSlots, registration.SeedSlot) || len(registration.ControllerSlots) == 0 || len(registration.ControllerSlots) > MaxBootstrapAnchorSlots ||
		!slices.IsSorted(registration.ControllerSlots) || hasDuplicate(registration.ControllerSlots) {
		return ErrBootstrapAnchorInvalid
	}
	for _, slot := range registration.ControllerSlots {
		if !controllerSlotRE.MatchString(slot) {
			return ErrBootstrapAnchorInvalid
		}
	}
	want := slices.Sorted(slices.Values(BootstrapLedgerCapabilityDomains()))
	actual := slices.Sorted(slices.Values(registration.LedgerRecordDomains))
	if !slices.Equal(actual, want) {
		return ErrBootstrapAnchorInvalid
	}
	return nil
}
