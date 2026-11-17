package fleetregion

import (
	"encoding/json"
	"fmt"

	document "github.com/TerraScale/ts-orchestrator/deploy/fleet"
)

type entry struct {
	Label         string `json:"label"`
	OCIRegion     string `json:"oci_region"`
	CompartmentID string `json:"compartment_id"`
}

func Of(ociRegion, compartmentID string) (string, error) {
	return In(document.Document, ociRegion, compartmentID)
}

func In(fleet []byte, ociRegion, compartmentID string) (string, error) {
	var listed struct {
		Regions []entry `json:"regions"`
		Staging entry   `json:"staging"`
	}
	if err := json.Unmarshal(fleet, &listed); err != nil {
		return "", fmt.Errorf("fleet document: %w", err)
	}
	for _, region := range append(listed.Regions, listed.Staging) {
		if region.OCIRegion == ociRegion && region.CompartmentID == compartmentID {
			return region.Label, nil
		}
	}
	return "", fmt.Errorf("compartment %s in %s is no region of the fleet document", compartmentID, ociRegion)
}
