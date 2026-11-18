package fleetregion

import (
	"encoding/json"
	"fmt"

	document "github.com/TerraScale/ts-orchestrator/deploy/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

type Location struct {
	Label         string `json:"label"`
	OCIRegion     string `json:"oci_region"`
	CompartmentID string `json:"compartment_id"`
	VaultID       string `json:"vault_id"`
}

func Of(ociRegion, compartmentID string) (string, error) {
	return In(document.Document, ociRegion, compartmentID)
}

func In(fleet []byte, ociRegion, compartmentID string) (string, error) {
	var listed struct {
		Regions []Location `json:"regions"`
		Staging Location   `json:"staging"`
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

func locations() ([]Location, error) {
	var listed struct {
		Regions []Location `json:"regions"`
		Staging Location   `json:"staging"`
	}
	if err := json.Unmarshal(document.Document, &listed); err != nil {
		return nil, fmt.Errorf("fleet document: %w", err)
	}
	return append(listed.Regions, listed.Staging), nil
}

func Lookup(label string) (Location, error) {
	listed, err := locations()
	if err != nil {
		return Location{}, err
	}
	for _, location := range listed {
		if location.Label == label {
			return location, nil
		}
	}
	if entry, ok := catalog.LookupName(label); ok {
		return Location{Label: label, OCIRegion: entry.OCIRegion}, nil
	}
	return Location{}, fmt.Errorf("unknown region %q", label)
}

func OfVault(vault, physicalRegion string) (string, error) {
	listed, err := locations()
	if err != nil {
		return "", err
	}
	for _, location := range listed {
		if location.VaultID != "" && location.VaultID == vault && location.OCIRegion == physicalRegion {
			return location.Label, nil
		}
	}
	if entry, ok := catalog.CellForOCIRegion(physicalRegion); ok {
		return entry.Name(), nil
	}
	return "", fmt.Errorf("Vault must name a TerraScale cell's region")
}
