package bootstrap

import (
	"encoding/json/v2"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// FoundationReferenceKeys returns only logical roles consumed by startup projection.
func (template StartupTemplate) FoundationReferenceKeys(cell string) ([]string, error) {
	if err := template.ValidateFoundation(cell); err != nil {
		return nil, err
	}
	var values []string
	for _, profile := range template.Profiles {
		values = append(values, profile.CompartmentOCID, profile.SubnetOCID)
		values = append(values, profile.NetworkSecurityGroupOCIDs...)
	}
	if domain := template.ManagedMaterial; domain != nil {
		values = append(values, domain.KMSKeyOCID, domain.MemberCompartmentOCID, domain.MemberSubnetOCID)
	}
	if resources := template.FounderResources; resources != nil {
		for _, slot := range resources.Slots {
			values = append(values, slot.ImageCompartmentOCID)
		}
	}
	var config oci.RegionConfig
	if err := json.Unmarshal(template.ControllerFiles[1].Bytes, &config, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	values = append(values, config.CompartmentID, config.ImageCompartmentID, config.SubnetID)
	values = append(values, config.NetworkSecurityGroupIDs...)
	var keys []string
	for _, value := range values {
		if strings.HasPrefix(value, "foundation:") {
			actualCell, key, err := foundationbinding.Parse(value)
			if err != nil || actualCell != cell {
				return nil, ErrManifestInvalid
			}
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

func foundationResource(value, kind, cell, role string) bool {
	if isOCID(value, kind) {
		return true
	}
	if cell == "" {
		return false
	}
	actualCell, actualRole, err := foundationbinding.Parse(value)
	return err == nil && actualCell == cell && actualRole == role
}

// ValidateFoundation accepts logical references only in their finite signed
// resource roles. It does not turn unresolved references into live OCI IDs.
func (template StartupTemplate) ValidateFoundation(cell string) error {
	if _, err := foundationbinding.Reference(cell, "control_compartment"); err != nil {
		return ErrManifestInvalid
	}
	if err := template.validateFoundation(cell); err != nil {
		return err
	}
	var config oci.RegionConfig
	if json.Unmarshal(template.ControllerFiles[1].Bytes, &config, json.RejectUnknownMembers(true)) != nil || string(config.Region) != cell || !foundationResource(config.CompartmentID, "compartment", cell, "control_compartment") || !foundationResource(config.ImageCompartmentID, "compartment", cell, "control_compartment") || !foundationResource(config.SubnetID, "subnet", cell, "subnet") {
		return ErrManifestInvalid
	}
	for _, nsg := range config.NetworkSecurityGroupIDs {
		if !foundationResource(nsg, "networksecuritygroup", cell, "network_security_group") {
			return ErrManifestInvalid
		}
	}
	return nil
}

// ProjectFoundationStartup resolves only the exact resource fields authorized
// by the independently verified bindings. Callers retain the original signed
// template and its digest beside this concrete installation projection.
func ProjectFoundationStartup(template StartupTemplate, bindings foundationbinding.VerifiedBindings) (StartupTemplate, error) {
	return projectFoundationStartup(template, bindings.Cell(), bindings.Resolve)
}

func projectFoundationStartup(template StartupTemplate, cell string, lookup func(string) (string, error)) (StartupTemplate, error) {
	if err := template.ValidateFoundation(cell); err != nil {
		return StartupTemplate{}, err
	}
	projected := template.Clone()
	resolve := func(value *string) error {
		if !strings.HasPrefix(*value, "foundation:") {
			return nil
		}
		resolved, err := lookup(*value)
		if err != nil {
			return err
		}
		*value = resolved
		return nil
	}
	for index := range projected.Profiles {
		profile := &projected.Profiles[index]
		for _, value := range []*string{&profile.CompartmentOCID, &profile.SubnetOCID} {
			if err := resolve(value); err != nil {
				return StartupTemplate{}, err
			}
		}
		for index := range profile.NetworkSecurityGroupOCIDs {
			if err := resolve(&profile.NetworkSecurityGroupOCIDs[index]); err != nil {
				return StartupTemplate{}, err
			}
		}
	}
	if domain := projected.ManagedMaterial; domain != nil {
		for _, value := range []*string{&domain.KMSKeyOCID, &domain.MemberCompartmentOCID, &domain.MemberSubnetOCID} {
			if err := resolve(value); err != nil {
				return StartupTemplate{}, err
			}
		}
	}
	if resources := projected.FounderResources; resources != nil {
		for index := range resources.Slots {
			if err := resolve(&resources.Slots[index].ImageCompartmentOCID); err != nil {
				return StartupTemplate{}, err
			}
		}
	}
	var config oci.RegionConfig
	if err := json.Unmarshal(projected.ControllerFiles[1].Bytes, &config, json.RejectUnknownMembers(true)); err != nil {
		return StartupTemplate{}, err
	}
	for _, value := range []*string{&config.CompartmentID, &config.ImageCompartmentID, &config.SubnetID} {
		if err := resolve(value); err != nil {
			return StartupTemplate{}, err
		}
	}
	for index := range config.NetworkSecurityGroupIDs {
		if err := resolve(&config.NetworkSecurityGroupIDs[index]); err != nil {
			return StartupTemplate{}, err
		}
	}
	wire, err := json.Marshal(config, json.Deterministic(true))
	if err != nil {
		return StartupTemplate{}, err
	}
	projected.ControllerFiles[1].Bytes = wire
	projected.ControllerFiles[1].SHA256 = digestBytes(wire)
	intent, err := oci.ParseRegionIntent(projected.ControllerFiles[0].Bytes)
	if err != nil {
		return StartupTemplate{}, err
	}
	if err := config.Validate(intent); err != nil {
		return StartupTemplate{}, err
	}
	if err := projected.Validate(); err != nil {
		return StartupTemplate{}, err
	}
	return projected, nil
}
