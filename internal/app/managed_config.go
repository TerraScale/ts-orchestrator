package app

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

type managedPlacementSettings struct {
	Environment string              `json:"environment"`
	MemberRole  string              `json:"member_role"`
	Resources   placement.Resources `json:"resources"`
}

type managedControllerConfig struct {
	intent    oci.RegionIntent
	region    oci.RegionConfig
	placement managedPlacementSettings
}

func (m managedControllerConfig) placementConfig(cell string, onError func(error), onHold func(string)) placement.Config {
	settings := m.placement
	return placement.Config{
		Cell: cell, Region: m.region.Region, FaultDomains: m.region.FaultDomains,
		ManagedOwner: m.region.Owner, FleetGeneration: m.region.Generation,
		ImageID:     m.region.ImageID,
		Environment: settings.Environment, MemberRole: settings.MemberRole, Resources: settings.Resources,
		OnError: onError, OnHold: onHold,
	}
}

// withKnownBad makes managed update admission enforce the cell's rollout
// known-bad list; a nil source (rollout store disabled) leaves it unset.
func withKnownBad(config placement.Config, knownBad *rolloutKnownBad) placement.Config {
	if knownBad != nil {
		config.KnownBad = knownBad
	}
	return config
}

func loadManagedControllerConfig(cfg Config) (*managedControllerConfig, error) {
	controller := cfg.Controller
	configured := controller.OciRegionIntentFile != "" || controller.OciRegionConfig != "" || controller.PlacementConfig != ""
	if !configured {
		return nil, nil
	}
	if controller.OciRegionIntentFile == "" || controller.OciRegionConfig == "" || controller.PlacementConfig == "" {
		return nil, errors.New("managed controller requires OCI region intent, fleet config, and placement config together")
	}
	intent, region, settings, err := loadSignedManagedControllerConfig(cfg)
	if err != nil {
		return nil, err
	}
	managed := &managedControllerConfig{intent: intent, region: region, placement: settings}
	if err := managed.validateWorkloads(controller.Workloads); err != nil {
		return nil, err
	}
	return managed, nil
}

func (m managedControllerConfig) validateWorkloads(workloads map[string]WorkloadProfile) error {
	if _, exists := workloads[m.placement.MemberRole]; exists {
		return fmt.Errorf("placement member role %q overlaps a generic delivery workload profile", m.placement.MemberRole)
	}
	return nil
}

func parseManagedPlacementSettings(data []byte) (managedPlacementSettings, error) {
	var settings managedPlacementSettings
	if err := json.Unmarshal(data, &settings, json.RejectUnknownMembers(true)); err != nil {
		return managedPlacementSettings{}, fmt.Errorf("parse TerraBase placement config: %w", err)
	}
	return settings, nil
}

// loadSignedManagedControllerConfig reads the accepted installation and its
// exact pinned sidecars before any regional provider or store is opened.
func loadSignedManagedControllerConfig(cfg Config) (oci.RegionIntent, oci.RegionConfig, managedPlacementSettings, error) {
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	if err := bootstrapstart.CheckIdentityRekeyPrestart(accepted); err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	inputs, err := bootstrapstart.LoadTrustInputs(accepted)
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	material, err := bootstrapstart.NewMaterialStore(nil, uid, gid)
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	want, err := material.ControllerConfigSHA256(accepted, inputs.Roots.Historical)
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	configWire, err := cfg.signedWire()
	if err != nil || controllerSHA256(configWire) != want {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, errors.New("loaded controller config differs from accepted installation")
	}
	files := make([]bootstrap.ControllerConfigFile, len(bootstrap.ControllerConfigFileNames))
	for index, name := range bootstrap.ControllerConfigFileNames {
		wire, err := readInstalledControllerFile(controllerConfigDirectory, name, 0, 0, 0o444, bootstrap.MaxControllerSidecarBytes)
		if err != nil {
			return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, fmt.Errorf("read installed sidecar %s: %w", name, err)
		}
		if controllerSHA256(wire) != accepted.ConfigSHA256[name] {
			return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, fmt.Errorf("installed sidecar %s differs from accepted identity", name)
		}
		files[index] = bootstrap.ControllerConfigFile{Name: name, Bytes: wire, SHA256: accepted.ConfigSHA256[name]}
	}
	if _, err := ValidateAcceptedControllerConfig(accepted, configWire, want, files); err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	intent, err := oci.ParseRegionIntent(files[0].Bytes)
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	region, err := oci.ParseRegionConfig(files[1].Bytes)
	if err != nil || region.Validate(intent) != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, errors.New("signed OCI region config is invalid")
	}
	settings, err := parseManagedPlacementSettings(files[2].Bytes)
	return intent, region, settings, err
}

func readBoundedConfigFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("managed regional configuration file is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxConfigBytes {
		return nil, errors.New("managed regional configuration must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxConfigBytes {
		return nil, errors.New("managed regional configuration exceeds size limit")
	}
	return data, nil
}
