package app

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

type managedPlacementSettings struct {
	Environment string              `json:"environment"`
	MemberRole  string              `json:"member_role"`
	Resources   placement.Resources `json:"resources"`
	TickMillis  int64               `json:"tick_millis,omitzero"`
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
		Environment: settings.Environment, MemberRole: settings.MemberRole, Resources: settings.Resources,
		TickInterval: time.Duration(settings.TickMillis) * time.Millisecond,
		OnError:      onError, OnHold: onHold,
	}
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
	intent, region, err := loadManagedRegion(cfg)
	if err != nil {
		return nil, err
	}
	settings, err := loadManagedPlacementSettings(controller.PlacementConfig)
	if err != nil {
		return nil, err
	}
	if _, exists := controller.Workloads[settings.MemberRole]; exists {
		return nil, fmt.Errorf("placement member role %q overlaps a generic delivery workload profile", settings.MemberRole)
	}
	return &managedControllerConfig{intent: intent, region: region, placement: settings}, nil
}

func loadManagedPlacementSettings(path string) (managedPlacementSettings, error) {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return managedPlacementSettings{}, fmt.Errorf("read TerraBase placement config: %w", err)
	}
	var settings managedPlacementSettings
	if err := json.Unmarshal(data, &settings, json.RejectUnknownMembers(true)); err != nil {
		return managedPlacementSettings{}, fmt.Errorf("parse TerraBase placement config: %w", err)
	}
	if settings.TickMillis < 0 || settings.TickMillis > 300_000 || settings.TickMillis > 0 && settings.TickMillis < 100 {
		return managedPlacementSettings{}, errors.New("TerraBase placement tick_millis must be zero or 100..300000")
	}
	return settings, nil
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

func loadManagedRegion(cfg Config) (oci.RegionIntent, oci.RegionConfig, error) {
	intent, err := oci.LoadRegionIntentFile(cfg.Controller.OciRegionIntentFile)
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, fmt.Errorf("read OCI region intent: %w", err)
	}
	configBytes, err := readBoundedConfigFile(cfg.Controller.OciRegionConfig)
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, fmt.Errorf("read OCI fleet config: %w", err)
	}
	region, err := oci.ParseRegionConfig(configBytes)
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, fmt.Errorf("parse OCI fleet config: %w", err)
	}
	if err := region.Validate(intent); err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, err
	}
	if strings.ToLower(string(region.Region)) != cfg.NATS.Cell {
		return oci.RegionIntent{}, oci.RegionConfig{}, errors.New("OCI fleet region does not match NATS cell")
	}
	return intent, region, nil
}
