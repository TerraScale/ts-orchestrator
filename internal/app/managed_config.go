package app

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type managedPlacementSettings struct {
	Environment string              `json:"environment"`
	MemberRole  string              `json:"member_role"`
	Resources   placement.Resources `json:"resources"`
	TickMillis  int64               `json:"tick_millis,omitzero"`
	// AutoGrowVolumes opts into grow-only resize of retained volumes created
	// under a smaller resource profile. Off by default.
	AutoGrowVolumes bool `json:"auto_grow_volumes,omitzero"`
	// ReattachOnHostLoss opts into moving a lost member's retained volume
	// to its replacement host once OCI reports the old host TERMINATED.
	// Off by default.
	ReattachOnHostLoss bool `json:"reattach_on_host_loss,omitzero"`
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
		TickInterval:       time.Duration(settings.TickMillis) * time.Millisecond,
		AutoGrowVolumes:    settings.AutoGrowVolumes,
		ReattachOnHostLoss: settings.ReattachOnHostLoss,
		OnError:            onError, OnHold: onHold,
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
	present, err := controllerBakedInputsPresent()
	if err != nil {
		return nil, err
	}
	var intent oci.RegionIntent
	var region oci.RegionConfig
	var settings managedPlacementSettings
	if present {
		intent, region, settings, err = loadSignedManagedControllerConfig(cfg)
	} else {
		intent, region, err = loadManagedRegion(cfg)
		if err == nil {
			settings, err = loadManagedPlacementSettings(controller.PlacementConfig)
		}
	}
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
	return parseManagedPlacementSettings(data)
}

func parseManagedPlacementSettings(data []byte) (managedPlacementSettings, error) {
	var settings managedPlacementSettings
	if err := json.Unmarshal(data, &settings, json.RejectUnknownMembers(true)); err != nil {
		return managedPlacementSettings{}, fmt.Errorf("parse TerraBase placement config: %w", err)
	}
	if settings.TickMillis < 0 || settings.TickMillis > 300_000 || settings.TickMillis > 0 && settings.TickMillis < 100 {
		return managedPlacementSettings{}, errors.New("TerraBase placement tick_millis must be zero or 100..300000")
	}
	return settings, nil
}

// loadSignedManagedControllerConfig parses only bytes that were checked in the
// same open against the root-owned installed manifest and accepted ledger hash.
func loadSignedManagedControllerConfig(cfg Config) (oci.RegionIntent, oci.RegionConfig, managedPlacementSettings, error) {
	marker, err := bootstrapstart.NewMarkerStore().Read()
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	wire, err := readInstalledControllerFile(controllerConfigDirectory, controllerManifestFilename,
		0, 0, 0o644, bootstrapstart.MaxControllerManifestMetadataBytes)
	if err != nil || controllerSHA256(wire) != marker.ManifestSHA256 {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, errors.New("installed signed controller manifest differs from accepted ledger")
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	manifest, err := bootstrap.ManifestPayload(envelope.Payload)
	if err != nil || manifest.Slot != marker.Slot {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, errors.New("installed controller manifest slot is invalid")
	}
	configWire, err := protocol.EncodeJSON(cfg)
	if err != nil || controllerSHA256(configWire) != manifest.ControllerConfigSHA256 {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, errors.New("loaded controller config differs from installed signed manifest")
	}
	if _, err := ValidateSignedControllerConfig(manifest, marker.PrimaryPrivateIP); err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	_, gid, err := controllerServiceIdentity()
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	var sidecars [3][]byte
	for index, file := range manifest.ControllerFiles {
		ownerUID, ownerGID, mode := uint32(0), uint32(0), uint32(0o644)
		if index == 0 {
			ownerUID, ownerGID, mode = 0, gid, 0o440
		}
		sidecars[index], err = readInstalledControllerFile(controllerConfigDirectory,
			file.Name, ownerUID, ownerGID, mode, bootstrap.MaxControllerSidecarBytes)
		if err != nil || controllerSHA256(sidecars[index]) != file.SHA256 ||
			!bytes.Equal(sidecars[index], file.Bytes) {
			return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{},
				fmt.Errorf("installed controller sidecar %s differs from signed bytes", file.Name)
		}
	}
	intent, err := oci.ParseRegionIntent(sidecars[0])
	if err != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, err
	}
	region, err := oci.ParseRegionConfig(sidecars[1])
	if err != nil || region.Validate(intent) != nil {
		return oci.RegionIntent{}, oci.RegionConfig{}, managedPlacementSettings{}, errors.New("signed OCI region config is invalid")
	}
	settings, err := parseManagedPlacementSettings(sidecars[2])
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
