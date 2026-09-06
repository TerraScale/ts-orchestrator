package main

import (
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

type productionDeploymentFile struct {
	Version  int                    `json:"version"`
	Cell     string                 `json:"cell"`
	Instance string                 `json:"instance"`
	Delivery productionDeliveryFile `json:"delivery"`
	Global   *productionGlobalFile  `json:"global,omitempty"`
}

type productionGlobalFile struct {
	Estate              productionEstateFile              `json:"estate"`
	HealthFile          string                            `json:"health_file"`
	KV                  productionKVFile                  `json:"kv"`
	Rotation            productionRotationFile            `json:"rotation"`
	Recovery            productionRecoveryFile            `json:"recovery"`
	Database            productionDatabaseFileConfig      `json:"database"`
	AuthBootstrapFile   string                            `json:"auth_bootstrap_file"`
	PlacementTransition productionPlacementTransitionFile `json:"placement_transition"`
}

func loadProductionDeployment(options *control.OrchestratorOptions) (productionDeploymentFile, error) {
	var config productionDeploymentFile
	if options == nil || !filepath.IsAbs(options.ProductionRuntimeFile) || filepath.Clean(options.ProductionRuntimeFile) != options.ProductionRuntimeFile {
		return config, errors.New("production runtime requires an absolute deployment file")
	}
	data, err := bootstrapcredentials.ReadFile(options.ProductionRuntimeFile, false, 1<<20)
	if err != nil {
		return config, err
	}
	if err = json.Unmarshal(data, &config, json.RejectUnknownMembers(true)); err != nil {
		return config, errors.New("production runtime deployment must contain one strict JSON object")
	}
	if config.Version != 1 || config.Cell != options.Cell || config.Instance != options.Instance || config.Cell == "local" || (config.Global != nil) != (config.Cell == "gru") {
		return config, errors.New("production runtime deployment differs from process role")
	}
	if config.Global != nil {
		if err := config.validateGlobalRelationships(estate.Default()); err != nil {
			return config, err
		}
	}
	return config, nil
}

func (f productionDeploymentFile) validateGlobalRelationships(spec estate.Spec) error {
	g := f.Global
	if g == nil {
		return errors.New("global runtime deployment is missing")
	}
	edge := g.Rotation.Edge
	if f.Delivery.Cloudflare.AccountID != edge.AccountID || f.Delivery.Cloudflare.ZoneID != edge.ZoneID || f.Delivery.Cloudflare.SnippetServices[edge.TemplateService] != edge.SnippetName || g.KV.AccountID != edge.AccountID || g.KV.ZoneID != edge.ZoneID || edge.AccountID == "" || edge.ZoneID == "" || edge.TemplateService == "" || edge.SnippetName == "" {
		return errors.New("global delivery, rotation and routing must use the same Cloudflare deployment")
	}
	regions := make([]string, 0, len(spec.Regions))
	for _, region := range spec.Regions {
		regions = append(regions, strings.ToLower(region.Code))
	}
	configured := slices.Clone(g.Rotation.Regions)
	slices.Sort(regions)
	slices.Sort(configured)
	if !slices.Equal(regions, configured) || g.HealthFile != f.Delivery.MembershipFile {
		return errors.New("global rotation and health must match the admitted delivery estate")
	}
	return nil
}
