package main

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/serviceidentityrotation"
)

type productionDeploymentFile struct {
	Version  int                    `json:"version"`
	Cell     string                 `json:"cell"`
	Instance string                 `json:"instance"`
	Delivery productionDeliveryFile `json:"delivery"`
	Global   *productionGlobalFile  `json:"global,omitempty"`
}

type productionGlobalFile struct {
	MembershipRevocations productionMembershipRevocationsFile `json:"membership_revocations"`
	Compute               productionGlobalComputeFile         `json:"compute"`
	Estate                productionEstateFile                `json:"estate"`
	HealthFile            string                              `json:"health_file"`
	KV                    productionKVFile                    `json:"kv"`
	Rotation              productionRotationFile              `json:"rotation"`
	Recovery              productionRecoveryFile              `json:"recovery"`
	Database              productionDatabaseFileConfig        `json:"database"`
	AuthBootstrapFile     string                              `json:"auth_bootstrap_file"`
	PlacementTransition   productionPlacementTransitionFile   `json:"placement_transition"`
	ServiceIdentity       serviceidentityrotation.FileConfig  `json:"service_identity"`
}

// productionGlobalComputeFile declares the lease-owned OCI mutation inputs.
// Credentials remain file references; secrets are never embedded here.
type productionComputeArtifactFile struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	PublicKey string `json:"public_key"`
}

type productionGlobalComputeFile struct {
	EstateFiles       map[string]string                        `json:"estate_files"`
	KeyID             string                                   `json:"key_id"`
	PrivateKeyFile    string                                   `json:"private_key_file"`
	ImageID           string                                   `json:"image_id"`
	FallbackImageID   string                                   `json:"fallback_image_id"`
	MutationJournalKV string                                   `json:"mutation_journal_kv"`
	ReleaseVersion    string                                   `json:"release_version"`
	ArtifactURL       string                                   `json:"artifact_url"`
	ArtifactSHA256    string                                   `json:"artifact_sha256"`
	ReleasePublicKey  string                                   `json:"release_public_key"`
	HostFiles         map[string]string                        `json:"host_files"`
	Artifacts         map[string]productionComputeArtifactFile `json:"artifacts"`
	// BootstrapSignerFile and BootstrapSignerPublicKeyPin are mandatory for
	// dynamically enrolled members. The private key is read only by GRU and
	// never copied into a host declaration.
	BootstrapSignerFile         string `json:"bootstrap_signer_file"`
	BootstrapSignerPublicKeyPin string `json:"bootstrap_signer_public_key_pin"`
}

func (f productionGlobalComputeFile) cloudInit() (string, error) { return f.cloudInitFor("arm64") }

func (f productionGlobalComputeFile) cloudInitFor(architecture string) (string, error) {
	a, ok := f.Artifacts[architecture]
	if !ok {
		return "", fmt.Errorf("missing %s release artifact", architecture)
	}
	files := make([]ocireconcile.BootstrapHostFile, 0, len(f.HostFiles))
	for path, content := range f.HostFiles {
		files = append(files, ocireconcile.BootstrapHostFile{Path: path, Content: []byte(content), Private: true})
	}
	return ocireconcile.TSNodeCloudInit(a.Version, a.SHA256, a.URL, a.URL+".sig", a.PublicKey, files)
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
	if len(g.Compute.EstateFiles) == 0 || g.Compute.KeyID == "" || g.Compute.PrivateKeyFile == "" || g.Compute.ImageID == "" || g.Compute.FallbackImageID == "" || g.Compute.MutationJournalKV == "" || g.Compute.ReleaseVersion == "" || g.Compute.ArtifactURL == "" || g.Compute.ArtifactSHA256 == "" || g.Compute.ReleasePublicKey == "" || len(g.Compute.HostFiles) == 0 || len(g.Compute.Artifacts) != 2 || g.Compute.Artifacts["arm64"].URL == "" || g.Compute.Artifacts["amd64"].URL == "" {
		return errors.New("global compute declaration is incomplete")
	}
	for _, region := range spec.Regions {
		if strings.TrimSpace(g.Compute.EstateFiles[region.Code]) == "" {
			return fmt.Errorf("global compute estate file for region %s is missing", region.Code)
		}
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
