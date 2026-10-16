package oci

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const maxRegionIntentBytes = 16 << 10
const maxRegionConfigBytes = 64 << 10

// Region is the product region that owns one OCI fleet. A Fleet is pinned to
// exactly one of these regions for its lifetime.
type Region string

const (
	RegionGRU Region = catalog.GRU
	RegionSFO Region = catalog.SFO
	RegionFRA Region = catalog.FRA
)

// Regions returns the founded regions (catalog.Founded) in catalog order:
// the regions with a reserved address plan that placement assigns seats in.
func Regions() []Region {
	founded := catalog.Founded()
	regions := make([]Region, 0, len(founded))
	for _, entry := range founded {
		regions = append(regions, Region(entry.Cell))
	}
	return regions
}

var (
	regionTokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	shapePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	faultDomainPattern = regexp.MustCompile(`^FAULT-DOMAIN-[1-3]$`)
)

// RegionMapping is one logical cell to OCI region entry in ts-infra's intent.
type RegionMapping struct {
	Cell      Region `json:"cell"`
	OCIRegion string `json:"ociRegion"`
}

// RegionIntent authorizes OCI regions for this deployment. It describes
// authority only; it is not proof that a region has been provisioned or that
// any OCI resource belongs to this controller.
type RegionIntent struct {
	SchemaVersion   int             `json:"schemaVersion"`
	Generation      uint64          `json:"generation"`
	BootstrapRegion Region          `json:"bootstrapRegion"`
	Regions         []RegionMapping `json:"regions"`
}

// ParseRegionIntent parses the closed, bounded region-intent format emitted by
// ts-infra and validates its fixed product-region mapping.
func ParseRegionIntent(data []byte) (RegionIntent, error) {
	if len(data) == 0 || len(data) > maxRegionIntentBytes {
		return RegionIntent{}, errors.New("OCI region intent exceeds its size bound")
	}
	var intent RegionIntent
	if err := json.Unmarshal(data, &intent, json.RejectUnknownMembers(true)); err != nil {
		return RegionIntent{}, fmt.Errorf("parse OCI region intent: %w", err)
	}
	if err := intent.Validate(); err != nil {
		return RegionIntent{}, err
	}
	return intent, nil
}

// LoadRegionIntentFile reads an owner-private regular file and parses the
// ts-infra region authorization document. Symlinks and group/world-readable
// files are rejected so a different local identity cannot silently widen scope.
func LoadRegionIntentFile(path string) (RegionIntent, error) {
	if strings.TrimSpace(path) == "" {
		return RegionIntent{}, errors.New("OCI region intent path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return RegionIntent{}, fmt.Errorf("stat OCI region intent: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxRegionIntentBytes ||
		info.Mode().Perm()&0o077 != 0 {
		return RegionIntent{}, errors.New("OCI region intent must be a bounded owner-private regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return RegionIntent{}, fmt.Errorf("read OCI region intent: %w", err)
	}
	return ParseRegionIntent(data)
}

// ParseRegionConfig decodes a bounded regional fleet template. Region intent
// admission is checked separately by RegionConfig.Validate.
func ParseRegionConfig(data []byte) (RegionConfig, error) {
	if len(data) == 0 || len(data) > maxRegionConfigBytes {
		return RegionConfig{}, errors.New("OCI region configuration exceeds its size bound")
	}
	var config RegionConfig
	if err := json.Unmarshal(data, &config, json.RejectUnknownMembers(true)); err != nil {
		return RegionConfig{}, fmt.Errorf("parse OCI region configuration: %w", err)
	}
	return config, nil
}

// Validate enforces the stable logical-to-OCI region mapping and requires GRU
// to remain the bootstrap region until a separately reviewed migration exists.
func (intent RegionIntent) Validate() error {
	if intent.SchemaVersion != 1 || intent.Generation == 0 || intent.BootstrapRegion != Region(catalog.Bootstrap) ||
		len(intent.Regions) == 0 || len(intent.Regions) > catalog.MaxRegions {
		return errors.New("OCI region intent has an unsupported version, generation, or region set")
	}
	seen := make(map[Region]struct{}, len(intent.Regions))
	for _, mapping := range intent.Regions {
		ociRegion := catalog.OCIRegion(string(mapping.Cell))
		if ociRegion == "" || mapping.OCIRegion != ociRegion {
			return fmt.Errorf("OCI region intent contains an unsupported mapping for %q", mapping.Cell)
		}
		if _, exists := seen[mapping.Cell]; exists {
			return fmt.Errorf("OCI region intent repeats %q", mapping.Cell)
		}
		seen[mapping.Cell] = struct{}{}
	}
	if _, ok := seen[intent.BootstrapRegion]; !ok {
		return errors.New("OCI region intent must include its GRU bootstrap region")
	}
	return nil
}

// OCIRegion returns the official OCI region key for a supported product cell.
func (region Region) OCIRegion() (string, error) {
	ociRegion := catalog.OCIRegion(string(region))
	if ociRegion == "" {
		return "", fmt.Errorf("unsupported TerraScale region %q", region)
	}
	return ociRegion, nil
}

// RegionConfig binds one regional fleet to a reviewed OCI intent generation
// and a fixed set of launch parameters. No credentials belong in this value.
type RegionConfig struct {
	Region                  Region   `json:"region"`
	Generation              uint64   `json:"generation"`
	Endpoint                string   `json:"endpoint"`
	CompartmentID           string   `json:"compartment_id"`
	ImageCompartmentID      string   `json:"image_compartment_id"`
	AvailabilityDomain      string   `json:"availability_domain"`
	FaultDomains            []string `json:"fault_domains"`
	SubnetID                string   `json:"subnet_id"`
	NetworkSecurityGroupIDs []string `json:"network_security_group_ids,omitempty"`
	ImageID                 string   `json:"image_id"`
	Shape                   string   `json:"shape"`
	BootVolumeGB            uint32   `json:"boot_volume_gb"`
	BootVolumeVPUsPerGB     uint32   `json:"boot_volume_vpus_per_gb"`
	DataVolumeVPUsPerGB     uint32   `json:"data_volume_vpus_per_gb"`
	MaxDataVolumeGB         int64    `json:"max_data_volume_gb"`
	Owner                   string   `json:"owner"`
}

// Validate refuses configurations that can escape the admitted OCI region or
// launch resources without a stable owner and exact regional scope.
func (config RegionConfig) Validate(intent RegionIntent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	ociRegion, err := config.Region.OCIRegion()
	if err != nil {
		return err
	}
	if config.Generation == 0 || config.Generation != intent.Generation {
		return errors.New("OCI fleet generation must match the admitted region-intent generation")
	}
	if !slices.ContainsFunc(intent.Regions, func(mapping RegionMapping) bool {
		return mapping.Cell == config.Region && mapping.OCIRegion == ociRegion
	}) {
		return fmt.Errorf("region %q is not admitted by OCI region intent", config.Region)
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint == nil || endpoint.Scheme != "https" || endpoint.Host != "iaas."+ociRegion+".oraclecloud.com" ||
		endpoint.User != nil || endpoint.Path != "" && endpoint.Path != "/" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("OCI endpoint must be pinned to %s", ociRegion)
	}
	if !isOCID(config.CompartmentID, "compartment") || !isOCID(config.ImageCompartmentID, "compartment") ||
		!isOCID(config.SubnetID, "subnet") ||
		!isOCID(config.ImageID, "image") || strings.TrimSpace(config.AvailabilityDomain) == "" ||
		len(config.AvailabilityDomain) > 128 || !shapePattern.MatchString(config.Shape) ||
		!regionTokenPattern.MatchString(config.Owner) {
		return errors.New("OCI fleet configuration has an invalid compartment, network, image, shape, domain, or owner")
	}
	if config.BootVolumeGB < 50 || config.BootVolumeGB > 32768 ||
		config.BootVolumeVPUsPerGB != 10 || config.DataVolumeVPUsPerGB != 10 ||
		config.MaxDataVolumeGB < 50 || config.MaxDataVolumeGB > 32768 {
		return errors.New("OCI fleet requires an explicit supported boot size and balanced boot/data volume tiers")
	}
	if len(config.FaultDomains) == 0 || len(config.FaultDomains) > 3 {
		return errors.New("OCI fleet must define one to three supported fault domains")
	}
	seenFaultDomains := make(map[string]struct{}, len(config.FaultDomains))
	for _, faultDomain := range config.FaultDomains {
		if !faultDomainPattern.MatchString(faultDomain) {
			return fmt.Errorf("invalid OCI fault domain %q", faultDomain)
		}
		if _, exists := seenFaultDomains[faultDomain]; exists {
			return fmt.Errorf("duplicate OCI fault domain %q", faultDomain)
		}
		seenFaultDomains[faultDomain] = struct{}{}
	}
	if len(config.NetworkSecurityGroupIDs) == 0 || len(config.NetworkSecurityGroupIDs) > 16 {
		return errors.New("OCI fleet requires one to sixteen network security groups")
	}
	seenNSGs := make(map[string]struct{}, len(config.NetworkSecurityGroupIDs))
	for _, nsg := range config.NetworkSecurityGroupIDs {
		if !isOCID(nsg, "networksecuritygroup") {
			return fmt.Errorf("invalid OCI network security group OCID %q", nsg)
		}
		if _, exists := seenNSGs[nsg]; exists {
			return fmt.Errorf("duplicate OCI network security group %q", nsg)
		}
		seenNSGs[nsg] = struct{}{}
	}
	return nil
}

func isOCID(value, kind string) bool {
	return strings.HasPrefix(value, "ocid1."+kind+".") && len(value) <= 255 &&
		!strings.ContainsAny(value, " \t\r\n")
}
