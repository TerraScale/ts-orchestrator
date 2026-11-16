package fleet

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	document "github.com/TerraScale/ts-orchestrator/deploy/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

const (
	MinNodes = 3
	MaxNodes = 3
)

type Fleet struct {
	DNS     DNS      `json:"dns"`
	Regions []Region `json:"regions"`
}

type DNS struct {
	Zone               string   `json:"zone"`
	CompartmentID      string   `json:"compartment_id"`
	SteeredNames       []string `json:"steered_names"`
	SteeringTTLSeconds int      `json:"steering_ttl_seconds"`
	HealthCheckPath    string   `json:"health_check_path"`
}

type Region struct {
	Label             string   `json:"label"`
	OCIRegion         string   `json:"oci_region"`
	CompartmentID     string   `json:"compartment_id"`
	VCNCIDR           string   `json:"vcn_cidr"`
	PublicSubnetCIDR  string   `json:"public_subnet_cidr"`
	PrivateSubnetCIDR string   `json:"private_subnet_cidr"`
	Nodes             Nodes    `json:"nodes"`
	GeoContinents     []string `json:"geo_continents"`
}

var Continents = []string{"AF", "AN", "AS", "EU", "NA", "OC", "SA"}

func (r Region) APIName(zone string) string {
	return r.Label + ".api." + zone
}

func (r Region) Key(kind, name string) ociresource.Key {
	entry, _ := catalog.LookupName(r.Label)
	return ociresource.Key{Region: entry.Cell, Kind: kind, Name: name}
}

func (f Fleet) DNSRegion() (Region, bool) {
	for _, region := range f.Regions {
		if region.CompartmentID == f.DNS.CompartmentID {
			return region, true
		}
	}
	return Region{}, false
}

type Nodes struct {
	Min           int     `json:"min"`
	Max           int     `json:"max"`
	Shape         string  `json:"shape"`
	OCPUs         float32 `json:"ocpus"`
	MemoryGB      float32 `json:"memory_gb"`
	BootGB        int64   `json:"boot_gb"`
	DataGB        int64   `json:"data_gb"`
	DataVPUsPerGB int64   `json:"data_vpus_per_gb"`
}

func Load() (Fleet, error) {
	var fleet Fleet
	if err := json.Unmarshal(document.Document, &fleet, json.RejectUnknownMembers(true)); err != nil {
		return Fleet{}, fmt.Errorf("fleet document: %w", err)
	}
	return fleet, fleet.Validate()
}

func (f Fleet) Validate() error {
	var errs []error
	zone := strings.ToLower(f.DNS.Zone)
	if zone == "" || strings.HasPrefix(zone, ".") || strings.HasSuffix(zone, ".") {
		errs = append(errs, fmt.Errorf("dns.zone %q is not a zone name", f.DNS.Zone))
	}
	names := map[string]string{}
	claim := func(field, name string) {
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, "."+zone) || strings.Contains(strings.TrimSuffix(lower, "."+zone), "..") {
			errs = append(errs, fmt.Errorf("%s %q is outside dns.zone %q", field, name, f.DNS.Zone))
		}
		if other, ok := names[lower]; ok {
			errs = append(errs, fmt.Errorf("%s %q is already named by %s", field, name, other))
		}
		names[lower] = field
	}
	if len(f.DNS.SteeredNames) == 0 {
		errs = append(errs, errors.New("dns.steered_names is empty"))
	}
	for i, name := range f.DNS.SteeredNames {
		claim(fmt.Sprintf("dns.steered_names[%d]", i), name)
	}
	if f.DNS.SteeringTTLSeconds <= 0 {
		errs = append(errs, fmt.Errorf("dns.steering_ttl_seconds %d must be positive", f.DNS.SteeringTTLSeconds))
	}
	if _, ok := f.DNSRegion(); !ok {
		errs = append(errs, fmt.Errorf("dns.compartment_id %q is not the compartment of a region", f.DNS.CompartmentID))
	}
	if !strings.HasPrefix(f.DNS.HealthCheckPath, "/") {
		errs = append(errs, fmt.Errorf("dns.health_check_path %q must start with /", f.DNS.HealthCheckPath))
	}
	if len(f.Regions) == 0 {
		errs = append(errs, errors.New("regions is empty"))
	}
	labels := map[string]bool{}
	continents := map[string]string{}
	type labelled struct {
		label  string
		prefix netip.Prefix
	}
	var vcns []labelled
	for i, region := range f.Regions {
		field := fmt.Sprintf("regions[%d]", i)
		if labels[region.Label] {
			errs = append(errs, fmt.Errorf("%s.label %q is a duplicate label", field, region.Label))
		}
		labels[region.Label] = true
		field = fmt.Sprintf("regions[%s]", region.Label)
		errs = append(errs, region.validate(field)...)
		vcn, err := netip.ParsePrefix(region.VCNCIDR)
		if err == nil {
			for _, other := range vcns {
				if other.prefix.Overlaps(vcn) {
					errs = append(errs, fmt.Errorf("%s.vcn_cidr %s overlaps regions[%s].vcn_cidr %s", field, vcn, other.label, other.prefix))
				}
			}
			vcns = append(vcns, labelled{region.Label, vcn})
		}
		claim(field+" api name", region.APIName(f.DNS.Zone))
		for j, continent := range region.GeoContinents {
			if !slices.Contains(Continents, continent) {
				errs = append(errs, fmt.Errorf("%s.geo_continents[%d] %q is not one of %v", field, j, continent, Continents))
			} else if other, ok := continents[continent]; ok {
				errs = append(errs, fmt.Errorf("%s.geo_continents[%d] %s is already answered by regions[%s]", field, j, continent, other))
			}
			continents[continent] = region.Label
		}
	}
	for _, continent := range Continents {
		if _, ok := continents[continent]; !ok {
			errs = append(errs, fmt.Errorf("geo_continents: no region answers %s", continent))
		}
	}
	return errors.Join(errs...)
}

func (r Region) validate(field string) []error {
	var errs []error
	entry, ok := catalog.LookupName(r.Label)
	if !ok {
		errs = append(errs, fmt.Errorf("%s.label %q is not in the region catalog", field, r.Label))
	} else if entry.OCIRegion != r.OCIRegion {
		errs = append(errs, fmt.Errorf("%s.oci_region %q is not %s's OCI region %s", field, r.OCIRegion, r.Label, entry.OCIRegion))
	}
	if !strings.HasPrefix(r.CompartmentID, "ocid1.compartment.") {
		errs = append(errs, fmt.Errorf("%s.compartment_id %q is not a compartment OCID", field, r.CompartmentID))
	}
	vcn, err := netip.ParsePrefix(r.VCNCIDR)
	if err != nil || vcn != vcn.Masked() {
		errs = append(errs, fmt.Errorf("%s.vcn_cidr %q is not a network CIDR", field, r.VCNCIDR))
	}
	subnets := map[string]netip.Prefix{}
	for _, subnet := range []struct{ name, cidr string }{{"public_subnet_cidr", r.PublicSubnetCIDR}, {"private_subnet_cidr", r.PrivateSubnetCIDR}} {
		prefix, err := netip.ParsePrefix(subnet.cidr)
		switch {
		case err != nil || prefix != prefix.Masked():
			errs = append(errs, fmt.Errorf("%s.%s %q is not a network CIDR", field, subnet.name, subnet.cidr))
		case vcn.IsValid() && (prefix.Bits() < vcn.Bits() || !vcn.Contains(prefix.Addr())):
			errs = append(errs, fmt.Errorf("%s.%s %s is outside vcn_cidr %s", field, subnet.name, prefix, vcn))
		default:
			subnets[subnet.name] = prefix
		}
	}
	if public, private := subnets["public_subnet_cidr"], subnets["private_subnet_cidr"]; public.IsValid() && private.IsValid() && public.Overlaps(private) {
		errs = append(errs, fmt.Errorf("%s.public_subnet_cidr %s overlaps private_subnet_cidr %s", field, public, private))
	}
	n := r.Nodes
	if n.Min < MinNodes {
		errs = append(errs, fmt.Errorf("%s.nodes.min %d is below the minimum of %d nodes per region", field, n.Min, MinNodes))
	}
	if n.Max < n.Min {
		errs = append(errs, fmt.Errorf("%s.nodes.max %d is below nodes.min %d", field, n.Max, n.Min))
	}
	if n.Max > MaxNodes {
		errs = append(errs, fmt.Errorf("%s.nodes.max %d is above the cap of %d nodes per region", field, n.Max, MaxNodes))
	}
	if n.Shape == "" {
		errs = append(errs, fmt.Errorf("%s.nodes.shape is empty", field))
	}
	if n.OCPUs <= 0 || n.MemoryGB <= 0 {
		errs = append(errs, fmt.Errorf("%s.nodes.ocpus and nodes.memory_gb must be positive", field))
	}
	if n.BootGB < 50 {
		errs = append(errs, fmt.Errorf("%s.nodes.boot_gb %d is below OCI's 50 GB minimum", field, n.BootGB))
	}
	if n.DataGB < 50 {
		errs = append(errs, fmt.Errorf("%s.nodes.data_gb %d is below OCI's 50 GB minimum", field, n.DataGB))
	}
	if n.DataVPUsPerGB < 0 || n.DataVPUsPerGB > 120 || n.DataVPUsPerGB%10 != 0 {
		errs = append(errs, fmt.Errorf("%s.nodes.data_vpus_per_gb %d is not one of OCI's 0-120 steps of 10", field, n.DataVPUsPerGB))
	}
	return errs
}
