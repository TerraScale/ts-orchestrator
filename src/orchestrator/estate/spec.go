// Package estate defines the provider-neutral desired state consumed by the
// OCI and Cloudflare reconcilers. Declarations contain names and policy, never
// provider credentials or generated resource identifiers.
package estate

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const SchemaVersion = 2

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
	hostnamePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	secretNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

// ValidationError identifies the exact declaration rejected before a
// reconciler can make a provider request.
type ValidationError struct {
	Path    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("estate %s: %s", e.Path, e.Message)
}

// Spec is the complete desired OCI and Cloudflare estate.
type Spec struct {
	Version      uint32
	HomeRegion   string
	ControlPlane ControlPlane
	Regions      []Region
	Cloudflare   Cloudflare
}

// ControlPlane declares the cross-Region embedded JetStream group.
type ControlPlane struct {
	Replicas uint16
	Regions  []string
}

type Region struct {
	Code         string
	OCIName      string
	Members      MemberPool
	Network      Network
	Buckets      []Bucket
	VaultKeys    []VaultKey
	Certificates []Certificate
}

// MemberPool declares plain systemd hosts. PrimaryShape is the Ampere shape;
// FallbackShape is used when Ampere capacity is unavailable.
type MemberPool struct {
	Count           uint16
	PrimaryShape    string
	FallbackShape   string
	OCPUs           uint16
	MemoryGiB       uint16
	BootVolumeGiB   uint16
	DataVolumeGiB   uint32
	ControlReplicas uint16
}

type Network struct {
	CIDR           string
	Subnets        []Subnet
	SecurityGroups []NetworkSecurityGroup
	RouteTables    []RouteTable
}

type Subnet struct {
	Name       string
	CIDR       string
	Public     bool
	RegionCode string
}

type NetworkSecurityGroup struct {
	Name  string
	Rules []NetworkSecurityRule
}

type NetworkSecurityRule struct {
	Direction string
	Protocol  string
	Peer      string
	PortMin   uint16
	PortMax   uint16
}

// RouteTable declares one subnet's routes. Member subnets are private, so
// the public internet (replication peers, OCI APIs, artifact fetches) is
// reachable only through the Region's NAT gateway (D-66); routes name it
// declaratively and the network reconciler owns the gateway resource.
type RouteTable struct {
	Name   string
	Subnet string
	Routes []RouteRule
}

// RouteRule sends one destination CIDR through the Region's NAT gateway.
type RouteRule struct {
	Destination string
	ViaNAT      bool
}

type Bucket struct {
	Name           string
	Purpose        string
	Versioning     bool
	LifecycleRules []BucketLifecycleRule
}

type BucketLifecycleRule struct {
	Name       string
	Prefix     string
	Action     string
	AfterDays  uint16
	KeepLatest uint16
}

type VaultKey struct {
	Name          string
	Purpose       string
	RotationHours uint32
}

type Certificate struct {
	Name             string
	Purpose          string
	DNSNames         []string
	RenewBeforeHours uint32
}

type Cloudflare struct {
	Zone           string
	DNSRecords     []DNSRecord
	CacheRules     []CacheRule
	SnippetRules   []SnippetRule
	WorkerRoutes   []WorkerRoute
	KVMaps         []KVMap
	WAFRules       []WAFRule
	RateRules      []RateRule
	CapabilityKeys []CapabilityKey
}

type DNSRecord struct {
	Name    string
	Type    string
	Content string
	Proxied bool
	TTL     uint32
}

type CacheRule struct {
	Name            string
	Hostname        string
	PathPrefix      string
	Eligible        bool
	Immutable       bool
	EdgeTTLSeconds  uint32
	SmartTiered     bool
	CacheTagPattern string
}

// SnippetRule declares source and routing for a zone Snippet. SecretNames are
// provider secret references, not secret values.
type SnippetRule struct {
	Name        string
	Hostname    string
	PathPrefix  string
	SourceFile  string
	SecretNames []string
}

type WorkerRoute struct {
	Name       string
	Hostname   string
	PathPrefix string
	ScriptName string
}

type KVMap struct {
	Name      string
	Namespace string
	Entries   []KVEntry
}

type KVEntry struct {
	Key   string
	Value string
}

type WAFRule struct {
	Name       string
	Expression string
	Action     string
}

type RateRule struct {
	Name           string
	Expression     string
	Requests       uint32
	PeriodSeconds  uint32
	MitigationTime uint32
}

// CapabilityKey declares rotation into both members and Cloudflare Secrets
// Store without putting key material in the estate declaration.
type CapabilityKey struct {
	Name             string
	MemberSecretName string
	EdgeSecretName   string
	RotationHours    uint32
	OverlapHours     uint32
}

type ResourceKind string

const (
	ResourceCompute       ResourceKind = "compute"
	ResourceNetwork       ResourceKind = "network"
	ResourceSubnet        ResourceKind = "subnet"
	ResourceNSG           ResourceKind = "network-security-group"
	ResourceBucket        ResourceKind = "bucket"
	ResourceVaultKey      ResourceKind = "vault-key"
	ResourceCertificate   ResourceKind = "certificate"
	ResourceDNS           ResourceKind = "dns-record"
	ResourceCacheRule     ResourceKind = "cache-rule"
	ResourceSnippetRule   ResourceKind = "snippet-rule"
	ResourceWorkerRoute   ResourceKind = "worker-route"
	ResourceKVMap         ResourceKind = "kv-map"
	ResourceWAFRule       ResourceKind = "waf-rule"
	ResourceRateRule      ResourceKind = "rate-rule"
	ResourceCapabilityKey ResourceKind = "capability-key"
)

// ResourceRef is the stable provider-neutral identity used by observation,
// reconciliation, and drift reporting.
type ResourceRef struct {
	Kind   ResourceKind `json:"kind"`
	Region string       `json:"region,omitempty"`
	Name   string       `json:"name"`
}

// Validate rejects incomplete, ambiguous, or unsafe declarations before they
// reach a provider adapter.
func (s Spec) Validate() error {
	if s.Version != SchemaVersion {
		return invalid("version", "must equal the current schema version")
	}
	if !validIdentifier(s.HomeRegion) {
		return invalid("homeRegion", "must be a canonical Region code")
	}
	if len(s.Regions) == 0 || len(s.Regions) > 20 {
		return invalid("regions", "must contain between 1 and 20 Regions")
	}

	regionCodes := make(map[string]struct{}, len(s.Regions))
	ociNames := make(map[string]struct{}, len(s.Regions))
	for i := range s.Regions {
		path := fmt.Sprintf("regions[%d]", i)
		region := s.Regions[i]
		if !validIdentifier(region.Code) {
			return invalid(path+".code", "must be a canonical Region code")
		}
		if _, exists := regionCodes[region.Code]; exists {
			return invalid(path+".code", "duplicates another Region")
		}
		regionCodes[region.Code] = struct{}{}
		if !validOCIRegion(region.OCIName) {
			return invalid(path+".ociName", "must be a canonical OCI Region name")
		}
		if _, exists := ociNames[region.OCIName]; exists {
			return invalid(path+".ociName", "duplicates another OCI Region")
		}
		ociNames[region.OCIName] = struct{}{}
		if err := validateRegion(path, region); err != nil {
			return err
		}
	}
	if _, exists := regionCodes[s.HomeRegion]; !exists {
		return invalid("homeRegion", "must name a declared Region")
	}
	if err := validateControlPlane(s.ControlPlane, regionCodes); err != nil {
		return err
	}
	controlRegions := make(map[string]struct{}, len(s.ControlPlane.Regions))
	for _, region := range s.ControlPlane.Regions {
		controlRegions[region] = struct{}{}
	}
	for i, region := range s.Regions {
		_, hostsControl := controlRegions[region.Code]
		if hostsControl && region.Members.ControlReplicas != 1 {
			return invalid(fmt.Sprintf("regions[%d].members.controlReplicas", i), "must co-host one launch control replica")
		}
		if !hostsControl && region.Members.ControlReplicas != 0 {
			return invalid(fmt.Sprintf("regions[%d].members.controlReplicas", i), "must be zero outside the control group")
		}
	}
	return validateCloudflare(s.Cloudflare)
}

func validateControlPlane(control ControlPlane, regions map[string]struct{}) error {
	if control.Replicas != 3 {
		return invalid("controlPlane.replicas", "must declare the launch R3 control group")
	}
	if len(control.Regions) != int(control.Replicas) {
		return invalid("controlPlane.regions", "must place one replica in each control Region")
	}
	seen := map[string]struct{}{}
	for i, region := range control.Regions {
		path := fmt.Sprintf("controlPlane.regions[%d]", i)
		if _, exists := regions[region]; !exists {
			return invalid(path, "must name a declared Region")
		}
		if _, exists := seen[region]; exists {
			return invalid(path, "duplicates another control Region")
		}
		seen[region] = struct{}{}
	}
	return nil
}

func validateRegion(path string, region Region) error {
	if region.Members.Count < 2 {
		return invalid(path+".members.count", "must keep at least two members")
	}
	if !validShape(region.Members.PrimaryShape) || !validShape(region.Members.FallbackShape) || region.Members.PrimaryShape == region.Members.FallbackShape {
		return invalid(path+".members", "must declare distinct primary and fallback OCI shapes")
	}
	if region.Members.OCPUs == 0 || region.Members.MemoryGiB == 0 || region.Members.BootVolumeGiB == 0 || region.Members.DataVolumeGiB == 0 {
		return invalid(path+".members", "must declare non-zero host resources")
	}
	if region.Members.ControlReplicas > region.Members.Count {
		return invalid(path+".members.controlReplicas", "cannot exceed the member count")
	}
	networkPrefix, err := netip.ParsePrefix(region.Network.CIDR)
	if err != nil {
		return invalid(path+".network.cidr", "must be a valid CIDR prefix")
	}
	networkPrefix = networkPrefix.Masked()
	if len(region.Network.Subnets) == 0 {
		return invalid(path+".network.subnets", "must not be empty")
	}
	if len(region.Network.SecurityGroups) == 0 {
		return invalid(path+".network.securityGroups", "must not be empty")
	}
	if err := uniqueNames(path+".network.subnets", len(region.Network.Subnets), func(i int) string { return region.Network.Subnets[i].Name }); err != nil {
		return err
	}
	for i, subnet := range region.Network.Subnets {
		subnetPath := fmt.Sprintf("%s.network.subnets[%d]", path, i)
		if subnet.Public {
			return invalid(subnetPath+".public", "member subnets must be private")
		}
		if subnet.RegionCode != region.Code {
			return invalid(subnetPath+".regionCode", "must match its Region")
		}
		subnetPrefix, err := netip.ParsePrefix(subnet.CIDR)
		if err != nil {
			return invalid(subnetPath+".cidr", "must be a valid CIDR prefix")
		}
		subnetPrefix = subnetPrefix.Masked()
		if subnetPrefix.Addr().BitLen() != networkPrefix.Addr().BitLen() || subnetPrefix.Bits() < networkPrefix.Bits() || !networkPrefix.Contains(subnetPrefix.Addr()) {
			return invalid(subnetPath+".cidr", "must be contained by the Region VCN")
		}
	}
	if err := uniqueNames(path+".network.securityGroups", len(region.Network.SecurityGroups), func(i int) string { return region.Network.SecurityGroups[i].Name }); err != nil {
		return err
	}
	for i, group := range region.Network.SecurityGroups {
		if len(group.Rules) == 0 {
			return invalid(fmt.Sprintf("%s.network.securityGroups[%d].rules", path, i), "must not be empty")
		}
		for j, rule := range group.Rules {
			if err := validateSecurityRule(fmt.Sprintf("%s.network.securityGroups[%d].rules[%d]", path, i, j), rule); err != nil {
				return err
			}
		}
	}
	if err := uniqueNames(path+".network.routeTables", len(region.Network.RouteTables), func(i int) string { return region.Network.RouteTables[i].Name }); err != nil {
		return err
	}
	for i, table := range region.Network.RouteTables {
		tablePath := fmt.Sprintf("%s.network.routeTables[%d]", path, i)
		if len(table.Routes) == 0 {
			return invalid(tablePath+".routes", "must not be empty")
		}
		declaredSubnet := false
		for _, subnet := range region.Network.Subnets {
			if subnet.Name == table.Subnet {
				declaredSubnet = true
				break
			}
		}
		if !declaredSubnet {
			return invalid(tablePath+".subnet", "must name a declared subnet")
		}
		destinations := make(map[string]struct{}, len(table.Routes))
		for j, rule := range table.Routes {
			rulePath := fmt.Sprintf("%s.routes[%d]", tablePath, j)
			destination, err := netip.ParsePrefix(rule.Destination)
			if err != nil {
				return invalid(rulePath+".destination", "must be a valid CIDR prefix")
			}
			destination = destination.Masked()
			if networkPrefix.Contains(destination.Addr()) && destination.Bits() >= networkPrefix.Bits() {
				return invalid(rulePath+".destination", "must not fall inside the Region VCN")
			}
			if !rule.ViaNAT {
				return invalid(rulePath+".viaNat", "must declare a supported route target")
			}
			canonical := destination.String()
			if _, duplicate := destinations[canonical]; duplicate {
				return invalid(rulePath+".destination", "duplicates another route destination")
			}
			destinations[canonical] = struct{}{}
		}
	}
	if len(region.Buckets) == 0 || len(region.VaultKeys) == 0 || len(region.Certificates) == 0 {
		return invalid(path, "must declare buckets, vault keys, and certificates")
	}
	if err := uniqueNames(path+".buckets", len(region.Buckets), func(i int) string { return region.Buckets[i].Name }); err != nil {
		return err
	}
	for i, bucket := range region.Buckets {
		bucketPath := fmt.Sprintf("%s.buckets[%d]", path, i)
		if !validIdentifier(bucket.Purpose) || len(bucket.LifecycleRules) == 0 {
			return invalid(bucketPath, "must declare a purpose and lifecycle rules")
		}
		if err := uniqueNames(bucketPath+".lifecycleRules", len(bucket.LifecycleRules), func(j int) string { return bucket.LifecycleRules[j].Name }); err != nil {
			return err
		}
		for j, rule := range bucket.LifecycleRules {
			if !oneOf(rule.Action, "delete", "archive", "infrequent-access") || rule.AfterDays == 0 {
				return invalid(fmt.Sprintf("%s.lifecycleRules[%d]", bucketPath, j), "must declare a supported action and age")
			}
		}
	}
	if err := uniqueNames(path+".vaultKeys", len(region.VaultKeys), func(i int) string { return region.VaultKeys[i].Name }); err != nil {
		return err
	}
	for i, key := range region.VaultKeys {
		if !validIdentifier(key.Purpose) || key.RotationHours == 0 {
			return invalid(fmt.Sprintf("%s.vaultKeys[%d]", path, i), "must declare a purpose and rotation interval")
		}
	}
	if err := uniqueNames(path+".certificates", len(region.Certificates), func(i int) string { return region.Certificates[i].Name }); err != nil {
		return err
	}
	for i, certificate := range region.Certificates {
		certificatePath := fmt.Sprintf("%s.certificates[%d]", path, i)
		if !validIdentifier(certificate.Purpose) || certificate.RenewBeforeHours == 0 || len(certificate.DNSNames) == 0 {
			return invalid(certificatePath, "must declare purpose, DNS names, and renewal window")
		}
		for j, name := range certificate.DNSNames {
			if !validHostname(name) {
				return invalid(fmt.Sprintf("%s.dnsNames[%d]", certificatePath, j), "must be a valid hostname")
			}
		}
	}
	return nil
}

func validateSecurityRule(path string, rule NetworkSecurityRule) error {
	if !oneOf(rule.Direction, "ingress", "egress") || !oneOf(rule.Protocol, "tcp", "udp", "icmp") {
		return invalid(path, "must declare a supported direction and protocol")
	}
	if _, err := netip.ParsePrefix(rule.Peer); err != nil {
		return invalid(path+".peer", "must be a valid CIDR prefix")
	}
	if rule.Protocol == "icmp" {
		if rule.PortMin != 0 || rule.PortMax != 0 {
			return invalid(path, "ICMP rules cannot declare ports")
		}
		return nil
	}
	if rule.PortMin == 0 || rule.PortMax < rule.PortMin {
		return invalid(path, "must declare a valid port range")
	}
	return nil
}

func validateCloudflare(cloud Cloudflare) error {
	if !validHostname(cloud.Zone) {
		return invalid("cloudflare.zone", "must be a valid zone hostname")
	}
	required := []struct {
		path string
		len  int
	}{
		{"cloudflare.dnsRecords", len(cloud.DNSRecords)},
		{"cloudflare.cacheRules", len(cloud.CacheRules)},
		{"cloudflare.snippetRules", len(cloud.SnippetRules)},
		{"cloudflare.workerRoutes", len(cloud.WorkerRoutes)},
		{"cloudflare.kvMaps", len(cloud.KVMaps)},
		{"cloudflare.wafRules", len(cloud.WAFRules)},
		{"cloudflare.rateRules", len(cloud.RateRules)},
		{"cloudflare.capabilityKeys", len(cloud.CapabilityKeys)},
	}
	for _, item := range required {
		if item.len == 0 {
			return invalid(item.path, "must not be empty")
		}
	}
	if err := uniqueValues("cloudflare.dnsRecords", len(cloud.DNSRecords), func(i int) string { return cloud.DNSRecords[i].Name }); err != nil {
		return err
	}
	for i, record := range cloud.DNSRecords {
		path := fmt.Sprintf("cloudflare.dnsRecords[%d]", i)
		if !withinZone(record.Name, cloud.Zone) || !oneOf(record.Type, "A", "AAAA", "CNAME") || strings.TrimSpace(record.Content) == "" || len(record.Content) > 253 || strings.ContainsAny(record.Content, "\r\n\x00") || record.TTL == 0 {
			return invalid(path, "must declare a valid in-zone address record")
		}
	}
	if err := uniqueNames("cloudflare.cacheRules", len(cloud.CacheRules), func(i int) string { return cloud.CacheRules[i].Name }); err != nil {
		return err
	}
	for i, rule := range cloud.CacheRules {
		path := fmt.Sprintf("cloudflare.cacheRules[%d]", i)
		if !withinZone(rule.Hostname, cloud.Zone) || !validPathPrefix(rule.PathPrefix) || rule.EdgeTTLSeconds == 0 || strings.TrimSpace(rule.CacheTagPattern) == "" {
			return invalid(path, "must declare an in-zone route, TTL, and cache tag")
		}
	}
	if err := uniqueNames("cloudflare.snippetRules", len(cloud.SnippetRules), func(i int) string { return cloud.SnippetRules[i].Name }); err != nil {
		return err
	}
	for i, rule := range cloud.SnippetRules {
		path := fmt.Sprintf("cloudflare.snippetRules[%d]", i)
		if !withinZone(rule.Hostname, cloud.Zone) || !validPathPrefix(rule.PathPrefix) || !validSourceFile(rule.SourceFile) || len(rule.SecretNames) == 0 {
			return invalid(path, "must declare an in-zone route, source file, and secrets")
		}
	}
	if err := uniqueNames("cloudflare.workerRoutes", len(cloud.WorkerRoutes), func(i int) string { return cloud.WorkerRoutes[i].Name }); err != nil {
		return err
	}
	for i, route := range cloud.WorkerRoutes {
		path := fmt.Sprintf("cloudflare.workerRoutes[%d]", i)
		if !withinZone(route.Hostname, cloud.Zone) || !validPathPrefix(route.PathPrefix) || !validIdentifier(route.ScriptName) {
			return invalid(path, "must declare an in-zone route and Worker script")
		}
		for _, snippet := range cloud.SnippetRules {
			if route.Hostname == snippet.Hostname && pathsOverlap(route.PathPrefix, snippet.PathPrefix) {
				return invalid(path, "must not put a Worker on a Snippet route")
			}
		}
	}
	for i, snippet := range cloud.SnippetRules {
		covered := false
		for _, cache := range cloud.CacheRules {
			if snippet.Hostname == cache.Hostname && pathsOverlap(snippet.PathPrefix, cache.PathPrefix) && cache.Eligible && cache.Immutable && cache.SmartTiered {
				covered = true
				break
			}
		}
		if !covered {
			return invalid(fmt.Sprintf("cloudflare.snippetRules[%d]", i), "must be covered by an immutable Smart Tiered Cache rule")
		}
	}
	if err := uniqueNames("cloudflare.kvMaps", len(cloud.KVMaps), func(i int) string { return cloud.KVMaps[i].Name }); err != nil {
		return err
	}
	for i, mapping := range cloud.KVMaps {
		path := fmt.Sprintf("cloudflare.kvMaps[%d]", i)
		if !validIdentifier(mapping.Namespace) || len(mapping.Entries) == 0 {
			return invalid(path, "must declare a namespace and entries")
		}
		seen := map[string]struct{}{}
		for j, entry := range mapping.Entries {
			entryPath := fmt.Sprintf("%s.entries[%d]", path, j)
			if strings.TrimSpace(entry.Key) == "" || len(entry.Key) > 512 || strings.ContainsAny(entry.Key, "\r\n\x00") || entry.Value == "" || len(entry.Value) > 16<<10 || strings.ContainsRune(entry.Value, '\x00') {
				return invalid(entryPath, "must be a bounded KV entry")
			}
			if _, exists := seen[entry.Key]; exists {
				return invalid(entryPath+".key", "duplicates another entry")
			}
			seen[entry.Key] = struct{}{}
		}
	}
	if err := uniqueNames("cloudflare.wafRules", len(cloud.WAFRules), func(i int) string { return cloud.WAFRules[i].Name }); err != nil {
		return err
	}
	for i, rule := range cloud.WAFRules {
		if strings.TrimSpace(rule.Expression) == "" || !oneOf(rule.Action, "block", "challenge", "log") {
			return invalid(fmt.Sprintf("cloudflare.wafRules[%d]", i), "must declare an expression and supported action")
		}
	}
	if err := uniqueNames("cloudflare.rateRules", len(cloud.RateRules), func(i int) string { return cloud.RateRules[i].Name }); err != nil {
		return err
	}
	for i, rule := range cloud.RateRules {
		if strings.TrimSpace(rule.Expression) == "" || rule.Requests == 0 || rule.PeriodSeconds == 0 || rule.MitigationTime == 0 {
			return invalid(fmt.Sprintf("cloudflare.rateRules[%d]", i), "must declare an expression and positive limits")
		}
	}
	if err := uniqueNames("cloudflare.capabilityKeys", len(cloud.CapabilityKeys), func(i int) string { return cloud.CapabilityKeys[i].Name }); err != nil {
		return err
	}
	for i, key := range cloud.CapabilityKeys {
		if !validSecretName(key.MemberSecretName) || !validSecretName(key.EdgeSecretName) || key.RotationHours != 24 || key.OverlapHours == 0 || key.OverlapHours > key.RotationHours {
			return invalid(fmt.Sprintf("cloudflare.capabilityKeys[%d]", i), "must declare secret references and a bounded overlap")
		}
	}
	return nil
}

// ResourceRefs returns every declared provider resource in stable order.
func (s Spec) ResourceRefs() ([]ResourceRef, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0)
	for _, region := range s.Regions {
		refs = append(refs,
			ResourceRef{Kind: ResourceCompute, Region: region.Code, Name: "members"},
			ResourceRef{Kind: ResourceNetwork, Region: region.Code, Name: "vcn"},
		)
		for _, subnet := range region.Network.Subnets {
			refs = append(refs, ResourceRef{Kind: ResourceSubnet, Region: region.Code, Name: subnet.Name})
		}
		for _, group := range region.Network.SecurityGroups {
			refs = append(refs, ResourceRef{Kind: ResourceNSG, Region: region.Code, Name: group.Name})
		}
		for _, bucket := range region.Buckets {
			refs = append(refs, ResourceRef{Kind: ResourceBucket, Region: region.Code, Name: bucket.Name})
		}
		for _, key := range region.VaultKeys {
			refs = append(refs, ResourceRef{Kind: ResourceVaultKey, Region: region.Code, Name: key.Name})
		}
		for _, certificate := range region.Certificates {
			refs = append(refs, ResourceRef{Kind: ResourceCertificate, Region: region.Code, Name: certificate.Name})
		}
	}
	appendGlobal := func(kind ResourceKind, names ...string) {
		for _, name := range names {
			refs = append(refs, ResourceRef{Kind: kind, Name: name})
		}
	}
	appendGlobal(ResourceDNS, names(len(s.Cloudflare.DNSRecords), func(i int) string { return s.Cloudflare.DNSRecords[i].Name })...)
	appendGlobal(ResourceCacheRule, names(len(s.Cloudflare.CacheRules), func(i int) string { return s.Cloudflare.CacheRules[i].Name })...)
	appendGlobal(ResourceSnippetRule, names(len(s.Cloudflare.SnippetRules), func(i int) string { return s.Cloudflare.SnippetRules[i].Name })...)
	appendGlobal(ResourceWorkerRoute, names(len(s.Cloudflare.WorkerRoutes), func(i int) string { return s.Cloudflare.WorkerRoutes[i].Name })...)
	appendGlobal(ResourceKVMap, names(len(s.Cloudflare.KVMaps), func(i int) string { return s.Cloudflare.KVMaps[i].Name })...)
	appendGlobal(ResourceWAFRule, names(len(s.Cloudflare.WAFRules), func(i int) string { return s.Cloudflare.WAFRules[i].Name })...)
	appendGlobal(ResourceRateRule, names(len(s.Cloudflare.RateRules), func(i int) string { return s.Cloudflare.RateRules[i].Name })...)
	appendGlobal(ResourceCapabilityKey, names(len(s.Cloudflare.CapabilityKeys), func(i int) string { return s.Cloudflare.CapabilityKeys[i].Name })...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Kind != refs[j].Kind {
			return refs[i].Kind < refs[j].Kind
		}
		if refs[i].Region != refs[j].Region {
			return refs[i].Region < refs[j].Region
		}
		return refs[i].Name < refs[j].Name
	})
	return refs, nil
}

func uniqueNames(path string, count int, name func(int) string) error {
	seen := make(map[string]struct{}, count)
	for i := 0; i < count; i++ {
		value := name(i)
		itemPath := fmt.Sprintf("%s[%d].name", path, i)
		if !validIdentifier(value) {
			return invalid(itemPath, "must be a canonical identifier")
		}
		if _, exists := seen[value]; exists {
			return invalid(itemPath, "duplicates another resource")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func uniqueValues(path string, count int, value func(int) string) error {
	seen := make(map[string]struct{}, count)
	for i := 0; i < count; i++ {
		item := value(i)
		if _, exists := seen[item]; exists {
			return invalid(fmt.Sprintf("%s[%d]", path, i), "duplicates another resource")
		}
		seen[item] = struct{}{}
	}
	return nil
}

func names(count int, name func(int) string) []string {
	values := make([]string, count)
	for i := range count {
		values[i] = name(i)
	}
	return values
}

func invalid(path, message string) error {
	return &ValidationError{Path: path, Message: message}
}

func validIdentifier(value string) bool {
	return len(value) <= 63 && identifierPattern.MatchString(value)
}

func validOCIRegion(value string) bool {
	return len(value) <= 63 && strings.Count(value, "-") >= 2 && identifierPattern.MatchString(value)
}

func validShape(value string) bool {
	return len(value) <= 96 && strings.HasPrefix(value, "VM.Standard.") && !strings.ContainsAny(value, " \t\r\n")
}

func validHostname(value string) bool {
	return len(value) <= 253 && hostnamePattern.MatchString(value)
}

func withinZone(hostname, zone string) bool {
	return validHostname(hostname) && (hostname == zone || strings.HasSuffix(hostname, "."+zone))
}

func validPathPrefix(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\r\n\x00?#")
}

func validSourceFile(value string) bool {
	return value != "" && !strings.HasPrefix(value, "/") && !strings.Contains(value, "..") && !strings.ContainsAny(value, "\r\n\x00")
}

func validSecretName(value string) bool {
	return secretNamePattern.MatchString(value)
}

func pathsOverlap(left, right string) bool {
	left = strings.TrimSuffix(left, "/")
	right = strings.TrimSuffix(right, "/")
	return left == right || strings.HasPrefix(left+"/", right+"/") || strings.HasPrefix(right+"/", left+"/")
}

func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
