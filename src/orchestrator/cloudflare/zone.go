package cloudflare

import (
	"fmt"
	"sort"
)

// The declared production zone. GOAL D-67: the whole estate is typed Go
// configuration in this repository and the orchestrator drives Cloudflare to
// match it; nothing is clicked in a console after O-4.
//
// Hostnames per D-24 (exactly these, no more):
//
//	api.terrascale.tech       ts-proxy REST first-contact Worker (D-58)
//	sync.api.terrascale.tech  CDN-backed reactive HTTP: Snippet + Cache Rules,
//	                          never a Worker (D-55)
//	gru|sfo|fra.api.          pinned REST/view-attach/WebSocket to members
//	gru|sfo|fra.sync.api.     region-pinned reactive cache targets
//	app.                      dashboard Worker (D-59)
//	docs., status.            docs site and status page
//
// Member addresses come from the observed estate (D-65: two member hosts per
// region); DNS follows whatever the estate currently is, so a replaced host
// repairs the records on the next pass.

const (
	ZoneName = "terrascale.tech"

	ProxyWorkerScript     = "ts-proxy"         // REST first-contact Worker (D-58)
	DashboardWorkerScript = "ts-dashboard"     // dashboard Worker (D-59)
	GateSnippetName       = "ts-gate"          // sync.api capability-gate Snippet (D-55); code ships from ts-proxy
	RegionHealthNamespace = "ts-region-health" // KV maps the ts-proxy Worker reads (D-58)
	DBPlacementNamespace  = "ts-db-placement"  // KV maps the ts-proxy Worker reads (D-58)

	// reactivePathPrefix covers the D-14 reactive surface: view attach,
	// snapshot chunks, and the delta log.
	reactivePathPrefix = "/api/v1/reactive/"

	// workerOrigin is a never-contacted placeholder origin for hostnames
	// served entirely by Worker routes or Workers Assets: the route
	// intercepts every request before the origin is used.
	workerOrigin = "192.0.2.1"
)

// Members maps a region code (D-05: gru, sfo, fra at launch) to the public
// addresses of its member hosts. Regions with no members yet (add-region in
// flight) simply contribute no records; sync.api carries the union and its
// region-pinned aliases carry only that Region's members.
type Members map[string][]string

// Zone is the whole Cloudflare zone as declared state: one reconcile pass
// drives every field below to match exactly, and alerts on what it cannot
// repair.
type Zone struct {
	ZoneName         string
	DNSRecords       []DNSRecord
	CacheRules       []CacheRule
	SmartTieredCache bool
	SnippetRules     []SnippetRule
	WorkerRoutes     []WorkerRoute
	KVNamespaces     []KVNamespaceDecl
	SecretStores     []SecretStoreDecl
	FirewallRules    []FirewallRule
	RateRules        []RateRule
	SSL              SSLSettings
	TotalTLS         bool
}

// Production is the declared terrascale.tech zone. tailscaleEgressIPs are the
// CIDRs staff traffic arrives from (D-79); Production refuses to build a zone
// whose /admin rule would block everyone.
func Production(members Members, tailscaleEgressIPs []string) (*Zone, error) {
	if len(tailscaleEgressIPs) == 0 {
		return nil, fmt.Errorf("cloudflare: declared zone needs the Tailscale egress CIDRs for the /admin rule (D-79)")
	}
	for region, addrs := range members {
		if len(addrs) == 0 {
			return nil, fmt.Errorf("cloudflare: region %s declares no member addresses", region)
		}
	}
	z := &Zone{
		ZoneName:         ZoneName,
		SmartTieredCache: true,
		TotalTLS:         true, // see SSLSettings: covers the two-label hostnames
		SSL:              SSLSettings{Mode: "strict", MinTLSVersion: "1.2", TLS13: true, AlwaysUseHTTPS: true},
	}

	// DNS (D-24). api/app/docs/status are Worker-served placeholders; member
	// addresses provide the regional and sync ingress records below.
	z.DNSRecords = []DNSRecord{
		{Type: "A", Name: "api." + ZoneName, Content: workerOrigin, TTL: 1, Proxied: true},
		{Type: "A", Name: "app." + ZoneName, Content: workerOrigin, TTL: 1, Proxied: true},
		{Type: "A", Name: "docs." + ZoneName, Content: workerOrigin, TTL: 1, Proxied: true},
		{Type: "A", Name: "status." + ZoneName, Content: workerOrigin, TTL: 1, Proxied: true},
	}
	var allMembers []string
	for _, addrs := range members {
		allMembers = append(allMembers, addrs...)
	}
	sort.Strings(allMembers)
	for _, addr := range allMembers {
		z.DNSRecords = append(z.DNSRecords, DNSRecord{Type: "A", Name: "sync.api." + ZoneName, Content: addr, TTL: 1, Proxied: true})
	}
	for _, region := range sortedRegions(members) {
		for _, addr := range members[region] {
			z.DNSRecords = append(z.DNSRecords, DNSRecord{Type: "A", Name: region + ".api." + ZoneName, Content: addr, TTL: 1, Proxied: true})
			z.DNSRecords = append(z.DNSRecords, DNSRecord{Type: "A", Name: region + ".sync.api." + ZoneName, Content: addr, TTL: 1, Proxied: true})
		}
	}

	// Cache Rules (D-55): exactly the snapshot-chunk and log leaves of the
	// reactive surface are cache-eligible; attach POSTs and unknown paths
	// stay ineligible. Edge TTL respects the origin because D-14 responses
	// carry their own verdicts — immutable retention TTLs on data-bearing
	// responses, no-store on long-poll timeouts.
	z.CacheRules = []CacheRule{{
		Ref: "sync-reactive", Hostname: "sync.api." + ZoneName,
		PathPrefix: reactiveViewsPath, PathSuffix: reactiveLogLeaf, PathSegment: reactiveSnapshotPart,
		Eligible: true, EdgeTTLMode: "respect_origin",
	}}
	for _, region := range sortedRegions(members) {
		z.CacheRules = append(z.CacheRules, CacheRule{
			Ref: "sync-reactive-" + region, Hostname: region + ".sync.api." + ZoneName,
			PathPrefix: reactiveViewsPath, PathSuffix: reactiveLogLeaf, PathSegment: reactiveSnapshotPart,
			Eligible: true, EdgeTTLMode: "respect_origin",
		})
	}

	// Public signed tenant leases are cacheable only on their signed Region's
	// OCI ingress. Native errors use no-store; never override that verdict.
	for _, region := range sortedRegions(members) {
		z.CacheRules = append(z.CacheRules, CacheRule{
			Ref: "authorization-leases-" + region, Hostname: region + ".sync.api." + ZoneName,
			PathPrefix: "/api/v1/authorization/leases/", Eligible: true, EdgeTTLMode: "respect_origin",
		})
	}

	// Snippet rules (D-55): the capability gate runs on the reactive paths.
	// The snippet code is deployed with ts-proxy releases (X-2); only the
	// rule is ours.
	z.SnippetRules = []SnippetRule{{
		SnippetName: GateSnippetName,
		Hostnames:   []string{"sync.api." + ZoneName, "gru.sync.api." + ZoneName, "sfo.sync.api." + ZoneName, "fra.sync.api." + ZoneName},
		PathPrefix:  reactivePathPrefix, Enabled: true,
	}}

	// Worker routes (D-58/D-59).
	z.WorkerRoutes = []WorkerRoute{
		{Pattern: "api." + ZoneName + "/*", Script: ProxyWorkerScript},
		{Pattern: "app." + ZoneName + "/*", Script: DashboardWorkerScript},
	}

	// KV maps the ts-proxy Worker reads (D-58); the writer loop is item I-4.
	z.KVNamespaces = []KVNamespaceDecl{
		{Title: RegionHealthNamespace},
		{Title: DBPlacementNamespace},
	}

	// WAF: /admin only from Tailscale egress (D-79).
	z.FirewallRules = []FirewallRule{{
		Ref: "admin-tailscale-only", Hostname: "app." + ZoneName, PathPrefix: "/admin",
		AllowCIDRs: tailscaleEgressIPs, Action: "block",
	}}

	// Rate rules: a coarse per-IP backstop on the REST first-contact host.
	// sync.api deliberately has none — long-poll cadence, catch-up, and
	// replay are free by design (D-14/D-16/D-40) and the CDN absorbs them.
	z.RateRules = []RateRule{{
		Ref: "api-per-ip", Hostname: "api." + ZoneName,
		RequestsPerPeriod: 1200, PeriodSeconds: 60, MitigationSeconds: 600,
	}}
	return z, nil
}

func sortedRegions(members Members) []string {
	regions := make([]string, 0, len(members))
	for region := range members {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	return regions
}
