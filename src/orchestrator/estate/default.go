package estate

// Default is the declared launch estate (D-65 under D-06/D-67): three
// Regions, two member hosts each, one co-hosted control replica per Region
// forming the single R3 group, and the Cloudflare zone rules the proxy and
// reactive edge need. The estate is code: adding a Region (I-5) is one entry
// here plus a release, never a console action.
func Default() Spec {
	return Spec{
		Version:    SchemaVersion,
		HomeRegion: "gru",
		ControlPlane: ControlPlane{
			Replicas: 3,
			Regions:  []string{"gru", "sfo", "fra"},
		},
		Regions: []Region{
			defaultRegion("gru", "sa-saopaulo-1", "10.10.0.0/16"),
			defaultRegion("sfo", "us-sanjose-1", "10.20.0.0/16"),
			defaultRegion("fra", "eu-frankfurt-1", "10.30.0.0/16"),
		},
		Cloudflare: Cloudflare{
			Zone: "terrascale.tech",
			DNSRecords: []DNSRecord{
				{Name: "api.terrascale.tech", Type: "CNAME", Content: "ts-proxy.terrascale.workers.dev", Proxied: true, TTL: 1},
				{Name: "sync.api.terrascale.tech", Type: "CNAME", Content: "ts-proxy.terrascale.workers.dev", Proxied: true, TTL: 1},
				{Name: "gru.api.terrascale.tech", Type: "CNAME", Content: "ts-proxy.terrascale.workers.dev", Proxied: true, TTL: 1},
				{Name: "sfo.api.terrascale.tech", Type: "CNAME", Content: "ts-proxy.terrascale.workers.dev", Proxied: true, TTL: 1},
				{Name: "fra.api.terrascale.tech", Type: "CNAME", Content: "ts-proxy.terrascale.workers.dev", Proxied: true, TTL: 1},
			},
			CacheRules: []CacheRule{{
				Name: "reactive-immutable", Hostname: "sync.api.terrascale.tech", PathPrefix: "/api/v1/reactive/views/",
				Eligible: true, Immutable: true, EdgeTTLSeconds: 86400, SmartTiered: true,
				CacheTagPattern: "database:{database}",
			}},
			SnippetRules: []SnippetRule{{
				Name: "reactive-capability-gate", Hostname: "sync.api.terrascale.tech", PathPrefix: "/api/v1/reactive/views/",
				SourceFile: "edge/snippet.js", SecretNames: []string{"capability-current", "capability-previous"},
			}},
			WorkerRoutes: []WorkerRoute{{
				Name: "rest-first-contact", Hostname: "api.terrascale.tech", PathPrefix: "/", ScriptName: "ts-proxy",
			}},
			KVMaps: []KVMap{{
				Name: "routing", Namespace: "routing",
				Entries: []KVEntry{
					{Key: "regions/gru", Value: "healthy"},
					{Key: "regions/sfo", Value: "healthy"},
					{Key: "regions/fra", Value: "healthy"},
					{Key: "placement/control", Value: "gru,sfo,fra"},
				},
			}},
			WAFRules: []WAFRule{{
				Name: "block-invalid-host", Action: "block",
				Expression: `not http.host in {"api.terrascale.tech" "sync.api.terrascale.tech" "gru.api.terrascale.tech" "sfo.api.terrascale.tech" "fra.api.terrascale.tech"}`,
			}},
			RateRules: []RateRule{{
				Name: "first-contact", Expression: `http.host eq "api.terrascale.tech"`,
				Requests: 1000, PeriodSeconds: 60, MitigationTime: 60,
			}},
			CapabilityKeys: []CapabilityKey{{
				Name: "reactive-capability", MemberSecretName: "CAPABILITY_MEMBER", EdgeSecretName: "CAPABILITY_EDGE",
				RotationHours: 24, OverlapHours: 1,
			}},
		},
	}
}

func defaultRegion(code, ociName, cidr string) Region {
	return Region{
		Code:    code,
		OCIName: ociName,
		Members: MemberPool{
			Count:           2,
			PrimaryShape:    "VM.Standard.A1.Flex",
			FallbackShape:   "VM.Standard.E5.Flex",
			OCPUs:           2,
			MemoryGiB:       12,
			BootVolumeGiB:   50,
			DataVolumeGiB:   200,
			ControlReplicas: 1,
		},
		Network: Network{
			CIDR:    cidr,
			Subnets: []Subnet{{Name: "members", CIDR: cidr, RegionCode: code}},
			// Member subnets are private: replication, OCI APIs, and
			// artifact fetches ride one default route through the Region NAT
			// gateway (D-66) and nothing else is exposed.
			RouteTables: []RouteTable{{
				Name: "members", Subnet: "members",
				Routes: []RouteRule{{Destination: "0.0.0.0/0", ViaNAT: true}},
			}},
			SecurityGroups: []NetworkSecurityGroup{{
				Name: "members",
				Rules: []NetworkSecurityRule{
					{Direction: "ingress", Protocol: "tcp", Peer: "0.0.0.0/0", PortMin: 443, PortMax: 443},
					{Direction: "ingress", Protocol: "tcp", Peer: cidr, PortMin: 9090, PortMax: 9091},
					{Direction: "egress", Protocol: "tcp", Peer: "0.0.0.0/0", PortMin: 443, PortMax: 443},
				},
			}},
		},
		Buckets: []Bucket{
			{
				// Native backup segment tiering per D-29: segments older than 24 h
				// move to Infrequent Access, older than 7 days to Archive, and
				// history expires after 35 days.
				Name: "backups", Purpose: "database-backup", Versioning: true,
				LifecycleRules: []BucketLifecycleRule{
					{Name: "segments-infrequent-access", Action: "infrequent-access", AfterDays: 1},
					{Name: "segments-archive", Action: "archive", AfterDays: 7},
					{Name: "expire-history", Action: "delete", AfterDays: 35},
				},
			},
			{
				Name: "control-snapshots", Purpose: "control-snapshot", Versioning: true,
				LifecycleRules: []BucketLifecycleRule{{Name: "expire-snapshots", Action: "delete", AfterDays: 35}},
			},
			{
				// D-71: the delivery API mirrors every accepted release
				// artifact into each Region before rollout starts, so a
				// Forgejo outage can block a new deploy but never strand one
				// mid-way. Rollback targets are always recent releases.
				Name: "releases", Purpose: "release-artifact", Versioning: true,
				LifecycleRules: []BucketLifecycleRule{{Name: "expire-releases", Action: "delete", AfterDays: 90}},
			},
		},
		VaultKeys: []VaultKey{{Name: "database-kek", Purpose: "database-kek", RotationHours: 24 * 90}},
		Certificates: []Certificate{{
			Name: "member-control", Purpose: "member-control",
			DNSNames:         []string{code + ".api.terrascale.tech"},
			RenewBeforeHours: 24 * 30,
		}},
	}
}
