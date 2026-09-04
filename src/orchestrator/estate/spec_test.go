package estate

import (
	"reflect"
	"strings"
	"testing"
)

func TestSpecCoversTheDeclaredOCIAndCloudflareEstate(t *testing.T) {
	spec := testSpec()
	refs, err := spec.ResourceRefs()
	if err != nil {
		t.Fatalf("valid estate rejected: %v", err)
	}

	wantKinds := map[ResourceKind]bool{
		ResourceCompute: true, ResourceNetwork: true, ResourceSubnet: true,
		ResourceNSG: true, ResourceBucket: true, ResourceVaultKey: true,
		ResourceCertificate: true, ResourceDNS: true, ResourceCacheRule: true,
		ResourceSnippetRule: true, ResourceWorkerRoute: true, ResourceKVMap: true,
		ResourceWAFRule: true, ResourceRateRule: true, ResourceCapabilityKey: true,
	}
	for _, ref := range refs {
		delete(wantKinds, ref.Kind)
	}
	if len(wantKinds) != 0 {
		t.Fatalf("resource kinds absent from reconciliation inventory: %v", wantKinds)
	}

	second, err := spec.ResourceRefs()
	if err != nil {
		t.Fatalf("second inventory failed: %v", err)
	}
	if !reflect.DeepEqual(refs, second) {
		t.Fatal("resource inventory is not deterministic")
	}
	for i := 1; i < len(refs); i++ {
		left, right := refs[i-1], refs[i]
		if left.Kind > right.Kind || left.Kind == right.Kind && (left.Region > right.Region || left.Region == right.Region && left.Name > right.Name) {
			t.Fatalf("resource inventory is not sorted at %d: %+v then %+v", i, left, right)
		}
	}
}

func TestSpecRejectsUnsafeOrAmbiguousDeclarations(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Spec)
	}{
		{
			name: "unsupported version",
			path: "version",
			edit: func(spec *Spec) { spec.Version = 1 },
		},
		{
			name: "unknown control region",
			path: "controlPlane.regions[2]",
			edit: func(spec *Spec) { spec.ControlPlane.Regions[2] = "iad" },
		},
		{
			name: "single member region",
			path: "regions[0].members.count",
			edit: func(spec *Spec) { spec.Regions[0].Members.Count = 1 },
		},
		{
			name: "public member subnet",
			path: "regions[0].network.subnets[0].public",
			edit: func(spec *Spec) { spec.Regions[0].Network.Subnets[0].Public = true },
		},
		{
			name: "subnet outside VCN",
			path: "regions[0].network.subnets[0].cidr",
			edit: func(spec *Spec) { spec.Regions[0].Network.Subnets[0].CIDR = "10.99.0.0/24" },
		},
		{
			name: "missing colocated control replica",
			path: "regions[0].members.controlReplicas",
			edit: func(spec *Spec) { spec.Regions[0].Members.ControlReplicas = 0 },
		},
		{
			name: "duplicate bucket",
			path: "regions[0].buckets[1].name",
			edit: func(spec *Spec) { spec.Regions[0].Buckets[1].Name = spec.Regions[0].Buckets[0].Name },
		},
		{
			name: "route outside zone",
			path: "cloudflare.workerRoutes[0]",
			edit: func(spec *Spec) { spec.Cloudflare.WorkerRoutes[0].Hostname = "api.example.com" },
		},
		{
			name: "Worker on reactive route",
			path: "cloudflare.workerRoutes[0]",
			edit: func(spec *Spec) {
				spec.Cloudflare.WorkerRoutes[0].Hostname = "sync.api.terrascale.tech"
				spec.Cloudflare.WorkerRoutes[0].PathPrefix = "/views/reader"
			},
		},
		{
			name: "Snippet without immutable cache",
			path: "cloudflare.snippetRules[0]",
			edit: func(spec *Spec) { spec.Cloudflare.CacheRules[0].Immutable = false },
		},
		{
			name: "duplicate KV entry",
			path: "cloudflare.kvMaps[0].entries[1].key",
			edit: func(spec *Spec) { spec.Cloudflare.KVMaps[0].Entries[1].Key = spec.Cloudflare.KVMaps[0].Entries[0].Key },
		},
		{
			name: "capability overlap beyond rotation",
			path: "cloudflare.capabilityKeys[0]",
			edit: func(spec *Spec) { spec.Cloudflare.CapabilityKeys[0].OverlapHours = 25 },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := testSpec()
			test.edit(&spec)
			err := spec.Validate()
			if err == nil || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("validation error = %v, want path %q", err, test.path)
			}
		})
	}
}

func testSpec() Spec {
	regions := []Region{
		testRegion("gru", "sa-saopaulo-1", "10.10.0.0/16"),
		testRegion("sfo", "us-sanjose-1", "10.20.0.0/16"),
		testRegion("fra", "eu-frankfurt-1", "10.30.0.0/16"),
	}
	return Spec{
		Version:    SchemaVersion,
		HomeRegion: "gru",
		ControlPlane: ControlPlane{
			Replicas: 3,
			Regions:  []string{"gru", "sfo", "fra"},
		},
		Regions: regions,
		Cloudflare: Cloudflare{
			Zone: "terrascale.tech",
			DNSRecords: []DNSRecord{{
				Name: "api.terrascale.tech", Type: "CNAME", Content: "proxy.workers.dev", Proxied: true, TTL: 1,
			}},
			CacheRules: []CacheRule{{
				Name: "reactive-immutable", Hostname: "sync.api.terrascale.tech", PathPrefix: "/views/", Eligible: true,
				Immutable: true, EdgeTTLSeconds: 86400, SmartTiered: true, CacheTagPattern: "database:{database}",
			}},
			SnippetRules: []SnippetRule{{
				Name: "reactive-capability-gate", Hostname: "sync.api.terrascale.tech", PathPrefix: "/views/",
				SourceFile: "edge/snippet.js", SecretNames: []string{"capability-current", "capability-previous"},
			}},
			WorkerRoutes: []WorkerRoute{{
				Name: "rest-first-contact", Hostname: "api.terrascale.tech", PathPrefix: "/", ScriptName: "ts-proxy",
			}},
			KVMaps: []KVMap{{
				Name: "routing", Namespace: "routing", Entries: []KVEntry{{Key: "regions/gru", Value: "healthy"}, {Key: "placement/control", Value: "gru,sfo,fra"}},
			}},
			WAFRules: []WAFRule{{
				Name: "block-invalid-host", Expression: `not http.host in {"api.terrascale.tech" "sync.api.terrascale.tech"}`, Action: "block",
			}},
			RateRules: []RateRule{{
				Name: "first-contact", Expression: `http.host eq "api.terrascale.tech"`, Requests: 1000, PeriodSeconds: 60, MitigationTime: 60,
			}},
			CapabilityKeys: []CapabilityKey{{
				Name: "reactive-capability", MemberSecretName: "CAPABILITY_MEMBER", EdgeSecretName: "CAPABILITY_EDGE",
				RotationHours: 24, OverlapHours: 1,
			}},
		},
	}
}

func testRegion(code, ociName, cidr string) Region {
	return Region{
		Code: code, OCIName: ociName,
		Members: MemberPool{
			Count: 2, PrimaryShape: "VM.Standard.A1.Flex", FallbackShape: "VM.Standard.E5.Flex",
			OCPUs: 2, MemoryGiB: 12, BootVolumeGiB: 50, DataVolumeGiB: 200, ControlReplicas: 1,
		},
		Network: Network{
			CIDR:    cidr,
			Subnets: []Subnet{{Name: "members", CIDR: cidr, RegionCode: code}},
			SecurityGroups: []NetworkSecurityGroup{{
				Name: "members", Rules: []NetworkSecurityRule{{Direction: "ingress", Protocol: "tcp", Peer: "0.0.0.0/0", PortMin: 443, PortMax: 443}},
			}},
		},
		Buckets: []Bucket{
			{Name: "backups", Purpose: "database-backup", Versioning: true, LifecycleRules: []BucketLifecycleRule{{Name: "expire-history", Action: "delete", AfterDays: 35}}},
			{Name: "control-snapshots", Purpose: "control-snapshot", Versioning: true, LifecycleRules: []BucketLifecycleRule{{Name: "expire-snapshots", Action: "delete", AfterDays: 35}}},
		},
		VaultKeys: []VaultKey{{Name: "database-kek", Purpose: "database-kek", RotationHours: 24 * 90}},
		Certificates: []Certificate{{
			Name: "member-control", Purpose: "member-control", DNSNames: []string{code + ".api.terrascale.tech"}, RenewBeforeHours: 24 * 30,
		}},
	}
}
