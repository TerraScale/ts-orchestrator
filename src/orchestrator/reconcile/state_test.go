package reconcile

import (
	"reflect"
	"sort"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// findResource returns the declared resource with the given identity.
func findResource(t *testing.T, state State, ref estate.ResourceRef) Resource {
	t.Helper()
	for _, resource := range state.Resources {
		if RefKey(resource.Ref) == RefKey(ref) {
			return resource
		}
	}
	t.Fatalf("declared state is missing %s", RefKey(ref))
	return Resource{}
}

// attributeValues collects the multiset values of one attribute name.
func attributeValues(resource Resource, name string) []string {
	var values []string
	for _, attribute := range resource.Attributes {
		if attribute.Name == name {
			values = append(values, attribute.Value)
		}
	}
	sort.Strings(values)
	return values
}

func gruRegion(t *testing.T, spec estate.Spec) estate.Region {
	t.Helper()
	for _, region := range spec.Regions {
		if region.Code == "gru" {
			return region
		}
	}
	t.Fatal("declared estate has no gru Region")
	return estate.Region{}
}

// TestDeclaredRendersTheRegionContract pins the exact attribute names and
// value encodings the OCI provider adapters must observe for regional kinds.
// I-2 reconcilers read this as their observation contract.
func TestDeclaredRendersTheRegionContract(t *testing.T) {
	spec := estate.Default()
	declared, err := Declared(spec)
	if err != nil {
		t.Fatalf("declared rendering failed: %v", err)
	}

	compute := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceCompute, Region: "gru", Name: "members"})
	want := []Attribute{
		{Name: "member.count", Value: "2"},
		{Name: "member.primary-shape", Value: "VM.Standard.A1.Flex"},
		{Name: "member.fallback-shape", Value: "VM.Standard.E5.Flex"},
		{Name: "member.ocpus", Value: "2"},
		{Name: "member.memory-gib", Value: "12"},
		{Name: "member.boot-volume-gib", Value: "50"},
		{Name: "member.data-volume-gib", Value: "200"},
		{Name: "member.control-replicas", Value: "1"},
	}
	if !reflect.DeepEqual(normalizeAttributes(compute.Attributes), normalizeAttributes(want)) {
		t.Fatalf("compute attributes = %v, want %v", compute.Attributes, want)
	}

	network := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceNetwork, Region: "gru", Name: "vcn"})
	if got := attributeValues(network, "network.cidr"); !reflect.DeepEqual(got, []string{"10.10.0.0/16"}) {
		t.Fatalf("network.cidr = %v", got)
	}

	subnet := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceSubnet, Region: "gru", Name: "members"})
	if got := attributeValues(subnet, "subnet.cidr"); !reflect.DeepEqual(got, []string{"10.10.0.0/16"}) {
		t.Fatalf("subnet.cidr = %v", got)
	}

	group := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceNSG, Region: "gru", Name: "members"})
	rules := attributeValues(group, "nsg.rule")
	wantRules := []string{
		"egress|tcp|0.0.0.0/0|443-443",
		"ingress|tcp|0.0.0.0/0|443-443",
		"ingress|tcp|10.10.0.0/16|9090-9091",
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Fatalf("nsg.rule values = %v, want %v", rules, wantRules)
	}

	bucket := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "backups"})
	if got := attributeValues(bucket, "bucket.purpose"); !reflect.DeepEqual(got, []string{"database-backup"}) {
		t.Fatalf("bucket.purpose = %v", got)
	}
	if got := attributeValues(bucket, "bucket.versioning"); !reflect.DeepEqual(got, []string{"true"}) {
		t.Fatalf("bucket.versioning = %v", got)
	}
	// D-29 tiering: the lifecycle encoding is "<name>|<action>|<after-days>".
	wantLifecycle := []string{
		"expire-history|delete|35",
		"segments-archive|archive|7",
		"segments-infrequent-access|infrequent-access|1",
	}
	if got := attributeValues(bucket, "bucket.lifecycle-rule"); !reflect.DeepEqual(got, wantLifecycle) {
		t.Fatalf("bucket.lifecycle-rule = %v, want %v", got, wantLifecycle)
	}

	key := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceVaultKey, Region: "gru", Name: "database-kek"})
	want = []Attribute{
		{Name: "vault-key.purpose", Value: "database-kek"},
		{Name: "vault-key.rotation-hours", Value: "2160"},
	}
	if !reflect.DeepEqual(normalizeAttributes(key.Attributes), normalizeAttributes(want)) {
		t.Fatalf("vault-key attributes = %v, want %v", key.Attributes, want)
	}

	certificate := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceCertificate, Region: "gru", Name: "member-control"})
	want = []Attribute{
		{Name: "certificate.purpose", Value: "member-control"},
		{Name: "certificate.renew-before-hours", Value: "720"},
		{Name: "certificate.dns-name", Value: "gru.api.terrascale.tech"},
	}
	if !reflect.DeepEqual(normalizeAttributes(certificate.Attributes), normalizeAttributes(want)) {
		t.Fatalf("certificate attributes = %v, want %v", certificate.Attributes, want)
	}
}

// TestDeclaredRendersTheCloudflareContract pins the exact attribute names and
// value encodings the Cloudflare provider adapter must observe.
func TestDeclaredRendersTheCloudflareContract(t *testing.T) {
	declared, err := Declared(estate.Default())
	if err != nil {
		t.Fatalf("declared rendering failed: %v", err)
	}

	record := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceDNS, Name: "sync.api.terrascale.tech"})
	want := []Attribute{
		{Name: "dns.type", Value: "CNAME"},
		{Name: "dns.content", Value: "ts-proxy.terrascale.workers.dev"},
		{Name: "dns.proxied", Value: "true"},
		{Name: "dns.ttl", Value: "1"},
	}
	if !reflect.DeepEqual(normalizeAttributes(record.Attributes), normalizeAttributes(want)) {
		t.Fatalf("dns attributes = %v, want %v", record.Attributes, want)
	}

	cache := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceCacheRule, Name: "reactive-immutable"})
	want = []Attribute{
		{Name: "cache.hostname", Value: "sync.api.terrascale.tech"},
		{Name: "cache.path-prefix", Value: "/api/v1/reactive/views/"},
		{Name: "cache.eligible", Value: "true"},
		{Name: "cache.immutable", Value: "true"},
		{Name: "cache.edge-ttl-seconds", Value: "86400"},
		{Name: "cache.smart-tiered", Value: "true"},
		{Name: "cache.tag-pattern", Value: "database:{database}"},
	}
	if !reflect.DeepEqual(normalizeAttributes(cache.Attributes), normalizeAttributes(want)) {
		t.Fatalf("cache attributes = %v, want %v", cache.Attributes, want)
	}

	snippet := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceSnippetRule, Name: "reactive-capability-gate"})
	if got := attributeValues(snippet, "snippet.secret"); !reflect.DeepEqual(got, []string{"capability-current", "capability-previous"}) {
		t.Fatalf("snippet.secret = %v", got)
	}
	if got := attributeValues(snippet, "snippet.source-file"); !reflect.DeepEqual(got, []string{"edge/snippet.js"}) {
		t.Fatalf("snippet.source-file = %v", got)
	}

	route := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceWorkerRoute, Name: "rest-first-contact"})
	want = []Attribute{
		{Name: "route.hostname", Value: "api.terrascale.tech"},
		{Name: "route.path-prefix", Value: "/"},
		{Name: "route.script", Value: "ts-proxy"},
	}
	if !reflect.DeepEqual(normalizeAttributes(route.Attributes), normalizeAttributes(want)) {
		t.Fatalf("route attributes = %v, want %v", route.Attributes, want)
	}

	mapping := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceKVMap, Name: "routing"})
	if got := attributeValues(mapping, "kv.namespace"); !reflect.DeepEqual(got, []string{"routing"}) {
		t.Fatalf("kv.namespace = %v", got)
	}
	wantEntries := []string{
		"placement/control=gru,sfo,fra",
		"regions/fra=healthy",
		"regions/gru=healthy",
		"regions/sfo=healthy",
	}
	if got := attributeValues(mapping, "kv.entry"); !reflect.DeepEqual(got, wantEntries) {
		t.Fatalf("kv.entry = %v, want %v", got, wantEntries)
	}

	waf := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceWAFRule, Name: "block-invalid-host"})
	if got := attributeValues(waf, "waf.action"); !reflect.DeepEqual(got, []string{"block"}) {
		t.Fatalf("waf.action = %v", got)
	}
	if len(attributeValues(waf, "waf.expression")) != 1 {
		t.Fatalf("waf.expression = %v", waf.Attributes)
	}

	rate := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceRateRule, Name: "first-contact"})
	want = []Attribute{
		{Name: "rate.expression", Value: `http.host eq "api.terrascale.tech"`},
		{Name: "rate.requests", Value: "1000"},
		{Name: "rate.period-seconds", Value: "60"},
		{Name: "rate.mitigation-seconds", Value: "60"},
	}
	if !reflect.DeepEqual(normalizeAttributes(rate.Attributes), normalizeAttributes(want)) {
		t.Fatalf("rate attributes = %v, want %v", rate.Attributes, want)
	}

	capability := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceCapabilityKey, Name: "reactive-capability"})
	want = []Attribute{
		{Name: "capability.member-secret", Value: "CAPABILITY_MEMBER"},
		{Name: "capability.edge-secret", Value: "CAPABILITY_EDGE"},
		{Name: "capability.rotation-hours", Value: "24"},
		{Name: "capability.overlap-hours", Value: "1"},
	}
	if !reflect.DeepEqual(normalizeAttributes(capability.Attributes), normalizeAttributes(want)) {
		t.Fatalf("capability attributes = %v, want %v", capability.Attributes, want)
	}
}

// TestDeclaredEncodesRetentionPolicyBranches covers value encodings the
// default estate does not exercise: the lifecycle keep-N suffix and repeated
// certificate DNS names.
func TestDeclaredEncodesRetentionPolicyBranches(t *testing.T) {
	spec := estate.Default()
	region := gruRegion(t, spec)
	for i := range spec.Regions {
		if spec.Regions[i].Code != region.Code {
			continue
		}
		spec.Regions[i].Buckets[0].LifecycleRules[0].KeepLatest = 3
		spec.Regions[i].Certificates[0].DNSNames = append(
			spec.Regions[i].Certificates[0].DNSNames, "wild."+region.Code+".api.terrascale.tech",
		)
	}
	declared, err := Declared(spec)
	if err != nil {
		t.Fatalf("declared rendering failed: %v", err)
	}
	bucket := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceBucket, Region: region.Code, Name: "backups"})
	if got := attributeValues(bucket, "bucket.lifecycle-rule"); !reflect.DeepEqual(got, []string{
		"expire-history|delete|35",
		"segments-archive|archive|7",
		"segments-infrequent-access|infrequent-access|1|keep-3",
	}) {
		t.Fatalf("keep-N lifecycle encoding = %v", got)
	}
	certificate := findResource(t, declared, estate.ResourceRef{Kind: estate.ResourceCertificate, Region: region.Code, Name: "member-control"})
	wantNames := []string{"gru.api.terrascale.tech", "wild.gru.api.terrascale.tech"}
	if got := attributeValues(certificate, "certificate.dns-name"); !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("certificate.dns-name = %v, want %v", got, wantNames)
	}
}

// TestDeclaredCoversEveryDeclaredRef keeps the rendered state and the
// estate's own resource inventory in lockstep.
func TestDeclaredCoversEveryDeclaredRef(t *testing.T) {
	spec := estate.Default()
	declared, err := Declared(spec)
	if err != nil {
		t.Fatalf("declared rendering failed: %v", err)
	}
	refs, err := spec.ResourceRefs()
	if err != nil {
		t.Fatalf("resource inventory failed: %v", err)
	}
	if len(declared.Resources) != len(refs) {
		t.Fatalf("declared %d resources, estate declares %d", len(declared.Resources), len(refs))
	}
	declaredKeys := map[string]int{}
	for _, resource := range declared.Resources {
		declaredKeys[RefKey(resource.Ref)]++
	}
	for _, ref := range refs {
		if declaredKeys[RefKey(ref)] != 1 {
			t.Fatalf("resource %s rendered %d times, want exactly once", RefKey(ref), declaredKeys[RefKey(ref)])
		}
	}
}

func TestDeclaredRejectsInvalidSpecs(t *testing.T) {
	spec := estate.Default()
	spec.Version = 1
	if _, err := Declared(spec); err == nil {
		t.Fatal("an invalid declared estate must not render")
	}
}

func TestStateByRefCollapsesDuplicatesAndRejectsConflicts(t *testing.T) {
	ref := estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "backups"}
	resource := Resource{Ref: ref, Attributes: []Attribute{{Name: "bucket.purpose", Value: "database-backup"}}}
	// Duplicate identical listings collapse: the reconciler keeps converging.
	indexed, err := State{Resources: []Resource{resource, resource}}.ByRef()
	if err != nil {
		t.Fatalf("collapsing duplicate observations failed: %v", err)
	}
	if len(indexed) != 1 {
		t.Fatalf("index has %d entries, want the duplicate collapsed", len(indexed))
	}
	// Conflicting observations of one identity are refused.
	conflicting := resource
	conflicting.Attributes = []Attribute{{Name: "bucket.purpose", Value: "unknown"}}
	if _, err := (State{Resources: []Resource{resource, conflicting}}).ByRef(); err == nil {
		t.Fatal("conflicting identities must fail observation indexing")
	}
}

func TestNormalizeAttributesSortsByNameThenValue(t *testing.T) {
	attributes := []Attribute{
		{Name: "nsg.rule", Value: "egress|tcp|0.0.0.0/0|443-443"},
		{Name: "nsg.rule", Value: "ingress|tcp|0.0.0.0/0|443-443"},
		{Name: "member.count", Value: "2"},
	}
	normalized := normalizeAttributes(attributes)
	want := []Attribute{
		{Name: "member.count", Value: "2"},
		{Name: "nsg.rule", Value: "egress|tcp|0.0.0.0/0|443-443"},
		{Name: "nsg.rule", Value: "ingress|tcp|0.0.0.0/0|443-443"},
	}
	if !reflect.DeepEqual(normalized, want) {
		t.Fatalf("normalized = %v, want %v", normalized, want)
	}
	// Normalization must not alias the input slice.
	if reflect.ValueOf(attributes).Pointer() == reflect.ValueOf(normalized).Pointer() {
		t.Fatal("normalizeAttributes must copy its input")
	}
}
