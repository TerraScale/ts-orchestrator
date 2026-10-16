package foundationbinding

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// All observations cross signed OCI SDK HTTP requests. The remote protocol
// fixture serves persisted records separately from the provider resource APIs.
type bindingScenario struct {
	t         *testing.T
	factory   *ociclient.Factory
	authority Authority
	root      ed25519.PrivateKey
	grant     grant
	intent    intent
	record    record
	wire      []byte
	live      map[string]map[string]any
	reads     map[string]int
	etag      string
}

func newBindingScenario(t *testing.T) *bindingScenario {
	t.Helper()
	const region = "us-sanjose-1"
	s := &bindingScenario{t: t, live: map[string]map[string]any{}, reads: map[string]int{}, etag: "record-1"}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.root = private
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	s.authority = Authority{Scope: trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: entityid.New(), Cell: "GRU", Environment: "production", Role: "foundation", Slot: entityid.New()},
		Roots: roots, Policy: trust.Policy{MaxLifetime: 2 * time.Hour}, Generation: 2, InstallationID: entityid.New(), TenancyID: "ocid1.tenancy.oc1..test", Namespace: "namespace", Bucket: "protected", Cell: "SFO"}
	ids := map[string]string{}
	for key, kind := range map[string]string{"control_compartment": "compartment", "network_compartment": "compartment", "workload_compartment": "compartment", "vcn": "vcn", "subnet": "subnet", "network_security_group": "networksecuritygroup", "workload_network_security_group": "networksecuritygroup", "vault": "vault", "key": "key"} {
		idRegion := region
		if kind == "compartment" {
			idRegion = ""
		}
		ids[key] = "ocid1." + kind + ".oc1." + idRegion + "." + strings.ReplaceAll(key, "_", "")
	}
	plan := map[string]any{"cell": "SFO", "region": region, "tenancy_id": s.authority.TenancyID, "parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "network_cidr": "10.42.0.0/16", "subnet_cidr": "10.42.0.0/24", "resource_ids": map[string]any{}}
	material := map[string]any{"sourceVaultTarget": map[string]any{"compartmentOcid": "foundation:SFO:control_compartment", "vaultOcid": "foundation:SFO:vault", "kmsKeyOcid": "foundation:SFO:key"},
		"startup": map[string]any{"profiles": []any{map[string]any{"compartmentOcid": "foundation:SFO:control_compartment", "subnetOcid": "foundation:SFO:subnet", "networkSecurityGroupOcids": []any{"foundation:SFO:network_security_group"}}}}}
	materialWire, err := json.Marshal(material, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	s.intent = intent{Generation: 2, Plan: plan, BootstrapMaterial: materialWire}
	s.grant = grant{SchemaVersion: 2, Generation: 2, InstallationID: s.authority.InstallationID, TenancyID: s.authority.TenancyID,
		ParentCompartmentID: plan["parent_compartment_id"].(string), SharedCompartmentID: plan["shared_compartment_id"].(string), Currency: "USD", MonthlyLimitMinor: 1000, CleanupOwner: "integration"}
	now := time.Now().UTC().Truncate(time.Second)
	s.record = record{SchemaVersion: 1, Cell: "SFO", OCIRegion: region, TenancyID: s.authority.TenancyID, ParentCompartmentID: s.grant.ParentCompartmentID, SharedCompartmentID: s.grant.SharedCompartmentID,
		Generation: 2, OperationID: entityid.Derive("regional-foundation", s.authority.TenancyID, "SFO", "2"), Epoch: 1, Stage: "reconciled", StartedAt: now.Add(-time.Minute), UpdatedAt: now, CompletedAt: now,
		ResourceIDs: ids, ResourceProvenance: map[string]provenance{}}
	s.publish()
	for key, id := range ids {
		s.record.ResourceProvenance[key] = provenance{ResourceID: id, Generation: 2, GrantSHA256: s.authority.GrantSHA256, Create: pendingCreate{OperationID: s.record.OperationID, IntentDigest: s.record.IntentDigest,
			FirstAttemptAt: s.record.StartedAt.Add(time.Second), Request: createRequest{Key: key, Region: region, RequestDigest: strings.Repeat("a", 64), RetryToken: strings.Repeat("b", 64)}}}
	}
	for _, role := range []string{"control_compartment", "network_compartment", "workload_compartment"} {
		s.live["/20160918/compartments/"+ids[role]] = map[string]any{"id": ids[role], "compartmentId": s.record.ParentCompartmentID, "lifecycleState": "ACTIVE"}
	}
	s.live["/20160918/vcns/"+ids["vcn"]] = map[string]any{"id": ids["vcn"], "compartmentId": ids["network_compartment"], "cidrBlock": plan["network_cidr"], "lifecycleState": "AVAILABLE"}
	s.live["/20160918/subnets/"+ids["subnet"]] = map[string]any{"id": ids["subnet"], "compartmentId": ids["network_compartment"], "vcnId": ids["vcn"], "cidrBlock": plan["subnet_cidr"], "prohibitPublicIpOnVnic": true, "lifecycleState": "AVAILABLE"}
	for _, role := range []string{"network_security_group", "workload_network_security_group"} {
		s.live["/20160918/networkSecurityGroups/"+ids[role]] = map[string]any{"id": ids[role], "compartmentId": ids["network_compartment"], "vcnId": ids["vcn"], "lifecycleState": "AVAILABLE"}
	}
	s.live["/20180608/vaults/"+ids["vault"]] = map[string]any{"id": ids["vault"], "compartmentId": ids["control_compartment"], "lifecycleState": "ACTIVE", "vaultType": "DEFAULT", "managementEndpoint": "https://fixture-management.kms." + region + ".oraclecloud.com"}
	s.live["/20180608/keys/"+ids["key"]] = map[string]any{"id": ids["key"], "compartmentId": ids["control_compartment"], "vaultId": ids["vault"], "lifecycleState": "ENABLED", "protectionMode": "HSM", "keyShape": map[string]any{"algorithm": "AES", "length": 32}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodGet || !strings.HasPrefix(request.Header.Get("Authorization"), "Signature ") {
			t.Errorf("unsigned or mutating request: %s %s", request.Method, request.URL)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.reads[request.URL.Path]++
		if request.URL.Path == "/n/namespace/b/protected/o/orchestrator/regions/v1/SFO.json" {
			if !strings.Contains(request.Host, "sa-saopaulo-1") {
				t.Errorf("record read escaped protected home region: %s", request.Host)
			}
			if s.etag != "" {
				w.Header().Set("ETag", s.etag)
			}
			if err := json.MarshalWrite(w, s.record); err != nil {
				t.Error(err)
			}
			return
		}
		if row := s.live[request.URL.Path]; row != nil {
			if !strings.Contains(request.Host, region) {
				t.Errorf("resource read escaped signed region: %s", request.Host)
			}
			if err := json.MarshalWrite(w, row); err != nil {
				t.Error(err)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"code":"NotFound","message":"missing exact resource"}`)
	}))
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	original := http.DefaultTransport
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(s.authority.TenancyID, "ocid1.user.oc1..test", region, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	s.factory, err = ociclient.New(provider, ociclient.Options{Region: region, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *bindingScenario) publish() {
	s.t.Helper()
	intentWire, err := json.Marshal(s.intent, json.Deterministic(true))
	if err != nil {
		s.t.Fatal(err)
	}
	s.grant.Regions = []jsontext.Value{intentWire}
	payload, err := trust.EncodePayload(s.grant)
	if err != nil {
		s.t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := trust.Sign(payload, s.authority.Scope, now.Add(-time.Minute), now.Add(time.Hour), s.root)
	if err != nil {
		s.t.Fatal(err)
	}
	s.wire, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		s.t.Fatal(err)
	}
	s.authority.GrantSHA256 = digest(s.wire)
	s.record.GrantSHA256 = s.authority.GrantSHA256
	var canonical map[string]any
	if err := json.Unmarshal(intentWire, &canonical); err != nil {
		s.t.Fatal(err)
	}
	canonicalWire, err := json.Marshal(canonical, json.Deterministic(true))
	if err != nil {
		s.t.Fatal(err)
	}
	s.record.IntentDigest = digest(canonicalWire)
	for key, proof := range s.record.ResourceProvenance {
		if proof.Generation == s.record.Generation {
			proof.GrantSHA256 = s.record.GrantSHA256
			proof.Create.IntentDigest = s.record.IntentDigest
			s.record.ResourceProvenance[key] = proof
		}
	}
}

func TestLogicalBindingsReadSignedGrantPersistedBirthAndFreshOCI(t *testing.T) {
	s := newBindingScenario(t)
	verified, err := Verify(t.Context(), s.factory, s.authority, s.wire)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Cell() != "SFO" || verified.Generation() != 2 || verified.GrantSHA256() != s.authority.GrantSHA256 {
		t.Fatal("verified binding lost its scope")
	}
	for _, key := range []string{"control_compartment", "subnet", "network_security_group", "vault", "key"} {
		reference, err := Reference("SFO", key)
		if err != nil {
			t.Fatal(err)
		}
		id, err := verified.Resolve(reference)
		if err != nil || id != s.record.ResourceIDs[key] {
			t.Fatalf("resolve %s: %q %v", reference, id, err)
		}
	}
	for _, ref := range []string{"foundation:sfo:key", "foundation:SFO:vcn", "foundation:SFO:unknown", "foundation:GRU:key", "foundation:SFO:key:extra", "foundation:SFO:workload_compartment", s.record.ResourceIDs["key"]} {
		if _, err := verified.Resolve(ref); err == nil {
			t.Fatalf("accepted unsupported/unrequested reference %q", ref)
		}
	}
	if _, err := (VerifiedBindings{}).Resolve("foundation:SFO:key"); err == nil {
		t.Fatal("zero-value bindings resolved a resource")
	}
	before := maps.Clone(s.reads)
	if err := verified.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	for path, count := range before {
		if s.reads[path] != count*2 {
			t.Fatalf("revalidation did not reread %s", path)
		}
	}
	s.live["/20180608/keys/"+s.record.ResourceIDs["key"]]["vaultId"] = "ocid1.vault.oc1.us-sanjose-1.replaced"
	if err := verified.Revalidate(t.Context()); err == nil {
		t.Fatal("revalidation accepted a changed provider key parent")
	}
}

func TestLogicalBindingsRejectUnownedStaleAndWrongRoleState(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*bindingScenario)
	}{
		{"schema one", func(s *bindingScenario) { s.grant.SchemaVersion = 1; s.publish() }},
		{"wrong wire pin", func(s *bindingScenario) { s.authority.GrantSHA256 = strings.Repeat("c", 64) }},
		{"wrong signer", func(s *bindingScenario) { s.authority.Roots = trust.Keyring{} }},
		{"wrong tenancy", func(s *bindingScenario) { s.authority.TenancyID = "ocid1.tenancy.oc1..other" }},
		{"wrong installation", func(s *bindingScenario) { s.authority.InstallationID = entityid.New() }},
		{"wrong generation", func(s *bindingScenario) { s.record.Generation++ }},
		{"wrong intent", func(s *bindingScenario) { s.record.IntentDigest = strings.Repeat("c", 64) }},
		{"wrong record grant", func(s *bindingScenario) { s.record.GrantSHA256 = strings.Repeat("c", 64) }},
		{"wrong operation", func(s *bindingScenario) { s.record.OperationID = entityid.New() }},
		{"unfinished record", func(s *bindingScenario) { s.record.Stage = "foundation" }},
		{"missing ETag", func(s *bindingScenario) { s.etag = "" }},
		{"missing birth", func(s *bindingScenario) { delete(s.record.ResourceProvenance, "key") }},
		{"birth from another operation", func(s *bindingScenario) {
			p := s.record.ResourceProvenance["key"]
			p.Create.OperationID = entityid.New()
			s.record.ResourceProvenance["key"] = p
		}},
		{"birth different resource", func(s *bindingScenario) {
			p := s.record.ResourceProvenance["key"]
			p.ResourceID += "other"
			s.record.ResourceProvenance["key"] = p
		}},
		{"birth different signed intent", func(s *bindingScenario) {
			p := s.record.ResourceProvenance["key"]
			p.Create.IntentDigest = strings.Repeat("c", 64)
			s.record.ResourceProvenance["key"] = p
		}},
		{"birth wrong request role", func(s *bindingScenario) {
			p := s.record.ResourceProvenance["key"]
			p.Create.Request.Key = "vault"
			s.record.ResourceProvenance["key"] = p
		}},
		{"birth invalid digest", func(s *bindingScenario) {
			p := s.record.ResourceProvenance["key"]
			p.Create.Request.RequestDigest = "bad"
			s.record.ResourceProvenance["key"] = p
		}},
		{"birth wrong region", func(s *bindingScenario) {
			p := s.record.ResourceProvenance["key"]
			p.Create.Request.Region = "eu-frankfurt-1"
			s.record.ResourceProvenance["key"] = p
		}},
		{"wrong role kind", func(s *bindingScenario) { s.record.ResourceIDs["subnet"] = s.record.ResourceIDs["key"] }},
		{"wrong signed pin", func(s *bindingScenario) {
			s.intent.Plan["resource_ids"].(map[string]any)["subnet"] = "ocid1.subnet.oc1.us-sanjose-1.other"
			s.publish()
		}},
		{"provider compartment moved", func(s *bindingScenario) {
			s.live["/20160918/compartments/"+s.record.ResourceIDs["control_compartment"]]["compartmentId"] = "ocid1.compartment.oc1..foreign"
		}},
		{"provider subnet wrong VCN", func(s *bindingScenario) {
			s.live["/20160918/subnets/"+s.record.ResourceIDs["subnet"]]["vcnId"] = "ocid1.vcn.oc1.us-sanjose-1.foreign"
		}},
		{"provider subnet CIDR", func(s *bindingScenario) {
			s.live["/20160918/subnets/"+s.record.ResourceIDs["subnet"]]["cidrBlock"] = "10.90.0.0/24"
		}},
		{"provider NSG wrong compartment", func(s *bindingScenario) {
			s.live["/20160918/networkSecurityGroups/"+s.record.ResourceIDs["network_security_group"]]["compartmentId"] = "ocid1.compartment.oc1..foreign"
		}},
		{"provider key missing", func(s *bindingScenario) { delete(s.live, "/20180608/keys/"+s.record.ResourceIDs["key"]) }},
		{"provider vault malicious endpoint", func(s *bindingScenario) {
			s.live["/20180608/vaults/"+s.record.ResourceIDs["vault"]]["managementEndpoint"] = "https://attacker.example"
		}},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			s := newBindingScenario(t)
			scenario.mutate(s)
			if _, err := Verify(t.Context(), s.factory, s.authority, s.wire); err == nil {
				t.Fatal("accepted invalid binding authority or provider state")
			}
		})
	}
}

func TestLogicalBindingsRetainOriginalBirthAndExactDependencies(t *testing.T) {
	s := newBindingScenario(t)
	// A root-pinned control compartment is only a dependency of this key ref.
	s.intent.BootstrapMaterial = jsontext.Value(`{"sourceVaultTarget":{"kmsKeyOcid":"foundation:SFO:key"}}`)
	control := s.record.ResourceIDs["control_compartment"]
	s.intent.Plan["resource_ids"].(map[string]any)["control_compartment"] = control
	s.intent.Plan["resource_ids"].(map[string]any)["vault"] = s.record.ResourceIDs["vault"]
	delete(s.record.ResourceProvenance, "control_compartment")
	delete(s.record.ResourceProvenance, "vault")
	for _, key := range []string{"network_compartment", "workload_compartment", "vcn", "subnet", "network_security_group", "workload_network_security_group"} {
		delete(s.record.ResourceIDs, key)
		delete(s.record.ResourceProvenance, key)
	}
	birth := s.record.ResourceProvenance["key"]
	birth.Generation, birth.GrantSHA256 = 1, strings.Repeat("d", 64)
	birth.Create.OperationID = entityid.Derive("regional-foundation", s.authority.TenancyID, "SFO", fmt.Sprint(birth.Generation))
	birth.Create.IntentDigest = strings.Repeat("e", 64)
	birth.Create.FirstAttemptAt = s.record.StartedAt.Add(-time.Hour)
	s.record.ResourceProvenance["key"] = birth
	s.publish()
	verified, err := Verify(t.Context(), s.factory, s.authority, s.wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.Resolve("foundation:SFO:key"); err != nil {
		t.Fatal(err)
	}
	if _, err := verified.Resolve("foundation:SFO:control_compartment"); err == nil {
		t.Fatal("exact dependency was promoted into a logical binding")
	}
	if len(s.reads) != 4 {
		t.Fatalf("read unrelated resource families: %v", s.reads)
	}
}
