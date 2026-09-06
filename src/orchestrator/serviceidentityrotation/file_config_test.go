package serviceidentityrotation

import (
	"context"
	"testing"
)

func TestIdentityConfigReferencesAndBoundedOverlap(t *testing.T) {
	c := FileConfig{Region: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1..fixture", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.fixture", KeyID: "ocid1.key.oc1.sa-saopaulo-1.fixture", CloudflareAccountID: "0123456789abcdef0123456789abcdef", CloudflareTokenFile: "/etc/terrascale/orchestrator/cloudflare-token", DashboardScript: "dashboard", CertificateFile: "/etc/terrascale/orchestrator/tls-cert", PrivateKeyFile: "/etc/terrascale/orchestrator/tls-key", TrustBundleFile: "/etc/terrascale/orchestrator/trust", Members: []RemoteMemberEndpoint{{NodeID: "node-gru-1", URL: "https://10.0.0.1:9443"}}, PeriodSeconds: 86400, OverlapSeconds: 300}
	if c.Validate() != nil {
		t.Fatal("valid references rejected")
	}
	for _, mutate := range []func(*FileConfig){func(c *FileConfig) { c.OverlapSeconds = 301 }, func(c *FileConfig) { c.OverlapSeconds = 0 }, func(c *FileConfig) { c.PeriodSeconds = 0 }, func(c *FileConfig) { c.CloudflareTokenFile = "relative" }, func(c *FileConfig) { c.Members = append(c.Members, c.Members[0]) }, func(c *FileConfig) { c.Members = []RemoteMemberEndpoint{{NodeID: "node", URL: "http://10.0.0.1"}} }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe identity configuration accepted")
		}
	}
}

func TestFileConfigCompositionPassesBootstrapMembersToCoordinator(t *testing.T) {
	c := FileConfig{Members: []RemoteMemberEndpoint{{NodeID: "node-gru-1", URL: "https://10.0.0.1:9443"}}, DashboardScript: "dashboard", PeriodSeconds: 3600, OverlapSeconds: 60}
	if _, err := New(c.coordinatorConfig(&memoryStore{}, fakeIssuer{}, &effects{}, &effects{}, func(context.Context) error { return nil })); err != nil {
		t.Fatal("file configuration did not compose a valid coordinator", err)
	}
}
