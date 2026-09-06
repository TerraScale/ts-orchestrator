package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
)

func rotationPrincipalFixture() productionRotationFile {
	return productionRotationFile{
		Regions:   []string{"gru", "fra"},
		Issuer:    keyrotation.OCIIdentityIssuerFileConfig{Principals: []keyrotation.OCIIdentityPrincipal{{ID: "m-gru"}, {ID: "m-fra"}, {ID: "c-gru", Control: true}, {ID: "c-fra", Control: true}}},
		Members:   keyrotation.MemberGatewayFileConfig{Members: []keyrotation.MemberEndpoint{{ID: "m-gru", Region: "gru"}, {ID: "m-fra", Region: "fra"}}},
		Reloaders: keyrotation.MemberGatewayFileConfig{Members: []keyrotation.MemberEndpoint{{ID: "c-gru", Region: "gru"}, {ID: "c-fra", Region: "fra"}}},
	}
}
func TestProductionRotationPrincipalCoverage(t *testing.T) {
	if err := rotationPrincipalFixture().admitPrincipals(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*productionRotationFile){
		"unconsumed identity": func(f *productionRotationFile) {
			f.Issuer.Principals = append(f.Issuer.Principals, keyrotation.OCIIdentityPrincipal{ID: "orphan"})
		},
		"wrong consumer class":     func(f *productionRotationFile) { f.Issuer.Principals[0].Control = true },
		"undeclared region":        func(f *productionRotationFile) { f.Members.Members[0].Region = "sfo" },
		"missing regional control": func(f *productionRotationFile) { f.Reloaders.Members = f.Reloaders.Members[:1] },
		"duplicate consumer":       func(f *productionRotationFile) { f.Members.Members[1].ID = "m-gru" },
		"duplicate region":         func(f *productionRotationFile) { f.Regions = append(f.Regions, "gru") },
	} {
		t.Run(name, func(t *testing.T) {
			f := rotationPrincipalFixture()
			mutate(&f)
			if f.admitPrincipals() == nil {
				t.Fatal("accepted mismatched deployment")
			}
		})
	}
}
func TestProductionRotationEdgeAdmission(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	source := filepath.Join(dir, "snippet.js")
	if err := os.WriteFile(token, []byte("private-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("const ring = "+cloudflare.CapabilityDeploymentMarker+";"), 0600); err != nil {
		t.Fatal(err)
	}
	zone, err := cloudflare.Production(nil, []string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	fixture := func() productionRotationEdgeFile {
		return productionRotationEdgeFile{AccountID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ZoneID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TokenFile: token, TemplateFile: source, TemplateService: "ts-proxy", SnippetName: cloudflare.GateSnippetName, Zone: *zone, ProbeURLs: []string{"https://sync.api.terrascale.tech/.well-known/terrascale-capability-generation"}, JournalBucket: "ROTATION_CAPABILITY", JournalKey: "active"}
	}
	if err := fixture().admit(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*productionRotationEdgeFile){
		"wrong service":    func(f *productionRotationEdgeFile) { f.TemplateService = "ts-dashboard" },
		"journal wildcard": func(f *productionRotationEdgeFile) { f.JournalKey = "active.>" },
		"missing account":  func(f *productionRotationEdgeFile) { f.AccountID = "" },
		"wrong probe":      func(f *productionRotationEdgeFile) { f.ProbeURLs = []string{"https://sync.api.terrascale.tech/health"} },
		"worker on reactive host": func(f *productionRotationEdgeFile) {
			f.Zone.WorkerRoutes = append(f.Zone.WorkerRoutes, cloudflare.WorkerRoute{Pattern: "sync.api.terrascale.tech/*", Script: "bad"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := fixture()
			mutate(&f)
			if f.admit() == nil {
				t.Fatal("accepted invalid edge declaration")
			}
		})
	}
	if err := os.Chmod(token, 0644); err != nil {
		t.Fatal(err)
	}
	if fixture().admit() == nil {
		t.Fatal("accepted public credential file")
	}
}

type rotationRecordingTransport struct{ calls int }

func (r *rotationRecordingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}
func TestProductionRotationTransportRechecksEveryDispatch(t *testing.T) {
	next := &rotationRecordingTransport{}
	fenced := false
	denied := errors.New("lease changed")
	transport := rotationAuthorityTransport{transport: next, check: func(context.Context) error {
		if fenced {
			return denied
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.cloudflare.com/client/v4/zones", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	fenced = true
	if _, err := transport.RoundTrip(request); !errors.Is(err, denied) {
		t.Fatalf("retry after lease changed: %v", err)
	}
	if next.calls != 1 {
		t.Fatalf("dispatched %d provider requests", next.calls)
	}
}
