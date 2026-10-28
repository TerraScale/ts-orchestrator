package geodns

import (
	"fmt"
	"testing"
)

// testHosts are the declared all-region hostnames.
var testHosts = func() []Host {
	hosts, err := Hosts()
	if err != nil {
		panic(err)
	}
	return hosts
}()

// Only the dashboard serves every region: ts-auth stays in gru and api's
// TerraBase routing is not steered here.
func TestHostsAreTheAllRegionDeclarations(t *testing.T) {
	if got := fmt.Sprint(testHosts); got != "[{dash.terrascale.tech dash.terrascale.tech} {mcp.terrascale.tech dash.terrascale.tech} {platform.terrascale.tech dash.terrascale.tech}]" {
		t.Fatalf("hosts = %s", got)
	}
}

func TestBuildSteersToNearestHealthyRegion(t *testing.T) {
	regions := []Region{
		{Name: "gru", IP: "163.176.124.12", Latitude: -23.43, Longitude: -46.47},
		{Name: "sjc", IP: "163.192.54.17", Latitude: 37.34, Longitude: -121.89},
		{Name: "fra", IP: "130.162.238.198", Latitude: 50.11, Longitude: 8.68},
	}
	plans := Build(regions, testHosts)
	if len(plans) != 3 {
		t.Fatalf("plans = %d, want 3", len(plans))
	}
	p := plans[0]
	if len(p.Policy.Answers) != 3 || len(p.Monitor.Targets) != 3 {
		t.Fatalf("answers %d targets %d, want 3 each", len(p.Policy.Answers), len(p.Monitor.Targets))
	}
	var types []string
	for _, r := range p.Policy.Rules {
		types = append(types, r.RuleType)
	}
	if got := fmt.Sprint(types); got != "[FILTER HEALTH PRIORITY LIMIT]" {
		t.Fatalf("rules = %s", got)
	}
	if p.Monitor.Headers["Host"] != "dash.terrascale.tech" || p.Monitor.Path != "/healthz" || p.Monitor.Protocol != "HTTP" || p.Monitor.Port != 80 {
		t.Fatalf("monitor = %+v", p.Monitor)
	}
	if p.Attachment.DomainName != "dash.edge.terrascale.tech" {
		t.Fatalf("attachment = %s", p.Attachment.DomainName)
	}
	if p.Monitor.FreeformTags["ts-cost"] != "edge-geodns" || p.Policy.FreeformTags["ts-cost"] != "edge-geodns" {
		t.Fatalf("billed objects lack the cost tag: %+v %+v", p.Monitor.FreeformTags, p.Policy.FreeformTags)
	}
	// mcp answers 401 on its own paths: its monitor probes the dashboard's liveness.
	if m := plans[1].Monitor; plans[1].Host != "mcp.terrascale.tech" || m.Headers["Host"] != "dash.terrascale.tech" || m.Path != "/healthz" {
		t.Fatalf("mcp monitor = %+v", m)
	}
	want := map[string]string{"South America": "gru", "North America": "sjc", "Europe": "fra", "Africa": "fra", "India": "fra", "Asia": "sjc", "Oceania": "sjc"}
	for area, region := range want {
		if p.Nearest[area] != region {
			t.Errorf("%s -> %s, want %s", area, p.Nearest[area], region)
		}
	}
	// Every case ranks all regions so a failing nearest region falls to the next.
	for _, c := range p.Policy.Rules[2].Cases {
		if len(c.AnswerData) != 3 {
			t.Fatalf("case %s ranks %d regions", c.CaseCondition, len(c.AnswerData))
		}
	}
}
