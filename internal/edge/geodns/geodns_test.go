package geodns

import (
	"fmt"
	"testing"
)

func TestBuildSteersToNearestHealthyRegion(t *testing.T) {
	regions := []Region{
		{Name: "gru", IP: "163.176.124.12", Latitude: -23.43, Longitude: -46.47},
		{Name: "sjc", IP: "163.192.54.17", Latitude: 37.34, Longitude: -121.89},
		{Name: "fra", IP: "130.162.238.198", Latitude: 50.11, Longitude: 8.68},
	}
	plans := Build(regions, Hosts)
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
	if p.Monitor.Headers["Host"] != "api.terrascale.tech" || p.Monitor.Path != "/readyz" || p.Monitor.Protocol != "HTTPS" {
		t.Fatalf("monitor = %+v", p.Monitor)
	}
	if p.Attachment.DomainName != "api.edge.terrascale.tech" {
		t.Fatalf("attachment = %s", p.Attachment.DomainName)
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
