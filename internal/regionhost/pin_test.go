package regionhost

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

func TestRegionsFileKeepsItsFormatAndNoOps(t *testing.T) {
	data, err := os.ReadFile("../../" + regionsFile)
	if err != nil {
		t.Fatal(err)
	}
	regions, err := releasepush.LoadRegions("../../" + regionsFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := formatRegions(regions); string(got) != string(data) {
		t.Fatalf("formatted regions.json differs:\n%s", got)
	}
	if _, changed := withRegion(regions, regions[1], false); changed {
		t.Error("an equal entry is a change")
	}
	moved := releasepush.Region{Region: regions[1].Region, NATS: "tls://192.0.2.1:4222", SPKISHA256: regions[1].SPKISHA256}
	if next, changed := withRegion(regions, moved, false); !changed || next[1] != moved || regions[1] == moved || len(next) != len(regions) {
		t.Error("a moved region was not updated in place")
	}
	added := releasepush.Region{Region: "nrt", NATS: "tls://192.0.2.2:4222", SPKISHA256: strings.Repeat("0", 64)}
	if next, changed := withRegion(regions, added, false); !changed || next[len(next)-1] != added {
		t.Error("a new region was not appended")
	}
	if next, changed := withRegion(regions, releasepush.Region{Region: regions[2].Region}, true); !changed ||
		slices.ContainsFunc(next, func(r releasepush.Region) bool { return r.Region == regions[2].Region }) || len(regions) != 3 {
		t.Error("rm did not drop the region")
	}
	if _, changed := withRegion(regions, releasepush.Region{Region: "nrt"}, true); changed {
		t.Error("dropping an absent region is a change")
	}
}
