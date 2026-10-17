package region

import (
	"encoding/json/v2"
	"testing"
)

func TestControlLineagePurposeRequiresExactSignedPurpose(t *testing.T) {
	for _, purpose := range []string{"", "foundation", "regional-control-lineage ", "REGIONAL-CONTROL-LINEAGE"} {
		if err := (FoundationIntent{ControlLineagePurpose: purpose}).validateControlLineagePurpose(); err == nil {
			t.Fatalf("purpose %q gained regional control lineage scope", purpose)
		}
	}
	intent := FoundationIntent{ControlLineagePurpose: RegionalControlLineagePurpose, Generation: 1, Plan: map[string]any{"cell": "GRU"}}
	if err := intent.validateControlLineagePurpose(); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(FoundationGrant{Regions: []FoundationIntent{intent}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded FoundationGrant
	if err := json.Unmarshal(wire, &decoded, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Regions) != 1 || decoded.Regions[0].ControlLineagePurpose != RegionalControlLineagePurpose {
		t.Fatal("signed grant lost its regional control lineage purpose")
	}
	original, err := FoundationIntentDigest(decoded.Regions[0])
	if err != nil {
		t.Fatal(err)
	}
	decoded.Regions[0].ControlLineagePurpose = ""
	changed, err := FoundationIntentDigest(decoded.Regions[0])
	if err != nil {
		t.Fatal(err)
	}
	if original == changed {
		t.Fatal("foundation intent digest did not bind its explicit purpose")
	}
}
