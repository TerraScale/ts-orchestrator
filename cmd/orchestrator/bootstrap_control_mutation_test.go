package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
)

func TestBootstrapControlMutationIdentitySurvivesDecodeProjectionAndIntent(t *testing.T) {
	raw := `{"version":1,"generation":1,"regions":[{"code":"gru"}],"actions":[{"Kind":"promote-global-r3","Region":"gru","ExpectedEpoch":1,"TargetEpoch":2,"ReplicaUpdates":[{"Store":"global","Streams":["GLOBAL_SPEC"],"Replicas":3}],"Checks":[{"Store":"global","Region":"gru","AuthorityID":"global","LeaseKey":"authority.global","AuthorityTerm":7,"AuthorityCandidateID":"global-controller-gru-one","AuthorityLeaseID":"lease-original"}]}]}`
	var declaration bootstrapControlConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&declaration); err != nil {
		t.Fatal(err)
	}
	declaration.ReceiptFile = filepath.Join(t.TempDir(), "receipt.json")
	loaded := loadedBootstrapControl{declaration: declaration, members: []bootstrap.ControlRuntimeMember{{MemberID: "gru-one", HostID: "gru-one", Region: "gru", ServerName: "gru-server"}}}
	for _, source := range declaration.Actions {
		loaded.actions = append(loaded.actions, source.ControlRuntimeActionPlan)
	}
	before, err := bootstrapControlIntentDigest(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectBootstrapControlStage(&loaded, "gru"); err != nil {
		t.Fatal(err)
	}
	check := loaded.actions[0].Checks[0]
	if check.AuthorityCandidateID != "global-controller-gru-one" || check.AuthorityLeaseID != "lease-original" || check.AuthorityTerm != 7 {
		t.Fatalf("projected identity changed: %+v", check)
	}
	// The persisted CLI admission digest prevents replacing an exact lease pin
	// inside the same generation, including when the process is reconstructed.
	if err := persistBootstrapControlReceipt(declaration.ReceiptFile, bootstrapControlReceipt{Generation: 1, DeclarationSHA256: before, Regions: []bootstrap.ControlRegionBinding{{Code: "gru"}}}); err != nil {
		t.Fatal(err)
	}
	loaded.declaration.Actions[0].Checks[0].AuthorityLeaseID = "same-term-replacement"
	after, err := bootstrapControlIntentDigest(loaded)
	if err != nil || after == before {
		t.Fatal("lease pin missing from admitted intent digest")
	}
	if _, err := selectBootstrapControlStage(&loaded, "gru"); err == nil {
		t.Fatal("replacement lease admitted in same generation")
	}
}
