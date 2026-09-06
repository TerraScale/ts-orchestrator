package transitiongrant_test

import (
	"bytes"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func TestCandidateStorageTransitionDeliveryIsPartOfCanonicalConfiguration(t *testing.T) {
	_, c := grantFixture()
	before, err := json.Marshal(c, jsonv1.DefaultOptionsV1())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("storageTransition")) {
		t.Fatal("absent delivery changed original wire")
	}
	c.StorageTransition = controltransition.Delivery{TransitionID: c.TransitionID, PlanFile: "/etc/terrascale/storage-plan.json"}
	raw, err := json.Marshal(c, jsonv1.DefaultOptionsV1())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := transitiongrant.ParseConfig(raw)
	if err != nil || parsed.StorageTransition != c.StorageTransition {
		t.Fatal("lost signed delivery", err)
	}
	for _, path := range []string{c.GrantFile, c.GrantPublicKeyFile, c.StoreDir + "/plan.json"} {
		c.StorageTransition.PlanFile = path
		if c.Validate() == nil {
			t.Fatal("overlapping delivery accepted", path)
		}
	}
	c.StorageTransition.PlanFile = "/etc/terrascale/storage-plan.json"
	c.StorageTransition.TransitionID = "different"
	if c.Validate() == nil {
		t.Fatal("candidate transition identity changed")
	}
}
