package initialgrant

import (
	"bytes"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
)

func TestInitialStorageTransitionDeliveryRemainsSignedAndOutsideCapture(t *testing.T) {
	c := preliminaryConfigFixture(t)
	before, err := json.Marshal(c, jsonv1.DefaultOptionsV1())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("storageTransition")) {
		t.Fatal("absent delivery changed original wire")
	}
	c.StorageTransition = controltransition.Delivery{TransitionID: "first-r3", PlanFile: "/etc/terrascale/storage-plan.json"}
	raw, err := json.Marshal(c, jsonv1.DefaultOptionsV1())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseConfig(raw)
	if err != nil || parsed.StorageTransition != c.StorageTransition {
		t.Fatal("lost signed delivery", err)
	}
	c.StorageTransition.PlanFile = c.PreliminaryCapture.OutputDir + "/plan.json"
	if c.Validate() == nil {
		t.Fatal("capture can overwrite delivered plan")
	}
	c.StorageTransition.PlanFile = "/etc/terrascale/storage-plan.json"
	c.Role = "participant"
	if c.Validate() == nil {
		t.Fatal("participant accepted source transition delivery")
	}
}
