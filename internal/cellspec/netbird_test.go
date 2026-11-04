package cellspec

import (
	"errors"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

func TestNetBirdPinValidationAndAmendment(t *testing.T) {
	pin, err := client.LoadPin("../../deploy/image/image-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{DeploymentID: "5MDYB72MN6NMSTJ8H7WCQ6ZK5P", Cell: "gru", Environment: "production"}
	managed := NetBird{Pin: pin, Enrollment: netbird.Config{
		ManagementURL: netbird.DefaultManagementURL, Region: netbird.DefaultRegion,
		SetupKeySecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.setupkey"}}
	spec := testSpec(id, 2)
	spec.NetBird = &managed
	if spec.Level() != 20 || !errors.Is(spec.Validate(), ErrInvalid) {
		t.Fatal("NetBird did not require binary level 20")
	}
	spec.RequiresBinary = 20
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	before := testSpec(id, 1)
	plan, err := Diff(before, spec, nil)
	if err != nil || plan.NetBird != "added" || plan.Empty() || !slices.Contains(plan.RootRequired, "netbird enrollment") {
		t.Fatalf("first pin = %+v, %v", plan, err)
	}
	bump := spec
	next := managed
	next.Pin.Archives.AMD64.BinarySHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bump.NetBird = &next
	plan, err = Diff(spec, bump, nil)
	if err != nil || plan.NetBird != "updated" || slices.Contains(plan.RootRequired, "netbird enrollment") {
		t.Fatalf("artifact-only bump = %+v, %v", plan, err)
	}
	plan, err = Diff(spec, spec, nil)
	if err != nil || !plan.Empty() {
		t.Fatalf("unchanged pin = %+v, %v", plan, err)
	}
	plan, err = Diff(spec, before, nil)
	if err != nil || plan.NetBird != "removed" || len(plan.RootRequired) != 0 {
		t.Fatalf("removed pin = %+v, %v", plan, err)
	}
}
