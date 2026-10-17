package cellspec

import (
	"errors"
	"slices"
	"strings"
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
		ManagementURL: netbird.DefaultManagementURL, Region: netbird.DefaultRegion}}
	spec := testSpec(id, 2)
	spec.NetBird = &managed
	if spec.Level() != 20 || !errors.Is(spec.Validate(), ErrInvalid) {
		t.Fatal("NetBird did not require binary level 20")
	}
	spec.RequiresBinary = 20
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	defaultRegion := managed
	defaultRegion.Enrollment.Region = ""
	if err := defaultRegion.Validate("gru"); err != nil {
		t.Fatalf("documented default region rejected for GRU: %v", err)
	}
	if err := defaultRegion.Validate("sfo"); err == nil || !strings.Contains(err.Error(), "region differs") {
		t.Fatalf("default GRU region accepted for SFO: %v", err)
	}
	if err := managed.Validate("lab"); err == nil || !strings.Contains(err.Error(), "requires a catalog cell") {
		t.Fatalf("unknown cell did not identify its missing catalog region: %v", err)
	}
	for name, change := range map[string]func(*NetBird){
		"foreign source":     func(n *NetBird) { n.Pin.Archives.AMD64.URL = "https://example.com/netbird" },
		"missing checksum":   func(n *NetBird) { n.Pin.Archives.Arm64.SHA256 = "" },
		"unbounded artifact": func(n *NetBird) { n.Pin.Archives.Arm64.Bytes = client.MaxBinaryBytes + 1 },
		"input traversal":    func(n *NetBird) { n.Pin.EnrollmentConfig.Path = "deploy/image/inputs/../netbird.json" },
		"input checksum":     func(n *NetBird) { n.Pin.EnrollmentConfig.SHA256 = "" },
		"foreign region": func(n *NetBird) {
			n.Enrollment.Region = "us-sanjose-1"
		},
		"foreign manager": func(n *NetBird) { n.Enrollment.ManagementURL = "https://example.com" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid, altered := spec, managed
			change(&altered)
			invalid.NetBird = &altered
			if !errors.Is(invalid.Validate(), ErrInvalid) {
				t.Fatal("invalid NetBird settings accepted")
			}
		})
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
