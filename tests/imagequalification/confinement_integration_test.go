package imagequalification

import (
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

func TestConfinementScopeUsesSealedApprovalAndDurableExactIDs(t *testing.T) {
	f := fixture(t)
	path := filepath.Join(t.TempDir(), "resources.json")
	initial, err := f.prepared.ConfinementScope(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.HostNames) != 4 || len(initial.ExistingHosts) != 0 || initial.IAMRegion != f.prepared.approval.IAMRegion || initial.ApprovalSHA256 != f.prepared.approvalSHA256 {
		t.Fatalf("initial confinement differs: %+v", initial)
	}
	initial.PolicyStatements[0] = "changed returned copy"
	if f.prepared.Approval().PolicyStatements[0] == initial.PolicyStatements[0] {
		t.Fatal("returned confinement mutated sealed authority")
	}
	client := cloud{prepared: f.prepared}
	j, err := client.load(path)
	if err != nil {
		t.Fatal(err)
	}
	j.Hosts[f.prepared.approval.Hosts[0].Name] = "ocid1.instance.oc1..exact"
	if err := checkpoint(path, j); err != nil {
		t.Fatal(err)
	}
	scope, err := f.prepared.ConfinementScope(path)
	if err != nil {
		t.Fatal(err)
	}
	if scope.ExistingHosts["ocid1.instance.oc1..exact"] != client.name(f.prepared.approval.Hosts[0].Name) {
		t.Fatal("journal identity not bound to exact approved name")
	}
	if _, err := newConfinedCloud(t.Context(), f.prepared, confinement.Verified{}, path); err == nil {
		t.Fatal("approval without actual confinement constructed executable SDK adapter")
	}
	if _, err := (Prepared{}).ConfinementScope(path); err == nil {
		t.Fatal("unsealed approval accepted")
	}
}
