package bootstrapstart

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
)

func TestControllerActivationRequiresCompleteSignedTopology(t *testing.T) {
	f := newControllerRecipientFixture(t)
	grants := []cellspec.HostGrant{f.grant("controller-a"), f.grant("controller-b"), f.grant("controller-c")}
	read := func(grants []cellspec.HostGrant) *ControllerHostRecipient {
		t.Helper()
		wire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: cellspec.Identity{
			DeploymentID: f.issuer.DeploymentID, Cell: strings.ToLower(f.issuer.Cell), Environment: f.issuer.Environment},
			Generation: 1, RequiresBinary: 17, HostGrants: grants}, nil,
			f.founder.baked.Roots, time.Now().UTC(), time.Hour, f.founder.root)
		if err != nil {
			t.Fatal(err)
		}
		grant := f.grant("controller-b")
		proof, err := readControllerHostRecipient(t.Context(), f.reader, f.issuer, wire, grant.Node,
			f.states["controller-b"].Result.InstanceOCID, grant.PrivateIP, f.sources)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	proof := read(grants)
	domains, err := proof.VerifyActivationTopology(t.Context())
	if err != nil || len(domains) != 3 {
		t.Fatalf("three genuine signed grants rejected: %v", err)
	}
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		sibling, err := proof.ReadSlotRecipient(t.Context(), slot, f.states[slot].Result.InstanceOCID)
		if err != nil || sibling.FailureDomain() != domains[slot] || sibling.ExpiresAt().After(proof.ExpiresAt()) {
			t.Fatalf("signed slot recipient lost its domain or original deadline: %s %v", slot, err)
		}
	}
	if _, err := read(grants[:2]).VerifyActivationTopology(t.Context()); err == nil {
		t.Fatal("incomplete TSAuth topology admitted")
	}
	changed := append([]cellspec.HostGrant(nil), grants...)
	changed[2].Roles = []string{"ts-console"}
	if _, err := read(changed).VerifyActivationTopology(t.Context()); err == nil {
		t.Fatal("third controller without TSAuth grant admitted")
	}
	if _, err := proof.ReadSlotRecipient(t.Context(), "controller-a", f.states["controller-c"].Result.InstanceOCID); err == nil {
		t.Fatal("foreign instance accepted for a signed slot")
	}
	proof.validUntil = time.Now().Add(-time.Second)
	if _, err := proof.VerifyActivationTopology(t.Context()); err == nil {
		t.Fatal("expired original recipient renewed topology authority")
	}
	if _, err := proof.ReadSlotRecipient(t.Context(), "controller-a", f.states["controller-a"].Result.InstanceOCID); err == nil {
		t.Fatal("expired original recipient renewed sibling authority")
	}
}
