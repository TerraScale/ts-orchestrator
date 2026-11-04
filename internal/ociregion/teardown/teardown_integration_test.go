package teardown

import (
	"strings"
	"testing"
	"time"
)

const (
	parentCompartment = "ocid1.compartment.oc1..terrascale"
	cellCompartment   = "ocid1.compartment.oc1..control"
)

func gruPlan() Plan {
	return Plan{Cell: "GRU", Region: "sa-saopaulo-1",
		// Listed out of dependency order on purpose.
		Delete: []Resource{
			{Kind: "compartment", ID: cellCompartment, Name: "terrascale-control", Compartment: parentCompartment},
			{Kind: "kms-vault", ID: "vault", Name: "terrascale-control-vault-gru", Compartment: cellCompartment},
			{Kind: "kms-key", ID: "key", Name: "terrascale-control-key-gru", Compartment: cellCompartment, VaultID: "vault"},
			{Kind: "vault-secret", ID: "secret", Name: "terrascale-gru-netbird-setup-key", Compartment: cellCompartment},
		},
		Keep: []Resource{{Kind: "instance", ID: "ts-ops", Name: "ts-ops", Reason: "operations host and NetBird manager"}},
	}
}

func liveCell(t *testing.T) *teardownAPI {
	return newTeardownAPI(t, &teardownAPI{state: map[string]Observed{
		cellCompartment: {Name: "terrascale-control", Compartment: parentCompartment, State: "ACTIVE"},
		"vault":         {Name: "terrascale-control-vault-gru", Compartment: cellCompartment, State: "ACTIVE"},
		"key":           {Name: "terrascale-control-key-gru", Compartment: cellCompartment, State: "ENABLED"},
		"secret":        {Name: "terrascale-gru-netbird-setup-key", Compartment: cellCompartment, State: "ACTIVE"},
	}, contents: map[string][]Resource{"vault": {
		{Kind: "kms-key", ID: "key", Name: "terrascale-control-key-gru", Compartment: cellCompartment, VaultID: "vault"},
		{Kind: "vault-secret", ID: "secret", Name: "terrascale-gru-netbird-setup-key", Compartment: cellCompartment, VaultID: "vault"},
	}}})
}

func run(t *testing.T, plan Plan, oci *teardownAPI, apply bool) string {
	t.Helper()
	oci.out = &strings.Builder{}
	if err := oci.teardown(t, plan, apply, oci.out); err != nil {
		t.Fatal(err)
	}
	return oci.out.String()
}

func TestApplyFollowsDeletionUntilProvenComplete(t *testing.T) {
	oci := liveCell(t)
	run(t, gruPlan(), oci, true)
	if got := strings.Join(oci.deleted, ","); got != "secret,key,vault" {
		t.Fatalf("first apply deleted %s, want secret,key,vault and the compartment held", got)
	}
	oci.state["secret"] = Observed{Name: "terrascale-gru-netbird-setup-key", Compartment: cellCompartment,
		State: "PENDING_DELETION", DeleteAt: new(time.Date(2026, 10, 5, 1, 45, 58, 0, time.UTC))}
	out := run(t, gruPlan(), oci, true)
	if len(oci.deleted) != 3 || !strings.Contains(out, "pending  vault-secret terrascale-gru-netbird-setup-key secret purge 2026-10-05T01:45:58Z") {
		t.Fatalf("rerun while purging deleted %v:\n%s", oci.deleted, out)
	}
	// After the purge OCI answers 404, which does not prove absence while
	// the compartment exists, but no longer holds the compartment either.
	oci.purge()
	out = run(t, gruPlan(), oci, true)
	if got := oci.deleted[len(oci.deleted)-1]; len(oci.deleted) != 4 || got != cellCompartment ||
		!strings.Contains(out, "absent   kms-key") || !strings.Contains(out, "incomplete: gone 0, absent 3") {
		t.Fatalf("after purge deleted %v:\n%s", oci.deleted, out)
	}
	oci.purge()
	if out := run(t, gruPlan(), oci, true); !strings.Contains(out, "complete: gone 4,") || strings.Contains(out, "incomplete") || len(oci.deleted) != 4 {
		t.Fatalf("final run deleted %v:\n%s", oci.deleted, out)
	}
}

func TestRefusesResourcesOutsideThePlan(t *testing.T) {
	for name, mutate := range map[string]func(*teardownAPI){
		"other compartment": func(f *teardownAPI) {
			f.state["vault"] = Observed{Name: "terrascale-control-vault-gru", Compartment: "ocid1.compartment.oc1..ts-ops", State: "ACTIVE"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			oci := liveCell(t)
			mutate(oci)
			oci.out = &strings.Builder{}
			if err := oci.teardown(t, gruPlan(), true, oci.out); err == nil || len(oci.deleted) != 0 {
				t.Fatalf("err %v, deleted %v", err, oci.deleted)
			}
		})
	}
}
