package teardown

import (
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
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

func TestDryRunPrintsDiffWithoutDeleting(t *testing.T) {
	oci := liveCell(t)
	out := run(t, gruPlan(), oci, false)
	if len(oci.deleted) != 0 {
		t.Fatalf("dry run deleted %v", oci.deleted)
	}
	for _, want := range []string{
		"teardown GRU sa-saopaulo-1 (dry run)",
		"delete   vault-secret terrascale-gru-netbird-setup-key secret",
		"held     compartment  terrascale-control " + cellCompartment + " waits for 3 resources inside it to be gone",
		"keep     instance     ts-ops ts-ops operations host and NetBird manager",
		"incomplete: gone 0, absent 0, pending 0, delete 3, held 1, keep 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
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

func TestChildCompartmentHoldsItsParent(t *testing.T) {
	plan := Plan{Cell: "GRU", Region: "sa-saopaulo-1", Delete: []Resource{
		{Kind: "compartment", ID: cellCompartment, Name: "parent", Compartment: parentCompartment},
		{Kind: "compartment", ID: "child", Name: "child", Compartment: cellCompartment},
	}}
	oci := newTeardownAPI(t, &teardownAPI{state: map[string]Observed{
		cellCompartment: {Name: "parent", Compartment: parentCompartment, State: "ACTIVE"},
		"child":         {Name: "child", Compartment: cellCompartment, State: "ACTIVE"},
	}})
	run(t, plan, oci, true)
	if got := strings.Join(oci.deleted, ","); got != "child" {
		t.Fatalf("deleted %s, want only the child while it exists", got)
	}
	run(t, plan, oci, true)
	if len(oci.deleted) != 1 {
		t.Fatalf("deleted the parent while the child was deleting: %v", oci.deleted)
	}
	oci.purge()
	run(t, plan, oci, true)
	if got := strings.Join(oci.deleted, ","); got != "child,"+cellCompartment {
		t.Fatalf("deleted %s", got)
	}
}

func TestRefusesResourcesOutsideThePlan(t *testing.T) {
	for name, mutate := range map[string]func(*teardownAPI){
		"renamed": func(f *teardownAPI) {
			f.state["secret"] = Observed{Name: "ts-forgejo", Compartment: cellCompartment, State: "ACTIVE"}
		},
		"other compartment": func(f *teardownAPI) {
			f.state["vault"] = Observed{Name: "terrascale-control-vault-gru", Compartment: "ocid1.compartment.oc1..ts-ops", State: "ACTIVE"}
		},
		"vault holds an unlisted key": func(f *teardownAPI) {
			f.contents["vault"] = append(f.contents["vault"], Resource{Kind: "kms-key", ID: "ts-ops-key", Name: "shared key", Compartment: "ts-ops", VaultID: "vault"})
		},
		"vault holds an unlisted secret": func(f *teardownAPI) {
			f.contents["vault"] = append(f.contents["vault"], Resource{Kind: "vault-secret", ID: "ts-ops-secret", Name: "shared secret", Compartment: "ts-ops", VaultID: "vault"})
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

func TestVaultDeletionRequiresVerifiedContents(t *testing.T) {
	for name, mutate := range map[string]func(*Plan, *teardownAPI){
		"key not found": func(_ *Plan, f *teardownAPI) { delete(f.state, "key") },
		"key gone": func(_ *Plan, f *teardownAPI) {
			f.state["key"] = Observed{State: "DELETED"}
		},
		"secret not found": func(_ *Plan, f *teardownAPI) { delete(f.state, "secret") },
		"secret gone": func(_ *Plan, f *teardownAPI) {
			f.state["secret"] = Observed{State: "DELETED"}
		},
		"key belongs to a different vault": func(p *Plan, _ *teardownAPI) {
			p.Delete[2].VaultID = "other-vault"
		},
		"listed key moved to a shared compartment": func(_ *Plan, f *teardownAPI) {
			f.contents["vault"][0].Compartment = "ts-ops"
		},
		"listed secret renamed in the live list": func(_ *Plan, f *teardownAPI) {
			f.contents["vault"][1].Name = "shared secret"
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, apply := range []bool{false, true} {
				plan, oci := gruPlan(), liveCell(t)
				mutate(&plan, oci)
				oci.out = &strings.Builder{}
				err := oci.teardown(t, plan, apply, oci.out)
				if err == nil || len(oci.deleted) != 0 || !strings.Contains(oci.out.String(), "blocked  kms-vault") ||
					!strings.Contains(oci.out.String(), "not verified as cell-owned by the inventory") {
					t.Fatalf("apply %v: err %v, deleted %v, output %s", apply, err, oci.deleted, oci.out)
				}
			}
		})
	}
}

func TestDryRunReportsEveryUnexpectedVaultContent(t *testing.T) {
	for _, pending := range []bool{false, true} {
		oci := liveCell(t)
		if pending {
			observed := oci.state["vault"]
			observed.State = "PENDING_DELETION"
			oci.state["vault"] = observed
		}
		oci.contents["vault"] = append(oci.contents["vault"],
			Resource{Kind: "kms-key", ID: "unknown-key", Name: "shared key", Compartment: "ts-ops", VaultID: "vault"},
			Resource{Kind: "vault-secret", ID: "unknown-secret", Name: "shared secret", Compartment: "ts-ops", VaultID: "vault"})
		oci.out = &strings.Builder{}
		err := oci.teardown(t, gruPlan(), false, oci.out)
		for _, want := range []string{"unknown-key", "shared key", "unknown-secret", "shared secret", "keep     instance"} {
			if !strings.Contains(oci.out.String(), want) {
				t.Fatalf("pending %v: output lacks %q: %s", pending, want, oci.out)
			}
		}
		if err == nil || len(oci.deleted) != 0 || !strings.Contains(oci.out.String(), "blocked: 1 vaults") {
			t.Fatalf("err %v, deleted %v, output %s", err, oci.deleted, oci.out)
		}
	}
}

func TestVaultContentsRecheckedBeforeScheduling(t *testing.T) {
	oci := liveCell(t)
	oci.onDelete = func(r Resource) {
		if r.Kind == "kms-key" {
			oci.contents["vault"] = append(oci.contents["vault"], Resource{Kind: "kms-key", ID: "late-key", Name: "shared key", Compartment: "ts-ops", VaultID: "vault"})
		}
	}
	oci.out = &strings.Builder{}
	err := oci.teardown(t, gruPlan(), true, oci.out)
	if err == nil || strings.Join(oci.deleted, ",") != "secret,key" || !strings.Contains(oci.out.String(), "late-key") {
		t.Fatalf("err %v, deleted %v, output %s", err, oci.deleted, oci.out)
	}
}

func TestCLIRejectsAmbiguousPlanFiles(t *testing.T) {
	for name, mutate := range map[string]func(*Plan){
		"keep overlaps delete": func(p *Plan) { p.Keep = append(p.Keep, p.Delete[0]) },
		"keeps a key of a deleted vault": func(p *Plan) {
			p.Keep = append(p.Keep, Resource{Kind: "kms-key", ID: "kept", Name: "kept", VaultID: "vault"})
		},
		"keeps a resource of a deleted compartment": func(p *Plan) {
			p.Keep[0].Compartment = cellCompartment
		},
		"duplicate":                     func(p *Plan) { p.Delete = append(p.Delete, p.Delete[1]) },
		"unknown kind":                  func(p *Plan) { p.Delete[0].Kind = "instance" },
		"key without vault":             func(p *Plan) { p.Delete[2].VaultID = "" },
		"no compartment":                func(p *Plan) { p.Delete[3].Compartment = "" },
		"outside a deleted compartment": func(p *Plan) { p.Delete[3].Compartment = parentCompartment },
		"unknown region":                func(p *Plan) { p.Region = "gru" },
	} {
		t.Run(name, func(t *testing.T) {
			p := gruPlan()
			mutate(&p)
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			if err := Run(t.Context(), []string{"--plan", path, "--apply"}, &out); err == nil || !strings.HasPrefix(err.Error(), "teardown plan") && !strings.HasPrefix(err.Error(), "invalid teardown resource") && !strings.Contains(err.Error(), "which the plan does not delete") {
				t.Fatalf("invalid plan was not rejected before constructing the OCI provider: %v", err)
			}
		})
	}
}

func TestUnverified404CannotComplete(t *testing.T) {
	oci := liveCell(t)
	oci.state = map[string]Observed{}
	out := run(t, gruPlan(), oci, true)
	if !strings.Contains(out, "incomplete: gone 0, absent 4") || len(oci.deleted) != 0 {
		t.Fatalf("404s reported complete or deleted resources: %s; deleted %v", out, oci.deleted)
	}
}

type failWriter struct {
	remaining int
	err       error
}

func (w *failWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, w.err
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestCompleteDiffMustBeWrittenBeforeDeleting(t *testing.T) {
	diff := run(t, gruPlan(), liveCell(t), true)
	diff, _, _ = strings.Cut(diff, "deleted  ")
	for _, remaining := range []int{0, strings.Index(diff, "keep  "), len(diff) - 1} {
		oci := liveCell(t)
		oci.out = &strings.Builder{}
		want := errors.New("output unavailable")
		err := oci.teardown(t, gruPlan(), true, &failWriter{remaining: remaining, err: want})
		if !errors.Is(err, want) || len(oci.deleted) != 0 {
			t.Fatalf("writer failed after %d bytes: err %v, deleted %v", remaining, err, oci.deleted)
		}
	}
}

func TestTeardownStopsOnOCIPermissionErrors(t *testing.T) {
	for name, scenario := range map[string]struct {
		deny    string
		deleted string
	}{
		"secret unreadable":    {deny: "GET /20180608/secrets/secret"},
		"inventory denied":     {deny: "GET /20180608/keys"},
		"secret delete denied": {deny: "POST /20180608/secrets/secret/actions/scheduleDeletion"},
		"key delete denied":    {deny: "POST /20180608/keys/key/actions/scheduleDeletion", deleted: "secret"},
	} {
		t.Run(name, func(t *testing.T) {
			oci := liveCell(t)
			oci.deny = scenario.deny
			var out strings.Builder
			err := oci.teardown(t, gruPlan(), true, &out)
			if err == nil || !strings.Contains(err.Error(), "NotAuthorized") || strings.Join(oci.deleted, ",") != scenario.deleted {
				t.Fatalf("permission failure: err %v, deleted %v, output %s", err, oci.deleted, &out)
			}
		})
	}
}
