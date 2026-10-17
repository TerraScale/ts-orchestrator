package teardown_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/teardown"
)

const (
	parentCompartment = "ocid1.compartment.oc1..terrascale"
	cellCompartment   = "ocid1.compartment.oc1..control"
)

// fakeOCI models deletion the way OCI does: a vault, key or secret enters
// PENDING_DELETION and a compartment DELETING; purge then turns a compartment
// DELETED and makes everything else answer 404.
type fakeOCI struct {
	state    map[string]teardown.Observed
	contents map[string][]teardown.Resource
	deleted  []string
	out      *strings.Builder
	onDelete func(teardown.Resource)
}

func (f *fakeOCI) Get(_ context.Context, r teardown.Resource) (teardown.Observed, error) {
	o, ok := f.state[r.ID]
	if !ok {
		return teardown.Observed{State: teardown.NotFound}, nil
	}
	return o, nil
}

func (f *fakeOCI) Delete(_ context.Context, r teardown.Resource) error {
	if !strings.Contains(f.out.String(), "complete: ") {
		return fmt.Errorf("deleted %s before the diff was printed", r.ID)
	}
	o := f.state[r.ID]
	o.State = "PENDING_DELETION"
	if r.Kind == "compartment" {
		o.State = "DELETING"
	}
	f.state[r.ID] = o
	f.deleted = append(f.deleted, r.ID)
	if f.onDelete != nil {
		f.onDelete(r)
	}
	return nil
}

func (f *fakeOCI) VaultContents(_ context.Context, r teardown.Resource) ([]teardown.Resource, error) {
	return f.contents[r.ID], nil
}

func (f *fakeOCI) purge() {
	for id, o := range f.state {
		switch o.State {
		case "DELETING":
			o.State = "DELETED"
			f.state[id] = o
		case "PENDING_DELETION":
			delete(f.state, id)
		}
	}
}

func gruPlan() teardown.Plan {
	return teardown.Plan{Cell: "GRU", Region: "sa-saopaulo-1",
		// Listed out of dependency order on purpose.
		Delete: []teardown.Resource{
			{Kind: "compartment", ID: cellCompartment, Name: "terrascale-control", Compartment: parentCompartment},
			{Kind: "kms-vault", ID: "vault", Name: "terrascale-control-vault-gru", Compartment: cellCompartment},
			{Kind: "kms-key", ID: "key", Name: "terrascale-control-key-gru", Compartment: cellCompartment, VaultID: "vault"},
			{Kind: "vault-secret", ID: "secret", Name: "terrascale-gru-netbird-setup-key", Compartment: cellCompartment},
		},
		Keep: []teardown.Resource{{Kind: "instance", ID: "ts-ops", Name: "ts-ops", Reason: "operations host and NetBird manager"}},
	}
}

func liveCell() *fakeOCI {
	return &fakeOCI{state: map[string]teardown.Observed{
		cellCompartment: {Name: "terrascale-control", Compartment: parentCompartment, State: "ACTIVE"},
		"vault":         {Name: "terrascale-control-vault-gru", Compartment: cellCompartment, State: "ACTIVE"},
		"key":           {Name: "terrascale-control-key-gru", Compartment: cellCompartment, State: "ENABLED"},
		"secret":        {Name: "terrascale-gru-netbird-setup-key", Compartment: cellCompartment, State: "ACTIVE"},
	}, contents: map[string][]teardown.Resource{"vault": {
		{Kind: "kms-key", ID: "key", Name: "terrascale-control-key-gru", Compartment: cellCompartment, VaultID: "vault"},
		{Kind: "vault-secret", ID: "secret", Name: "terrascale-gru-netbird-setup-key", Compartment: cellCompartment, VaultID: "vault"},
	}}}
}

func run(t *testing.T, plan teardown.Plan, oci *fakeOCI, apply bool) string {
	t.Helper()
	oci.out = &strings.Builder{}
	if err := teardown.Teardown(t.Context(), plan, oci, apply, oci.out); err != nil {
		t.Fatal(err)
	}
	return oci.out.String()
}

func TestDryRunPrintsDiffWithoutDeleting(t *testing.T) {
	oci := liveCell()
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
	oci := liveCell()
	run(t, gruPlan(), oci, true)
	if got := strings.Join(oci.deleted, ","); got != "secret,key,vault" {
		t.Fatalf("first apply deleted %s, want secret,key,vault and the compartment held", got)
	}
	oci.state["secret"] = teardown.Observed{Name: "terrascale-gru-netbird-setup-key", Compartment: cellCompartment,
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
	plan := teardown.Plan{Cell: "GRU", Region: "sa-saopaulo-1", Delete: []teardown.Resource{
		{Kind: "compartment", ID: cellCompartment, Name: "parent", Compartment: parentCompartment},
		{Kind: "compartment", ID: "child", Name: "child", Compartment: cellCompartment},
	}}
	oci := &fakeOCI{state: map[string]teardown.Observed{
		cellCompartment: {Name: "parent", Compartment: parentCompartment, State: "ACTIVE"},
		"child":         {Name: "child", Compartment: cellCompartment, State: "ACTIVE"},
	}}
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
	for name, mutate := range map[string]func(*fakeOCI){
		"renamed": func(f *fakeOCI) {
			f.state["secret"] = teardown.Observed{Name: "ts-forgejo", Compartment: cellCompartment, State: "ACTIVE"}
		},
		"other compartment": func(f *fakeOCI) {
			f.state["vault"] = teardown.Observed{Name: "terrascale-control-vault-gru", Compartment: "ocid1.compartment.oc1..ts-ops", State: "ACTIVE"}
		},
		"vault holds an unlisted key": func(f *fakeOCI) {
			f.contents["vault"] = append(f.contents["vault"], teardown.Resource{Kind: "kms-key", ID: "ts-ops-key", Name: "shared key", Compartment: "ts-ops", VaultID: "vault"})
		},
		"vault holds an unlisted secret": func(f *fakeOCI) {
			f.contents["vault"] = append(f.contents["vault"], teardown.Resource{Kind: "vault-secret", ID: "ts-ops-secret", Name: "shared secret", Compartment: "ts-ops", VaultID: "vault"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			oci := liveCell()
			mutate(oci)
			oci.out = &strings.Builder{}
			if err := teardown.Teardown(t.Context(), gruPlan(), oci, true, oci.out); err == nil || len(oci.deleted) != 0 {
				t.Fatalf("err %v, deleted %v", err, oci.deleted)
			}
		})
	}
}

func TestVaultDeletionRequiresVerifiedContents(t *testing.T) {
	for name, mutate := range map[string]func(*teardown.Plan, *fakeOCI){
		"key not found": func(_ *teardown.Plan, f *fakeOCI) { delete(f.state, "key") },
		"key gone": func(_ *teardown.Plan, f *fakeOCI) {
			f.state["key"] = teardown.Observed{State: "DELETED"}
		},
		"secret not found": func(_ *teardown.Plan, f *fakeOCI) { delete(f.state, "secret") },
		"secret gone": func(_ *teardown.Plan, f *fakeOCI) {
			f.state["secret"] = teardown.Observed{State: "DELETED"}
		},
		"key belongs to a different vault": func(p *teardown.Plan, _ *fakeOCI) {
			p.Delete[2].VaultID = "other-vault"
		},
		"listed key moved to a shared compartment": func(_ *teardown.Plan, f *fakeOCI) {
			f.contents["vault"][0].Compartment = "ts-ops"
		},
		"listed secret renamed in the live list": func(_ *teardown.Plan, f *fakeOCI) {
			f.contents["vault"][1].Name = "shared secret"
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, apply := range []bool{false, true} {
				plan, oci := gruPlan(), liveCell()
				mutate(&plan, oci)
				oci.out = &strings.Builder{}
				err := teardown.Teardown(t.Context(), plan, oci, apply, oci.out)
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
		oci := liveCell()
		if pending {
			observed := oci.state["vault"]
			observed.State = "PENDING_DELETION"
			oci.state["vault"] = observed
		}
		oci.contents["vault"] = append(oci.contents["vault"],
			teardown.Resource{Kind: "kms-key", ID: "unknown-key", Name: "shared key", Compartment: "ts-ops", VaultID: "vault"},
			teardown.Resource{Kind: "vault-secret", ID: "unknown-secret", Name: "shared secret", Compartment: "ts-ops", VaultID: "vault"})
		oci.out = &strings.Builder{}
		err := teardown.Teardown(t.Context(), gruPlan(), oci, false, oci.out)
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
	oci := liveCell()
	oci.onDelete = func(r teardown.Resource) {
		if r.Kind == "kms-key" {
			oci.contents["vault"] = append(oci.contents["vault"], teardown.Resource{Kind: "kms-key", ID: "late-key", Name: "shared key", Compartment: "ts-ops", VaultID: "vault"})
		}
	}
	oci.out = &strings.Builder{}
	err := teardown.Teardown(t.Context(), gruPlan(), oci, true, oci.out)
	if err == nil || strings.Join(oci.deleted, ",") != "secret,key" || !strings.Contains(oci.out.String(), "late-key") {
		t.Fatalf("err %v, deleted %v, output %s", err, oci.deleted, oci.out)
	}
}

func TestValidateRejectsAmbiguousPlans(t *testing.T) {
	for name, mutate := range map[string]func(*teardown.Plan){
		"keep overlaps delete": func(p *teardown.Plan) { p.Keep = append(p.Keep, p.Delete[0]) },
		"keeps a key of a deleted vault": func(p *teardown.Plan) {
			p.Keep = append(p.Keep, teardown.Resource{Kind: "kms-key", ID: "kept", Name: "kept", VaultID: "vault"})
		},
		"keeps a resource of a deleted compartment": func(p *teardown.Plan) {
			p.Keep[0].Compartment = cellCompartment
		},
		"duplicate":                     func(p *teardown.Plan) { p.Delete = append(p.Delete, p.Delete[1]) },
		"unknown kind":                  func(p *teardown.Plan) { p.Delete[0].Kind = "instance" },
		"key without vault":             func(p *teardown.Plan) { p.Delete[2].VaultID = "" },
		"no compartment":                func(p *teardown.Plan) { p.Delete[3].Compartment = "" },
		"outside a deleted compartment": func(p *teardown.Plan) { p.Delete[3].Compartment = parentCompartment },
		"unknown region":                func(p *teardown.Plan) { p.Region = "gru" },
	} {
		t.Run(name, func(t *testing.T) {
			p := gruPlan()
			mutate(&p)
			if p.Validate() == nil {
				t.Fatal("accepted")
			}
		})
	}
	if err := gruPlan().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestUnverified404CannotComplete(t *testing.T) {
	oci := liveCell()
	oci.state = map[string]teardown.Observed{}
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
	diff := run(t, gruPlan(), liveCell(), true)
	diff = diff[:strings.Index(diff, "deleted  ")]
	for _, remaining := range []int{0, strings.Index(diff, "keep  "), len(diff) - 1} {
		oci := liveCell()
		oci.out = &strings.Builder{}
		want := errors.New("output unavailable")
		err := teardown.Teardown(t.Context(), gruPlan(), oci, true, &failWriter{remaining: remaining, err: want})
		if !errors.Is(err, want) || len(oci.deleted) != 0 {
			t.Fatalf("writer failed after %d bytes: err %v, deleted %v", remaining, err, oci.deleted)
		}
	}
}
