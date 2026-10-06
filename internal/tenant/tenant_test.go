package tenant

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	t0      = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	digestA = strings.Repeat("a", 64)
	digestB = strings.Repeat("b", 64)
	digestC = strings.Repeat("c", 64)
)

func newTenant(t *testing.T) Tenant {
	t.Helper()
	tenant, err := New("acme", "org_01", "prj_01", "gru",
		Spec{Plan: "standard", Members: 3, TerraBase: digestA, Auth: digestB}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func TestNewValidatesIdentityAndSpec(t *testing.T) {
	good := Spec{Plan: "starter", Members: 1, TerraBase: digestA}
	for name, tc := range map[string]struct {
		id, cell string
		spec     Spec
	}{
		"hyphenated id":   {"ac-me", "gru", good},
		"short id":        {"ab", "gru", good},
		"reserved id":     {"api", "gru", good},
		"upper id":        {"Acme", "gru", good},
		"server cell":     {"acme", "gru-1", good},
		"unknown cell":    {"acme", "xyz", good},
		"unknown plan":    {"acme", "gru", Spec{Plan: "huge", Members: 1, TerraBase: digestA}},
		"two members":     {"acme", "gru", Spec{Plan: "starter", Members: 2, TerraBase: digestA}},
		"no terrabase":    {"acme", "gru", Spec{Plan: "starter", Members: 1}},
		"upper digest":    {"acme", "gru", Spec{Plan: "starter", Members: 1, TerraBase: strings.Repeat("A", 64)}},
		"short ts-auth":   {"acme", "gru", Spec{Plan: "starter", Members: 1, TerraBase: digestA, Auth: "abc"}},
		"prefixed digest": {"acme", "gru", Spec{Plan: "starter", Members: 1, TerraBase: "sha256:" + digestA[7:]}},
	} {
		if _, err := New(tc.id, "org_01", "prj_01", tc.cell, tc.spec, t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: New error = %v, want ErrInvalid", name, err)
		}
	}
	tenant, err := New("acme", "org_01", "prj_01", "gru", good, t0)
	if err != nil || tenant.Generation != 1 || tenant.State != StateActive || !tenant.CreatedAt.Equal(t0) ||
		tenant.Spec.Member != Plans[0].Member {
		t.Fatalf("New = %+v, %v; want active generation 1 with the starter plan's resources", tenant, err)
	}
}

func TestLifecycle(t *testing.T) {
	tenant := newTenant(t)
	at := t0
	step := func(name string) func(Tenant, error) Tenant {
		return func(next Tenant, err error) Tenant {
			t.Helper()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if next.Generation != tenant.Generation+1 {
				t.Fatalf("%s: generation %d after %d", name, next.Generation, tenant.Generation)
			}
			at = at.Add(time.Minute)
			return next
		}
	}
	spec := tenant.Spec
	spec.Plan = "pro"
	tenant = step("resize")(tenant.Change(spec, at))
	if pro, _ := LookupPlan("pro"); tenant.Spec.Member != pro.Member {
		t.Fatalf("resized member = %+v, want the pro plan's", tenant.Spec.Member)
	}
	spec = tenant.Spec
	spec.Members = 1
	tenant = step("scale in")(tenant.Change(spec, at))
	spec.TerraBase = digestC
	tenant = step("upgrade")(tenant.Change(spec, at))
	spec.TerraBase = digestA
	tenant = step("roll back")(tenant.Change(spec, at))
	spec.Auth = ""
	tenant = step("drop ts-auth")(tenant.Change(spec, at))
	tenant = step("suspend")(tenant.Suspend(at))
	tenant = step("resume")(tenant.Resume(at))
	tenant = step("suspend again")(tenant.Suspend(at))
	tenant = step("delete")(tenant.Delete(DefaultRetention, at))
	if tenant.State != StateDeleted || !tenant.RetainUntil.Equal(tenant.UpdatedAt.Add(DefaultRetention)) {
		t.Fatalf("deleted tenant = %+v", tenant)
	}
	if _, err := tenant.Purge(tenant.RetainUntil.Add(-time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Purge before retention ends = %v, want ErrInvalid", err)
	}
	tenant = step("purge")(tenant.Purge(tenant.RetainUntil))
	if _, err := tenant.Resume(at); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Resume of a purged tenant = %v, want ErrInvalid", err)
	}
}

func TestRefusedTransitions(t *testing.T) {
	active := newTenant(t)
	suspended, err := active.Suspend(t0)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := active.Delete(DefaultRetention, t0)
	if err != nil {
		t.Fatal(err)
	}
	changed := func(edit func(*Spec)) Spec {
		spec := active.Spec
		edit(&spec)
		return spec
	}
	for name, tc := range map[string]struct {
		do   func() (Tenant, error)
		want error
	}{
		"same spec":         {func() (Tenant, error) { return active.Change(active.Spec, t0) }, ErrUnchanged},
		"resume active":     {func() (Tenant, error) { return active.Resume(t0) }, ErrUnchanged},
		"suspend suspended": {func() (Tenant, error) { return suspended.Suspend(t0) }, ErrUnchanged},
		"change suspended":  {func() (Tenant, error) { return suspended.Change(changed(func(s *Spec) { s.Members = 1 }), t0) }, ErrInvalid},
		"shrink disk":       {func() (Tenant, error) { return active.Change(changed(func(s *Spec) { s.Plan = "starter" }), t0) }, ErrInvalid},
		"unknown plan":      {func() (Tenant, error) { return active.Change(changed(func(s *Spec) { s.Plan = "huge" }), t0) }, ErrInvalid},
		"release + topology": {func() (Tenant, error) {
			return active.Change(changed(func(s *Spec) { s.Members, s.TerraBase = 1, digestC }), t0)
		}, ErrInvalid},
		"auth upgrade + scale": {func() (Tenant, error) {
			return active.Change(changed(func(s *Spec) { s.Members, s.Auth = 1, digestC }), t0)
		}, ErrInvalid},
		"resume deleted":  {func() (Tenant, error) { return deleted.Resume(t0) }, ErrInvalid},
		"delete deleted":  {func() (Tenant, error) { return deleted.Delete(DefaultRetention, t0) }, ErrInvalid},
		"purge active":    {func() (Tenant, error) { return active.Purge(t0.Add(MaxRetention)) }, ErrInvalid},
		"short retention": {func() (Tenant, error) { return active.Delete(time.Hour, t0) }, ErrInvalid},
		"long retention":  {func() (Tenant, error) { return active.Delete(MaxRetention+time.Hour, t0) }, ErrInvalid},
	} {
		if _, err := tc.do(); !errors.Is(err, tc.want) {
			t.Errorf("%s: error = %v, want %v", name, err, tc.want)
		}
	}
}

// TestClockSkewNeverFreezesATenant: a leader whose clock is behind the
// previous writer's still moves the tenant forward, keeping time monotonic.
func TestClockSkewNeverFreezesATenant(t *testing.T) {
	fast, err := newTenant(t).Suspend(t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	slow, err := fast.Resume(t0)
	if err != nil {
		t.Fatalf("Resume on a slower clock = %v", err)
	}
	if !slow.UpdatedAt.Equal(fast.UpdatedAt) {
		t.Fatalf("UpdatedAt = %v, want the previous %v", slow.UpdatedAt, fast.UpdatedAt)
	}
	deleted, err := slow.Delete(DefaultRetention, t0)
	if err != nil || !deleted.RetainUntil.Equal(fast.UpdatedAt.Add(DefaultRetention)) {
		t.Fatalf("Delete on a slower clock = %+v, %v", deleted, err)
	}
}

// TestPlanEditsNeverResizeATenant: a tenant keeps the resources it chose;
// Plans only matter when a tenant picks a plan.
func TestPlanEditsNeverResizeATenant(t *testing.T) {
	tenant := newTenant(t)
	saved := Plans
	t.Cleanup(func() { Plans = saved })
	Plans = []Plan{{Name: "standard", Member: Plans[1].Member}}
	Plans[0].Member.CPU = 3
	if err := tenant.Validate(); err != nil {
		t.Fatalf("stored tenant after a plan edit: %v", err)
	}
	spec := tenant.Spec
	spec.Members = 1
	scaled, err := tenant.Change(spec, t0)
	if err != nil || scaled.Spec.Member != tenant.Spec.Member {
		t.Fatalf("scale after a plan edit = %+v, %v; want the tenant's own resources", scaled.Spec, err)
	}
	spec.Plan = "pro"
	if _, err := tenant.Change(spec, t0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("move to a withdrawn plan = %v, want ErrInvalid", err)
	}
}

// TestCheckSuccessorRefusesForgedRecords covers records a writer builds by
// hand instead of through a lifecycle method.
func TestCheckSuccessorRefusesForgedRecords(t *testing.T) {
	prev := newTenant(t)
	good, err := prev.Suspend(t0)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Tenant){
		"skipped generation":    func(n *Tenant) { n.Generation += 1 },
		"replayed":              func(n *Tenant) { n.Generation = prev.Generation },
		"earlier":               func(n *Tenant) { n.UpdatedAt = t0.Add(-time.Second) },
		"moved organization":    func(n *Tenant) { n.Organization = "org_02" },
		"moved cell":            func(n *Tenant) { n.Cell = "fra" },
		"rewritten creation":    func(n *Tenant) { n.CreatedAt = t0.Add(-time.Hour) },
		"retention not deleted": func(n *Tenant) { n.RetainUntil = t0.Add(DefaultRetention) },
		"unknown state":         func(n *Tenant) { n.State = "paused" },
		"other schema":          func(n *Tenant) { n.Schema = "terrascale.tenant.v2" },
		"resized in place":      func(n *Tenant) { n.State, n.Spec.Member.CPU = StateActive, 64 },
		"undeclared plan":       func(n *Tenant) { n.State, n.Spec.Plan = StateActive, "scale" },
	} {
		next := good
		edit(&next)
		if err := CheckSuccessor(prev, next); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: CheckSuccessor = %v, want ErrInvalid", name, err)
		}
	}
	if err := CheckSuccessor(prev, good); err != nil {
		t.Fatalf("CheckSuccessor(lifecycle successor) = %v", err)
	}
}
