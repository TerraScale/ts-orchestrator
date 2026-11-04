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
	tenant, err := New("0000000000WT9WWA18KD4ET6PG", "0000000000GG77KS2XN2FPA9SS", "00000000005C91M54AQR9YGVT5", "gru",
		Spec{Plan: "standard", Members: 3, TerraBase: digestA, Auth: digestB}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
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
