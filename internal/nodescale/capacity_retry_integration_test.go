package nodescale

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// Root operations replay explicitly; preparation must reread current selectors every time.
func TestCapacityPreparationRechecksCurrentSelectors(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	recipe := capacityEnrollmentRecipe(t)
	record := capacityBirthRecord(recipe)
	records, err := OpenStore(ctx, capacityJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	revoked := errors.New("current finite selectors revoked")
	var currentErr error
	pool := chosenProtocolPool(t, protocolPool(t, cloud, recipe.Capacity), records, func(ctx context.Context, r Record) (rootoci.PoolChildExpectation, error) {
		if currentErr != nil {
			return rootoci.PoolChildExpectation{}, currentErr
		}
		return capacitySelectors(ctx, r)
	})
	if size, err := pool.TargetSize(ctx, recipe); err != nil || size != 0 {
		t.Fatalf("actual empty target read: size=%d err=%v", size, err)
	}
	revision, err := records.Save(ctx, record, 0)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err = records.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.PrepareGrowth(ctx, record)
	if err != nil {
		t.Fatalf("valid request preparation failed: %v", err)
	}
	record.Child = new(first)
	revision, err = records.Save(ctx, record, revision)
	if err != nil {
		t.Fatal(err)
	}
	currentErr = revoked
	if err := pool.Grow(ctx, 0); !errors.Is(err, revoked) {
		t.Fatalf("durable replay reused stale current selectors: %v", err)
	}
	currentErr = nil
	again, err := pool.PrepareGrowth(ctx, record)
	if err != nil || first.OperationID != again.OperationID || first.ReservationID != again.ReservationID || first.RecipeSHA256 != again.RecipeSHA256 {
		t.Fatalf("fresh selectors replaced original request: %+v err=%v", again, err)
	}
	for _, change := range []struct {
		name  string
		apply func(*rootoci.PoolChildExpectation)
		want  string
	}{
		{"wrong cell", func(s *rootoci.PoolChildExpectation) { s.Cell = "IAD" }, "current finite root capacity selectors are unavailable"},
		{"missing grant", func(s *rootoci.PoolChildExpectation) { s.GrantSHA256 = "" }, "current finite root capacity selectors are unavailable"},
		{"missing generation", func(s *rootoci.PoolChildExpectation) { s.Generation = 0 }, "current finite root capacity selectors are unavailable"},
		{"missing epoch", func(s *rootoci.PoolChildExpectation) { s.Epoch = 0 }, "current finite root capacity selectors are unavailable"},
		{"changed operation", func(s *rootoci.PoolChildExpectation) { s.OperationID = entityid.New() }, "cannot replace the original durable pool birth"},
		{"changed reservation", func(s *rootoci.PoolChildExpectation) { s.ReservationID = entityid.New() }, "cannot replace the original durable pool birth"},
		{"changed recipe", func(s *rootoci.PoolChildExpectation) { s.RecipeSHA256 = strings.Repeat("b", 64) }, "cannot replace the original durable pool birth"},
		{"changed CA", func(s *rootoci.PoolChildExpectation) { s.PublicCAPEM = []byte("replacement") }, "cannot replace the original durable pool birth"},
		{"changed AD", func(s *rootoci.PoolChildExpectation) { s.AvailabilityDomains = []string{"replacement"} }, "cannot replace the original durable pool birth"},
	} {
		t.Run(change.name, func(t *testing.T) {
			chosen := chosenProtocolPool(t, pool.observed, records, func(ctx context.Context, r Record) (rootoci.PoolChildExpectation, error) {
				s, err := capacitySelectors(ctx, r)
				change.apply(&s)
				return s, err
			})
			if err := chosen.Grow(ctx, 0); err == nil || !strings.Contains(err.Error(), change.want) {
				t.Fatalf("malformed selector was not locally refused: %v", err)
			}
		})
	}
	for _, change := range []struct {
		name  string
		apply func(*Record)
	}{
		{"missing action", func(r *Record) { r.Action = nil }},
		{"wrong action kind", func(r *Record) { r.Action.Kind = Down }},
		{"invalid operation", func(r *Record) { r.Action.ID = "invalid" }},
		{"missing recipe", func(r *Record) { r.Recipe = nil }},
		{"missing reservation", func(r *Record) { r.Reservation = nil }},
		{"changed reservation operation", func(r *Record) { r.Reservation.OperationID = entityid.New() }},
		{"changed reservation recipe", func(r *Record) { r.Reservation.RecipeSHA256 = strings.Repeat("c", 64) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := record
			changed.Action = new(*record.Action)
			changed.Reservation = new(*record.Reservation)
			change.apply(&changed)
			var saveErr error
			revision, saveErr = records.Save(ctx, changed, revision)
			if saveErr != nil {
				t.Fatal(saveErr)
			}
			if err := pool.Grow(ctx, 0); !errors.Is(err, ErrCapacityPending) || !strings.Contains(err.Error(), "exact original birth and reservation are not durable") {
				t.Fatalf("malformed durable precondition reached selector/IPC validation: %v", err)
			}
		})
	}
	if _, err := records.Save(ctx, record, revision); err != nil {
		t.Fatal(err)
	}
	for _, from := range []int{-1, 1, MaxPoolNodes} {
		if err := pool.Grow(ctx, from); !errors.Is(err, ErrCapacityPending) || !strings.Contains(err.Error(), "exact original root birth is not durable") {
			t.Fatalf("invalid original starting size %d reached IPC: %v", from, err)
		}
	}
	if len(cloud.configs) != 0 || len(cloud.pools) != 0 {
		t.Fatal("preparation changed OCI")
	}
}
