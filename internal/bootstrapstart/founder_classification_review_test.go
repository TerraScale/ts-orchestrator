package bootstrapstart

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// A selected plan read after its launch deadline must reach the founder
// supervisor as an operator-required failure, through the same wrappers the
// production founder path applies.
func TestExpiredSelectedPlanIsClassifiedAsOperatorActionThroughWrappers(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	selection := fixture.signSelection(t, fixture.selection, fixture.now.Add(23*time.Hour))
	key := fixture.domain.HeadBucket + "/" + FounderSelectionObjectName(fixture.domain, "0000000000F9PR1WNVDTEXS31Z", "GRU", "production")
	fixture.publish(t, fixture.selection)
	fixture.objects.items[key] = selection
	if err := fixture.floor.Initialize(1, digestWire(selection)); err != nil {
		t.Fatal(err)
	}
	afterDeadline := fixture.plan.LaunchDeadline.Add(30 * time.Minute)
	_, err := fixture.reader(t).ReadCurrent(t.Context(), afterDeadline)
	if !errors.Is(err, bootstrap.ErrFounderPlanExpired) || !errors.Is(err, ErrFounderSelection) {
		t.Fatalf("expired plan read = %v", err)
	}
	// runAdmittedFounder wraps the read once more.
	wrapped := fmt.Errorf("%w: read selected seed authority: %w", ErrFounderRuntime, err)
	if !founderNeedsOperator(wrapped) {
		t.Fatalf("expired plan is not operator action: %v", wrapped)
	}
}

func TestSelectionFloorRollbackIsClassifiedAsOperatorActionThroughWrappers(t *testing.T) {
	fixture := newFounderSelectionFixture(t)
	a := fixture.publish(t, fixture.selection)
	if err := fixture.floor.Initialize(2, digestWire(a)); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now)
	wrapped := fmt.Errorf("%w: read selected seed authority: %w", ErrFounderRuntime, err)
	if !errors.Is(err, ErrFounderSelectionFloor) || !founderNeedsOperator(wrapped) {
		t.Fatalf("floor rollback = %v", err)
	}
}
