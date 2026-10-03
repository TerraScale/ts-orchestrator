package delivery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/nats.go/jetstream"
)

type diagnosticPlanner struct{ err error }

func (p diagnosticPlanner) Plan(context.Context, Intent) ([]host.Desired, error) {
	return nil, p.err
}

func TestDeliveryProcessReportsPreclaimPlannerStage(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	intent := testIntent(t, s, ctx)
	s.config.Planner = diagnosticPlanner{err: fmt.Errorf("placement could not fit: %w", placement.ErrInsufficientCapacity)}

	terminal, err := s.process(ctx, mustJSON(intent))
	if terminal || !errors.Is(err, placement.ErrInsufficientCapacity) {
		t.Fatalf("process terminal=%t err=%v", terminal, err)
	}
	staged, ok := errors.AsType[deliveryStageError](err)
	if !ok || staged.stage != "planner" {
		t.Fatalf("preclaim stage = %+v, found=%t", staged, ok)
	}
	if class, _ := deliveryFailureClass(err); class != "insufficient_capacity" {
		t.Fatalf("preclaim error class = %q", class)
	}
	if _, err := s.Status(ctx, intent.OperationID); !errors.Is(err, ErrPending) {
		t.Fatalf("planner failure created an operation: %v", err)
	}
}

func TestDeliveryFailureClassUsesSafeKnownCategories(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		class string
		code  uint16
	}{
		{"host snapshot race", errors.New("report changed during host status read: private detail"), "host_snapshot_changed", 0},
		{"unverified host", errors.New("unverified host status cannot drive placement"), "host_status_unverified", 0},
		{"deadline", context.DeadlineExceeded, "timeout", 0},
		{"jetstream API", &jetstream.APIError{Code: 503, Description: "private detail"}, "jetstream_api", 503},
		{"unknown", errors.New("private detail"), "other", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			class, code := deliveryFailureClass(stageDeliveryError("planner", test.err))
			if class != test.class || code != test.code {
				t.Fatalf("class=%q code=%d, want %q %d", class, code, test.class, test.code)
			}
		})
	}
}

// Both host snapshot classes are retryable races, so neither may count
// toward holding an intent; capacity and workload refusals do.
func TestPlannerRefusalExemptsRetryableHostSnapshotClasses(t *testing.T) {
	for _, test := range []struct {
		err     error
		refusal bool
	}{
		{errors.New("report changed during host status read"), false},
		{errors.New("unverified host status cannot drive placement"), false},
		{context.DeadlineExceeded, false},
		{fmt.Errorf("no room: %w", placement.ErrInsufficientCapacity), true},
		{errors.New("unknown planner failure"), true},
	} {
		if got := plannerRefusal(stageDeliveryError("planner", test.err)); got != test.refusal {
			t.Errorf("plannerRefusal(%v) = %t, want %t", test.err, got, test.refusal)
		}
	}
}

func TestDeliveryRetryDiagnosticIsRateLimitedAndOmitsRawError(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	var diagnostics deliveryRetryDiagnostics
	err := stageDeliveryError("planner", fmt.Errorf("private tenant content: %w", placement.ErrInsufficientCapacity))

	diagnostics.report(logger, err)
	diagnostics.report(logger, err)
	if count := strings.Count(output.String(), "delivery intent processing deferred"); count != 1 {
		t.Fatalf("immediate warning count = %d", count)
	}
	diagnostics.next = time.Now().Add(-time.Second)
	diagnostics.report(logger, err)
	message := output.String()
	if count := strings.Count(message, "delivery intent processing deferred"); count != 2 {
		t.Fatalf("later warning count = %d", count)
	}
	if !strings.Contains(message, "stage=planner") || !strings.Contains(message, "cause_class=insufficient_capacity") ||
		!strings.Contains(message, "suppressed=1") || strings.Contains(message, "private tenant content") {
		t.Fatalf("warning fields are unsafe or incomplete: %s", message)
	}
}
