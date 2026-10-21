package observability

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTruncatedViewsAreVisibleOnMetrics(t *testing.T) {
	t.Parallel()
	collector, _ := testCollector(t, "truncated", nil)
	collector.config.Placement = func(context.Context) (PlacementView, error) { return PlacementView{Truncated: true}, nil }
	collector.config.NATS = func(context.Context) (NATSView, error) { return NATSView{Truncated: true}, nil }
	out := metricsOverHTTP(t, collector)
	for _, want := range []string{"ts_orch_terrabase_view_truncated 1", "ts_orch_nats_view_truncated 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics lack %q:\n%s", want, out)
		}
	}

	databases := make([]DatabaseView, maxLabeledDatabases+1)
	for index := range databases {
		databases[index] = DatabaseView{DatabaseID: fmt.Sprint(index), PartitionID: "00000000002J6YKHD7MH6HKSBC"}
	}
	collector, _ = testCollector(t, "capped", nil)
	collector.config.Placement = func(context.Context) (PlacementView, error) { return PlacementView{Databases: databases}, nil }
	out = metricsOverHTTP(t, collector)
	if !strings.Contains(out, "ts_orch_terrabase_view_truncated 1") {
		t.Fatalf("labeled-series cap is not reported:\n%s", out)
	}
}

func TestMetricsOmitCurrentServingWithoutLiveNativeReadiness(t *testing.T) {
	t.Parallel()
	collector, _ := testCollector(t, "durable-only", nil)
	out := metricsOverHTTP(t, collector)
	if strings.Contains(out, `ts_orch_terrabase_replicas{database="db",partition="p0",state="serving"}`) ||
		!strings.Contains(out, `ts_orch_terrabase_members{stage="serving"} 2`) ||
		!strings.Contains(out, `ts_orch_terrabase_replicas{database="db",partition="p0",state="desired"} 3`) {
		t.Fatalf("metrics confused durable progress with current serving:\n%s", out)
	}
}

func TestParseProcStatAcceptsLongInterruptLine(t *testing.T) {
	t.Parallel()
	intr := "intr" + strings.Repeat(" 12345678", 20000)
	data := []byte("cpu 100 0 50 1000 5 0 0 0\ncpu0 100 0 50 1000 5 0 0 0\n" + intr + "\nctxt 1\n")
	root := writeProcFixture(t)
	if err := os.WriteFile(filepath.Join(root, "stat"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	view, err := readSystem(root, nil, nil)
	if err != nil || view.CPUCount != 1 || view.CPUSeconds.User == 0 {
		t.Fatalf("long stat = %+v, %v", view, err)
	}
}
