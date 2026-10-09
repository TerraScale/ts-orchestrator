package observability

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSystemSectionFailureIsVisibleOnMetrics(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(false)
	if _, err := NewCollector(CollectorConfig{Cell: "gru", Member: "a", Role: "host", Registry: registry,
		Health: new(Health), System: func() (SystemView, error) { return SystemView{}, errors.New("proc") }}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	registry.WritePrometheus(&out)
	if !strings.Contains(out.String(), `ts_orch_collect_ok{section="system"} 0`) {
		t.Fatalf("failing system section is not alertable:\n%s", out.String())
	}
}

func TestTruncatedViewsAreVisibleOnMetrics(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	WritePlacementMetrics(&out, PlacementView{Truncated: true})
	WriteNATSMetrics(&out, NATSView{Truncated: true})
	for _, want := range []string{"ts_orch_terrabase_view_truncated 1", "ts_orch_nats_view_truncated 1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("metrics lack %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	databases := make([]DatabaseView, maxLabeledDatabases+1)
	for index := range databases {
		databases[index] = DatabaseView{DatabaseID: fmt.Sprint(index), PartitionID: "00000000002J6YKHD7MH6HKSBC"}
	}
	WritePlacementMetrics(&out, PlacementView{Databases: databases})
	if !strings.Contains(out.String(), "ts_orch_terrabase_view_truncated 1") {
		t.Fatalf("labeled-series cap is not reported:\n%s", out.String())
	}
}

func TestParseProcStatAcceptsLongInterruptLine(t *testing.T) {
	t.Parallel()
	intr := "intr" + strings.Repeat(" 12345678", 20000)
	data := []byte("cpu 100 0 50 1000 5 0 0 0\ncpu0 100 0 50 1000 5 0 0 0\n" + intr + "\nctxt 1\n")
	total, cpus, err := parseProcStat(data)
	if err != nil || cpus != 1 || total.User == 0 {
		t.Fatalf("parseProcStat = %+v, %d, %v", total, cpus, err)
	}
}
