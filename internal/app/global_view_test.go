package app

import (
	"reflect"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/logs"
)

func TestLogErrorsMapsEveryField(t *testing.T) {
	t.Parallel()
	last := time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC)
	classes := []logs.ReplyClass{{Service: "terrabase", Level: "ERROR", Component: "replica", Message: "lag high",
		Count: 7, Nodes: []string{"gru-n01", "gru-n02", "gru-n03"}, First: last.Add(-time.Hour), Last: last, Example: "lag 9s"}}

	got := logErrors(classes)
	want := []globalview.Error{{At: last, Level: "ERROR", Service: "terrabase", Component: "replica", Message: "lag high",
		Count: 7, Nodes: []string{"gru-n01", "gru-n02", "gru-n03"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("logErrors = %+v, want %+v", got, want)
	}
}

func TestLogErrorsNilIsNil(t *testing.T) {
	t.Parallel()
	if got := logErrors(nil); got != nil {
		t.Fatalf("logErrors(nil) = %+v, want nil", got)
	}
}
