package logs

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNormalizeReplacesVolatileParts(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"  peer 42 failed  ", "peer N failed"},
		{"request 3f2504e0-4f89-11d3-9a0c-0305e82c3301 timed out", "request N timed out"},
		{"lease 01ARZ3NDEKTSV4RRFFQ69G5FAV expired", "lease N expired"},
		{"dial tcp 10.251.0.11:6222 refused", "dial tcp N refused"},
		{"node 10.200.0.1 ready", "node N ready"},
		{"store abc1f9 at deadbeef01", "store N at N"},
		{"word dead beef", "word dead beef"},
	} {
		if got := Normalize(tc.in); got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeKeepsAtMost160BytesAtAUTF8Boundary(t *testing.T) {
	got := Normalize(strings.Repeat("é", 200))
	if len(got) > 160 || len(got)%2 != 0 || got != strings.Repeat("é", len(got)/2) {
		t.Fatalf("Normalize kept %d bytes, want at most 160 whole runes", len(got))
	}
}

func TestCounterCountsClassesAndKeepsTheFirstExample(t *testing.T) {
	c := NewCounter("gru", "gru-1-ctl-1")
	c.Add(Record{Service: "terrabase", Level: LevelWarn, Component: "Sender", Message: "retry N", Example: "retry 1"})
	c.Add(Record{Service: "terrabase", Level: LevelWarn, Component: "Sender", Message: "retry N", Example: "retry 2"})
	c.Add(Record{Service: "terrabase", Level: LevelError, Component: "Sender", Message: "retry N", Example: "retry 3"})

	window := c.Flush(time.Date(2026, 10, 9, 19, 31, 0, 0, time.UTC))
	want := []Class{
		{Service: "terrabase", Level: LevelWarn, Component: "Sender", Message: "retry N", Count: 2, Example: "retry 1"},
		{Service: "terrabase", Level: LevelError, Component: "Sender", Message: "retry N", Count: 1, Example: "retry 3"},
	}
	if !slices.Equal(window.Classes, want) {
		t.Fatalf("classes = %+v\nwant %+v", window.Classes, want)
	}
}

func TestFlushStartsTheNextMinuteEmptyAndNumbersWindows(t *testing.T) {
	c := NewCounter("gru", "gru-1-ctl-1")
	minute := time.Date(2026, 10, 9, 19, 31, 0, 0, time.UTC)
	c.Add(Record{Service: "x", Level: LevelInfo, Message: "a"})
	first := c.Flush(minute)
	second := c.Flush(minute.Add(time.Minute))

	if first.Seq != 0 || second.Seq != 1 || first.Boot != second.Boot || first.Boot == "" {
		t.Fatalf("seq %d, %d; boot %q, %q", first.Seq, second.Seq, first.Boot, second.Boot)
	}
	if len(second.Classes) != 0 || second.Classes == nil {
		t.Fatalf("silent minute classes = %#v, want an empty list", second.Classes)
	}
	if other := NewCounter("gru", "gru-1-ctl-1"); other.Flush(minute).Boot == first.Boot {
		t.Fatal("a new counter reused the boot")
	}
}

func TestWindowJSONMatchesWindowV1(t *testing.T) {
	c := NewCounter("gru", "gru-1-ctl-1")
	c.Add(Record{Service: "ts-orchestrator", Level: LevelWarn, Component: "nats", Message: "slow consumer N", Example: "[1] [WRN] slow consumer 3"})
	data, err := json.Marshal(c.Flush(time.Date(2026, 10, 9, 19, 31, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"region":"gru","node":"gru-1-ctl-1","minute":"2026-10-09T19:31:00Z","boot":"`
	if !strings.HasPrefix(string(data), want) {
		t.Fatalf("window = %s, want prefix %s", data, want)
	}
	tail := `"seq":0,"classes":[{"service":"ts-orchestrator","level":"WARN","component":"nats","message":"slow consumer N","count":1,"example":"[1] [WRN] slow consumer 3"}],"dropped":0}`
	if !strings.HasSuffix(string(data), tail) {
		t.Fatalf("window = %s, want suffix %s", data, tail)
	}
}

func TestFlushKeepsTheMostFrequent128ClassesAndCountsTheRest(t *testing.T) {
	c := NewCounter("gru", "gru-1-ctl-1")
	for i := range 130 {
		for range i + 1 {
			c.Add(Record{Service: "terrabase", Level: LevelWarn, Message: fmt.Sprintf("class %03d", i)})
		}
	}
	window := c.Flush(time.Date(2026, 10, 9, 19, 31, 0, 0, time.UTC))
	if len(window.Classes) != 128 || window.Classes[0].Count != 130 || window.Classes[127].Count != 3 {
		t.Fatalf("kept %d classes, first %d, last %d", len(window.Classes), window.Classes[0].Count, window.Classes[127].Count)
	}
	if window.Dropped != 1+2 {
		t.Fatalf("dropped %d, want the 1 and 2 records of the two least frequent classes", window.Dropped)
	}
}

func TestFlushOrdersTiesBySeverityThenText(t *testing.T) {
	c := NewCounter("gru", "gru-1-ctl-1")
	c.Add(Record{Service: "a", Level: LevelInfo, Message: "b"})
	c.Add(Record{Service: "a", Level: LevelError, Message: "z"})
	c.Add(Record{Service: "a", Level: LevelWarn, Message: "a"})
	window := c.Flush(time.Date(2026, 10, 9, 19, 31, 0, 0, time.UTC))
	var levels []string
	for _, class := range window.Classes {
		levels = append(levels, class.Level)
	}
	if fmt.Sprint(levels) != "[ERROR WARN INFO]" {
		t.Fatalf("order %v, want the more severe level first", levels)
	}
}

func TestFlushKeepsEachWindowUnder64KiB(t *testing.T) {
	c := NewCounter("gru", "gru-1-ctl-1")
	long := strings.Repeat("m", 160)
	for i := range 128 {
		c.Add(Record{Service: "terrabase", Level: LevelWarn, Message: fmt.Sprintf("%03d%s", i, long), Example: strings.Repeat("e", 512)})
	}
	window := c.Flush(time.Date(2026, 10, 9, 19, 31, 0, 0, time.UTC))
	data, err := json.Marshal(window)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxWindowBytes {
		t.Fatalf("window is %d bytes", len(data))
	}
	if len(window.Classes) >= 128 || window.Dropped != 128-len(window.Classes) {
		t.Fatalf("kept %d classes and dropped %d records; each class has one record", len(window.Classes), window.Dropped)
	}
}
