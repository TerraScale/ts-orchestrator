package logs

import (
	"reflect"
	"strconv"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 10, 12, 30, 0, 0, time.UTC)

func testClass(service, level, message string, count int) Class {
	return Class{Service: service, Level: level, Component: "core", Message: message, Count: count, Example: message + " example"}
}

func testWindow(node, boot string, seq uint64, minute time.Time, classes ...Class) Window {
	return Window{Version: 1, Region: "gru", Node: node, Minute: minute, Boot: boot, Seq: seq, Classes: classes}
}

func TestSummaryCountsNodesAndLatestExample(t *testing.T) {
	view := NewView("gru")
	older := testClass("api", "WARN", "slow", 3)
	newer := older
	newer.Example = "slow, newest"
	view.Add(testWindow("node-a", "b1", 0, testNow.Add(-10*time.Minute), older), testNow)
	view.Add(testWindow("node-b", "b1", 0, testNow.Add(-5*time.Minute), newer, testClass("api", "ERROR", "boom", 1)), testNow)

	reply := view.Summary(Request{Version: 1, Window: "1h", MinLevel: LevelDebug}, testNow)
	wantTotals := []Total{{Service: "api", Level: LevelWarn, Count: 6}, {Service: "api", Level: LevelError, Count: 1}}
	if !reflect.DeepEqual(reply.Totals, wantTotals) {
		t.Fatalf("totals = %+v, want %+v", reply.Totals, wantTotals)
	}
	if len(reply.Classes) != 2 || reply.Classes[0].Message != "slow" {
		t.Fatalf("classes = %+v, want slow first", reply.Classes)
	}
	slow := reply.Classes[0]
	if slow.Count != 6 || !reflect.DeepEqual(slow.Nodes, []string{"node-a", "node-b"}) || slow.Example != "slow, newest" {
		t.Fatalf("slow = %+v", slow)
	}
	if !slow.First.Equal(testNow.Add(-10*time.Minute)) || !slow.Last.Equal(testNow.Add(-5*time.Minute)) {
		t.Fatalf("first, last = %v, %v", slow.First, slow.Last)
	}
}

func TestSummaryWindowsAndRetention(t *testing.T) {
	view := NewView("gru")
	view.Add(testWindow("node-a", "b1", 0, testNow.Add(-30*time.Minute), testClass("api", "INFO", "a", 1)), testNow)
	view.Add(testWindow("node-a", "b1", 1, testNow.Add(-3*time.Hour), testClass("api", "INFO", "b", 1)), testNow)
	view.Add(testWindow("node-a", "b1", 2, testNow.Add(-25*time.Hour), testClass("api", "INFO", "c", 1)), testNow)

	count := func(window string) int {
		total := 0
		for _, row := range view.Summary(Request{Version: 1, Window: window, MinLevel: LevelDebug}, testNow).Totals {
			total += row.Count
		}
		return total
	}
	if got := count("1h"); got != 1 {
		t.Fatalf("1h count = %d, want 1", got)
	}
	if got := count("24h"); got != 2 {
		t.Fatalf("24h count = %d, want 2: the 25-hour-old window is outside the retention", got)
	}
}

func TestAddSkipsReplayedWindowsAndCountsGaps(t *testing.T) {
	view := NewView("gru")
	classes := testClass("api", "INFO", "tick", 1)
	for _, seq := range []uint64{0, 1, 2, 1} {
		view.Add(testWindow("node-a", "b1", seq, testNow, classes), testNow)
	}
	if got := view.Summary(Request{Version: 1, Window: "1h", MinLevel: LevelDebug}, testNow).Totals[0].Count; got != 3 {
		t.Fatalf("count after replay = %d, want 3", got)
	}

	view.Add(testWindow("node-a", "b1", 5, testNow, classes), testNow)
	if gaps := view.Summary(Request{Version: 1, Window: "1h", MinLevel: LevelDebug}, testNow).Gaps; gaps != 2 {
		t.Fatalf("gaps = %d, want 2 lost minutes", gaps)
	}

	view.Add(testWindow("node-a", "b2", 0, testNow, classes), testNow)
	if gaps := view.Summary(Request{Version: 1, Window: "1h", MinLevel: LevelDebug}, testNow).Gaps; gaps != 2 {
		t.Fatalf("a new boot counted gaps: %d", gaps)
	}
}

func TestAddEvictsLeastRecentlySeenClassWhenFull(t *testing.T) {
	view := NewView("gru")
	early := testNow.Add(-time.Minute)
	view.Add(testWindow("node-a", "b1", 0, early, testClass("api", "INFO", "old", 1)), testNow)
	var filler []Class
	for i := range maxClassKeys - 1 {
		filler = append(filler, testClass("api", "INFO", strconv.Itoa(i), 1))
	}
	view.Add(testWindow("node-a", "b1", 1, testNow, filler...), testNow)
	if len(view.classes) != maxClassKeys || view.evicted != 0 {
		t.Fatalf("classes = %d, evicted = %d; want a full view", len(view.classes), view.evicted)
	}

	view.Add(testWindow("node-a", "b1", 2, testNow, testClass("api", "ERROR", "new", 1)), testNow)
	if _, ok := view.classes[Class{Service: "api", Level: "INFO", Component: "core", Message: "old"}]; ok {
		t.Fatal("the least recently seen class was kept")
	}
	if len(view.classes) != maxClassKeys || view.evicted != 1 {
		t.Fatalf("classes = %d, evicted = %d; want one eviction", len(view.classes), view.evicted)
	}
}

func TestSummaryFiltersSortsAndLimits(t *testing.T) {
	view := NewView("gru")
	view.Add(testWindow("node-a", "b1", 0, testNow,
		testClass("api", "WARN", "a", 10),
		testClass("api", "ERROR", "b", 10),
		testClass("web", "ERROR", "c", 30),
		testClass("api", "INFO", "d", 1),
	), testNow)

	reply := view.Summary(Request{Version: 1, Window: "1h", MinLevel: LevelWarn, Limit: 2}, testNow)
	var messages []string
	for _, class := range reply.Classes {
		messages = append(messages, class.Message)
	}
	if !reflect.DeepEqual(messages, []string{"c", "b"}) || !reply.Truncated {
		t.Fatalf("classes = %v truncated = %v; want the two most frequent, ties to the more severe", messages, reply.Truncated)
	}
	wantTotals := []Total{{"api", LevelWarn, 10}, {"api", LevelError, 10}, {"web", LevelError, 30}}
	if !reflect.DeepEqual(reply.Totals, wantTotals) {
		t.Fatalf("totals = %+v, want %+v; totals are not limited", reply.Totals, wantTotals)
	}

	reply = view.Summary(Request{Version: 1, Window: "1h", MinLevel: LevelDebug, Service: "api"}, testNow)
	messages = messages[:0]
	for _, class := range reply.Classes {
		messages = append(messages, class.Message)
	}
	if !reflect.DeepEqual(messages, []string{"b", "a", "d"}) || reply.Truncated {
		t.Fatalf("api classes = %v truncated = %v", messages, reply.Truncated)
	}
}

func TestErrorsListsLastHourWarnAndError(t *testing.T) {
	view := NewView("gru")
	view.Add(testWindow("node-a", "b1", 0, testNow.Add(-30*time.Minute),
		testClass("api", "WARN", "recent", 2), testClass("api", "INFO", "quiet", 9)), testNow)
	view.Add(testWindow("node-a", "b1", 1, testNow.Add(-2*time.Hour), testClass("api", "ERROR", "old", 5)), testNow)

	classes := view.Errors(10, testNow)
	if len(classes) != 1 || classes[0].Message != "recent" || classes[0].Level != LevelWarn {
		t.Fatalf("errors = %+v, want only the recent WARN", classes)
	}
}

func TestRequestValidate(t *testing.T) {
	valid := Request{Version: 1, Window: "24h", MinLevel: LevelWarn, Limit: 500}
	cases := map[string]func(*Request){
		"version":   func(r *Request) { r.Version = 2 },
		"window":    func(r *Request) { r.Window = "2h" },
		"min_level": func(r *Request) { r.MinLevel = "LOUD" },
		"limit":     func(r *Request) { r.Limit = 501 },
		"service":   func(r *Request) { r.Service = string(make([]byte, maxServiceBytes+1)) },
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	for name, change := range cases {
		request := valid
		change(&request)
		if request.Validate() == nil {
			t.Errorf("%s: request accepted", name)
		}
	}
}
