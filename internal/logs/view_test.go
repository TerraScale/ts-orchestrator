package logs

import (
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestSummaryCountsNodesAndLatestExample(t *testing.T) {
	p := newLogPipeline(t)
	testNow := time.Now().UTC().Truncate(time.Minute)
	older := testClass("api", "WARN", "slow", 3)
	newer := older
	newer.Example = "slow, newest"
	p.publish(t, p.key, testWindow("node-a", "b1", 0, testNow.Add(-10*time.Minute), older))
	p.publish(t, p.key, testWindow("node-b", "b1", 0, testNow.Add(-5*time.Minute), newer, testClass("api", "ERROR", "boom", 1)))

	reply := p.query(t, "window=1h")
	wantTotals := []Total{{Service: "api", Level: LevelWarn, Count: 6}, {Service: "api", Level: LevelError, Count: 1}}
	if !slices.Equal(reply.Totals, wantTotals) {
		t.Fatalf("totals = %+v, want %+v", reply.Totals, wantTotals)
	}
	if len(reply.Classes) != 2 || reply.Classes[0].Message != "slow" {
		t.Fatalf("classes = %+v, want slow first", reply.Classes)
	}
	slow := reply.Classes[0]
	if slow.Count != 6 || !slices.Equal(slow.Nodes, []string{"node-a", "node-b"}) || slow.Example != "slow, newest" {
		t.Fatalf("slow = %+v", slow)
	}
	if !slow.First.Equal(testNow.Add(-10*time.Minute)) || !slow.Last.Equal(testNow.Add(-5*time.Minute)) {
		t.Fatalf("first, last = %v, %v", slow.First, slow.Last)
	}
}

func TestSummaryWindowsAndRetention(t *testing.T) {
	p := newLogPipeline(t)
	testNow := time.Now().UTC().Truncate(time.Minute)
	p.publish(t, p.key, testWindow("node-a", "b1", 0, testNow.Add(-30*time.Minute), testClass("api", "INFO", "a", 1)))
	p.publish(t, p.key, testWindow("node-a", "b1", 1, testNow.Add(-3*time.Hour), testClass("api", "INFO", "b", 1)))
	p.publish(t, p.key, testWindow("node-a", "b1", 2, testNow.Add(-25*time.Hour), testClass("api", "INFO", "c", 1)))

	count := func(window string) int {
		total := 0
		for _, row := range p.query(t, "window="+window).Totals {
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
	p := newLogPipeline(t)
	testNow := time.Now().UTC().Truncate(time.Minute)
	classes := testClass("api", "INFO", "tick", 1)
	for _, seq := range []uint64{0, 1, 2, 1} {
		p.publish(t, p.key, testWindow("node-a", "b1", seq, testNow, classes))
	}
	if got := p.query(t, "window=1h").Totals[0].Count; got != 3 {
		t.Fatalf("count after replay = %d, want 3", got)
	}

	p.publish(t, p.key, testWindow("node-a", "b1", 5, testNow, classes))
	if gaps := p.query(t, "window=1h").Gaps; gaps != 2 {
		t.Fatalf("gaps = %d, want 2 lost minutes", gaps)
	}

	p.publish(t, p.key, testWindow("node-a", "b2", 0, testNow, classes))
	if gaps := p.query(t, "window=1h").Gaps; gaps != 2 {
		t.Fatalf("a new boot counted gaps: %d", gaps)
	}

	p.stop()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("log follower did not stop before replay")
	}
	p.http.Close()
	p.follow(t, NewView("gru"))
	if reply := p.query(t, "service=api"); len(reply.Classes) != 1 || reply.Classes[0].Count != 5 || reply.Gaps != 2 {
		t.Fatalf("rebuilt durable log view = %+v", reply)
	}
}

func TestAddEvictsLeastRecentlySeenClassWhenFull(t *testing.T) {
	p := newLogPipeline(t)
	now := time.Now().UTC().Truncate(time.Minute)
	p.publish(t, p.key, testWindow("node-a", "b1", 0, now.Add(-time.Minute), testClass("obsolete", LevelInfo, "old", 1)))
	p.sync(t)
	// The barrier occupies one of the retained class keys.
	filler := make([]Class, 0, maxClassKeys-2)
	for i := range maxClassKeys - 2 {
		filler = append(filler, testClass("filler", LevelInfo, strconv.Itoa(i), 1))
	}
	var seq uint64 = 1
	for len(filler) > 0 {
		n := min(128, len(filler))
		p.publish(t, p.key, testWindow("node-a", "b1", seq, now, filler[:n]...))
		filler = filler[n:]
		seq++
	}
	if reply := p.query(t, "service=filler&limit=500"); len(reply.Totals) != 1 || reply.Totals[0].Count != maxClassKeys-2 || !reply.Truncated {
		t.Fatalf("full view filler totals = %+v, truncated = %v", reply.Totals, reply.Truncated)
	}
	if reply := p.query(t, "service=obsolete"); len(reply.Classes) != 1 {
		t.Fatalf("old class before eviction = %+v", reply.Classes)
	}
	p.publish(t, p.key, testWindow("node-a", "b1", seq, now, testClass("new", LevelError, "new", 1)))
	if reply := p.query(t, "service=obsolete"); len(reply.Classes) != 0 {
		t.Fatalf("old class after eviction = %+v", reply.Classes)
	}
	if reply := p.query(t, "service=new"); len(reply.Classes) != 1 || reply.Classes[0].Count != 1 {
		t.Fatalf("new class after eviction = %+v", reply.Classes)
	}
	if reply := p.query(t, "service=filler"); len(reply.Totals) != 1 || reply.Totals[0].Count != maxClassKeys-2 {
		t.Fatalf("filler classes after eviction = %+v", reply.Totals)
	}
}

func TestSummaryFiltersSortsAndLimits(t *testing.T) {
	p := newLogPipeline(t)
	testNow := time.Now().UTC().Truncate(time.Minute)
	p.publish(t, p.key, testWindow("node-a", "b1", 0, testNow,
		testClass("api", "WARN", "a", 10),
		testClass("api", "ERROR", "b", 10),
		testClass("web", "ERROR", "c", 30),
		testClass("api", "INFO", "d", 1),
	))

	reply := p.query(t, "window=1h&min_level=WARN&limit=2")
	var messages []string
	for _, class := range reply.Classes {
		messages = append(messages, class.Message)
	}
	if !slices.Equal(messages, []string{"c", "b"}) || !reply.Truncated {
		t.Fatalf("classes = %v truncated = %v; want the two most frequent, ties to the more severe", messages, reply.Truncated)
	}
	wantTotals := []Total{{"api", LevelWarn, 10}, {"api", LevelError, 10}, {"web", LevelError, 30}}
	if !slices.Equal(reply.Totals, wantTotals) {
		t.Fatalf("totals = %+v, want %+v; totals are not limited", reply.Totals, wantTotals)
	}

	reply = p.query(t, "window=1h&service=api")
	messages = messages[:0]
	for _, class := range reply.Classes {
		messages = append(messages, class.Message)
	}
	if !slices.Equal(messages, []string{"b", "a", "d"}) || reply.Truncated {
		t.Fatalf("api classes = %v truncated = %v", messages, reply.Truncated)
	}
}

func TestErrorsListsLastHourWarnAndError(t *testing.T) {
	p := newLogPipeline(t)
	testNow := time.Now().UTC().Truncate(time.Minute)
	p.publish(t, p.key, testWindow("node-a", "b1", 0, testNow.Add(-30*time.Minute),
		testClass("api", "WARN", "recent", 2), testClass("api", "INFO", "quiet", 9)))
	p.publish(t, p.key, testWindow("node-a", "b1", 1, testNow.Add(-2*time.Hour), testClass("api", "ERROR", "old", 5)))

	classes := p.query(t, "min_level=WARN&limit=10").Classes
	if len(classes) != 1 || classes[0].Message != "recent" || classes[0].Level != LevelWarn {
		t.Fatalf("errors = %+v, want only the recent WARN", classes)
	}
}
