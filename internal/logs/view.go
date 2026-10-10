package logs

import (
	"cmp"
	"errors"
	"slices"
	"sync"
	"time"
)

// The summary's bounds. The minute ring answers "1h" and the hour ring "24h".
const (
	retention        = 24 * time.Hour
	minuteSlots      = 60
	hourSlots        = 24
	maxClassKeys     = 2048
	maxNodesPerClass = 64
	defaultLimit     = 50
	maxLimit         = 500
	maxServiceBytes  = 64
)

// Request is one query of the region's log summary.
type Request struct {
	Version  int    `json:"v"`
	Window   string `json:"window"`
	MinLevel string `json:"min_level"`
	Service  string `json:"service"`
	Limit    int    `json:"limit"`
}

// Reply answers a Request for one region.
type Reply struct {
	Version   int          `json:"v"`
	Region    string       `json:"region"`
	From      time.Time    `json:"from"`
	To        time.Time    `json:"to"`
	Totals    []Total      `json:"totals"`
	Classes   []ReplyClass `json:"classes"`
	Gaps      int          `json:"gaps"`
	Truncated bool         `json:"truncated"`
}

// Total is the records of one service and level in the window.
type Total struct {
	Service string `json:"service"`
	Level   string `json:"level"`
	Count   int    `json:"count"`
}

// ReplyClass is one class in the window, with the nodes that logged it.
type ReplyClass struct {
	Service   string    `json:"service"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	Nodes     []string  `json:"nodes"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Example   string    `json:"example"`
}

// View is one region's log summary, built from the node windows. It is safe for concurrent use.
type View struct {
	mu      sync.Mutex
	region  string
	classes map[Class]*classStats
	seqs    map[nodeBoot]seqState
	pruned  time.Time
	gaps    int
	evicted int
}

// classStats is one class's counts, per minute and per hour, over the retention.
type classStats struct {
	minutes     [minuteSlots]bucket
	hours       [hourSlots]bucket
	nodes       map[string]struct{}
	first, last time.Time
	example     string
}

// bucket counts one period. A slot holds the newest period that maps to it.
type bucket struct {
	period int64
	count  int
}

type nodeBoot struct{ node, boot string }

type seqState struct {
	seq  uint64
	seen time.Time
}

// hit is a matching class with its window count in Class.Count.
type hit struct {
	Class
	stats *classStats
}

// NewView returns an empty summary for region.
func NewView(region string) *View {
	return &View{region: region, classes: make(map[Class]*classStats), seqs: make(map[nodeBoot]seqState)}
}

// Add counts one node window at now. A window older than the retention, or one
// the view already counted, is ignored: a replay after a restart delivers both.
func (v *View) Add(w Window, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if w.Minute.Before(now.Add(-retention)) || !v.track(w, now) {
		return
	}
	for _, c := range w.Classes {
		key := Class{Service: c.Service, Level: c.Level, Component: c.Component, Message: c.Message}
		stats, ok := v.classes[key]
		if !ok {
			stats = v.admit()
			v.classes[key] = stats
		}
		stats.add(w.Node, w.Minute, c)
	}
}

// track reports whether w is new within its boot and counts the sequence gap it reveals.
func (v *View) track(w Window, now time.Time) bool {
	if now.Sub(v.pruned) >= time.Hour {
		v.pruned = now
		for key, state := range v.seqs {
			if state.seen.Before(now.Add(-retention)) {
				delete(v.seqs, key)
			}
		}
	}
	key := nodeBoot{w.Node, w.Boot}
	last, seen := v.seqs[key]
	if seen && w.Seq <= last.seq {
		return false
	}
	if seen && w.Seq > last.seq+1 {
		v.gaps += int(w.Seq - last.seq - 1)
	}
	v.seqs[key] = seqState{seq: w.Seq, seen: now}
	return true
}

// admit makes room for a new class. A full region evicts the class seen least recently.
func (v *View) admit() *classStats {
	if len(v.classes) >= maxClassKeys {
		var oldest Class
		var oldestStats *classStats
		for key, stats := range v.classes {
			if oldestStats == nil || stats.last.Before(oldestStats.last) {
				oldest, oldestStats = key, stats
			}
		}
		delete(v.classes, oldest)
		v.evicted++
	}
	return &classStats{nodes: make(map[string]struct{})}
}

func (s *classStats) add(node string, minute time.Time, c Class) {
	if s.first.IsZero() || minute.Before(s.first) {
		s.first = minute
	}
	if !minute.Before(s.last) {
		s.last, s.example = minute, c.Example
	}
	if len(s.nodes) < maxNodesPerClass {
		s.nodes[node] = struct{}{}
	}
	addBucket(s.minutes[:], minute.Unix()/60, c.Count)
	addBucket(s.hours[:], minute.Unix()/3600, c.Count)
}

// count is the class's records in the window that ends at now.
func (s *classStats) count(window string, now time.Time) int {
	if window == "24h" {
		return sumBuckets(s.hours[:], now.Unix()/3600)
	}
	return sumBuckets(s.minutes[:], now.Unix()/60)
}

func (s *classStats) reply(class Class) ReplyClass {
	nodes := make([]string, 0, len(s.nodes))
	for node := range s.nodes {
		nodes = append(nodes, node)
	}
	slices.Sort(nodes)
	return ReplyClass{Service: class.Service, Level: class.Level, Component: class.Component, Message: class.Message,
		Count: class.Count, Nodes: nodes, First: s.first, Last: s.last, Example: s.example}
}

// addBucket counts into its period's slot. A period older than the slot's is
// outside the ring, so its count is dropped.
func addBucket(slots []bucket, period int64, count int) {
	slot := &slots[period%int64(len(slots))]
	if slot.period < period {
		*slot = bucket{period: period}
	}
	if slot.period == period {
		slot.count += count
	}
}

// sumBuckets totals the periods of the ring that end at now.
func sumBuckets(slots []bucket, now int64) int {
	total := 0
	for _, slot := range slots {
		if slot.period > now-int64(len(slots)) && slot.period <= now {
			total += slot.count
		}
	}
	return total
}

// Validate reports whether the query serves the request.
func (r Request) Validate() error {
	switch {
	case r.Version != 1:
		return errors.New("version must be 1")
	case r.Window != "1h" && r.Window != "24h":
		return errors.New("window must be 1h or 24h")
	case !validLevel(r.MinLevel):
		return errors.New("min_level must be DEBUG, INFO, WARN or ERROR")
	case r.Limit < 0 || r.Limit > maxLimit:
		return errors.New("limit must be from 0 to 500")
	case len(r.Service) > maxServiceBytes:
		return errors.New("service must be at most 64 bytes")
	}
	return nil
}

func (r Request) keeps(class Class) bool {
	return severity(class.Level) >= severity(r.MinLevel) && (r.Service == "" || class.Service == r.Service)
}

// Summary answers req as of now. Totals cover every matching class; the classes
// are the most frequent up to the limit.
func (v *View) Summary(req Request, now time.Time) Reply {
	v.mu.Lock()
	defer v.mu.Unlock()
	reply := Reply{Version: 1, Region: v.region, From: windowStart(req.Window, now), To: now.UTC(), Gaps: v.gaps,
		Totals: []Total{}, Classes: []ReplyClass{}}
	totals := make(map[[2]string]int)
	var hits []hit
	for key, stats := range v.classes {
		if !req.keeps(key) {
			continue
		}
		count := stats.count(req.Window, now)
		if count == 0 {
			continue
		}
		key.Count = count
		totals[[2]string{key.Service, key.Level}] += count
		hits = append(hits, hit{key, stats})
	}
	for pair, count := range totals {
		reply.Totals = append(reply.Totals, Total{Service: pair[0], Level: pair[1], Count: count})
	}
	slices.SortFunc(reply.Totals, compareTotals)
	slices.SortFunc(hits, func(a, b hit) int { return compareClasses(a.Class, b.Class) })
	limit := min(cmp.Or(req.Limit, defaultLimit), maxLimit)
	if len(hits) > limit {
		hits = hits[:limit]
		reply.Truncated = true
	}
	for _, h := range hits {
		reply.Classes = append(reply.Classes, h.stats.reply(h.Class))
	}
	return reply
}

// Errors returns the most frequent WARN and ERROR classes of the last hour, for
// the global rollup. It does no I/O.
func (v *View) Errors(limit int, now time.Time) []ReplyClass {
	return v.Summary(Request{Version: 1, Window: "1h", MinLevel: LevelWarn, Limit: limit}, now).Classes
}

// windowStart is the first instant of the window: 59 minutes back for "1h", 23 hours back for "24h".
func windowStart(window string, now time.Time) time.Time {
	if window == "24h" {
		return now.Truncate(time.Hour).Add(-23 * time.Hour).UTC()
	}
	return now.Truncate(time.Minute).Add(-59 * time.Minute).UTC()
}

func compareTotals(a, b Total) int {
	return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(severity(a.Level), severity(b.Level)))
}
