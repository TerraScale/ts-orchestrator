package logs

import (
	"cmp"
	"encoding/json"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const (
	maxClasses     = 128
	maxWindowBytes = 64 << 10
)

// Window is one node's records for one minute, the JSON the host agent publishes.
type Window struct {
	Version int       `json:"v"`
	Region  string    `json:"region"`
	Node    string    `json:"node"`
	Minute  time.Time `json:"minute"`
	Boot    string    `json:"boot"`
	Seq     uint64    `json:"seq"`
	Classes []Class   `json:"classes"`
	Dropped int       `json:"dropped"`
}

// Class is one message class in a window, with its records in the minute.
type Class struct {
	Service   string `json:"service"`
	Level     string `json:"level"`
	Component string `json:"component"`
	Message   string `json:"message"`
	Count     int    `json:"count"`
	Example   string `json:"example"`
}

// Counter counts a node's records one minute at a time.
type Counter struct {
	region, node string
	// boot is new per process: a restarted agent starts seq again.
	boot    string
	seq     uint64
	classes map[Class]tally
}

type tally struct {
	count   int
	example string
}

// NewCounter starts a counter for a process, with a new boot.
func NewCounter(region, node string) *Counter {
	return &Counter{region: region, node: node, boot: entityid.New(), classes: make(map[Class]tally)}
}

// Add counts one record in the minute being counted. A class keeps the example of its first record.
func (c *Counter) Add(r Record) {
	key := Class{Service: r.Service, Level: r.Level, Component: r.Component, Message: r.Message}
	t, seen := c.classes[key]
	if !seen {
		t.example = r.Example
	}
	t.count++
	c.classes[key] = t
}

// Flush ends a minute and returns its window. The window keeps the most frequent
// classes and counts the rest as dropped; the counter starts the next minute empty.
func (c *Counter) Flush(minute time.Time) Window {
	classes := make([]Class, 0, len(c.classes))
	for key, t := range c.classes {
		key.Count, key.Example = t.count, t.example
		classes = append(classes, key)
	}
	clear(c.classes)
	slices.SortFunc(classes, compareClasses)
	window := Window{Version: 1, Region: c.region, Node: c.node, Minute: minute.UTC(), Boot: c.boot, Seq: c.seq, Classes: classes}
	c.seq++
	if len(classes) > maxClasses {
		window.Dropped = sumCounts(classes[maxClasses:])
		window.Classes = classes[:maxClasses]
	}
	for encodedLen(window) > maxWindowBytes {
		last := len(window.Classes) - 1
		window.Dropped += window.Classes[last].Count
		window.Classes = window.Classes[:last]
	}
	return window
}

// compareClasses puts the most frequent first. Ties go to the more severe level, then to text.
func compareClasses(a, b Class) int {
	return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(severity(b.Level), severity(a.Level)),
		cmp.Compare(a.Service, b.Service), cmp.Compare(a.Component, b.Component), cmp.Compare(a.Message, b.Message))
}

func sumCounts(classes []Class) int {
	total := 0
	for _, class := range classes {
		total += class.Count
	}
	return total
}

// encodedLen is the window's JSON size. Marshal cannot fail: every field is a string or a number.
func encodedLen(window Window) int {
	data, _ := json.Marshal(window)
	return len(data)
}
