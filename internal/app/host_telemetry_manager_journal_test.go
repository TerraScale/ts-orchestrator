package app

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
)

func TestManagerUsageCoverageEndsAtPriorJournalPoint(t *testing.T) {
	from := time.Now().UTC().Add(-time.Minute)
	to := from.Add(50 * time.Second)
	registration := host.Registration{Cell: "gru", Node: "host-a", Environment: "production"}
	var points []host.CommittedUsage
	for index := range 3 {
		observation := host.UsageObservation{Registration: registration, Tasks: []host.UsageTask{{Role: "api"}}}
		if index > 0 {
			observation.PriorSequence = uint64(index * 10)
		}
		if index == 2 {
			observation.PreviousSequence, observation.CoveredSequence = 10, 20
		}
		points = append(points, host.CommittedUsage{Observation: observation, Entry: authority.LogEntry{SubjectKey: "gru.host-a", Sequence: uint64((index + 1) * 10), CreatedAt: from.Add(time.Duration(index+1) * 10 * time.Second)}})
	}
	native := []hostload.UsageInterval{{Node: "host-a", Environment: "production", From: from, To: to}, {Node: "host-a", Environment: "production", Role: "terrabase", From: from, To: to}}
	owns := func(role string) bool { return role == "api" }
	intervals := managedUsageIntervals(points, native, nil, owns, from, to)
	var gaps []hostload.UsageInterval
	var managed []hostload.UsageInterval
	for _, interval := range intervals {
		if interval.Unknown != "" {
			gaps = append(gaps, interval)
		}
		if interval.Role == "api" {
			managed = append(managed, interval)
		}
	}
	if len(managed) != 1 || !managed[0].From.Equal(points[0].Entry.CreatedAt) || !managed[0].To.Equal(points[1].Entry.CreatedAt) {
		t.Fatalf("coverage exceeded proven journal bounds: %+v", managed)
	}
	if len(gaps) != 2 || !gaps[0].From.Equal(from) || !gaps[0].To.Equal(points[0].Entry.CreatedAt) || !gaps[1].From.Equal(points[1].Entry.CreatedAt) || !gaps[1].To.Equal(to) {
		t.Fatalf("unknown head/tail was hidden: %+v", gaps)
	}
	if !slices.ContainsFunc(intervals, func(value hostload.UsageInterval) bool { return value.Role == "terrabase" }) {
		t.Fatal("manager history dropped native DATA expectations")
	}
	points[2].Observation.PreviousSequence, points[2].Observation.CoveredSequence = 0, 0
	intervals = managedUsageIntervals(points, native, nil, owns, from, to)
	if slices.ContainsFunc(intervals, func(value hostload.UsageInterval) bool { return value.Role == "api" }) {
		t.Fatal("equal point snapshots invented manager continuity")
	}
	intervals = managedUsageIntervals(points, nil, errors.New("missing native baseline"), owns, from, to)
	if !slices.ContainsFunc(intervals, func(value hostload.UsageInterval) bool { return value.Node == "" && value.Unknown != "" }) {
		t.Fatal("restart backfilled native admission before its baseline")
	}
}
