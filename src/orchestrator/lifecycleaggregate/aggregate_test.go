package lifecycleaggregate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func fixture() (Placement, []Sample, time.Time) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	p := Placement{Scope: Scope{"org", "project", "database"}, Revision: "4", Regions: []Region{{"GRU", "4", "8"}, {"FRA", "4", "9"}}}
	samples := []Sample{}
	for i, r := range p.Regions {
		samples = append(samples, Sample{Scope: p.Scope, SchemaVersion: 1, Region: r.Name, PlacementRevision: r.PlacementRevision, WriterEpoch: r.WriterEpoch, ObservedAt: now, LastAuthorizedRequestAt: new(now.Add(-time.Duration(i+1) * time.Hour)), Generation: "3"})
	}
	return p, samples, now
}
func TestCombineRequiresCompleteFreshSet(t *testing.T) {
	for _, name := range []string{"missing", "duplicate", "stale", "epoch", "foreign scope", "future activity"} {
		t.Run(name, func(t *testing.T) {
			p, s, now := fixture()
			switch name {
			case "missing":
				s = s[:1]
			case "duplicate":
				s[1] = s[0]
			case "stale":
				s[1].ObservedAt = now.Add(-time.Minute - time.Second)
			case "epoch":
				s[1].WriterEpoch = "7"
			case "foreign scope":
				s[1].DatabaseID = "other"
			case "future activity":
				s[1].LastAuthorizedRequestAt = new(now.Add(time.Second))
			}
			if _, err := Combine(p, s, now, time.Minute); !errors.Is(err, ErrIncomplete) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
func TestCombineActualActivityAndProtection(t *testing.T) {
	p, s, now := fixture()
	s[1].DeletionProtection = true
	a, err := Combine(p, s, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !a.DeletionProtection || a.LastAuthorizedRequestAt == nil || !a.LastAuthorizedRequestAt.Equal(*s[0].LastAuthorizedRequestAt) {
		t.Fatalf("incorrect aggregate: %+v", a)
	}
	s[1].LastAuthorizedRequestAt = nil
	a, err = Combine(p, s, now, time.Minute)
	if err != nil || a.LastAuthorizedRequestAt != nil {
		t.Fatalf("unknown activity became idle: %+v %v", a, err)
	}
}

type changingAuthority struct {
	p     Placement
	calls int
}

func (a *changingAuthority) Placement(context.Context, Scope) (Placement, error) {
	a.calls++
	p := a.p
	if a.calls > 1 {
		p.Revision = "5"
	}
	return p, nil
}

type sampleSource []Sample

func (s sampleSource) Sample(_ context.Context, _ Scope, r Region) (Sample, error) {
	for _, v := range s {
		if v.Region == r.Name {
			return v, nil
		}
	}
	return Sample{}, ErrIncomplete
}

type recordingPublisher struct{ calls int }

func (p *recordingPublisher) Publish(context.Context, Aggregate) error { p.calls++; return nil }
func TestRunFencesPlacementGenerationChange(t *testing.T) {
	p, s, now := fixture()
	a := &changingAuthority{p: p}
	pub := new(recordingPublisher)
	err := Run(t.Context(), p.Scope, a, sampleSource(s), pub, func() time.Time { return now })
	if !errors.Is(err, ErrConflict) || pub.calls != 0 {
		t.Fatalf("err=%v publications=%d", err, pub.calls)
	}
}
