// Package lifecycleaggregate publishes only complete, fresh lifecycle observations.
package lifecycleaggregate

import (
	"context"
	"errors"
	"slices"
	"time"
)

var ErrIncomplete = errors.New("lifecycle aggregate: incomplete or stale observation")
var ErrConflict = errors.New("lifecycle aggregate: generation conflict")

type Scope struct {
	OrganizationID string `json:"organizationId"`
	ProjectID      string `json:"projectId"`
	DatabaseID     string `json:"databaseId"`
}

// Placement must come from the accepted durable placement authority, including
// every accepted region even when that region is currently unavailable.
type Placement struct {
	Scope
	Revision string
	Regions  []Region
}
type Region struct {
	Name              string
	PlacementRevision string
	WriterEpoch       string
}
type Sample struct {
	Scope
	SchemaVersion           int        `json:"schemaVersion"`
	Region                  string     `json:"region"`
	PlacementRevision       string     `json:"placementRevision"`
	WriterEpoch             string     `json:"writerEpoch"`
	ObservedAt              time.Time  `json:"observedAt"`
	LastAuthorizedRequestAt *time.Time `json:"lastAuthorizedRequestAt"`
	DeletionProtection      bool       `json:"deletionProtection"`
	AccessRevoked           bool       `json:"accessRevoked"`
	UsageStoppedAt          *time.Time `json:"usageStoppedAt"`
	RetainUntil             *time.Time `json:"retainUntil"`
	Generation              string     `json:"generation"`
}
type Aggregate struct {
	Scope
	PlacementRevision       string     `json:"placementRevision"`
	Regions                 []Sample   `json:"regions"`
	LastAuthorizedRequestAt *time.Time `json:"lastAuthorizedRequestAt"`
	DeletionProtection      bool       `json:"deletionProtection"`
	ObservedAt              time.Time  `json:"observedAt"`
}

// Combine preserves unknown activity as unknown; sample collection time is
// never substituted for actual authorized customer activity.
func Combine(p Placement, samples []Sample, now time.Time, maxAge time.Duration) (Aggregate, error) {
	if p.OrganizationID == "" || p.ProjectID == "" || p.DatabaseID == "" || p.Revision == "" || len(p.Regions) == 0 || len(p.Regions) > 3 || len(samples) != len(p.Regions) || now.IsZero() || maxAge <= 0 || maxAge > time.Minute {
		return Aggregate{}, ErrIncomplete
	}
	wanted := map[string]Region{}
	for _, region := range p.Regions {
		if !slices.Contains([]string{"GRU", "SFO", "FRA"}, region.Name) || region.PlacementRevision == "" || region.WriterEpoch == "" || wanted[region.Name].Name != "" {
			return Aggregate{}, ErrIncomplete
		}
		wanted[region.Name] = region
	}
	a := Aggregate{Scope: p.Scope, PlacementRevision: p.Revision, Regions: slices.Clone(samples), ObservedAt: now}
	unknown := false
	for _, sample := range samples {
		r, ok := wanted[sample.Region]
		if !ok || sample.SchemaVersion != 1 || sample.Scope != p.Scope || sample.PlacementRevision != r.PlacementRevision || sample.WriterEpoch != r.WriterEpoch || sample.Generation == "" || sample.ObservedAt.IsZero() || now.Sub(sample.ObservedAt) > maxAge || sample.ObservedAt.After(now.Add(5*time.Second)) {
			return Aggregate{}, ErrIncomplete
		}
		delete(wanted, sample.Region)
		for _, stamp := range []*time.Time{sample.LastAuthorizedRequestAt, sample.UsageStoppedAt, sample.RetainUntil} {
			if stamp != nil && stamp.IsZero() {
				return Aggregate{}, ErrIncomplete
			}
		}
		if sample.AccessRevoked != (sample.UsageStoppedAt != nil) || sample.LastAuthorizedRequestAt != nil && sample.LastAuthorizedRequestAt.After(sample.ObservedAt) {
			return Aggregate{}, ErrIncomplete
		}
		if sample.LastAuthorizedRequestAt == nil {
			unknown = true
		} else if a.LastAuthorizedRequestAt == nil || sample.LastAuthorizedRequestAt.After(*a.LastAuthorizedRequestAt) {
			a.LastAuthorizedRequestAt = new(*sample.LastAuthorizedRequestAt)
		}
		a.DeletionProtection = a.DeletionProtection || sample.DeletionProtection
		if sample.ObservedAt.Before(a.ObservedAt) {
			a.ObservedAt = sample.ObservedAt
		}
	}
	if unknown {
		a.LastAuthorizedRequestAt = nil
	}
	slices.SortFunc(a.Regions, func(a, b Sample) int {
		if a.Region < b.Region {
			return -1
		}
		if a.Region > b.Region {
			return 1
		}
		return 0
	})
	return a, nil
}

type Source interface {
	Sample(context.Context, Scope, Region) (Sample, error)
}
type Authority interface {
	Placement(context.Context, Scope) (Placement, error)
}
type Publisher interface {
	Publish(context.Context, Aggregate) error
}

// Run rereads placement after collecting all regions, preventing publication
// against a roster that changed during collection. Publisher also fences this
// revision transactionally against its durable accepted placement generation.
func Run(ctx context.Context, scope Scope, authority Authority, source Source, publisher Publisher, now func() time.Time) error {
	if ctx == nil || authority == nil || source == nil || publisher == nil || now == nil {
		return ErrIncomplete
	}
	p, err := authority.Placement(ctx, scope)
	if err != nil {
		return err
	}
	samples := make([]Sample, 0, len(p.Regions))
	for _, r := range p.Regions {
		s, err := source.Sample(ctx, scope, r)
		if err != nil {
			return err
		}
		samples = append(samples, s)
	}
	a, err := Combine(p, samples, now(), time.Minute)
	if err != nil {
		return err
	}
	latest, err := authority.Placement(ctx, scope)
	if err != nil {
		return err
	}
	if latest.Scope != p.Scope || latest.Revision != p.Revision || !slices.Equal(latest.Regions, p.Regions) {
		return ErrConflict
	}
	return publisher.Publish(ctx, a)
}
