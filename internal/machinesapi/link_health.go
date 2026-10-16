package machinesapi

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// LinkHealth is the public health projection of authenticated regional
// snapshots. Consumers must expire the original per-probe times independently.
type LinkHealth struct {
	Version    int                `json:"version"`
	Region     string             `json:"region"`
	ObservedAt time.Time          `json:"observed_at"`
	Expected   []string           `json:"expected"`
	Missing    []string           `json:"missing"`
	Members    []LinkHealthMember `json:"members"`
}

// LinkHealthMember deliberately excludes addresses, credentials and errors.
type LinkHealthMember struct {
	Member     string                          `json:"member"`
	ObservedAt time.Time                       `json:"observed_at"`
	Links      []observability.RegionLinkProbe `json:"links"`
}

func (s *Server) linkHealth(w http.ResponseWriter, r *http.Request) {
	unavailable := func() {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "regional link health is unavailable")
	}
	if s.links == nil {
		unavailable()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	// Public requests share one bounded local gather, including failed gathers.
	cluster, err := s.linkCache.Get(ctx, func(ctx context.Context) (observability.ClusterSnapshot, error) {
		return s.links.Cluster(ctx, false)
	})
	if err != nil || cluster.Cell == "" || cluster.ObservedAt.IsZero() ||
		len(cluster.Expected) == 0 || len(cluster.Expected) > 16 || len(cluster.Members) > 16 || len(cluster.Missing) > 16 {
		unavailable()
		return
	}
	report := LinkHealth{Version: observability.SnapshotVersion, Region: cluster.Cell, ObservedAt: cluster.ObservedAt,
		Expected: cluster.Expected, Missing: slices.Clone(cluster.Expected), Members: []LinkHealthMember{}}
	seen := map[string]bool{}
	for _, snapshot := range cluster.Members {
		if snapshot.Cell != cluster.Cell || !slices.Contains(cluster.Expected, snapshot.Member) ||
			seen[snapshot.Member] || len(snapshot.Links) > 32 {
			unavailable()
			return
		}
		seen[snapshot.Member] = true
		report.Missing = slices.DeleteFunc(report.Missing, func(member string) bool { return member == snapshot.Member })
		links := slices.Clone(snapshot.Links)
		if links == nil {
			links = []observability.RegionLinkProbe{}
		}
		report.Members = append(report.Members, LinkHealthMember{Member: snapshot.Member, ObservedAt: snapshot.ObservedAt, Links: links})
	}
	if report.Missing == nil {
		report.Missing = []string{}
	}
	data, err := json.Marshal(report)
	if err != nil || len(data) > 128<<10 {
		unavailable()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
