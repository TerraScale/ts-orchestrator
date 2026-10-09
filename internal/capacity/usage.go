// Package capacity exposes read-only resource usage for benchmark windows.
package capacity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

const Retention = time.Hour
const MaxGap = time.Minute

type Stats struct {
	Mean          float64   `json:"mean"`
	Min           float64   `json:"min"`
	Max           float64   `json:"max"`
	Samples       int       `json:"samples"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Complete      bool      `json:"complete"`
	MaxUpperBound *float64  `json:"max_upper_bound,omitempty"`
}

type Resource struct {
	Usage    *Stats `json:"usage"`
	Request  *Stats `json:"request"`
	Limit    *Stats `json:"limit"`
	Headroom *Stats `json:"headroom"`
}

type Row struct {
	Node        string   `json:"node,omitempty"`
	Service     string   `json:"service,omitempty"`
	Environment string   `json:"environment,omitempty"`
	CPU         Resource `json:"cpu_cores"`
	Memory      Resource `json:"memory_bytes"`
}

type Usage struct {
	Region    string    `json:"region"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Complete  bool      `json:"complete"`
	Truncated bool      `json:"truncated"`
	Nodes     []Row     `json:"nodes"`
	Services  []Row     `json:"services"`
	Replicas  []Row     `json:"replicas"`
	Missing   []string  `json:"missing"`
}

type Store struct {
	Region   string
	History  *observability.History
	mu       sync.Mutex
	last     map[string]time.Time
	expected func(context.Context, time.Time, time.Time) ([]hostload.UsageInterval, error)
}

func (s *Store) SetExpected(f func(context.Context, time.Time, time.Time) ([]hostload.UsageInterval, error)) {
	s.mu.Lock()
	s.expected = f
	s.mu.Unlock()
}
func (s *Store) Expected(ctx context.Context, from, to time.Time) ([]hostload.UsageInterval, error) {
	s.mu.Lock()
	f := s.expected
	s.mu.Unlock()
	if f == nil {
		return nil, errors.New("regional inventory unavailable")
	}
	return f(ctx, from, to)
}

func NewStore(region string) *Store {
	return &Store{Region: region, History: observability.NewHistory(observability.HistoryConfig{Interval: 5 * time.Second, StaleAfter: Retention}), last: map[string]time.Time{}}
}

// Record uses controller receive time and adopted requests for every allocated
// role, including placeholders supplied by the controller when usage is unknown.
func (s *Store) Record(origin hostload.Origin, report hostload.Report, requests map[string]hostload.Request) error {
	if origin.Cell != s.Region || origin.Node == "" {
		return errors.New("capacity report origin mismatch")
	}
	if err := report.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.last[origin.Node]) < hostload.DefaultMinInterval {
		return hostload.ErrTooFrequent
	}
	for node, at := range s.last {
		if now.Sub(at) > Retention {
			delete(s.last, node)
		}
	}
	if _, ok := s.last[origin.Node]; !ok && len(s.last) >= 256 {
		return errors.New("capacity node limit reached")
	}
	s.last[origin.Node] = now
	var samples []observability.Sample
	add := func(service, metric string, value float64) {
		samples = append(samples, observability.Sample{Metric: "capacity_" + metric, Labels: observability.L("node", origin.Node, "service", service, "environment", origin.Environment), Value: value})
	}
	var cpuRequest, memoryRequest float64
	requestsKnown := true
	for _, role := range report.Roles {
		request, known := requests[role.Role]
		if known {
			add(role.Role, "cpu_request", request.CPUCores)
			add(role.Role, "memory_request", float64(request.MemoryBytes))
			cpuRequest += request.CPUCores
			memoryRequest += float64(request.MemoryBytes)
		} else {
			requestsKnown = false
		}
		if role.CPUCores != nil {
			add(role.Role, "cpu_usage", *role.CPUCores)
		}
		if role.MemoryBytes != nil {
			add(role.Role, "memory_usage", float64(*role.MemoryBytes))
		}
		if role.LimitsRead {
			cpuLimit, memoryLimit := float64(report.Host.CPUCores), float64(report.Host.MemoryBytes)
			if role.CPULimit != nil {
				cpuLimit = *role.CPULimit
			}
			if role.MemoryLimit != nil {
				memoryLimit = float64(*role.MemoryLimit)
			}
			if cpuLimit > 0 {
				add(role.Role, "cpu_limit", cpuLimit)
				if role.CPUCores != nil {
					add(role.Role, "cpu_headroom", max(0, cpuLimit-*role.CPUCores))
				}
			}
			if memoryLimit > 0 {
				add(role.Role, "memory_limit", memoryLimit)
				if role.MemoryBytes != nil {
					add(role.Role, "memory_headroom", max(0, memoryLimit-float64(*role.MemoryBytes)))
				}
			}
		}
	}
	if requestsKnown {
		add("", "cpu_request", cpuRequest)
		add("", "memory_request", memoryRequest)
	}
	if report.Host.CPUCores > 0 {
		limit := float64(report.Host.CPUCores)
		add("", "cpu_limit", limit)
		if report.Host.CPU != nil {
			add("", "cpu_usage", limit**report.Host.CPU)
			add("", "cpu_headroom", limit*(1-*report.Host.CPU))
		}
	}
	if report.Host.MemoryBytes > 0 {
		limit := float64(report.Host.MemoryBytes)
		add("", "memory_limit", limit)
		if report.Host.Memory != nil {
			add("", "memory_usage", limit**report.Host.Memory)
			add("", "memory_headroom", limit*(1-*report.Host.Memory))
		}
	}
	s.History.Append(now, samples)
	return nil
}

func ValidateWindow(region string, from, to, now time.Time) error {
	if region != "gru" && region != "sfo" {
		return errors.New("region must be gru or sfo")
	}
	if from.IsZero() || !from.Before(to) || from.Before(now.Add(-Retention)) || to.After(now.Add(5*time.Second)) {
		return errors.New("from/to must be an increasing RFC3339 window within the last hour")
	}
	return nil
}

func summarize(points []observability.Point, from, to time.Time) *Stats {
	if len(points) == 0 {
		return nil
	}
	s := &Stats{Min: points[0].Min, Max: points[0].Max, From: points[0].Time, To: points[len(points)-1].Time, Complete: len(points) >= 2}
	previous := from
	allowedGap := min(MaxGap, max(10*time.Second, to.Sub(from)/4))
	for _, point := range points {
		s.Mean += point.Value
		s.Min, s.Max = min(s.Min, point.Min), max(s.Max, point.Max)
		if point.Time.Sub(previous) > allowedGap {
			s.Complete = false
		}
		previous = point.Time
		s.Samples++
	}
	s.Mean /= float64(s.Samples)
	if s.From.After(from.Add(allowedGap)) || s.To.Before(to.Add(-allowedGap)) {
		s.Complete = false
	}
	return s
}

// Query aligns active replica measurements before summarizing service totals.
func (s *Store) Query(from, to time.Time, expected []hostload.UsageInterval) (Usage, error) {
	result := Usage{Region: s.Region, From: from, To: to, Nodes: []Row{}, Services: []Row{}, Replicas: []Row{}, Missing: []string{}, Complete: true}
	if err := ValidateWindow(s.Region, from, to, time.Now()); err != nil {
		return result, err
	}
	rows := map[string]*replicaSeries{}
	keyFor := func(node, environment, service string) string { return node + "/" + environment + "/" + service }
	for _, interval := range expected {
		key := keyFor(interval.Node, interval.Environment, interval.Role)
		if rows[key] == nil {
			rows[key] = &replicaSeries{Row: Row{Node: interval.Node, Environment: interval.Environment, Service: interval.Role}, metrics: map[string][]observability.Point{}}
		}
		rows[key].active = append(rows[key].active, interval)
	}
	for _, metric := range resourceMetrics {
		rangeResult := s.History.Range(observability.HistoryQuery{Metric: "capacity_" + metric, Start: from, End: to, Tier: observability.TierRaw, MaxSeries: 4096})
		result.Truncated = result.Truncated || rangeResult.Truncated
		for _, series := range rangeResult.Series {
			// Raw timestamps have millisecond precision; keep the window exclusive at its end.
			points := windowPoints(series.Points, from, to)
			if len(points) == 0 {
				continue
			}
			node, environment, service := series.Labels["node"], series.Labels["environment"], series.Labels["service"]
			key := keyFor(node, environment, service)
			row := rows[key]
			if row == nil {
				if expected != nil {
					continue // Authoritative inventory says this identity was inactive.
				}
				row = &replicaSeries{Row: Row{Node: node, Service: service, Environment: environment}, active: []hostload.UsageInterval{{From: from, To: to}}, metrics: map[string][]observability.Point{}}
				rows[key] = row
			}
			row.metrics[metric] = points
		}
	}
	services := map[string][]*replicaSeries{}
	for _, key := range slices.Sorted(maps.Keys(rows)) {
		series := rows[key]
		for _, metric := range resourceMetrics {
			setStats(&series.Row, metric, summarizeReplica(series.metrics[metric], series.active))
		}
		row := series.Row
		if !rowComplete(row) {
			result.Complete = false
		}
		if row.Service == "" {
			result.Nodes = append(result.Nodes, row)
			if row.CPU.Usage == nil && row.Memory.Usage == nil {
				result.Missing = append(result.Missing, row.Node)
			}
			continue
		}
		result.Replicas = append(result.Replicas, row)
		if row.CPU.Usage == nil && row.Memory.Usage == nil {
			result.Missing = append(result.Missing, row.Node+"/"+row.Service)
		}
		key = row.Environment + "/" + row.Service
		services[key] = append(services[key], series)
	}
	for _, key := range slices.Sorted(maps.Keys(services)) {
		replicas := services[key]
		row := Row{Service: replicas[0].Service, Environment: replicas[0].Environment}
		for _, metric := range resourceMetrics {
			setStats(&row, metric, aggregateMetric(replicas, metric, from, to))
		}
		if !rowComplete(row) {
			result.Complete = false
		}
		result.Services = append(result.Services, row)
	}
	slices.Sort(result.Missing)
	result.Missing = slices.Compact(result.Missing)
	result.Truncated = result.Truncated || s.History.DroppedBetween(from, to)
	result.Complete = result.Complete && !result.Truncated && len(result.Missing) == 0 && len(result.Nodes) > 0 && len(result.Replicas) > 0
	return result, nil
}

func rowComplete(row Row) bool {
	for _, r := range []Resource{row.CPU, row.Memory} {
		for _, stat := range []*Stats{r.Usage, r.Request, r.Limit, r.Headroom} {
			if stat == nil || !stat.Complete {
				return false
			}
		}
	}
	return true
}

func (s *Store) Handler(expected func(context.Context, time.Time, time.Time) ([]hostload.UsageInterval, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("from"))
		to, toErr := time.Parse(time.RFC3339Nano, r.URL.Query().Get("to"))
		if err != nil || toErr != nil || r.URL.Query().Get("region") != s.Region {
			http.Error(w, "region, from and to are required", 400)
			return
		}
		if err := ValidateWindow(s.Region, from, to, time.Now()); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var nodes []hostload.UsageInterval
		if expected != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			nodes, err = expected(ctx, from, to)
			if err != nil {
				http.Error(w, "regional inventory unavailable", 503)
				return
			}
		}
		result, err := s.Query(from, to, nodes)
		if err != nil {
			http.Error(w, fmt.Sprint(err), 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(result)
	})
}
