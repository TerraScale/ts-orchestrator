package terrabase

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	EnvRegion     = "TERRABASE_REGION"
	WANFreshFor   = 2 * time.Minute
	MaxWANRegions = 64
	// WANMaxValue preserves exact integer counts in shared float64 history.
	WANMaxValue  = 1<<53 - 1
	wanBodyBytes = 1 << 20
)

// WANObservation measures incoming replication at one local receiver.
// ObservedAt is the original loopback scrape time, never delivery time.
type WANObservation struct {
	ObservedAt     time.Time   `json:"observed_at"`
	ReceiverRegion string      `json:"receiver_region"`
	Sources        []WANSource `json:"sources"`
}

type WANSource struct {
	SourceRegion       string   `json:"source_region"`
	LagGroups          *float64 `json:"lag_groups"`
	StalenessSeconds   *float64 `json:"staleness_seconds"`
	Members            *float64 `json:"members"`
	Unregistered       *float64 `json:"unregistered"`
	Conflicts          *float64 `json:"conflicts"`
	AheadFailuresTotal *float64 `json:"ahead_failures_total,omitempty"`
}

func (w WANObservation) Fresh(now time.Time) bool {
	return !w.ObservedAt.IsZero() && !w.ObservedAt.After(now) && now.Sub(w.ObservedAt) <= WANFreshFor
}

func (w WANObservation) Validate() error {
	_, offset := w.ObservedAt.Zone()
	if w.ObservedAt.UnixMilli() <= 0 || offset != 0 || !wanRegionRE.MatchString(w.ReceiverRegion) || len(w.Sources) == 0 || len(w.Sources) > MaxWANRegions {
		return errors.New("invalid WAN observation time or source count")
	}
	seen := make(map[string]bool, len(w.Sources))
	for _, source := range w.Sources {
		if !wanRegionRE.MatchString(source.SourceRegion) || seen[source.SourceRegion] {
			return errors.New("invalid or duplicate WAN source region")
		}
		seen[source.SourceRegion] = true
		for _, value := range []*float64{source.LagGroups, source.StalenessSeconds, source.Members, source.Unregistered, source.Conflicts} {
			if value == nil || !validWANValue(*value) {
				return errors.New("missing or invalid WAN gauge")
			}
		}
		for _, value := range []*float64{source.LagGroups, source.Members, source.Unregistered, source.Conflicts, source.AheadFailuresTotal} {
			if value != nil && (!validWANValue(*value) || math.Trunc(*value) != *value) {
				return errors.New("WAN count must be an exact nonnegative integer")
			}
		}
	}
	return nil
}

func validWANValue(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= WANMaxValue
}

// CollectWAN scrapes the native member's unauthenticated loopback admin endpoint.
// The verified host session authenticates delivery onward, not this HTTP scrape.
func CollectWAN(ctx context.Context, env map[string]string) (*WANObservation, error) {
	profile, err := ParseProfile(env)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(profile.AdminPort)+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	observedAt := time.Now().UTC()
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WAN metrics HTTP status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, wanBodyBytes+1))
	if err != nil {
		return nil, err
	}
	return ParseWANMetrics(data, env[EnvRegion], observedAt)
}

var wanLabelRE = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*("(?:[^"\\\n]|\\[\\"n])*")`)
var wanRegionRE = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ParseWANMetrics accepts only the bounded native Prometheus WAN contract.
// A missing gauge, duplicate, unsupported label or invalid value discards the scrape.
func ParseWANMetrics(data []byte, receiverRegion string, observedAt time.Time) (*WANObservation, error) {
	if len(data) > wanBodyBytes {
		return nil, errors.New("WAN metrics exceed size bound")
	}
	sources := make(map[string]*WANSource)
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 16<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		end := strings.IndexAny(line, "{ \t")
		if end < 0 {
			end = len(line)
		}
		metric := line[:end]
		switch metric {
		case "terrabase_wan_lag", "terrabase_wan_staleness_seconds", "terrabase_wan_members",
			"terrabase_wan_unregistered", "terrabase_wan_conflicts", "terrabase_wan_failures_total":
		default:
			continue
		}
		labels, raw, err := parseWANLabels(strings.TrimSpace(line[end:]))
		if err != nil {
			return nil, err
		}
		region, reason := labels["region"], labels["reason"]
		_, hasReason := labels["reason"]
		if !wanRegionRE.MatchString(region) || (metric == "terrabase_wan_failures_total" && !slices.Contains([]string{"heads", "pull", "apply", "ahead"}, reason)) ||
			(metric != "terrabase_wan_failures_total" && hasReason) {
			return nil, errors.New("invalid WAN region or reason label")
		}
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil || !validWANValue(value) || (metric != "terrabase_wan_staleness_seconds" && math.Trunc(value) != value) {
			return nil, errors.New("invalid WAN metric value")
		}
		key := metric + "\x00" + region + "\x00" + reason
		if seen[key] || len(seen) >= MaxWANRegions*9 {
			return nil, errors.New("duplicate or excessive WAN metrics")
		}
		seen[key] = true
		if metric == "terrabase_wan_failures_total" && reason != "ahead" {
			continue
		}
		source := sources[region]
		if source == nil {
			if len(sources) == MaxWANRegions {
				return nil, errors.New("WAN metrics exceed source count bound")
			}
			source = &WANSource{SourceRegion: region}
			sources[region] = source
		}
		switch metric {
		case "terrabase_wan_lag":
			source.LagGroups = new(value)
		case "terrabase_wan_staleness_seconds":
			source.StalenessSeconds = new(value)
		case "terrabase_wan_members":
			source.Members = new(value)
		case "terrabase_wan_unregistered":
			source.Unregistered = new(value)
		case "terrabase_wan_conflicts":
			source.Conflicts = new(value)
		case "terrabase_wan_failures_total":
			source.AheadFailuresTotal = new(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, nil
	}
	observation := &WANObservation{ObservedAt: observedAt, ReceiverRegion: receiverRegion}
	for _, source := range sources {
		observation.Sources = append(observation.Sources, *source)
	}
	slices.SortFunc(observation.Sources, func(a, b WANSource) int { return strings.Compare(a.SourceRegion, b.SourceRegion) })
	if err := observation.Validate(); err != nil {
		return nil, err
	}
	return observation, nil
}

func parseWANLabels(raw string) (map[string]string, string, error) {
	labels := make(map[string]string)
	if !strings.HasPrefix(raw, "{") {
		return nil, "", errors.New("WAN metrics require region labels")
	}
	raw = strings.TrimSpace(raw[1:])
	for {
		match := wanLabelRE.FindStringSubmatch(raw)
		if match == nil {
			return nil, "", errors.New("malformed WAN metric labels")
		}
		name := match[1]
		value, err := strconv.Unquote(match[2])
		if _, duplicate := labels[name]; err != nil || duplicate {
			return nil, "", errors.New("invalid or duplicate WAN label")
		}
		switch name {
		case "region", "reason":
		case "otel_scope_name":
			if value != "TerraScale.TerraBase" {
				return nil, "", errors.New("unexpected WAN instrument scope")
			}
		case "otel_scope_version":
			if len(value) > 64 {
				return nil, "", errors.New("WAN instrument version exceeds bound")
			}
		default:
			return nil, "", errors.New("unsupported WAN metric label")
		}
		labels[name] = value
		raw = strings.TrimSpace(raw[len(match[0]):])
		if tail, ok := strings.CutPrefix(raw, "}"); ok {
			fields := strings.Fields(tail)
			if len(fields) != 1 {
				return nil, "", errors.New("WAN metric requires one value without an external timestamp")
			}
			return labels, fields[0], nil
		}
		tail, ok := strings.CutPrefix(raw, ",")
		if !ok {
			return nil, "", errors.New("malformed WAN label separator")
		}
		raw = strings.TrimSpace(tail)
	}
}
