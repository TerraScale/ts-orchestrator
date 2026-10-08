package observability

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ParseHistoryQuery reads a range query from URL parameters: metric (required),
// label.<name>=<value> filters, range (a duration back from now, default 1h)
// or start/end as RFC 3339 times, tier (raw, 1m, 5m or 1h), rate=1 and max.
func ParseHistoryQuery(values url.Values, now time.Time) (HistoryQuery, error) {
	query := HistoryQuery{Metric: values.Get("metric"), End: now, Tier: values.Get("tier")}
	if query.Metric == "" {
		return HistoryQuery{}, errors.New("metric is required")
	}
	switch query.Tier {
	case "", TierRaw, Tier1m, Tier5m, Tier1h:
	default:
		return HistoryQuery{}, errors.New("tier must be raw, 1m, 5m or 1h")
	}
	for name, value := range values {
		if label, ok := strings.CutPrefix(name, "label."); ok && label != "" && len(value) > 0 {
			if query.Labels == nil {
				query.Labels = map[string]string{}
			}
			query.Labels[label] = value[0]
		}
	}
	window := time.Hour
	if raw := values.Get("range"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 || parsed > HistoryRetention {
			return HistoryQuery{}, errors.New("range must be a positive duration of at most 14 days")
		}
		window = parsed
	}
	query.Start = now.Add(-window)
	var err error
	if raw := values.Get("start"); raw != "" {
		if query.Start, err = time.Parse(time.RFC3339, raw); err != nil {
			return HistoryQuery{}, errors.New("start must be an RFC 3339 time")
		}
	}
	if raw := values.Get("end"); raw != "" {
		if query.End, err = time.Parse(time.RFC3339, raw); err != nil {
			return HistoryQuery{}, errors.New("end must be an RFC 3339 time")
		}
	}
	if !query.Start.Before(query.End) {
		return HistoryQuery{}, errors.New("start must be before end")
	}
	query.Rate = values.Get("rate") == "1" || values.Get("rate") == "true"
	if raw := values.Get("max"); raw != "" {
		if query.MaxSeries, err = strconv.Atoi(raw); err != nil || query.MaxSeries < 0 || query.MaxSeries > 512 {
			return HistoryQuery{}, errors.New("max must be between 0 and 512")
		}
	}
	return query, nil
}

// HistoryHandler serves GET /v1/history (a range query) and
// GET /v1/history/metrics (the stored metric names) as JSON. Mount it only
// on an authenticated listener.
func HistoryHandler(source HistorySource) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/history", func(writer http.ResponseWriter, request *http.Request) {
		query, err := ParseHistoryQuery(request.URL.Query(), time.Now())
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(writer, source.Range(query))
	})
	mux.HandleFunc("GET /v1/history/metrics", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, source.Metrics())
	})
	return mux
}
