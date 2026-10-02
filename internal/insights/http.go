package insights

import (
	"encoding/json"
	"net/http"
	"time"
)

// Handler serves GET /v1/insights (the latest ranked evaluation) and
// GET /v1/summary?window=1h|24h (the plain-language summary) as JSON. Mount
// it only on an authenticated listener.
func Handler(source Source, summarizer Summarizer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/insights", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, source.Current())
	})
	mux.HandleFunc("GET /v1/summary", func(writer http.ResponseWriter, request *http.Request) {
		window := time.Hour
		if raw := request.URL.Query().Get("window"); raw != "" {
			parsed, err := time.ParseDuration(raw)
			if err != nil || parsed < time.Minute || parsed > 7*24*time.Hour {
				http.Error(writer, "window must be a duration between 1m and 168h", http.StatusBadRequest)
				return
			}
			window = parsed
		}
		summary, err := summarizer.Summary(request.Context(), window)
		if err != nil {
			http.Error(writer, "summary unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, summary)
	})
	return mux
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(writer).Encode(value)
}
