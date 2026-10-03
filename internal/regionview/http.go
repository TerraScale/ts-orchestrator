package regionview

import (
	"encoding/json"
	"net/http"
)

// Handler serves GET /v1/regions (every region, local first) and
// GET /v1/regions/{region} as JSON. Mount it only on an authenticated
// listener.
func Handler(source Source) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/regions", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, source.Regions(request.Context()))
	})
	mux.HandleFunc("GET /v1/regions/{region}", func(writer http.ResponseWriter, request *http.Request) {
		summary, err := source.Region(request.Context(), request.PathValue("region"))
		if err != nil {
			http.Error(writer, "region is not configured", http.StatusNotFound)
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
