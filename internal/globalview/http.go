package globalview

import (
	"encoding/json"
	"net/http"
)

// Handler serves GET /v1/regions (every listed region, local first) and
// GET /v1/regions/{region} from view as JSON. Mount it only on an
// authenticated listener.
func Handler(view *View) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/regions", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, view.Regions())
	})
	mux.HandleFunc("GET /v1/regions/{region}", func(writer http.ResponseWriter, request *http.Request) {
		region, ok := view.Region(request.PathValue("region"))
		if !ok {
			http.Error(writer, "region is not configured", http.StatusNotFound)
			return
		}
		writeJSON(writer, region)
	})
	return mux
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(writer).Encode(value)
}
