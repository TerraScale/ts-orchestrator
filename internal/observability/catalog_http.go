package observability

import (
	"net/http"
	"time"
)

// MetricCatalog returns the same live source used by the authenticated API.
// A dashboard can retain it before regional history finishes initializing.
func (server *Server) MetricCatalog() CatalogSource { return server.catalog }

func (server *Server) metricCatalogHTTP(writer http.ResponseWriter, request *http.Request) {
	result, err := server.catalog.Catalog(request.Context())
	if err != nil {
		writePlain(writer, http.StatusServiceUnavailable, "metric catalog unavailable\n")
		return
	}
	writeJSON(writer, result)
}

// HandleMetricHistory installs or replaces the history source shared by the
// catalog, dashboard and API. Callers must not mount HistoryHandler separately.
func (server *Server) HandleMetricHistory(source HistorySource) {
	if source == nil {
		return
	}
	server.catalog.history.Store(&source)
	server.historyOnce.Do(func() {
		server.HandleAuthenticated("GET /v1/history", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			query, err := ParseHistoryQuery(request.URL.Query(), time.Now())
			if err != nil {
				writePlain(writer, http.StatusBadRequest, err.Error()+"\n")
				return
			}
			result, err := server.catalog.History(request.Context(), query)
			if err != nil {
				writePlain(writer, http.StatusBadRequest, err.Error()+"\n")
				return
			}
			writeJSON(writer, result)
		}))
		server.HandleAuthenticated("GET /v1/history/metrics", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			result, err := server.catalog.Catalog(request.Context())
			if err != nil {
				writePlain(writer, http.StatusServiceUnavailable, "metric catalog unavailable\n")
				return
			}
			names := []string{}
			for _, metric := range result.Metrics {
				if metric.HistoryState == "available" {
					names = append(names, metric.Name)
				}
			}
			writeJSON(writer, names)
		}))
	})
}
