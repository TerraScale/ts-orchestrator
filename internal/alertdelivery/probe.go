package alertdelivery

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Readiness uses no proxy, credentials or caller-selected destinations.
func newReadinessClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func readinessMetrics(client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		services := [...]string{"terrabase", "ts-auth", "ts-dashboard"}
		values := [3]int{}
		var wg sync.WaitGroup
		for i, service := range services {
			wg.Go(func() {
				if probeReady(request.Context(), client, service) {
					values[i] = 1
				}
			})
		}
		wg.Wait()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintln(w, "# HELP terrascale_service_readiness Public endpoint readiness, not request SLO success.")
		fmt.Fprintln(w, "# TYPE terrascale_service_readiness gauge")
		for i, service := range services {
			fmt.Fprintf(w, "terrascale_service_readiness{service=%q} %d\n", service, values[i])
		}
	}
}

func probeReady(ctx context.Context, client *http.Client, service string) bool {
	var endpoint string
	switch service {
	case "terrabase":
		endpoint = "https://api.terrascale.tech/readyz"
	case "ts-auth":
		endpoint = "https://auth.terrascale.tech/readyz"
	case "ts-dashboard":
		endpoint = "https://dash.terrascale.tech/readyz"
	default:
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil || len(body) > 16<<10 {
		return false
	}
	var result struct {
		Status       string            `json:"status"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if json.Unmarshal(body, &result) != nil {
		return false
	}
	if service == "ts-dashboard" {
		return result.Status == "ok" && result.Dependencies["ts-auth"] == "ok" && result.Dependencies["terrabase"] == "ok"
	}
	return result.Status == "ready"
}
