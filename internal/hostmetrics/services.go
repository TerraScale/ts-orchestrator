package hostmetrics

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

var serviceClient = &http.Client{
	Transport:     &http.Transport{DisableKeepAlives: true},
	Timeout:       4 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func serveServices(w http.ResponseWriter, r *http.Request, region, address string, executor *swarmruntime.Executor) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	targets, err := executor.SLOTargets(ctx, region)
	if err != nil {
		http.Error(w, "local task discovery unavailable", http.StatusServiceUnavailable)
		return
	}
	host, err := os.Hostname()
	if err != nil {
		http.Error(w, "local identity unavailable", http.StatusServiceUnavailable)
		return
	}
	for i := range targets {
		target := &targets[i]
		path := "/services/" + target.Labels["instance"] + "/metrics"
		if r.URL.Path == path {
			proxyService(ctx, w, target.Targets[0])
			return
		}
		target.Targets = []string{address}
		target.Labels["host"] = host
		target.Labels["__metrics_path__"] = path
	}
	if r.URL.Path != "/services" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(targets)
}

func proxyService(ctx context.Context, w http.ResponseWriter, address string) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		http.Error(w, "task exporter unavailable", http.StatusServiceUnavailable)
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/metrics", nil)
	if err != nil {
		http.Error(w, "task exporter unavailable", http.StatusServiceUnavailable)
		return
	}
	request.Header.Set("Accept", "text/plain; version=0.0.4")
	response, err := serviceClient.Do(request)
	if err != nil {
		http.Error(w, "task exporter unavailable", http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if response.StatusCode != http.StatusOK || err != nil || len(data) > 16<<20 || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/plain") {
		http.Error(w, "task exporter unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", response.Header.Get("Content-Type"))
	_, _ = w.Write(data)
}
