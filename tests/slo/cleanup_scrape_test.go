package slo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCleanupFleetScrape(t *testing.T, tool string) {
	t.Helper()
	t.Parallel()
	dir := t.TempDir()
	binary := filepath.Join(filepath.Dir(tool), "prometheus")
	if _, err := os.Stat(binary); err != nil {
		archive := filepath.Join(filepath.Dir(filepath.Dir(tool)), "prometheus.tar.gz")
		member := filepath.Base(filepath.Dir(tool)) + "/prometheus"
		cmd := exec.CommandContext(t.Context(), "tar", "-xzf", archive, "--strip-components=1", "-C", dir, member)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("extract pinned Prometheus: %v\n%s", err, output)
		}
		binary = filepath.Join(dir, "prometheus")
	}
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "terrabase_shape_cleanup_parked 1\nterrabase_shape_cleanup_oldest_age_seconds 3601\nterrabase_shape_cleanup_saturated 1\nterrabase_storage_queued 0\nunrelated_metric 99")
	}))
	t.Cleanup(metrics.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(metrics.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(targets, []byte(`[{"targets":["127.0.0.1:9108"],"labels":{"host":"sjc-1","region":"sjc","service":"host-storage"}}]`), 0600); err != nil {
		t.Fatal(err)
	}
	shipped, err := os.ReadFile("../../deploy/observability/production/prometheus.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, job, found := strings.Cut(string(shipped), "  - job_name: terrabase-host-storage\n")
	if !found {
		t.Fatal("fleet scrape job missing")
	}
	job, _, _ = strings.Cut(job, "\n  - job_name:")
	job = strings.ReplaceAll(job, "/run/ts-orch-observability/storage.json", targets)
	job = strings.ReplaceAll(job, "${1}:9091", "${1}:"+port)
	config := "global:\n  scrape_interval: 100ms\n  scrape_timeout: 100ms\nscrape_configs:\n  - job_name: terrabase-host-storage\n" + job
	configPath := filepath.Join(dir, "prometheus.yml")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config.file="+configPath, "--storage.tsdb.path="+filepath.Join(dir, "data"), "--web.listen-address="+address)
	log, err := os.Create(filepath.Join(dir, "prometheus.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	client := &http.Client{Timeout: time.Second}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := client.Get("http://" + address + "/api/v1/query?query=" + url.QueryEscape(`{__name__=~"terrabase_.*|unrelated_metric"}`))
		if err == nil {
			var result struct {
				Data struct {
					Result []struct{ Metric map[string]string }
				}
			}
			err = json.NewDecoder(response.Body).Decode(&result)
			_ = response.Body.Close()
			if err == nil && len(result.Data.Result) == 4 {
				want := map[string]string{
					"terrabase_shape_cleanup_parked":             "terrabase",
					"terrabase_shape_cleanup_oldest_age_seconds": "terrabase",
					"terrabase_shape_cleanup_saturated":          "terrabase",
					"terrabase_storage_queued":                   "host-storage",
				}
				for _, series := range result.Data.Result {
					labels := series.Metric
					service, ok := want[labels["__name__"]]
					if !ok || labels["service"] != service || labels["region"] != "sjc" || labels["host"] != "sjc-1" {
						t.Fatalf("fleet metric labels: %v", labels)
					}
					delete(want, labels["__name__"])
				}
				if len(want) != 0 {
					t.Fatalf("missing fleet metrics: %v", want)
				}
				return
			}
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			output, _ := os.ReadFile(log.Name())
			t.Fatalf("cleanup metric did not survive the shipped fleet scrape: %v\n%s", err, output)
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}
