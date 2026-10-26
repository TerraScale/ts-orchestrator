package mesh

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type bakeRoundTrip func(*http.Request) (*http.Response, error)

func (f bakeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBakeDependencyBodies(t *testing.T) {
	for _, tc := range []struct {
		service, body, want string
		code                int
	}{
		{"ts-auth", `{"status":"ready"}`, "ok", 200},
		{"ts-auth", `{"status":"ready"}`, "HTTP 503", 503},
		{"ts-auth", `{"status":"ok"}`, "dependency-unavailable-or-missing", 200},
		{"ts-dashboard", `{"status":"ok","dependencies":{"ts-auth":"ok","terrabase":"ok"}}`, "ok", 200},
		{"ts-dashboard", `{"status":"ok","dependencies":{"terrabase":"ok"}}`, "dependency-unavailable-or-missing", 200},
		{"ts-dashboard", `ok`, "invalid-readiness-body", 200},
		{"ts-auth", strings.Repeat("s", (16<<10)+1), "invalid-readiness-body", 200},
	} {
		client := &http.Client{Transport: bakeRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme != "https" || r.URL.Path != "/readyz" || r.Method != "GET" {
				t.Fatalf("unexpected probe: %s %s", r.Method, r.URL)
			}
			return &http.Response{StatusCode: tc.code, Body: io.NopCloser(strings.NewReader(tc.body)), Header: http.Header{}}, nil
		})}
		if got := bakeDependency(t.Context(), client, tc.service); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.service, got, tc.want)
		}
	}
}

func TestBakeLogsOnlyNewFaultsAndCoverage(t *testing.T) {
	anchor := `{"msg":"This machine's catalog anchor could not be written; it is tried again","Error":"private-marker"}` + "\n"
	writer := `{"msg":"Waited 5 s for a database's writer and took it: write queued behind holder"}` + "\n"
	for _, scenario := range []string{"healthy", "anchor", "writer", "split", "truncated", "replaced", "missing", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stdout")
			if err := os.WriteFile(path, []byte(anchor), 0600); err != nil {
				t.Fatal(err)
			}
			log := &bakeLog{path: path}
			if err := log.check(); err != nil {
				t.Fatalf("old warning counted: %v", err)
			}
			appendLog := func(s string) {
				t.Helper()
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString(s)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "healthy":
				appendLog("{\"msg\":\"healthy\"}\n")
			case "anchor":
				appendLog(anchor)
			case "writer":
				appendLog(writer)
			case "split":
				appendLog(writer[:15])
				if err := log.check(); err != nil {
					t.Fatal(err)
				}
				appendLog(writer[15:])
			case "truncated":
				if err := os.WriteFile(path, []byte(strings.Repeat("x", len(anchor))), 0600); err != nil {
					t.Fatal(err)
				}
			case "replaced":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(anchor), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				appendLog(strings.Repeat("x", (1<<20)+1))
			}
			err := log.check()
			if (err == nil) != (scenario == "healthy") || err != nil && strings.Contains(err.Error(), "private-marker") {
				t.Fatalf("%s: %v", scenario, err)
			}
		})
	}
}

func TestBakeRejectsReplacedAndAbsentTasks(t *testing.T) {
	a := []swarmruntime.ServiceTaskEvidence{{TaskID: "one"}, {TaskID: "two"}}
	if !bakeSameTasks(a, []swarmruntime.ServiceTaskEvidence{a[1], a[0]}) || bakeSameTasks(a, []swarmruntime.ServiceTaskEvidence{{TaskID: "one"}, {TaskID: "new"}}) || bakeSameTasks(nil, nil) || bakeSameTasks(a, []swarmruntime.ServiceTaskEvidence{a[0], a[0]}) {
		t.Fatal("task replacement or missing runtime identity passed")
	}
}
