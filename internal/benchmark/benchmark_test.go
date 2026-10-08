package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func workload(t *testing.T) Workload {
	t.Helper()
	var w Workload
	if err := json.Unmarshal([]byte(`{"name":"point-reads","duration_s":30,"warmup_s":0,"concurrency":4,"dataset":{"documents":100,"doc_size_bytes":128},"mix":[{"op":"doc.get","weight":1}],"targets":{"p99_ms":10}}`), &w); err != nil {
		t.Fatal(err)
	}
	return w
}

type memoryRepository struct {
	runs    []Run
	results []Sample
	fail    bool
}

func (m *memoryRepository) SaveRun(_ context.Context, r Run) error {
	m.runs = append(m.runs, r)
	return nil
}
func (m *memoryRepository) SaveResult(_ context.Context, _ string, _ int, s Sample) error {
	if m.fail {
		return errors.New("storage unavailable")
	}
	m.results = append(m.results, s)
	return nil
}
func (m *memoryRepository) SaveUsage(context.Context, string, int, capacity.Usage) error { return nil }

type generatorFunc func(context.Context, string, Workload, []string, func(Sample) error) error

func (f generatorFunc) Execute(ctx context.Context, id string, w Workload, c []string, emit func(Sample) error) error {
	return f(ctx, id, w, c, emit)
}

func usageFixture(_ context.Context, region string, from, to time.Time) (capacity.Usage, error) {
	s := func(v float64) *capacity.Stats {
		return &capacity.Stats{Mean: v, Min: v, Max: v, Complete: true, From: from, To: to, Samples: 30}
	}
	row := capacity.Row{Node: "serving", CPU: capacity.Resource{Usage: s(1), Request: s(2), Limit: s(4), Headroom: s(3)}, Memory: capacity.Resource{Usage: s(1 << 30), Request: s(2 << 30), Limit: s(4 << 30), Headroom: s(3 << 30)}}
	return capacity.Usage{Region: region, From: from, To: to, Complete: true, Nodes: []capacity.Row{row}, Replicas: []capacity.Row{{Node: "serving", Service: "terrabase", CPU: row.CPU, Memory: row.Memory}}}, nil
}

func TestRunnerRampPersistsAndStopsAtFirstUnsafeStep(t *testing.T) {
	w := workload(t)
	w.Name = "ramp"
	w.Duration = 90
	now := time.Now().UTC().Add(-time.Minute)
	repo := new(memoryRepository)
	calls := 0
	g := generatorFunc(func(ctx context.Context, id string, w Workload, clients []string, emit func(Sample) error) error {
		calls++
		if !idPattern.MatchString(id) {
			t.Fatal("run ID is not a ULID")
		}
		for i := 0; i < 30; i++ {
			now = now.Add(time.Second)
			for _, client := range clients {
				s := Sample{TS: now, Client: client, SDK: client, SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100, P50: 10, P95: 20, P99: 30, Max: 40}
				if w.Concurrency == 2 {
					s.Errors = 2
				}
				if err := emit(s); err != nil {
					return err
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
			}
		}
		for _, client := range clients {
			if err := emit(Sample{Type: "summary", Client: client, Region: "gru", Workload: w.Name, OpsPerS: 100, PerOp: map[string]json.RawMessage{"doc.get": json.RawMessage(`{"p99_us":30}`)}}); err != nil {
				return err
			}
		}
		return nil
	})
	var output bytes.Buffer
	run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usageFixture}).Execute(t.Context(), "gru", w, []string{"go", "rust"}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(run.Stages) != 2 || run.Stages[1].Stopped == "" || len(repo.runs) != 2 || repo.runs[1].Status != "completed" {
		t.Fatalf("bounded ramp failed: calls=%d run=%+v", calls, run)
	}
	if run.Verdict.MaxSustainedOps != 200 || !run.Verdict.Qualified || run.Verdict.Scale != "up" {
		t.Fatalf("capacity verdict %+v", run.Verdict)
	}
	if len(repo.results) != len(run.Stages[0].Samples)+len(run.Stages[1].Samples) {
		t.Fatal("streamed results lost")
	}
	if run.TemporaryInstanceUSD != 0 {
		t.Fatal("existing host billed as temporary instance")
	}
}

func TestUnknownUsageAndStorageFailureCannotProduceQualifiedVerdict(t *testing.T) {
	w := workload(t)
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			now := time.Now().UTC()
			repo := &memoryRepository{fail: fail}
			cleaned := false
			g := generatorFunc(func(ctx context.Context, _ string, w Workload, clients []string, emit func(Sample) error) error {
				defer func() { cleaned = true }()
				for i := 0; i < 30; i++ {
					now = now.Add(time.Second)
					if err := emit(Sample{TS: now, Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100, P50: 1, P95: 2, P99: 3, Max: 4}); err != nil {
						return err
					}
				}
				return emit(Sample{Type: "summary", Client: "go", Region: "gru", Workload: w.Name, OpsPerS: 100, PerOp: map[string]json.RawMessage{"doc.get": json.RawMessage(`{}`)}})
			})
			usage := func(ctx context.Context, region string, from, to time.Time) (capacity.Usage, error) {
				u, _ := usageFixture(ctx, region, from, to)
				u.Complete = false
				return u, nil
			}
			run, err := (Runner{Now: func() time.Time { return now }, Generator: g, Repository: repo, Usage: usage}).Execute(t.Context(), "gru", w, []string{"go"}, io.Discard)
			if (err != nil) != fail || !cleaned || run.Verdict.Qualified || run.Verdict.Scale != "unknown" || len(repo.runs) != 2 {
				t.Fatalf("unsafe verdict %+v err=%v cleanup=%t", run.Verdict, err, cleaned)
			}
		})
	}
}

func TestAdmissionRejectsServingNodesAndOtherRegions(t *testing.T) {
	id := "ocid1.instance.oc1.sa-saopaulo-1.example"
	name := "benchmark-gru"
	instance := core.Instance{Id: &id, DisplayName: &name, LifecycleState: core.InstanceLifecycleStateRunning, FreeformTags: map[string]string{"ts-benchmark": "load-generator", "ts-benchmark-region": "gru"}}
	if err := admitInstance(instance, "gru", id); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ts-cell", "ts-pool", "terrascale-host-node", "terrascale-managed-by", "terrascale-owner"} {
		instance.FreeformTags[key] = "serving"
		if admitInstance(instance, "gru", id) == nil {
			t.Fatalf("accepted serving tag %s", key)
		}
		delete(instance.FreeformTags, key)
	}
	if admitInstance(instance, "sfo", id) == nil {
		t.Fatal("accepted cross-region instance")
	}
	name = "mariogk-desktop"
	if admitInstance(instance, "gru", id) == nil {
		t.Fatal("accepted forbidden desktop")
	}
}

func TestServiceLimitCanBeTheBottleneckOnAnIdleNode(t *testing.T) {
	w := workload(t)
	from := time.Now().UTC().Add(-time.Minute)
	to := from.Add(30 * time.Second)
	u, _ := usageFixture(t.Context(), "gru", from, to)
	u.Replicas[0].CPU.Headroom = &capacity.Stats{Min: 0.05, Max: 0.05, Mean: 0.05, Complete: true}
	u.Replicas[0].CPU.Limit = &capacity.Stats{Min: 1, Max: 1, Mean: 1, Complete: true}
	v := capacityVerdict(w, []Stage{{From: from, To: to, Usage: u}}, []string{"go"})
	if v.Bottleneck != "cpu" || v.Scale != "up" {
		t.Fatalf("ignored service cgroup pressure: %+v", v)
	}
}

func TestPinnedSDKRejectsULIDProjectBeforeNetwork(t *testing.T) {
	project := newID()
	runID := newID()
	requests := 0
	key := "tb_" + strings.Repeat("a", 43)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer "+key {
			t.Error("SDK did not authenticate")
		}
		prefix := "/v1/projects/" + project + "/databases/benchmark"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			t.Errorf("non-public SDK path %s", r.URL.Path)
		}
		if strings.Contains(r.URL.Path, "/documents/") {
			id := filepath.Base(r.URL.Path)
			if !idPattern.MatchString(id) {
				t.Errorf("non-ULID entity %s", id)
			}
			data, _ := io.ReadAll(r.Body)
			if strings.Contains(r.URL.Path, "/runs/") && strings.Contains(string(data), `"samples":[`) {
				t.Error("run duplicated result history")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"tbv1-test"`)
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"name":"benchmark","id":"`+runID+`","version":"tbv1-test"}`)
	}))
	defer server.Close()
	_, err := NewRepository(t.Context(), server.URL, project, key)
	if err == nil || !strings.Contains(err.Error(), "SDK_BLOCKED") || !strings.Contains(err.Error(), "UUID") {
		t.Fatalf("SDK contract blocker was hidden: %v", err)
	}
	if requests != 0 {
		t.Fatalf("SDK emitted %d requests before rejecting ULID", requests)
	}
}

func TestJSONLPreservesRequiredZeroFields(t *testing.T) {
	data, err := json.Marshal(Sample{Client: "go", Region: "gru", Op: "doc.get"})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"count", "errors", "p50_us", "p95_us", "p99_us", "max_us"} {
		if string(value[key]) != "0" {
			t.Errorf("required zero field %s omitted", key)
		}
	}
	data, err = json.Marshal(Sample{Type: "summary", Client: "go", Region: "gru", Workload: "point-reads", PerOp: map[string]json.RawMessage{"doc.get": json.RawMessage(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"ts"`) || !strings.Contains(string(data), `"error_rate":0`) {
		t.Fatalf("summary contract changed: %s", data)
	}
}

func TestContainersCleanUpAfterMalformedOutputWithoutExposingSecrets(t *testing.T) {
	dir := t.TempDir()
	state := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(exe, "'", "'\\''") + "' -test.run=^TestPodmanHelper$ -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TS_761_PODMAN_STATE", state)
	if err := os.WriteFile(filepath.Join(state, "foreign"), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	job := Job{ID: newID(), Region: "gru", Workload: workload(t), Clients: []string{"go", "rust"}, Images: map[string]string{"go": "image-go", "rust": "image-rust"}}
	var output bytes.Buffer
	err = runContainers(t.Context(), job, map[string]string{"TS_BENCH_CLIENT_ID": "test-client", "TS_BENCH_CLIENT_SECRET": "private-test-value"}, &output)
	if err == nil {
		t.Fatal("malformed output was accepted")
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "foreign" {
		t.Fatalf("containers were leaked or foreign container removed: %v", entries)
	}
	if strings.Contains(output.String(), "private-test-value") {
		t.Fatal("credential leaked")
	}
}

func TestPodmanHelper(t *testing.T) {
	state := os.Getenv("TS_761_PODMAN_STATE")
	if state == "" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	name := args[len(args)-1]
	switch args[0] {
	case "run":
		label := ""
		for i, arg := range args {
			if arg == "--name" {
				name = args[i+1]
			}
			if arg == "--label" {
				label = strings.TrimPrefix(args[i+1], "ts-bench-job=")
			}
		}
		f, err := os.Open("/proc/self/fd/3")
		if err != nil {
			os.Exit(2)
		}
		env, err := io.ReadAll(f)
		f.Close()
		if err != nil || !bytes.Contains(env, []byte("TS_BENCH_CLIENT_SECRET=private-test-value")) {
			os.Exit(2)
		}
		if err := os.WriteFile(filepath.Join(state, name), []byte(label), 0600); err != nil {
			os.Exit(2)
		}
		switch os.Getenv("TS_761_PODMAN_MODE") {
		case "oversized":
			_, _ = io.WriteString(os.Stdout, strings.Repeat("x", 1<<20))
			for {
				time.Sleep(time.Minute)
			}
		case "stream":
			_ = json.NewEncoder(os.Stdout).Encode(Sample{TS: time.Now().UTC(), Client: "go", SDK: "go", SDKVersion: "test", Region: "gru", Op: "doc.get", Count: 100, P99: 30, Max: 40})
			for {
				time.Sleep(time.Minute)
			}
		}
		fmt.Println("invalid-result")
		os.Exit(0)
	case "inspect":
		data, err := os.ReadFile(filepath.Join(state, name))
		if err != nil {
			os.Exit(1)
		}
		fmt.Println(string(data))
		os.Exit(0)
	case "container":
		if _, err := os.Stat(filepath.Join(state, name)); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "stop":
		os.Exit(0)
	case "rm":
		_ = os.Remove(filepath.Join(state, name))
		os.Exit(0)
	default:
		os.Exit(2)
	}
}
