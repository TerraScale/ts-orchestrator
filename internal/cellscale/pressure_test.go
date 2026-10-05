package cellscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
)

func validPressure() NodePressure {
	return NodePressure{Schema: PressureSchema, Node: "gru-1-db-2", InstanceID: "ocid-gru-1-db-2", State: StateReady, Release: "sha256:abc",
		ProcessID: "p1", SampledAt: time.Now().UTC(),
		CPUUtil: 0.4, MemoryUtil: 0.5, DiskUsedBytes: 10, DiskTotalBytes: 100, DiskIOPS: 900, RequestRate: 1200,
		IOQueueDepth: 1.5, P95LatencyMS: 12, Load: memberstatus.Load{Connections: 4, StorageBytes: 5, ReplicationLagSeq: 6, WriteQPS: 7.5},
		TopTenants: []TenantLoad{{Org: "acme", Plan: PlanPro, RequestRate: 700, CPUShare: 0.6}}}
}

func TestNodePressureValidate(t *testing.T) {
	if err := validPressure().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*NodePressure){
		"schema":             func(p *NodePressure) { p.Schema = 2 },
		"zero sampled_at":    func(p *NodePressure) { p.SampledAt = time.Time{} },
		"empty process_id":   func(p *NodePressure) { p.ProcessID = "" },
		"invalid process_id": func(p *NodePressure) { p.ProcessID = "p/1" },
		"long process_id":    func(p *NodePressure) { p.ProcessID = strings.Repeat("p", 129) },
		"foreign node":       func(p *NodePressure) { p.Node = "gru-1-ctl-1" },
		"state":              func(p *NodePressure) { p.State = "serving" },
		"release":            func(p *NodePressure) { p.Release = "" },
		"cpu above 1":        func(p *NodePressure) { p.CPUUtil = 1.5 },
		"disk overfull":      func(p *NodePressure) { p.DiskUsedBytes = 101 },
		"negative rate":      func(p *NodePressure) { p.RequestRate = -1 },
		"absurd latency":     func(p *NodePressure) { p.P95LatencyMS = 1e12 },
		"unknown plan":       func(p *NodePressure) { p.TopTenants[0].Plan = "free" },
		"tenant share":       func(p *NodePressure) { p.TopTenants[0].CPUShare = 2 },
		"duplicate tenant":   func(p *NodePressure) { p.TopTenants = append(p.TopTenants, p.TopTenants[0]) },
		"too many tenant":    func(p *NodePressure) { p.TopTenants = make([]TenantLoad, MaxTopTenants+1) },
		"load block":         func(p *NodePressure) { p.Load.WriteQPS = -1 },
	} {
		p := validPressure()
		mutate(&p)
		if err := p.Validate(); !errors.Is(err, ErrInvalidPressure) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestNodePressureAcceptsOpaqueProcessIDs(t *testing.T) {
	for _, processID := range []string{"p", "A0._:+-", strings.Repeat("p", 128)} {
		p := validPressure()
		p.ProcessID = processID
		if err := p.Validate(); err != nil {
			t.Fatalf("process_id %q: %v", processID, err)
		}
	}
}

func TestHTTPSourceReadsTheContract(t *testing.T) {
	var body []byte
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/gru-1-db-2"+PressurePath {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	source := HTTPSource{Endpoint: EndpointTemplate(server.URL + "/{node}")}
	want := validPressure()
	body, _ = json.Marshal(want)
	got, err := source.Pressure(t.Context(), "gru-1-db-2")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Pressure = %+v, %v", got, err)
	}
	for name, setup := range map[string]func(){
		"another node": func() {
			other := validPressure()
			other.Node = "gru-1-db-3"
			body, _ = json.Marshal(other)
		},
		"duplicate tenant": func() {
			p := validPressure()
			p.TopTenants = append(p.TopTenants, p.TopTenants[0])
			body, _ = json.Marshal(p)
		},
		"invalid":   func() { body = []byte(`{"schema":1,"node":"gru-1-db-2","state":"ready","cpu_util":7}`) },
		"oversized": func() { body = bytes.Repeat([]byte(" "), maxPressureBytes+1) },
		"http 503":  func() { body, status = nil, http.StatusServiceUnavailable },
	} {
		status = http.StatusOK
		setup()
		if _, err := source.Pressure(t.Context(), "gru-1-db-2"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestHTTPSourceRequiresPressureFields(t *testing.T) {
	complete, err := json.Marshal(validPressure())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"schema", "node", "instance_id", "state", "process_id", "sampled_at", "release", "cpu_util", "mem_util", "disk_used_bytes", "disk_total_bytes",
		"disk_iops", "request_rate", "io_queue_depth", "p95_latency_ms", "load",
		"load.connections", "load.storage_bytes", "load.replication_lag_seq", "load.write_qps",
		"top_tenants.org", "top_tenants.plan", "top_tenants.request_rate", "top_tenants.cpu_share",
	} {
		for _, missing := range []bool{true, false} {
			name := field + "/null"
			if missing {
				name = field + "/missing"
			}
			t.Run(name, func(t *testing.T) {
				var report map[string]any
				if err := json.Unmarshal(complete, &report); err != nil {
					t.Fatal(err)
				}
				object, key := report, field
				if counter, ok := strings.CutPrefix(field, "load."); ok {
					object, key = report["load"].(map[string]any), counter
				} else if counter, ok := strings.CutPrefix(field, "top_tenants."); ok {
					object, key = report["top_tenants"].([]any)[0].(map[string]any), counter
				}
				if missing {
					delete(object, key)
				} else {
					object[key] = nil
				}
				body, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write(body)
				}))
				defer server.Close()
				source := HTTPSource{Client: server.Client(), Endpoint: EndpointTemplate(server.URL)}
				if got, err := source.Pressure(t.Context(), "gru-1-db-2"); !errors.Is(err, ErrInvalidPressure) {
					t.Fatalf("Pressure = %+v, %v; want invalid pressure", got, err)
				}
			})
		}
	}
}

func TestHTTPSourceAcceptsExplicitZeroCounters(t *testing.T) {
	// A disk needs positive capacity; every utilization, rate and load counter
	// may explicitly be zero. The optional tenant list may be absent.
	want := NodePressure{Schema: PressureSchema, Node: "gru-1-db-2", InstanceID: "ocid-gru-1-db-2", State: StateReady, Release: "r1",
		ProcessID: "p1", SampledAt: time.Now().UTC(), DiskTotalBytes: 1}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	source := HTTPSource{Client: server.Client(), Endpoint: EndpointTemplate(server.URL)}
	if got, err := source.Pressure(t.Context(), want.Node); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Pressure = %+v, %v; want %+v", got, err, want)
	}
}

func TestHTTPSourceUnknownLagHoldsController(t *testing.T) {
	for _, kind := range []Kind{KindScaleIn, KindResize} {
		for _, missing := range []bool{true, false} {
			name := string(kind) + "/null"
			if missing {
				name = string(kind) + "/missing"
			}
			t.Run(name, func(t *testing.T) {
				captureJournal(t)
				policy := testPolicy()
				cell := newFakeCell(4, small, 2, 150)
				if kind == KindScaleIn {
					policy.Nodes.Max = 3 // Force a scale-in without a sustain wait.
				} else {
					cell = newFakeCell(3, small, 4, 250)
					cell.instances[2].Shape = Shape{OCPUs: 4, MemoryGB: 24}
				}
				if action := act(policy, observeState(t, policy, cell), History{}); action.Kind != kind {
					t.Fatalf("complete reports should request %s: %+v", kind, action)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					node := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), PressurePath)
					pressure, err := cell.Pressure(r.Context(), node)
					if err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					body, err := json.Marshal(pressure)
					if err != nil {
						t.Error(err)
						return
					}
					if node == "gru-1-db-1" {
						var report map[string]any
						if err := json.Unmarshal(body, &report); err != nil {
							t.Error(err)
							return
						}
						load := report["load"].(map[string]any)
						if missing {
							delete(load, "replication_lag_seq")
						} else {
							load["replication_lag_seq"] = nil
						}
						body, err = json.Marshal(report)
						if err != nil {
							t.Error(err)
							return
						}
					}
					_, _ = w.Write(body)
				}))
				defer server.Close()
				s := newSim(t, policy, cell, time.Minute)
				s.controller.config.Source = HTTPSource{Client: server.Client(), Endpoint: EndpointTemplate(server.URL + "/{node}"),
					Now: s.controller.config.Now}
				if action, err := s.controller.Tick(t.Context()); err != nil || action.Kind != KindHold || action.Reason != ReasonNotSettled {
					t.Fatalf("unknown lag: %+v, %v", action, err)
				}
				if calls := cell.callLog(); len(calls) != 0 {
					t.Fatalf("unknown lag mutated the cell: %v", calls)
				}
			})
		}
	}
}

func fakeNodeIdentity(name string) NodeIdentity {
	return NodeIdentity{Name: name, InstanceID: "ocid-" + name, Incarnation: name + "-p1"}
}

func TestHTTPMembersCallsTheHooks(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var request struct {
			Expected NodeIdentity `json:"expected"`
			To       string       `json:"to"`
			Target   NodeIdentity `json:"expected_target"`
		}
		name := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
		if err := json.Unmarshal(data, &request); err != nil || request.Expected != fakeNodeIdentity(name) {
			t.Errorf("missing mutation identity precondition: %s %v", data, err)
		}
		if strings.HasSuffix(r.URL.Path, "/move") && (request.To != "gru-1-db-1" || request.Target != fakeNodeIdentity(request.To)) {
			t.Errorf("missing destination identity precondition: %s", data)
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/drain") {
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer server.Close()
	members := HTTPMembers{Endpoint: EndpointTemplate(server.URL + "/{node}")}
	if err := members.Join(t.Context(), fakeNodeIdentity("gru-1-db-4")); err != nil {
		t.Fatal(err)
	}
	if err := members.Drain(t.Context(), fakeNodeIdentity("gru-1-db-4")); err != nil {
		t.Fatal(err)
	}
	if err := members.MoveTenant(t.Context(), "acme", fakeNodeIdentity("gru-1-db-2"), fakeNodeIdentity("gru-1-db-1")); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /gru-1-db-4/v1/node/join", "POST /gru-1-db-4/v1/node/drain",
		"POST /gru-1-db-2/v1/tenants/acme/move"}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %q", calls)
	}
	failing := httptest.NewServer(http.NotFoundHandler())
	defer failing.Close()
	if err := (HTTPMembers{Endpoint: EndpointTemplate(failing.URL)}).Drain(t.Context(), fakeNodeIdentity("gru-1-db-4")); err == nil {
		t.Fatal("a node without the hook must fail the action")
	}
}

func TestHTTPMembersRequireCompleteIdentity(t *testing.T) {
	for _, part := range []string{"instance", "incarnation", "destination"} {
		t.Run(part, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
			defer server.Close()
			members := HTTPMembers{Endpoint: EndpointTemplate(server.URL)}
			source, target := fakeNodeIdentity("gru-1-db-2"), fakeNodeIdentity("gru-1-db-1")
			switch part {
			case "instance":
				source.InstanceID = ""
			case "incarnation":
				source.Incarnation = ""
			case "destination":
				target.Incarnation = ""
			}
			if part != "destination" && (members.Join(t.Context(), source) == nil || members.Drain(t.Context(), source) == nil) {
				t.Fatal("name-only membership mutation was accepted")
			}
			if err := members.MoveTenant(t.Context(), "acme", source, target); err == nil || requests != 0 {
				t.Fatalf("incomplete identity reached HTTP: err=%v requests=%d", err, requests)
			}
		})
	}
}

func TestHTTPMembersRejectsMutationRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, supplied := range []bool{false, true} {
			for _, hook := range []string{"join", "drain", "move"} {
				name := http.StatusText(status) + "/default/" + hook
				if supplied {
					name = http.StatusText(status) + "/supplied/" + hook
				}
				t.Run(name, func(t *testing.T) {
					calls := make(chan string, 2)
					handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls <- r.Method
						if r.URL.Path != "/success" {
							w.Header().Set("Location", "/success")
							w.WriteHeader(status)
						}
					})
					var server *httptest.Server
					if supplied {
						server = httptest.NewTLSServer(handler)
					} else {
						server = httptest.NewServer(handler)
					}
					defer server.Close()
					members := HTTPMembers{Endpoint: EndpointTemplate(server.URL)}
					redirectCalls := 0
					if supplied {
						members.Client = server.Client()
						members.Client.CheckRedirect = func(*http.Request, []*http.Request) error { redirectCalls++; return nil }
					}
					var err error
					switch hook {
					case "join":
						err = members.Join(t.Context(), fakeNodeIdentity("gru-1-db-4"))
					case "drain":
						err = members.Drain(t.Context(), fakeNodeIdentity("gru-1-db-4"))
					case "move":
						err = members.MoveTenant(t.Context(), "acme", fakeNodeIdentity("gru-1-db-2"), fakeNodeIdentity("gru-1-db-1"))
					}
					if err == nil || !strings.Contains(err.Error(), "HTTP") || <-calls != http.MethodPost || len(calls) != 0 || redirectCalls != 0 {
						t.Fatalf("redirect authorized a mutation: err=%v follow-up requests=%d callbacks=%d", err, len(calls), redirectCalls)
					}
					if supplied && (members.Client.CheckRedirect(nil, nil) != nil || redirectCalls != 1) {
						t.Fatal("mutation request changed the supplied client's redirect policy")
					}
				})
			}
		}
	}
}

type httpTenantMove struct {
	Members
	http HTTPMembers
}

func (m httpTenantMove) MoveTenant(ctx context.Context, org string, from, to NodeIdentity) error {
	return m.http.MoveTenant(ctx, org, from, to)
}

func TestRedirectedTenantMoveRecordsFailure(t *testing.T) {
	journal := captureJournal(t)
	policy := testPolicy()
	policy.SustainUpSeconds, policy.SustainDownSeconds = 0, 0
	cell := newFakeCell(3, small, 4, 200)
	cell.tenants["gru-1-db-2"] = append(cell.tenants["gru-1-db-2"], TenantLoad{Org: "noisy", Plan: PlanHobby, RequestRate: 1300})
	cell.tenants["gru-1-db-1"] = cell.tenants["gru-1-db-1"][:2]
	s := newSim(t, policy, cell, time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/success" {
			w.Header().Set("Location", "/success")
			w.WriteHeader(http.StatusSeeOther)
		}
	}))
	defer server.Close()
	s.controller.config.Members = httpTenantMove{s.controller.config.Members, HTTPMembers{Endpoint: EndpointTemplate(server.URL)}}
	action, err := s.controller.Tick(t.Context())
	if action.Kind != KindRebalance || err == nil || s.controller.History().Failures != 1 || len(cell.callLog()) != 0 {
		t.Fatalf("redirected move was not failed: action=%+v err=%v history=%+v calls=%v", action, err, s.controller.History(), cell.callLog())
	}
	if len(journal.decisions) != 2 || journal.decisions[1].Status != decisionlog.StatusFailed {
		t.Fatalf("redirected move was recorded as success: %+v", journal.decisions)
	}
}

func TestNaming(t *testing.T) {
	if NodeName("gru-1", 3) != "gru-1-db-3" {
		t.Fatal(NodeName("gru-1", 3))
	}
	for node, want := range map[string]int{"gru-1-db-3": 3, "gru-1-db-64": 64} {
		if n, ok := Ordinal("gru-1", node); !ok || n != want {
			t.Fatalf("Ordinal(%s) = %d, %v", node, n, ok)
		}
	}
	for _, node := range []string{"gru-2-db-3", "gru-1-db-0", "gru-1-db-03", "gru-1-db-65", "gru-1-ctl-1"} {
		if _, ok := Ordinal("gru-1", node); ok {
			t.Fatalf("Ordinal accepted %s", node)
		}
	}
	for cell, ok := range map[string]bool{"gru-1": true, "fra-12": true, "xyz-1": false, "gru-0": false, "gru": false} {
		if err := ValidateCell(cell); (err == nil) != ok {
			t.Fatalf("ValidateCell(%s) = %v", cell, err)
		}
	}
}

func TestCheckCommand(t *testing.T) {
	config := FileConfig{Cell: "gru-1", IntervalSeconds: 60, Endpoint: "http://{node}.netbird.selfhosted:9440",
		Policy: testPolicy(), Template: testTemplate()}
	path := filepath.Join(t.TempDir(), "cell.json")
	write := func(value any) {
		data, _ := json.Marshal(value)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(config)
	var out bytes.Buffer
	if err := Run(t.Context(), []string{"check", "--config", path}, &out); err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report["cell"] != "gru-1" ||
		report["max_monthly_cost"].(float64) <= report["min_monthly_cost"].(float64) {
		t.Fatalf("check output %q: %v", out.String(), err)
	}
	config.Endpoint = "http://gru-1-db-1:9440"
	write(config)
	if err := Run(t.Context(), []string{"check", "--config", path}, io.Discard); err == nil || !strings.Contains(err.Error(), "{node}") {
		t.Fatalf("endpoint without {node}: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"cell":"gru-1","surprise":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(t.Context(), []string{"check", "--config", path}, io.Discard); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("unknown field: %v", err)
	}
	if err := Run(t.Context(), []string{"apply"}, io.Discard); err == nil {
		t.Fatal("unknown subcommand accepted")
	}

	write(FileConfig{Cell: "gru-1", IntervalSeconds: 60, Endpoint: "http://{node}:9440", Policy: testPolicy(), Template: testTemplate()})
	if err := Run(t.Context(), []string{"run", "--config", path, "--live"}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "--rollout-gate") {
		t.Fatalf("live run without a rollout gate: %v", err)
	}
}

func TestRolloutGateFailsClosed(t *testing.T) {
	answer, status := `{"in_flight": true}`, http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	defer server.Close()
	gate := RolloutGate(nil, server.URL)
	if inFlight, err := gate(t.Context()); err != nil || !inFlight {
		t.Fatalf("in flight = %v, %v", inFlight, err)
	}
	answer = `{"in_flight": false}`
	if inFlight, err := gate(t.Context()); err != nil || inFlight {
		t.Fatalf("idle = %v, %v", inFlight, err)
	}
	for _, bad := range []struct {
		answer string
		status int
	}{
		{`{}`, http.StatusOK}, {`not json`, http.StatusOK}, {`null`, http.StatusOK},
		{`{"in_flight": null}`, http.StatusOK}, {`{"in_flight": false}`, http.StatusInternalServerError},
		{`{"in_flight":true,"in_flight":false}`, http.StatusOK},
		{`{"in_flight":false}{"in_flight":true}`, http.StatusOK},
		{`{"in_flight":false}garbage`, http.StatusOK},
		{`{"in_flight":false,"unknown":true}`, http.StatusOK},
		{`{"in_flight":false}` + strings.Repeat(" ", maxPressureBytes), http.StatusOK},
	} {
		answer, status = bad.answer, bad.status
		if _, err := gate(t.Context()); err == nil {
			t.Fatalf("gate accepted %d %s", bad.status, bad.answer)
		}
	}
}

func TestJSONLinesAuditKeepsEvidence(t *testing.T) {
	var out bytes.Buffer
	threshold := 1.0
	var failed error
	jsonLines{out: brokenWriter{}, fail: func(err error) { failed = err }}.Record(t.Context(), decisionlog.Decision{Summary: "x"})
	if failed == nil {
		t.Fatal("a failed audit write must stop the run")
	}
	jsonLines{out: &out, fail: func(err error) { t.Fatal(err) }}.Record(t.Context(), decisionlog.Decision{Kind: decisionlog.KindScaleUp, Summary: "add node",
		Signals: []decisionlog.Signal{{Name: "request_rate", Value: 1.3, Threshold: &threshold}},
		Attrs:   map[string]string{"undo": `{"kind":"scale_in"}`, "monthly_cost": "150.95"}})
	var got decisionlog.Decision
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.ID == "" || got.Attrs["undo"] == "" ||
		got.Attrs["monthly_cost"] != "150.95" || len(got.Signals) != 1 {
		t.Fatalf("audit line %q: %v", out.String(), err)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
