package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

func TestTaskTrafficSDKPinsExactSetAndSignedQuorum(t *testing.T) {
	const id = "ocid1.loadbalancer.oc1.sa-saopaulo-1.tasktraffic"
	const compartment = "ocid1.compartment.oc1..workload"
	var mu sync.Mutex
	mode := ""
	writes := 0
	factory := rootResourceSDKFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned actual SDK request")
			w.WriteHeader(401)
			return
		}
		if r.Method != http.MethodGet {
			writes++
			w.WriteHeader(405)
			return
		}
		var response any
		switch r.URL.Path {
		case "/20170115/loadBalancers/" + id:
			actual := compartment
			if mode == "foreign compartment" {
				actual = "ocid1.compartment.oc1..foreign"
			}
			response = map[string]any{"id": id, "compartmentId": actual, "lifecycleState": "ACTIVE"}
		case "/20170115/loadBalancers/" + id + "/backendSets/auth":
			name := "auth"
			if mode == "foreign set" {
				name = "other"
			}
			response = map[string]any{"name": name}
		case "/20170115/loadBalancers/" + id + "/backendSets/auth/backends":
			response = []map[string]any{{"ipAddress": "10.0.0.11", "port": 9443, "name": "10.0.0.11:9443", "weight": 1}, {"ipAddress": "10.0.0.12", "port": 9443, "name": "10.0.0.12:9443", "weight": 1}, {"ipAddress": "10.0.0.13", "port": 9443, "name": "10.0.0.13:9443", "weight": 1}}
		case "/20170115/loadBalancers/" + id + "/backendSets/auth/health":
			status, count, unhealthy := "OK", 3, []string{}
			if mode == "one healthy alternative" {
				status, unhealthy = "WARNING", []string{"10.0.0.13:9443"}
			}
			if mode == "unknown health" {
				status = "UNKNOWN"
			}
			if mode == "incomplete health" {
				count = 2
			}
			response = map[string]any{"status": status, "totalBackendCount": count, "warningStateBackendNames": unhealthy, "criticalStateBackendNames": []string{}, "unknownStateBackendNames": []string{}}
		default:
			t.Errorf("unexpected actual SDK path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		wire, err := json.Marshal(response)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(wire)
	}))
	api, err := lb.NewSDKAPI(factory)
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.LoadBalancer()
	if err != nil {
		t.Fatal(err)
	}
	spec := rootTaskTrafficSpec{LoadBalancerID: id, BackendSet: "auth", Port: 9443, MinServing: 2, Backends: []rootTaskTrafficBackend{
		{Node: "ctl-1", IP: "10.0.0.11", Hold: holdHealth, DrainSince: time.Now()}, {Node: "ctl-2", IP: "10.0.0.12"}, {Node: "ctl-3", IP: "10.0.0.13"},
	}}
	resource := rootTaskTrafficResource{kind: "task-traffic-test", api: api, client: client, region: "sa-saopaulo-1", compartment: compartment, pins: map[string]rootTaskTrafficSpec{"auth": spec}}
	target := ociresource.Target[rootTaskTrafficSpec]{Spec: spec, Guard: func(ctx context.Context) error { return ctx.Err() }}
	if _, found, err := resource.Observe(t.Context(), target); err != nil || !found {
		t.Fatalf("pinned actual SDK set: found=%v err=%v", found, err)
	}
	if err := resource.quorum(t.Context(), spec, "10.0.0.11"); err != nil {
		t.Fatalf("two actual alternatives refused: %v", err)
	}
	for _, scenario := range []string{"foreign compartment", "foreign set", "one healthy alternative", "unknown health", "incomplete health"} {
		t.Run(scenario, func(t *testing.T) {
			mu.Lock()
			mode = scenario
			mu.Unlock()
			if err := resource.Apply(t.Context(), target, nil, true, ociresource.Plan{}); err == nil {
				t.Fatal("outside signed pin/quorum accepted")
			}
			mu.Lock()
			defer mu.Unlock()
			if writes != 0 {
				t.Fatalf("unsafe OCI writes=%d", writes)
			}
		})
	}
}

func TestTaskTrafficSDKAdditiveRecoveryRetainsOriginalGuardAfterWorkRequest(t *testing.T) {
	const id = "ocid1.loadbalancer.oc1.sa-saopaulo-1.tasktraffic"
	var mu sync.Mutex
	alive, writes := true, 0
	factory := rootResourceSDKFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned actual SDK request")
			w.WriteHeader(401)
			return
		}
		var response any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/20170115/loadBalancers/"+id:
			response = map[string]any{"id": id, "compartmentId": "ocid1.compartment.oc1..workload", "lifecycleState": "ACTIVE"}
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/backendSets/auth"):
			response = map[string]any{"name": "auth"}
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/backends"):
			response = []any{}
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/backends"):
			var body map[string]any
			if err := json.UnmarshalRead(r.Body, &body); err != nil {
				t.Error(err)
			}
			if body["ipAddress"] != "10.0.0.11" || body["drain"] != false || body["offline"] != false || r.Header.Get("opc-retry-token") == "" {
				t.Errorf("unexpected SDK create %v", body)
			}
			writes++
			w.Header().Set("opc-work-request-id", "accepted-traffic")
			w.WriteHeader(http.StatusAccepted)
			return
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/loadBalancerWorkRequests/accepted-traffic"):
			alive = false
			response = map[string]any{"lifecycleState": "SUCCEEDED"}
		default:
			t.Errorf("unexpected SDK path %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		wire, err := json.Marshal(response)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(wire)
	}))
	api, err := lb.NewSDKAPI(factory)
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.LoadBalancer()
	if err != nil {
		t.Fatal(err)
	}
	spec := rootTaskTrafficSpec{LoadBalancerID: id, BackendSet: "auth", Port: 9443, MinServing: 2, Backends: []rootTaskTrafficBackend{{Node: "ctl-1", IP: "10.0.0.11"}}}
	resource := rootTaskTrafficResource{kind: "task-traffic-test", api: api, client: client, region: "sa-saopaulo-1", compartment: "ocid1.compartment.oc1..workload", pins: map[string]rootTaskTrafficSpec{"auth": spec}}
	target := ociresource.Target[rootTaskTrafficSpec]{Spec: spec, Guard: func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if !alive {
			return ociresource.ErrFenced
		}
		return ctx.Err()
	}}
	if err := resource.Apply(t.Context(), target, nil, true, ociresource.Plan{}); !errors.Is(err, ociresource.ErrFenced) {
		t.Fatalf("lost original source accepted after wait: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if writes != 1 {
		t.Fatalf("additive recovery writes=%d; want one, no writes after source loss", writes)
	}
}

func TestTaskTrafficProtectedHoldsNeedActualReadyTasksAndSignedRestore(t *testing.T) {
	now := time.Now().UTC()
	manager := managerEdgeSnapshot{"ctl-1": {ready: true, roles: map[string]managerEdgeState{"auth": {ready: true}}}}
	address := map[string]string{"ctl-1": "10.0.0.11"}
	previous := []rootTaskTrafficBackend{{Node: "ctl-1", IP: "10.0.0.11", Hold: "nodeop:original", DrainSince: now.Add(-time.Minute), Offline: true}}
	got, err := rootTrafficBackends(manager, address, "auth", previous, nil, nil, defaultFenceGrace, now)
	if err != nil || len(got) != 1 || got[0].Hold != "nodeop:original" {
		t.Fatalf("missing signed restore released protected hold: %+v %v", got, err)
	}
	got, err = rootTrafficBackends(manager, address, "auth", previous, nil, map[string]bool{"ctl-1": true}, defaultFenceGrace, now)
	if err != nil || got[0].Hold != "" || got[0].Offline {
		t.Fatalf("signed restoration with actual readiness refused: %+v %v", got, err)
	}
	manager["ctl-1"] = managerEdgeNode{roles: map[string]managerEdgeState{"auth": {ready: false}}}
	got, err = rootTrafficBackends(manager, address, "auth", nil, nil, nil, defaultFenceGrace, now)
	if err != nil || len(got) != 1 || got[0].Hold != holdHealth {
		t.Fatalf("new unready allocation entered rotation: %+v %v", got, err)
	}
}
