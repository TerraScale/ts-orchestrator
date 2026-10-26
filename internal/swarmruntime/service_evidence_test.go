package swarmruntime

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestProbeServiceSpecExactDoesNotRetryReadiness(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			t.Errorf("unexpected probe path: %s", r.URL.Path)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	spec, control := safetyFixture(t)
	spec.ReadyPath, spec.Port = "/readyz", uint32(server.Listener.Addr().(*net.TCPAddr).Port)
	swarm, err := spec.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	control.service.Spec = *swarm
	control.task.Spec, control.task.ServiceAnnotations = *swarm.Task.Copy(), *swarm.Annotations.Copy()
	control.task.Endpoint = &api.Endpoint{Spec: swarm.Endpoint.Copy()}
	if _, err := ProbeServiceSpecExact(t.Context(), control, spec); err == nil || !strings.Contains(err.Error(), "HTTP 503") || calls.Load() != 1 {
		t.Fatalf("first failed sample was retried: calls=%d err=%v", calls.Load(), err)
	}
	if ready, err := ProbeServiceSpecExact(t.Context(), control, spec); err != nil || len(ready.Tasks) != 1 || !ready.Tasks[0].Ready || calls.Load() != 2 {
		t.Fatalf("later independent healthy sample: %+v calls=%d err=%v", ready, calls.Load(), err)
	}
	calls.Store(0)
	if ready, err := WaitServiceSpecExact(t.Context(), control, spec); err != nil || calls.Load() != 3 || ready.Ready == 0 || ready.Running == 0 {
		t.Fatalf("wait lost retry behavior or phase timings: %+v calls=%d err=%v", ready, calls.Load(), err)
	}
	control.task.Spec.ForceUpdate++
	if _, err := ProbeServiceSpecExact(t.Context(), control, spec); err == nil || calls.Load() != 3 {
		t.Fatalf("changed task reached readiness: calls=%d err=%v", calls.Load(), err)
	}
}
