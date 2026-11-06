package edge

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
)

func TestBootstrapIngressDrainsAndRetainsItsHoldAfterRestart(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var primes atomic.Int32
	bodyStarted, finishBody := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(peerCredentialHeader) != strings.Repeat("a", 64) {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/rollout/status":
			node := strings.Split(r.Host, ":")[0]
			_ = json.NewEncoder(w).Encode(regionalStatus{Node: node, Owner: "n1", Epoch: 7, Writer: node == "n1", Ready: true})
		case "/v1/rollout/prime":
			primes.Add(1)
			w.WriteHeader(204)
		case "/v1/rollout/drain":
			t.Error("bootstrap invoked legacy ownership handoff")
			w.WriteHeader(500)
		case "/long":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(bodyStarted)
			select {
			case <-finishBody:
			case <-r.Context().Done():
			}
			_, _ = io.WriteString(w, "acknowledged")
		default:
			_, _ = io.WriteString(w, "n1")
		}
	}))
	defer server.Close()
	state := t.TempDir()
	open := func() *Edge {
		e := New(state)
		if err := e.SetRequestProofSecret(strings.Repeat("a", 64)); err != nil {
			t.Fatal(err)
		}
		e.SetRegionalNodes(func() []mesh.WorkerPeer {
			return []mesh.WorkerPeer{{Node: "n1", Address: "n1"}, {Node: "n2", Address: "n2"}}
		})
		r := e.regional.Load()
		r.transport.Protocols = nil
		r.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		t.Cleanup(r.transport.CloseIdleConnections)
		return e
	}
	e := open()
	j := rolloutmaintenance.Job{Member: "n1", ID: "owner-bootstrap", Owner: "n1", Epoch: 7,
		Source: rolloutmaintenance.Pin{Node: "swarm-node", Service: "terrabase", Task: "old", Fingerprint: strings.Repeat("a", 64), Image: "registry/app@sha256:" + strings.Repeat("1", 64)},
		Target: rolloutmaintenance.Pin{Node: "swarm-node", Service: "terrabase", Image: "registry/app@sha256:" + strings.Repeat("2", 64)}, Process: rolloutmaintenance.Process{PID: 1, Start: 1}, Phase: "quiescing", Deadline: time.Now().Add(time.Minute)}
	request := func(path string) *http.Request {
		r := httptest.NewRequest("POST", "http://localhost:8080"+path, nil).WithContext(ctx)
		r.RemoteAddr = "192.0.2.1:1234"
		return r
	}
	response, err := e.regionalRoundTrip(request("/long"), false)
	if err != nil {
		t.Fatal(err)
	}
	<-bodyStarted
	defer response.Body.Close()
	held := make(chan error, 1)
	go func() { held <- e.Bootstrap(ctx, "hold", j) }()
	for !e.regional.Load().holding.Load() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-held:
		t.Fatal("hold completed before in-flight response", err)
	default:
	}
	close(finishBody)
	if body, err := io.ReadAll(response.Body); err != nil || string(body) != "acknowledged" {
		t.Fatalf("lost in-flight response: %q %v", body, err)
	}
	if err := <-held; err != nil || primes.Load() != 1 {
		t.Fatal("hold did not certify follower catch-up", err, primes.Load())
	}
	// A restarted edge has no in-memory mutex state. The durable hold still
	// refuses both public and internal traffic before any backend call.
	restarted := open()
	for _, internal := range []bool{false, true} {
		if _, err := restarted.regionalRoundTrip(request("/write"), internal); err == nil {
			t.Fatal("restart reopened held ingress")
		}
	}
	if err := restarted.Bootstrap(ctx, "release", j); err == nil {
		t.Fatal("restart released without reacquiring the barrier")
	}
	if err := restarted.Bootstrap(ctx, "hold", j); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Bootstrap(ctx, "verify", j); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Bootstrap(ctx, "release", j); err != nil {
		t.Fatal(err)
	}
	response, err = restarted.regionalRoundTrip(request("/write"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if body, err := io.ReadAll(response.Body); err != nil || string(body) != "n1" {
		t.Fatalf("restored owner: %q %v", body, err)
	}
	// A held follower (e.g. a rebooted worker) may only read its pinned owner.
	follower := j
	follower.Member, follower.ID = "n2", "follower-bootstrap"
	if err := restarted.Bootstrap(ctx, "owner", follower); err != nil {
		t.Fatal("ready pinned owner refused", err)
	}
	follower.Epoch = 8
	if err := restarted.Bootstrap(ctx, "owner", follower); err == nil {
		t.Fatal("owner at another epoch accepted")
	}
	// Release the defunct fixture's in-memory barrier after the restart proof.
	e.bootstrapBarrier.release()
}
