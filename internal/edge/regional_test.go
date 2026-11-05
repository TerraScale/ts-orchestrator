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
)

// A long response must finish before the handoff. Afterwards the same ingress
// routes to the new writer, with public identity preserved and peer proof set.
func TestRegionalHandoffDrainsResponseBeforeMovingWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var moved atomic.Bool
	var drainCalls atomic.Int32
	bodyStarted := make(chan struct{})
	finishBody := make(chan struct{})
	servers := map[string]*httptest.Server{}
	for _, node := range []string{"n1", "n2"} {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(peerCredentialHeader) != strings.Repeat("a", 64) {
				t.Error("missing peer authentication")
				w.WriteHeader(401)
				return
			}
			switch r.URL.Path {
			case "/v1/rollout/status":
				owner := "n1"
				if moved.Load() {
					owner = "n2"
				}
				_ = json.NewEncoder(w).Encode(regionalStatus{Node: node, Owner: owner, Epoch: 1, Writer: owner == node, Ready: true})
			case "/v1/rollout/prime":
				w.WriteHeader(204)
			case "/v1/rollout/drain":
				drainCalls.Add(1)
				moved.Store(true)
				w.WriteHeader(204)
			case "/long":
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				close(bodyStarted)
				select {
				case <-finishBody:
				case <-r.Context().Done():
				}
				_, _ = io.WriteString(w, node)
			default:
				if r.Header.Get(forwardedClientHeader) != "192.0.2.1" {
					t.Error("client identity changed")
				}
				_, _ = io.WriteString(w, node)
			}
		}))
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		server.Config.Protocols = protocols
		server.Start()
		defer server.Close()
		servers[node] = server
	}
	edge := New(t.TempDir())
	if err := edge.SetRequestProofSecret(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	edge.SetRegionalNodes(func() []mesh.WorkerPeer {
		return []mesh.WorkerPeer{{Node: "n1", Address: "n1"}, {Node: "n2", Address: "n2"}}
	})
	router := edge.regional.Load()
	router.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		return (&net.Dialer{}).DialContext(ctx, network, servers[host].Listener.Addr().String())
	}
	request := httptest.NewRequest("GET", "http://localhost:8080/long", nil).WithContext(ctx)
	request.RemoteAddr = "192.0.2.1:1234"
	response, err := edge.regionalRoundTrip(request, false)
	if err != nil {
		t.Fatal(err)
	}
	<-bodyStarted
	drained := make(chan error, 1)
	go func() { drained <- edge.DrainRegionalNode(ctx, "n1") }()
	// The admission barrier is observable without relying on a timing sleep.
	for !router.holding.Load() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}
	}
	if drainCalls.Load() != 0 {
		t.Fatal("handoff began before the response finished")
	}
	close(finishBody)
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest("POST", "http://localhost:8080/write", strings.NewReader("one")).WithContext(ctx)
	request.RemoteAddr = "192.0.2.1:1234"
	response, err = edge.regionalRoundTrip(request, false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "n2" {
		t.Fatalf("after handoff: %q, %v", body, err)
	}
}

func TestRegionalDrainRejectsAnUnreadySurvivingPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(regionalStatus{Node: "n1", Owner: "n1", Writer: true, Ready: false})
	}))
	defer server.Close()
	edge := New(t.TempDir())
	_ = edge.SetRequestProofSecret(strings.Repeat("a", 64))
	edge.SetRegionalNodes(func() []mesh.WorkerPeer {
		return []mesh.WorkerPeer{{Node: "n1", Address: "n1"}, {Node: "n2", Address: "n2"}}
	})
	router := edge.regional.Load()
	router.transport.Protocols = nil
	router.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	if err := edge.DrainRegionalNode(ctx, "n2"); err == nil {
		t.Fatal("unready peer authorized stop")
	}
}
