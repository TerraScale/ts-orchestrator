package swarmruntime

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func readinessListener(t *testing.T) (net.Listener, netip.Addr) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() {
			continue
		}
		listener, err := net.Listen("tcp4", net.JoinHostPort(prefix.Addr().String(), "0"))
		if err != nil {
			t.Fatal(err)
		}
		return listener, prefix.Addr()
	}
	t.Fatal("integration scenario requires a local private IPv4 interface")
	return nil, netip.Addr{}
}

func TestReadinessIngressIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	client, _, worker := serviceCluster(t, ctx)
	listener, address := readinessListener(t)
	port := uint32(listener.Addr().(*net.TCPAddr).Port)
	var status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	var redirectHits atomic.Int32
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			redirectHits.Add(1)
			http.NotFound(w, r)
			return
		}
		if status.Load() == http.StatusFound {
			w.Header().Set("Location", "/other")
		}
		w.WriteHeader(int(status.Load()))
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	intent := serviceIntent()
	intent.Ports = []*api.PortConfig{{Name: "http", Protocol: api.ProtocolTCP, TargetPort: port, PublishedPort: port, PublishMode: api.PublishModeHost}}
	service, err := applyService(ctx, client, intent)
	if err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		view, err := ObserveService(ctx, client, service.ID, nil)
		return err == nil && view.RunningReplicas == 1 && view.ReadyReplicas == 0
	})
	hosts := map[string]netip.Addr{worker.ID(): address}
	backends := func() (int, uint64) {
		t.Helper()
		spec, view, err := ServiceBackends(ctx, client, service.ID, "ocid1.networkloadbalancer.oc1..integration", "http", hosts)
		if err != nil {
			t.Fatal(err)
		}
		if !spec.AllowEmpty {
			t.Fatal("observed failures must permit removal of stale backends")
		}
		return len(spec.Backends), view.ReadyReplicas
	}
	if count, ready := backends(); count != 0 || ready != 0 {
		t.Fatalf("RUNNING with HTTP 503 entered traffic: backends=%d ready=%d", count, ready)
	}
	status.Store(http.StatusOK)
	if count, ready := backends(); count != 1 || ready != 1 {
		t.Fatalf("healthy task did not enter traffic: backends=%d ready=%d", count, ready)
	}
	status.Store(http.StatusFound)
	if count, ready := backends(); count != 0 || ready != 0 || redirectHits.Load() != 0 {
		t.Fatalf("redirect followed or retained traffic: backends=%d ready=%d redirects=%d", count, ready, redirectHits.Load())
	}
	status.Store(http.StatusOK)
	delete(hosts, worker.ID())
	if count, ready := backends(); count != 0 || ready != 0 {
		t.Fatalf("unadmitted host entered traffic: backends=%d ready=%d", count, ready)
	}
	hosts[worker.ID()] = netip.MustParseAddr("127.0.0.1")
	if count, ready := backends(); count != 0 || ready != 0 {
		t.Fatalf("loopback target entered traffic: backends=%d ready=%d", count, ready)
	}
	hosts[worker.ID()] = address
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if count, ready := backends(); count != 0 || ready != 0 {
		t.Fatalf("closed listener retained traffic: backends=%d ready=%d", count, ready)
	}
	if _, _, err := ServiceBackends(ctx, client, "nonexistent", "ocid1.networkloadbalancer.oc1..integration", "http", hosts); err == nil {
		t.Fatal("unavailable service was relabeled as an observed empty service")
	}
}
