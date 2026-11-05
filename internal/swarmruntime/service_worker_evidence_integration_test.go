package swarmruntime

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real SwarmKit membership/scheduling plus HTTP applications prove that an
// admitted holder participates in a release and cannot borrow founder health.
func TestPerNodeReleaseVerifiesWorkerReadiness(t *testing.T) {
	if testing.Short() {
		t.Skip("two-node release qualification runs in Slow")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	client, _, _ := serviceCluster(t, ctx)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var private netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && prefix.Addr().IsPrivate() {
			private = prefix.Addr()
			break
		}
	}
	if !private.IsValid() {
		t.Fatal("release proof needs a local private IPv4 address")
	}
	founder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer founder.Close()
	port := founder.Listener.Addr().(*net.TCPAddr).Port
	listener, err := net.Listen("tcp", net.JoinHostPort(private.String(), strings.Split(founder.Listener.Addr().String(), ":")[1]))
	if err != nil {
		t.Fatal(err)
	}
	var status atomic.Int32
	status.Store(http.StatusOK)
	holder := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(status.Load())) }))
	holder.Listener.Close()
	holder.Listener = listener
	holder.Start()
	defer holder.Close()
	spec := ServiceSpec{Name: "worker-evidence", Image: "example.invalid/fixture@sha256:" + strings.Repeat("a", 64),
		Port: uint32(port), ReadyPath: "/readyz", Replicas: 2, Region: "gru", Node: "ts-gru-1", Generation: 1,
		Mounts:          []ServiceMount{{Source: "/var/lib/ts-data/worker-evidence", Target: "/data"}},
		WorkerAddresses: map[string]string{"ts-gru-2": private.String()}}
	if _, err := ApplyServiceSpec(ctx, client, spec); err != nil {
		t.Fatal(err)
	}
	ready, err := WaitServiceSpecExact(ctx, client, spec)
	if err != nil || len(ready.Tasks) != 2 {
		t.Fatalf("two-node release: %+v, %v", ready, err)
	}
	machines := map[string]bool{}
	for _, task := range ready.Tasks {
		machines[task.Machine] = true
	}
	if !machines["ts-gru-1"] || !machines["ts-gru-2"] {
		t.Fatalf("release machines: %v", machines)
	}
	status.Store(http.StatusServiceUnavailable)
	if _, err := ProbeServiceSpecExact(ctx, client, spec); err == nil {
		t.Fatal("unready holder borrowed the healthy founder's readiness")
	}
}
