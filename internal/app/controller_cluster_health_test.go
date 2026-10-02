package app

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

// Every broker of a formed three-node cell, followers included, must evaluate
// the cluster as healthy from its own real NATS Raft view. A NATS follower
// reports other followers as not current, which must not read as lagging.
func TestClusterHealthIsHealthyOnEveryFormedBroker(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	root := t.TempDir()
	routePorts, routes := make([]int, 3), make([]string, 3)
	for index := range routePorts {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		routePorts[index] = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", routePorts[index])
	}
	runtimes := make([]*natscell.Runtime, 3)
	for index := range runtimes {
		instance := fmt.Sprintf("peer%d", index)
		runtime, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: instance, Replicas: 3, Lab: true,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, RouteHost: "127.0.0.1",
				RoutePort: routePorts[index], Routes: natscell.PeerRoutes(routes, routes[index]),
				StoreDir: filepath.Join(root, instance), BrokerIDs: []string{"peer0", "peer1", "peer2"}}})
		if err != nil {
			t.Fatal(err)
		}
		runtimes[index] = runtime
		defer runtime.Close()
	}
	for _, runtime := range runtimes {
		for !runtime.FullClusterReady(3) {
			if ctx.Err() != nil {
				t.Fatal("cluster did not fully form")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	evaluate := func(runtime *natscell.Runtime) (string, membership.Status) {
		observed, err := runtime.ObserveCluster()
		if err != nil {
			t.Fatal(err)
		}
		return observed.ServerName, membership.Evaluate(membershipObservation(observed),
			membership.DefaultLagThreshold, time.Now())
	}
	for _, runtime := range runtimes {
		for {
			name, status := evaluate(runtime)
			if status.Healthy() {
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("formed cluster is not healthy from %s: %+v", name, status)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// A settled cluster stays healthy from every broker, not only transiently.
	time.Sleep(2 * time.Second)
	for _, runtime := range runtimes {
		if name, status := evaluate(runtime); !status.Healthy() {
			t.Fatalf("settled cluster is not healthy from %s: %+v", name, status)
		}
	}
}
