package app

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership/clusterhealth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

// Every broker of a formed three-node cell, followers included, must evaluate
// the cluster as healthy from its own real NATS Raft view. A NATS follower
// reports other followers as not current, which must not read as lagging.
func TestClusterHealthIsHealthyOnEveryFormedBroker(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	root := t.TempDir()
	runtimes := make([]*natscell.Runtime, 3)
	for index := range runtimes {
		var routes []string
		for _, peer := range runtimes[:index] {
			routes = append(routes, "nats-route://"+peer.RouteAddress().String())
		}
		if len(routes) == 0 {
			routes = []string{"nats-route://127.0.0.1:1"}
		}
		instance := fmt.Sprintf("peer%d", index)
		runtime, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: instance, Replicas: 3, Lab: true,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, RouteHost: "127.0.0.1",
				RoutePort: -1, Routes: routes,
				StoreDir: filepath.Join(root, instance), BrokerIDs: []string{"peer0", "peer1", "peer2"}}})
		if err != nil {
			t.Fatal(err)
		}
		runtimes[index] = runtime
		defer runtime.Close()
		for runtime.RouteAddress() == nil {
			if ctx.Err() != nil {
				t.Fatal("route listener did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for _, runtime := range runtimes {
		for !runtime.FullClusterReady(3) {
			if ctx.Err() != nil {
				t.Fatal("cluster did not fully form")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	evaluate := func(runtime *natscell.Runtime) (string, clusterhealth.Status) {
		observed, err := runtime.ObserveCluster()
		if err != nil {
			t.Fatal(err)
		}
		return observed.ServerName, clusterhealth.Evaluate(clusterHealthObservation(observed),
			clusterhealth.DefaultLagThreshold, time.Now())
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
