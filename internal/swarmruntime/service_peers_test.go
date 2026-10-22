package swarmruntime

import (
	"slices"
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestServiceSpecPeersEnv(t *testing.T) {
	spec := ServiceSpec{Name: "terrabase", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764",
		Port: 8080, Replicas: 1, Env: map[string]string{"A": "1"}, Region: "gru", Node: "gru-1-ctl-1"}
	swarm, err := spec.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	container, err := DecodeContainer(&api.Task{ID: "t", ServiceID: "s", Spec: swarm.Task, ServiceAnnotations: swarm.Annotations})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A=1", "TS_NODE=gru-1-ctl-1", "TS_PEERS_FILE=/run/ts-orch/peers/peers", "TS_REGION=gru"}; !slices.Equal(container.Env, want) {
		t.Fatalf("env = %v, want %v", container.Env, want)
	}
	for _, key := range peersEnv {
		bad := spec
		bad.Env = map[string]string{key: "x"}
		if _, err := bad.SwarmSpec(); err == nil {
			t.Fatalf("a spec setting %s was accepted", key)
		}
	}
	bad := spec
	bad.Node = "Gru_1"
	if _, err := bad.SwarmSpec(); err == nil {
		t.Fatal("an invalid node name was accepted")
	}
}
