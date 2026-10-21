package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

func TestDeriveCAIsDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	a, err := DeriveCA(secret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveCA(bytes.Clone(secret))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Cert.Raw, b.Cert.Raw) {
		t.Fatal("two derivations from one secret built different CA certificates")
	}
	other, err := DeriveCA(bytes.Repeat([]byte{8}, 32))
	if err != nil || bytes.Equal(a.Cert.Raw, other.Cert.Raw) {
		t.Fatalf("a different secret must build a different CA: %v", err)
	}
}

// fakeApplier records the generation each service runs in one region.
type fakeApplier struct {
	mu      sync.Mutex
	running map[string]int64
}

func (f *fakeApplier) Apply(_ context.Context, spec swarmruntime.ServiceSpec) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.running[spec.Name] == spec.Generation {
		return false, nil
	}
	f.running[spec.Name] = spec.Generation
	return true, nil
}

func (f *fakeApplier) Remove(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.running[name]
	delete(f.running, name)
	return ok, nil
}

func (f *fakeApplier) Running(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.running[name]
	return ok, nil
}

func (f *fakeApplier) generation(name string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running[name]
}

func freePorts(t *testing.T, count int) []int {
	ports := []int{}
	for range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestMeshAppliesInEveryRegionAndCatchesUpAfterRestart(t *testing.T) {
	regions := Regions()
	if len(regions) != 3 {
		t.Fatalf("ordered regions = %v", regions)
	}
	ca, err := DeriveCA(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 9)
	configs := map[string]config{}
	appliers := map[string]*fakeApplier{}
	for i, region := range regions {
		gateways := map[string]string{}
		for j, peer := range regions {
			if peer != region {
				gateways[peer] = fmt.Sprintf("nats://127.0.0.1:%d", ports[3*j+1])
			}
		}
		appliers[region] = &fakeApplier{running: map[string]int64{}}
		configs[region] = config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), host: "127.0.0.1",
			clientPort: ports[3*i], gatewayPort: ports[3*i+1], localPort: ports[3*i+2],
			gateways: gateways, ca: ca, applier: appliers[region], every: 300 * time.Millisecond,
		}
	}
	nodes := map[string]*Node{}
	launch := func(region string) {
		node, err := start(configs[region])
		if err != nil {
			t.Fatal(err)
		}
		nodes[region] = node
		go node.run(t.Context())
	}
	for _, region := range regions {
		launch(region)
	}
	t.Cleanup(func() {
		for _, node := range nodes {
			node.Close()
		}
	})
	gru, sjc, fra := nodes[regions[0]], nodes[regions[1]], regions[2]

	// The root CLI's loopback listener needs the token.
	if _, err := nats.Connect(fmt.Sprintf("ws://127.0.0.1:%d", configs[fra].localPort)); err == nil {
		t.Fatal("loopback listener accepted a client without the token")
	}
	// The public listener accepts a CA-signed client and refuses any other.
	public := fmt.Sprintf("tls://127.0.0.1:%d", configs[fra].clientPort)
	if conn, err := nats.Connect(public, nats.Secure(ca.TLS("ci.mesh.terrascale.tech"))); err != nil {
		t.Fatalf("public listener refused a mesh client: %v", err)
	} else {
		conn.Close()
	}
	if _, err := nats.Connect(public, nats.Secure(&tls.Config{InsecureSkipVerify: true})); err == nil {
		t.Fatal("public listener accepted a client without a mesh certificate")
	}

	var out bytes.Buffer
	eventually(t, "every region to answer ping", func() bool {
		out.Reset()
		return Ping(t.Context(), gru.conn, time.Second, &out) == nil
	})
	for _, region := range regions {
		if !strings.Contains(out.String(), region+" ") {
			t.Fatalf("ping output misses %s:\n%s", region, out.String())
		}
	}

	spec := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Port: 8099, Replicas: 1}
	out.Reset()
	if err := send(t.Context(), gru.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: 1, Spec: &spec}}, 5*time.Second, &out); err != nil {
		t.Fatalf("apply from %s: %v\n%s", regions[0], err, out.String())
	}
	for _, region := range regions {
		if appliers[region].generation("whoami") != 1 {
			t.Fatalf("%s did not apply generation 1:\n%s", region, out.String())
		}
	}

	nodes[fra].Close()
	delete(nodes, fra)
	spec.Args = []string{"/bin/true"}
	out.Reset()
	err = send(t.Context(), sjc.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: 2, Spec: &spec}}, 2*time.Second, &out)
	if err == nil || !strings.Contains(err.Error(), "failed in "+fra) || !strings.Contains(out.String(), "NO REPLY") {
		t.Fatalf("apply with %s down: %v\n%s", fra, err, out.String())
	}
	if appliers[regions[0]].generation("whoami") != 2 || appliers[regions[1]].generation("whoami") != 2 || appliers[fra].generation("whoami") != 1 {
		t.Fatalf("generations after partial apply:\n%s", out.String())
	}

	launch(fra)
	eventually(t, fra+" to converge by anti-entropy", func() bool { return appliers[fra].generation("whoami") == 2 })

	// A removal not targeting a region is still a removal there.
	out.Reset()
	if err := send(t.Context(), gru.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: 3}}, 5*time.Second, &out); err != nil {
		t.Fatalf("remove: %v\n%s", err, out.String())
	}
	for _, region := range regions {
		if ok, _ := appliers[region].Running(t.Context(), "whoami"); ok {
			t.Fatalf("%s still runs whoami after remove:\n%s", region, out.String())
		}
	}
}
