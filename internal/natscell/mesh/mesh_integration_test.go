package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
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

// Mesh TLS accepts a peer of the same CA in both directions and refuses a
// peer of another CA, whatever name either presents.
func TestMeshTLSTrustsOnlyItsCA(t *testing.T) {
	handshake := func(server, client *CA) error {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		done := make(chan error, 1)
		go func() { done <- tls.Server(a, server.TLS("gru."+Domain)).Handshake() }()
		clientErr := tls.Client(b, client.TLS("any.example")).Handshake()
		if clientErr != nil {
			_ = a.Close()
		}
		return errors.Join(clientErr, <-done)
	}
	mesh, err := DeriveCA(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	other, err := DeriveCA(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(mesh, mesh); err != nil {
		t.Fatalf("same CA: %v", err)
	}
	if handshake(mesh, other) == nil || handshake(other, mesh) == nil {
		t.Fatal("a peer of another CA was accepted")
	}
}

// fakeApplier records the generation each service runs in one region.
type fakeApplier struct {
	mu      sync.Mutex
	running map[string]int64
	// unready is an image that never gets ready.
	unready string
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

func (f *fakeApplier) PrePull(context.Context, string) error { return nil }

func (f *fakeApplier) Wait(ctx context.Context, spec swarmruntime.ServiceSpec) (swarmruntime.ServiceRollout, error) {
	if ok, err := f.Running(ctx, spec.Name); err != nil || !ok {
		return swarmruntime.ServiceRollout{}, errors.Join(errors.New("not running"), err)
	}
	if spec.Image == f.unready {
		return swarmruntime.ServiceRollout{}, errors.New("not ready")
	}
	return swarmruntime.ServiceRollout{}, nil
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
	ports := freePorts(t, 6)
	configs := map[string]config{}
	appliers := map[string]*fakeApplier{}
	for i, region := range regions {
		gateways := map[string]string{}
		for j, peer := range regions {
			if peer != region {
				gateways[peer] = fmt.Sprintf("nats://127.0.0.1:%d", ports[2*j])
			}
		}
		appliers[region] = &fakeApplier{running: map[string]int64{}}
		configs[region] = config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), host: "127.0.0.1",
			advertise: fmt.Sprintf("127.0.0.1:%d", ports[2*i]), gatewayPort: ports[2*i], localPort: ports[2*i+1],
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
	if _, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", configs[fra].localPort)); err == nil {
		t.Fatal("loopback listener accepted a client without the token")
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

	// CI's bridge returns the same rows as JSON, one per region.
	if data, err := bridge(t.Context(), sjc.conn, "ping", nil); err != nil || strings.Count(string(data), `"region"`) != len(regions) {
		t.Fatalf("bridge ping = %s, %v", data, err)
	}
	if _, err := bridge(t.Context(), sjc.conn, "apply", json.RawMessage(`{"name":"whoami","unknown":1}`)); err == nil {
		t.Fatal("bridge applied a spec with an unknown field")
	}

	spec := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Port: 8099, Replicas: 1}
	out.Reset()
	if err := printApply(&out)(send(t.Context(), gru.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: 1, Spec: &spec}}, 5*time.Second)); err != nil {
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
	err = printApply(&out)(send(t.Context(), sjc.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: 2, Spec: &spec}}, 2*time.Second))
	if err == nil || !strings.Contains(err.Error(), "failed in "+fra) || !strings.Contains(out.String(), "NO REPLY") {
		t.Fatalf("apply with %s down: %v\n%s", fra, err, out.String())
	}
	if appliers[regions[0]].generation("whoami") != 2 || appliers[regions[1]].generation("whoami") != 2 || appliers[fra].generation("whoami") != 1 {
		t.Fatalf("generations after partial apply:\n%s", out.String())
	}

	launch(fra)
	eventually(t, fra+" to converge by anti-entropy", func() bool { return appliers[fra].generation("whoami") == 2 })

	// An app release changes only the digest; an unready one rolls back everywhere.
	image := func(region string) string {
		node := nodes[region]
		node.mu.Lock()
		defer node.mu.Unlock()
		return node.desired["whoami"].Spec.Image
	}
	good, bad := "docker.io/library/alpine@sha256:"+strings.Repeat("a", 64), "docker.io/library/alpine@sha256:"+strings.Repeat("b", 64)
	if rows, err := release(t.Context(), gru.conn, "whoami", good, 5*time.Second, 5*time.Second); err != nil || len(rows) != len(regions) {
		t.Fatalf("release = %+v, %v", rows, err)
	}
	if _, err := release(t.Context(), gru.conn, "whoami", "docker.io/library/busybox@sha256:"+strings.Repeat("a", 64), 5*time.Second, 5*time.Second); err == nil {
		t.Fatal("a release changed the image repository")
	}
	if _, err := release(t.Context(), gru.conn, "absent", good, 5*time.Second, 5*time.Second); err == nil {
		t.Fatal("released a service the mesh does not run")
	}
	appliers[fra].unready = bad
	rows, err := release(t.Context(), sjc.conn, "whoami", bad, 2*time.Second, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "rolled back to "+good) || len(rows) != 2*len(regions) {
		t.Fatalf("unready release = %+v, %v", rows, err)
	}
	for _, region := range regions {
		if got := image(region); got != good {
			t.Fatalf("%s desires %s after rollback", region, got)
		}
	}

	// A removal not targeting a region is still a removal there.
	out.Reset()
	if err := printApply(&out)(send(t.Context(), gru.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: time.Now().UnixNano()}}, 5*time.Second)); err != nil {
		t.Fatalf("remove: %v\n%s", err, out.String())
	}
	for _, region := range regions {
		if ok, _ := appliers[region].Running(t.Context(), "whoami"); ok {
			t.Fatalf("%s still runs whoami after remove:\n%s", region, out.String())
		}
	}
}

// A region outside the seeds joins by dialing one seed: gateway gossip
// introduces it to the rest, and pings and applies from every region reach it.
func TestNewRegionJoinsByGossip(t *testing.T) {
	ca, err := DeriveCA(bytes.Repeat([]byte{43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	regions := append(Regions(), "ams")
	ports := freePorts(t, 2*len(regions))
	nodes := map[string]*Node{}
	appliers := map[string]*fakeApplier{}
	t.Cleanup(func() {
		for _, node := range nodes {
			node.Close()
		}
	})
	for i, region := range regions {
		gateways := map[string]string{}
		for j, peer := range Regions() {
			// ams knows only gru; the seeds know only each other.
			if peer != region && (region != "ams" || j == 0) {
				gateways[peer] = fmt.Sprintf("nats://127.0.0.1:%d", ports[2*j])
			}
		}
		appliers[region] = &fakeApplier{running: map[string]int64{}}
		node, err := start(config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), host: "127.0.0.1",
			advertise: fmt.Sprintf("127.0.0.1:%d", ports[2*i]), gatewayPort: ports[2*i], localPort: ports[2*i+1],
			gateways: gateways, ca: ca, applier: appliers[region], every: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes[region] = node
	}

	began := time.Now()
	for _, from := range []string{"sjc", "fra"} {
		var out bytes.Buffer
		for Ping(t.Context(), nodes[from].conn, time.Second, &out) != nil || !strings.Contains(out.String(), "ams ") {
			if time.Since(began) > 60*time.Second {
				t.Fatalf("%s got no ping reply from ams within 60 s:\n%s", from, out.String())
			}
			out.Reset()
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Logf("sjc and fra see ams after %s", time.Since(began))
	spec := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Port: 8099, Replicas: 1, Regions: []string{"ams", "fra"}}
	var out bytes.Buffer
	if err := printApply(&out)(send(t.Context(), nodes["fra"].conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: 1, Spec: &spec}}, 5*time.Second)); err != nil {
		t.Fatalf("apply from fra: %v\n%s", err, out.String())
	}
	if appliers["ams"].generation("whoami") != 1 || !strings.Contains(out.String(), "ams ") {
		t.Fatalf("apply from fra did not reach ams:\n%s", out.String())
	}
}

// A second host of a region joins its founder's NATS cluster as a worker:
// its ping and apply reach every region, and its region answers once.
func TestMeshWorkerJoinsItsRegionCluster(t *testing.T) {
	regions := Regions()
	ca, err := DeriveCA(bytes.Repeat([]byte{43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2*len(regions)+4)
	founderRoute, workerPorts := ports[2*len(regions)], ports[2*len(regions)+1:]
	configs := map[string]config{}
	appliers := map[string]*fakeApplier{}
	for i, region := range regions {
		gateways := map[string]string{}
		for j, peer := range regions {
			if peer != region {
				gateways[peer] = fmt.Sprintf("nats://127.0.0.1:%d", ports[2*j])
			}
		}
		appliers[region] = &fakeApplier{running: map[string]int64{}}
		configs[region] = config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), host: "127.0.0.1",
			advertise: fmt.Sprintf("127.0.0.1:%d", ports[2*i]), gatewayPort: ports[2*i], localPort: ports[2*i+1],
			gateways: gateways, ca: ca, applier: appliers[region], every: 300 * time.Millisecond,
		}
	}
	home := regions[0]
	founder := configs[home]
	founder.clusterHost, founder.clusterPort = "127.0.0.1", founderRoute
	configs[home] = founder
	worker := founder
	worker.server, worker.dir, worker.applier = "ts-"+home+"-2", t.TempDir(), nil
	worker.gatewayPort, worker.localPort, worker.clusterPort = workerPorts[0], workerPorts[1], workerPorts[2]
	worker.routes = []string{fmt.Sprintf("nats://127.0.0.1:%d", founderRoute)}
	var nodes []*Node
	t.Cleanup(func() {
		for _, node := range nodes {
			node.Close()
		}
	})
	for _, cfg := range append(slices.Collect(maps.Values(configs)), worker) {
		node, err := start(cfg)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
		go node.run(t.Context())
	}
	joined := nodes[len(nodes)-1]

	var out bytes.Buffer
	eventually(t, "every region to answer the worker's ping", func() bool {
		out.Reset()
		return Ping(t.Context(), joined.conn, time.Second, &out) == nil
	})
	inbox := nats.NewInbox()
	replies, err := joined.conn.SubscribeSync(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if err := joined.conn.PublishRequest(PingSubject, inbox, nil); err != nil {
		t.Fatal(err)
	}
	answered := map[string]int{}
	for {
		msg, err := replies.NextMsg(time.Second)
		if err != nil {
			break
		}
		var reply Reply
		if err := json.Unmarshal(msg.Data, &reply); err != nil {
			t.Fatal(err)
		}
		answered[reply.Region]++
	}
	for _, region := range regions {
		if answered[region] != 1 {
			t.Fatalf("ping answers per region %v, want one each", answered)
		}
	}

	spec := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Port: 8099, Replicas: 2}
	out.Reset()
	if err := printApply(&out)(send(t.Context(), joined.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: 1, Spec: &spec}}, 5*time.Second)); err != nil {
		t.Fatalf("apply from the worker: %v\n%s", err, out.String())
	}
	for _, region := range regions {
		if appliers[region].generation("whoami") != 1 {
			t.Fatalf("%s did not apply the worker's generation 1:\n%s", region, out.String())
		}
	}
}
