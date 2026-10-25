package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
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
	// settle is how long an applied generation takes to get ready.
	settle  time.Duration
	applied map[string]time.Time
	images  map[string]string
}

func (f *fakeApplier) Apply(_ context.Context, spec swarmruntime.ServiceSpec) (bool, *api.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	swarm, err := spec.SwarmSpec()
	if err != nil {
		return false, nil, err
	}
	service := &api.Service{ID: spec.Name, Spec: *swarm}
	if f.running[spec.Name] == spec.Generation {
		return false, service, nil
	}
	f.running[spec.Name] = spec.Generation
	if f.applied == nil {
		f.applied = map[string]time.Time{}
	}
	f.applied[spec.Name] = time.Now()
	if f.images == nil {
		f.images = map[string]string{}
	}
	f.images[spec.Name] = spec.Image
	return true, service, nil
}

func (f *fakeApplier) appliedImage(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.images[name]
}

func (f *fakeApplier) Ready(context.Context) (map[string]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ready := map[string]int64{}
	for name, generation := range f.running {
		if time.Since(f.applied[name]) >= f.settle {
			ready[name] = generation
		}
	}
	return ready, nil
}

func (f *fakeApplier) appliedAt(name string) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied[name]
}

func (f *fakeApplier) Remove(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.running[name]
	delete(f.running, name)
	return ok, nil
}

func (f *fakeApplier) PrePull(context.Context, swarmruntime.ServiceSpec) error { return nil }

func (f *fakeApplier) Wait(ctx context.Context, spec swarmruntime.ServiceSpec, _ *api.Service) (swarmruntime.ServiceRollout, error) {
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
		address := fmt.Sprintf("10.200.0.%d", i+1)
		configs[region] = config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), host: "127.0.0.1",
			advertise: fmt.Sprintf("127.0.0.1:%d", ports[2*i]), gatewayPort: ports[2*i], localPort: ports[2*i+1],
			gateways: gateways, ca: ca, applier: appliers[region], every: 300 * time.Millisecond,
			peersDir: t.TempDir(), peersEvery: 300 * time.Millisecond, address: func() (string, error) { return address, nil },
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

	// The edge orders replay targets by these round trips; gateways measure
	// them about a second after connecting, then every 15 s.
	eventually(t, "gru to measure RTT to sjc and fra", func() bool {
		rtt := gru.RTT()
		return rtt[sjc.Region()] > 0 && rtt[fra] > 0
	})

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
	peersFile := func(region string) string {
		data, _ := os.ReadFile(filepath.Join(configs[region].peersDir, "whoami", "peers"))
		return string(data)
	}
	// Lines sort by node name; region i's node has address 10.200.0.<i+1>.
	every := fmt.Sprintf("ts-%[3]s-1 %[3]s 10.200.0.3\nts-%[1]s-1 %[1]s 10.200.0.1\nts-%[2]s-1 %[2]s 10.200.0.2\n", regions[0], regions[1], fra)
	withoutFra := fmt.Sprintf("ts-%[1]s-1 %[1]s 10.200.0.1\nts-%[2]s-1 %[2]s 10.200.0.2\n", regions[0], regions[1])
	eventually(t, "every region's peers file to list every region", func() bool {
		return peersFile(regions[0]) == every && peersFile(regions[1]) == every && peersFile(fra) == every
	})
	// The task's non-root user reads the file through the bound directory.
	dir := filepath.Join(configs[regions[0]].peersDir, "whoami")
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("peers directory mode: %v %v", info, err)
	}
	if info, err := os.Stat(filepath.Join(dir, "peers")); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("peers file mode: %v %v", info, err)
	}

	nodes[fra].Close()
	delete(nodes, fra)
	eventually(t, fra+" to leave the peers file", func() bool { return peersFile(regions[0]) == withoutFra })
	spec.Args = []string{"/bin/true"}
	out.Reset()
	// gru rolls last and first waits out fra's missing state reply.
	err = printApply(&out)(send(t.Context(), sjc.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: 2, Spec: &spec}}, 5*time.Second))
	if err == nil || !strings.Contains(err.Error(), "failed in "+fra) || !strings.Contains(out.String(), "NO REPLY") {
		t.Fatalf("apply with %s down: %v\n%s", fra, err, out.String())
	}
	if appliers[regions[0]].generation("whoami") != 2 || appliers[regions[1]].generation("whoami") != 2 || appliers[fra].generation("whoami") != 1 {
		t.Fatalf("generations after partial apply:\n%s", out.String())
	}

	launch(fra)
	eventually(t, fra+" to converge by anti-entropy", func() bool { return appliers[fra].generation("whoami") == 2 })
	eventually(t, fra+" to rejoin the peers file", func() bool { return peersFile(regions[0]) == every })

	// An app release changes only the digest; an unready one rolls back everywhere.
	image := func(region string) string {
		node := nodes[region]
		node.mu.Lock()
		defer node.mu.Unlock()
		return node.desired["whoami"].entry().Spec.Image
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

	if data, err := bridge(t.Context(), gru.conn, "state", nil); err != nil || string(data) != `{"whoami":"`+good+`"}` {
		t.Fatalf("bridge state = %s, %v", data, err)
	}

	// A service targeting one region lists only that region's node.
	spec.Regions = []string{regions[1]}
	out.Reset()
	if err := printApply(&out)(send(t.Context(), gru.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: time.Now().UnixNano(), Spec: &spec}}, 5*time.Second)); err != nil {
		t.Fatalf("apply to %s only: %v\n%s", regions[1], err, out.String())
	}
	if got, want := peersFile(regions[1]), fmt.Sprintf("ts-%s-1 %s 10.200.0.2\n", regions[1], regions[1]); got != want {
		t.Fatalf("%s peers file = %q, want %q", regions[1], got, want)
	}
	if got := peersFile(regions[0]); got != "" {
		t.Fatalf("untargeted %s kept a peers file: %q", regions[0], got)
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
			peersDir: t.TempDir(), peersEvery: time.Hour, address: func() (string, error) { return fmt.Sprintf("10.200.1.%d", i+1), nil },
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
			peersDir: t.TempDir(), peersEvery: 300 * time.Millisecond, address: func() (string, error) { return fmt.Sprintf("10.200.2.%d", i+1), nil },
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

// One apply replaces regions one at a time, in catalog order: each region
// applies only once the previous one runs the generation ready, so the edge
// always has a serving region to hand a stop-first TerraBase swap off to.
func TestMeshRollsRegionsOneAtATime(t *testing.T) {
	const settle = time.Second
	regions, nodes, appliers := startMeshRegions(t, settle)
	gru := nodes[regions[0]]

	spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Port: 8080, Replicas: 1}
	var out bytes.Buffer
	if err := printApply(&out)(send(t.Context(), gru.conn, ApplyRequest{Name: "terrabase", Entry: Entry{Generation: 7, Spec: &spec}}, 30*time.Second)); err != nil {
		t.Fatalf("apply: %v\n%s", err, out.String())
	}
	t.Logf("apply:\n%s", out.String())
	// A spec for every region rolls gru (ts-auth, dashboard) last.
	assertOrder(t, appliers, "terrabase", rolloutOrder(&spec), settle)
	if order := rolloutOrder(&spec); order[len(order)-1] != regions[0] {
		t.Fatalf("default order %v does not end with %s", order, regions[0])
	}

	// A spec's own region list is its rollout order.
	spec.Regions = []string{regions[2], regions[0], regions[1]}
	out.Reset()
	if err := printApply(&out)(send(t.Context(), gru.conn, ApplyRequest{Name: "terrabase", Entry: Entry{Generation: 8, Spec: &spec}}, 30*time.Second)); err != nil {
		t.Fatalf("ordered apply: %v\n%s", err, out.String())
	}
	assertOrder(t, appliers, "terrabase", spec.Regions, settle)
}

func assertOrder(t *testing.T, appliers map[string]*fakeApplier, name string, order []string, settle time.Duration) {
	t.Helper()
	for i := 1; i < len(order); i++ {
		previous, next := appliers[order[i-1]].appliedAt(name), appliers[order[i]].appliedAt(name)
		if previous.IsZero() || next.Sub(previous) < settle {
			t.Fatalf("%s applied %s after %s; want at least %s, once %s is ready (order %v)", order[i], next.Sub(previous), order[i-1], settle, order[i-1], order)
		}
	}
}

// When the first region of a rollout fails readiness, the later regions never
// apply it and every region gets the previous spec back, well within the
// apply window.
func TestMeshFailedRegionStopsAndRollsBack(t *testing.T) {
	regions, nodes, appliers := startMeshRegions(t, 0)
	conn := nodes[regions[0]].conn
	good := swarmruntime.ServiceSpec{Name: "terrabase", Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	if _, err := applySpec(t.Context(), conn, good, "", false, 30*time.Second); err != nil {
		t.Fatalf("good apply: %v", err)
	}
	order := rolloutOrder(&good)
	appliers[order[0]].unready = "docker.io/library/alpine@sha256:" + strings.Repeat("b", 64)
	bad := good
	bad.Image = appliers[order[0]].unready
	start := time.Now()
	rows, err := applySpec(t.Context(), conn, bad, "", false, 60*time.Second)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "rolled back to "+good.Image) {
		t.Fatalf("bad apply = %v\n%+v", err, rows)
	}
	if elapsed > 30*time.Second {
		t.Fatalf("stop and rollback took %s", elapsed)
	}
	for _, region := range order[1:] {
		if appliers[region].appliedImage("terrabase") == bad.Image {
			t.Fatalf("%s applied the failed image after %s failed", region, order[0])
		}
	}
	eventually(t, "every region to run the previous image", func() bool {
		for _, region := range regions {
			if appliers[region].appliedImage("terrabase") != good.Image {
				return false
			}
		}
		return true
	})
}

// startMeshRegions runs every founded region's mesh node with a fake applier
// whose applied generation gets ready after settle.
func startMeshRegions(t *testing.T, settle time.Duration) ([]string, map[string]*Node, map[string]*fakeApplier) {
	t.Helper()
	regions := Regions()
	ca, err := DeriveCA(bytes.Repeat([]byte{43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 6)
	appliers := map[string]*fakeApplier{}
	nodes := map[string]*Node{}
	for i, region := range regions {
		gateways := map[string]string{}
		for j, peer := range regions {
			if peer != region {
				gateways[peer] = fmt.Sprintf("nats://127.0.0.1:%d", ports[2*j])
			}
		}
		appliers[region] = &fakeApplier{running: map[string]int64{}, settle: settle}
		address := fmt.Sprintf("10.201.0.%d", i+1)
		node, err := start(config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), host: "127.0.0.1",
			advertise: fmt.Sprintf("127.0.0.1:%d", ports[2*i]), gatewayPort: ports[2*i], localPort: ports[2*i+1],
			gateways: gateways, ca: ca, applier: appliers[region], every: 300 * time.Millisecond,
			peersDir: t.TempDir(), peersEvery: 300 * time.Millisecond, address: func() (string, error) { return address, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes[region] = node
		go node.run(t.Context())
	}
	t.Cleanup(func() {
		for _, node := range nodes {
			node.Close()
		}
	})
	eventually(t, "every region to answer ping", func() bool { return Ping(t.Context(), nodes[regions[0]].conn, time.Second, io.Discard) == nil })
	return regions, nodes, appliers
}

// A rollout's windows follow the spec's readiness timeout: each region waits
// for the earlier ones, then gets its own timeout.
func TestRolloutWindowsFollowReadyTimeout(t *testing.T) {
	regions := Regions()
	spec := &swarmruntime.ServiceSpec{Name: "terrabase", ReadyPath: "/readyz", ReadyTimeoutSeconds: 180, Regions: []string{regions[1], regions[2], regions[0]}}
	if got, want := rolloutWait(spec), 3*(210*time.Second); got != want {
		t.Fatalf("rolloutWait = %s, want %s", got, want)
	}
	last := &Node{cfg: config{region: regions[0]}}
	if got, want := last.applyWindow(spec), 3*(210*time.Second)-10*time.Second; got != want {
		t.Fatalf("last region's window = %s, want %s", got, want)
	}
	if got := rolloutWait(&swarmruntime.ServiceSpec{Name: "whoami"}); got != max(applyWait, 3*90*time.Second) {
		t.Fatalf("default rolloutWait = %s", got)
	}
	if rolloutWait(spec) > releasepush.HandlerWait-time.Minute {
		t.Fatalf("rollout %s does not fit the release handler's %s", rolloutWait(spec), releasepush.HandlerWait)
	}
}

// A canary hold: the rollout applies the first region only; the later ones
// keep the previous generation, also through the sync loop, until Resume.
func TestMeshCanaryHoldsUntilResume(t *testing.T) {
	regions, nodes, appliers := startMeshRegions(t, 0)
	conn := nodes[regions[0]].conn
	spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	if _, err := applySpec(t.Context(), conn, spec, "", false, 30*time.Second); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	order := rolloutOrder(&spec)
	next := spec
	next.Image = "docker.io/library/alpine@sha256:" + strings.Repeat("c", 64)
	if _, err := applySpec(t.Context(), conn, next, "nowhere", false, 30*time.Second); err == nil {
		t.Fatal("a hold after a region outside the rollout was accepted")
	}
	rows, err := applySpec(t.Context(), conn, next, order[0], false, 30*time.Second)
	if err != nil {
		t.Fatalf("held apply: %v\n%+v", err, rows)
	}
	for _, row := range rows {
		if row.Region != order[0] && row.Result != "held after "+order[0] {
			t.Fatalf("%s answered %q, want held", row.Region, row.Result)
		}
	}
	time.Sleep(time.Second) // a few sync ticks (300 ms) must not roll the held regions
	for i, region := range order {
		if got, want := appliers[region].appliedImage("terrabase"), map[bool]string{true: next.Image, false: spec.Image}[i == 0]; got != want {
			t.Fatalf("%s runs %s while held after %s, want %s", region, got, order[0], want)
		}
	}
	var out bytes.Buffer
	if err := Resume(t.Context(), conn, "terrabase", &out); err != nil {
		t.Fatalf("resume: %v\n%s", err, out.String())
	}
	for _, region := range order {
		if got := appliers[region].appliedImage("terrabase"); got != next.Image {
			t.Fatalf("%s runs %s after resume, want %s", region, got, next.Image)
		}
	}
	if err := Resume(t.Context(), conn, "terrabase", &out); err == nil {
		t.Fatal("resumed a rollout that is not held")
	}
}

// A ts-orch self-update stops one region's node and starts it again on the
// same state. Its TerraBase peers file must list every region throughout: the
// exit must not write a round only this node answered, and the new node must
// keep and re-render the file even while the rollout is held (2026-10-25 gru).
func TestMeshRestartKeepsPeersFile(t *testing.T) {
	regions := Regions()
	ca, err := DeriveCA(bytes.Repeat([]byte{44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 6)
	configs := map[string]config{}
	for i, region := range regions {
		gateways := map[string]string{}
		for j, peer := range regions {
			if peer != region {
				gateways[peer] = fmt.Sprintf("nats://127.0.0.1:%d", ports[2*j])
			}
		}
		address := fmt.Sprintf("10.202.0.%d", i+1)
		configs[region] = config{
			region: region, server: "ts-" + region + "-1", dir: t.TempDir(), host: "127.0.0.1",
			advertise: fmt.Sprintf("127.0.0.1:%d", ports[2*i]), gatewayPort: ports[2*i], localPort: ports[2*i+1],
			gateways: gateways, ca: ca, applier: &fakeApplier{running: map[string]int64{}}, every: 300 * time.Millisecond,
			peersDir: t.TempDir(), peersEvery: 300 * time.Millisecond, address: func() (string, error) { return address, nil },
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
	home := regions[0]
	lines := func() int {
		data, _ := os.ReadFile(filepath.Join(configs[home].peersDir, "terrabase", "peers"))
		return strings.Count(string(data), "\n")
	}
	eventually(t, "every region to answer ping", func() bool { return Ping(t.Context(), nodes[home].conn, time.Second, io.Discard) == nil })
	spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	if _, err := applySpec(t.Context(), nodes[home].conn, spec, "", false, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	eventually(t, home+"'s peers file to list every region", func() bool { return lines() == len(regions) })
	// A held canary: the home region waits, as gru did during batch 8b.
	next := spec
	next.Image = "docker.io/library/alpine@sha256:" + strings.Repeat("b", 64)
	if _, err := applySpec(t.Context(), nodes[regions[1]].conn, next, rolloutOrder(&next)[0], false, 30*time.Second); err != nil {
		t.Fatal(err)
	}

	nodes[home].Close()
	delete(nodes, home)
	time.Sleep(time.Second) // the exiting node's last ping round would land here
	if got := lines(); got != len(regions) {
		t.Fatalf("after the exit the peers file lists %d regions, want %d", got, len(regions))
	}
	launch(home)
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if got := lines(); got != len(regions) {
			t.Fatalf("after the restart the peers file lists %d regions, want %d", got, len(regions))
		}
	}
}

// A ping round cut short by shutdown (ts-orch's context is cancelled while it
// collects) sees only this node; it must not rewrite the peers files.
func TestMeshShutdownRoundKeepsPeersFile(t *testing.T) {
	regions, nodes, _ := startMeshRegions(t, 0)
	home := nodes[regions[0]]
	spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	if _, err := applySpec(t.Context(), home.conn, spec, "", false, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home.cfg.peersDir, "terrabase", "peers")
	lines := func() int { data, _ := os.ReadFile(file); return strings.Count(string(data), "\n") }
	eventually(t, "the peers file to list every region", func() bool { return lines() == len(regions) })
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	home.watchPeers(cancelled)
	if got := lines(); got != len(regions) {
		t.Fatalf("a shutdown round left %d regions in the peers file, want %d", got, len(regions))
	}
}

// After a restart the file's regions count as up: one round only this node
// answered keeps them; a region leaves only after peersMissedRounds misses.
func TestPeersKeepFileRegionsUntilMissedTwice(t *testing.T) {
	regions := Regions()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "terrabase"), 0o755); err != nil {
		t.Fatal(err)
	}
	var previous string
	for i, region := range regions {
		previous += fmt.Sprintf("ts-%s-1 %s 10.203.0.%d\n", region, region, i+1)
	}
	if err := os.WriteFile(filepath.Join(root, "terrabase", "peers"), []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &peers{root: root, region: regions[0], node: "ts-" + regions[0] + "-1", address: func() (string, error) { return "10.203.0.1", nil }}
	if err := p.track("terrabase", nil); err != nil {
		t.Fatal(err)
	}
	lines := func() int {
		data, _ := os.ReadFile(filepath.Join(root, "terrabase", "peers"))
		return strings.Count(string(data), "\n")
	}
	if got := lines(); got != len(regions) {
		t.Fatalf("track after a restart wrote %d regions, want %d", got, len(regions))
	}
	if err := p.observe(map[string]peer{}); err != nil || lines() != len(regions) {
		t.Fatalf("one round without the other regions left %d, %v", lines(), err)
	}
	if err := p.observe(map[string]peer{}); err != nil || lines() != 1 {
		t.Fatalf("two missed rounds left %d regions, want only this one (%v)", lines(), err)
	}
}

// 2026-10-25 20:27Z: B was held after the first region; an apply of C that the
// first region never got ready rolled back to B and dropped the hold, so every
// region ran B. A rollback restores the previous entry hold included, and any
// apply but resume keeps a held service held.
func TestMeshRollbackAndApplyKeepAHeldRollout(t *testing.T) {
	regions, nodes, appliers := startMeshRegions(t, 0)
	conn := nodes[regions[0]].conn
	image := func(c string) string { return "docker.io/library/alpine@sha256:" + strings.Repeat(c, 64) }
	a := swarmruntime.ServiceSpec{Name: "terrabase", Image: image("a"), Port: 8080, Replicas: 1}
	if _, err := applySpec(t.Context(), conn, a, "", false, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	order := rolloutOrder(&a)
	b, c, d := a, a, a
	b.Image, c.Image, d.Image = image("b"), image("c"), image("d")
	if _, err := applySpec(t.Context(), conn, b, order[0], false, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	later := func(want string, why string) {
		t.Helper()
		time.Sleep(time.Second) // sync ticks (300 ms) must not move the held regions either
		for _, region := range order[1:] {
			if got := appliers[region].appliedImage("terrabase"); got != want {
				t.Fatalf("%s: %s runs %s, want %s", why, region, got, want)
			}
		}
	}
	later(a.Image, "held after "+order[0])

	// C never gets ready in the canary region: the rollback brings held B back, not B everywhere.
	appliers[order[0]].unready = c.Image
	if _, err := applySpec(t.Context(), conn, c, "", false, 60*time.Second); err == nil || !strings.Contains(err.Error(), "rolled back to "+b.Image) {
		t.Fatalf("unready C = %v", err)
	}
	if got := appliers[order[0]].appliedImage("terrabase"); got != b.Image {
		t.Fatalf("%s runs %s after the rollback, want %s", order[0], got, b.Image)
	}
	later(a.Image, "after a rollback of a held rollout")

	// A plain apply of a held service stays held; only resume advances it.
	if _, err := applySpec(t.Context(), conn, d, "", false, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	later(a.Image, "after a plain apply of a held service")
	var out bytes.Buffer
	if err := Resume(t.Context(), conn, "terrabase", &out); err != nil {
		t.Fatalf("resume: %v\n%s", err, out.String())
	}
	for _, region := range order {
		if got := appliers[region].appliedImage("terrabase"); got != d.Image {
			t.Fatalf("%s runs %s after resume, want %s", region, got, d.Image)
		}
	}
}
