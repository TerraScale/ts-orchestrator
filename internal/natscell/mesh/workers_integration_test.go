package mesh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go/jetstream"
)

// A region's second node takes a per-node service (TerraBase with replicas 2)
// only once it is fully joined: it announces itself over the mesh and its
// founder's SwarmKit has it READY and ACTIVE. Then every peers file of that
// service lists it right after its founder, the founder applies 2 replicas,
// and the worker writes the same file for its own task. A drained worker
// drops out again; a founder-only service never lists it.
func TestFullyJoinedWorkerJoinsPerNodeServices(t *testing.T) {
	if testing.Short() {
		t.Skip("founder and worker mesh integration runs in the Slow suite")
	}
	regions, nodes, appliers := startMeshRegions(t, 0)
	home := regions[0]
	founder := nodes[home]
	ports := freePorts(t, 2)
	ca, err := DeriveCA(bytes.Repeat([]byte{43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	workerDir := t.TempDir()
	worker, err := start(config{
		region: home, server: "ts-" + home + "-2", dir: t.TempDir(), clusterHost: "127.0.0.1",
		clusterAdvertise: fmt.Sprintf("127.0.0.1:%d", ports[0]), clusterPort: ports[0], localPort: ports[1],
		routes: []string{"nats://" + founder.cfg.clusterAdvertise}, ca: ca, terrabaseToken: testTerraBaseToken, every: 300 * time.Millisecond,
		peersDir: workerDir, peersEvery: 300 * time.Millisecond, address: func() (string, error) { return "10.201.0.9", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	go worker.run(t.Context())

	image := "ghcr.io/terrascale/terrabase@sha256:" + fmt.Sprintf("%064d", 1)
	perNode := swarmruntime.ServiceSpec{Name: "terrabase", Image: image, Port: 8080, Replicas: 2,
		Mounts: []swarmruntime.ServiceMount{{Source: "/var/lib/ts-data/terrabase", Target: "/data"}}}
	single := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:" + fmt.Sprintf("%064d", 2), Port: 8099, Replicas: 1}
	for i, spec := range []swarmruntime.ServiceSpec{perNode, single} {
		if _, err := send(t.Context(), founder.conn, ApplyRequest{Name: spec.Name, Entry: Entry{Generation: int64(i + 1), Spec: &spec}}, 5*time.Second); err != nil {
			t.Fatalf("apply %s: %v", spec.Name, err)
		}
	}
	read := func(dir, service string) string {
		data, _ := os.ReadFile(filepath.Join(dir, service, "peers"))
		return string(data)
	}
	founderLine := fmt.Sprintf("ts-%s-1 %s 10.201.0.1\n", home, home)
	workerLine := fmt.Sprintf("ts-%s-2 %s 10.201.0.9\n", home, home)
	listsWorker := func(file string) bool {
		i := bytes.Index([]byte(file), []byte(founderLine))
		return i >= 0 && bytes.HasPrefix([]byte(file[i+len(founderLine):]), []byte(workerLine))
	}

	// Announced, but not yet READY and ACTIVE in SwarmKit: not a target.
	time.Sleep(time.Second)
	if listsWorker(read(founder.cfg.peersDir, "terrabase")) || appliers[home].appliedReplicas("terrabase") != 1 {
		t.Fatalf("half-joined worker counted: replicas %d, file %q", appliers[home].appliedReplicas("terrabase"), read(founder.cfg.peersDir, "terrabase"))
	}

	appliers[home].mu.Lock()
	appliers[home].workers = map[string]bool{"ts-" + home + "-2": true}
	appliers[home].mu.Unlock()
	eventually(t, "the joined worker in every per-node peers file, after its founder", func() bool {
		for _, region := range regions {
			if !listsWorker(read(nodes[region].cfg.peersDir, "terrabase")) {
				return false
			}
		}
		return listsWorker(read(workerDir, "terrabase")) && appliers[home].appliedReplicas("terrabase") == 2
	})
	if got, want := read(workerDir, "terrabase"), read(founder.cfg.peersDir, "terrabase"); got != want {
		t.Fatalf("worker file %q differs from founder file %q", got, want)
	}
	if file := read(founder.cfg.peersDir, "whoami"); !bytes.Contains([]byte(file), []byte(founderLine)) || bytes.Contains([]byte(file), []byte(workerLine)) {
		t.Fatalf("founder-only service file %q", file)
	}

	// TerraBase on the worker reaches the cluster's JetStream through the
	// worker's own mesh server, which stores nothing.
	js := terrabaseJetStream(t, worker)
	waitFor(t, 60*time.Second, "an R3 bucket created from the worker", func() error {
		_, err := js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "tb-worker-proof", Replicas: 3})
		return err
	})

	// Drained: out of the files and back to one replica.
	appliers[home].mu.Lock()
	appliers[home].workers = nil
	appliers[home].mu.Unlock()
	eventually(t, "the drained worker to leave the per-node files", func() bool {
		return !listsWorker(read(founder.cfg.peersDir, "terrabase")) && appliers[home].appliedReplicas("terrabase") == 1
	})
}
