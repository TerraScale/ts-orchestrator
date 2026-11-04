package mesh

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func stateTestNodesWithAppliers(t *testing.T, factory func(string) Applier, regions ...string) []*Node {
	t.Helper()
	if factory == nil {
		factory = func(string) Applier { return &fakeApplier{running: map[string]int64{}} }
	}
	ca, err := DeriveCA(bytes.Repeat([]byte{57}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2*len(regions))
	var nodes []*Node
	for i, region := range regions {
		seeds := map[string]string{}
		for j, peer := range regions {
			if i != j {
				seeds[peer] = fmt.Sprintf("nats://127.0.0.1:%d", ports[2*j])
			}
		}
		node, err := start(config{region: region, server: region + "-1", dir: t.TempDir(), clusterHost: "127.0.0.1",
			clusterPort: ports[2*i], localPort: ports[2*i+1], ca: ca, terrabaseToken: testTerraBaseToken, seeds: seeds,
			applier: factory(region), peersDir: t.TempDir(), peersEvery: 20 * time.Millisecond,
			address: func() (string, error) { return "10.200.0.1", nil }})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(node.Close)
		nodes = append(nodes, node)
	}
	eventually(t, "all test mesh nodes to answer", func() bool {
		seen := map[string]bool{}
		_ = collect(t.Context(), nodes[0].conn, PingSubject, nil, len(nodes), time.Second, func(data []byte) bool {
			var reply Reply
			if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
				seen[reply.Region] = true
			}
			return true
		})
		for _, node := range nodes {
			node.peers.mu.Lock()
			complete := len(node.peers.admitted) == len(nodes)
			node.peers.mu.Unlock()
			if !complete {
				return false
			}
		}
		return len(seen) == len(nodes)
	})
	return nodes
}
