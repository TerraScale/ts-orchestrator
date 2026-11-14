package mesh

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/moby/swarmkit/v2/api"

	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type RegionalHost struct {
	State, Region, Server string
	CA                    *CA
	TerraBaseToken        string
	Seeds                 map[string][]string
	Routes                []string
	ClusterAddress        string
	Address               func() (string, error)
	Worker                bool
}

func StartRegionalHost(host RegionalHost) (*Node, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodeID, err := swarmruntime.SingleHostNodeID(ctx, host.State)
	if err != nil {
		return nil, err
	}
	admission, stored, err := swarmruntime.StoredAdmission(host.State)
	if err != nil {
		return nil, err
	}
	if !stored {
		return nil, errors.New("mesh requires stored SwarmKit admission")
	}
	var applier Applier = swarmApplier{state: host.State, region: host.Region}
	if host.Worker {
		applier = nil
	}
	fence, err := rolloutmaintenance.Open(host.State)
	if err != nil {
		return nil, err
	}
	return start(config{maintenance: fence,
		nodeID: nodeID, founder: admission.HostID == admission.FounderID,
		region: host.Region, server: host.Server, dir: filepath.Join(host.State, "mesh"),
		clusterHost: "0.0.0.0", clusterAdvertise: host.ClusterAddress, clusterPort: ClusterPort, localPort: LocalPort,
		seeds: host.Seeds, routes: host.Routes, ca: host.CA, terrabaseToken: host.TerraBaseToken,
		applier: applier, every: antiEntropyEvery,
		peersDir: swarmruntime.PeersDirectory, peersEvery: peersEvery, address: host.Address,
	})
}

func (n *Node) isLeader(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialSingleHost(filepath.Dir(n.cfg.dir))
	if err != nil {
		return false
	}
	defer conn.Close()
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	return err == nil && swarmruntime.IsLeader(listed.Nodes, n.cfg.nodeID)
}
