package mesh

import (
	"path/filepath"

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
	var applier Applier = swarmApplier{state: host.State, region: host.Region}
	if host.Worker {
		applier = nil
	}
	fence, err := rolloutmaintenance.Open(host.State)
	if err != nil {
		return nil, err
	}
	return start(config{maintenance: fence,
		region: host.Region, server: host.Server, dir: filepath.Join(host.State, "mesh"),
		clusterHost: "0.0.0.0", clusterAdvertise: host.ClusterAddress, clusterPort: ClusterPort, localPort: LocalPort,
		seeds: host.Seeds, routes: host.Routes, ca: host.CA, terrabaseToken: host.TerraBaseToken,
		applier: applier, every: antiEntropyEvery,
		peersDir: swarmruntime.PeersDirectory, peersEvery: peersEvery, address: host.Address,
	})
}
