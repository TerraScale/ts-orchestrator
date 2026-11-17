package edge

import (
	"net"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func (e *Edge) meshName() string {
	node := e.meshNode()
	if node == nil {
		return ""
	}
	for _, region := range fleet.Embedded().Regions {
		if region.Label == node.Region() {
			return region.Label + "." + mesh.Domain
		}
	}
	return ""
}

func (e *Edge) meshHost(host string) bool {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	name := e.meshName()
	return name != "" && strings.EqualFold(strings.TrimSuffix(host, "."), name)
}
