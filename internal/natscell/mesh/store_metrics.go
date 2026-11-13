package mesh

import (
	"fmt"
	"io"
)

func (n *Node) writeStoreMetrics(w io.Writer) {
	leader, quorum, observed := 0, 0, 0
	view, err := n.server.Varz(nil)
	if err == nil && view.JetStream.Meta != nil {
		observed = 1
		meta := view.JetStream.Meta
		if meta.Leader != "" {
			leader = 1
		}
		available := 0
		if n.server.Running() {
			available = 1
		}
		if meta.Leader != "" && meta.Leader != view.Name {
			available++
		}
		for _, peer := range meta.Replicas {
			if peer != nil && peer.Name != view.Name && peer.Name != meta.Leader && !peer.Offline && peer.Current {
				available++
			}
		}
		if meta.QuorumNeeded > 0 && available >= meta.QuorumNeeded {
			quorum = 1
		}
	}
	fmt.Fprintf(w, "ts_orch_mesh_store_observed %d\nts_orch_mesh_store_leader_available %d\nts_orch_mesh_store_quorum_available %d\n", observed, leader, quorum)
}
