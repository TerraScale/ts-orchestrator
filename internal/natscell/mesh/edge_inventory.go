package mesh

import (
	"log/slog"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

type EdgeRoute struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
}

type EdgeInventory struct {
	Web       map[string]int    `json:"web"`
	Postgres  map[string]int    `json:"postgres,omitempty"`
	Services  map[string]string `json:"services"`
	Readiness []EdgeRoute       `json:"readiness,omitempty"`
	Nodes     []WorkerPeer      `json:"nodes,omitempty"`
	ProofRef  string            `json:"proof_ref,omitempty"`
}

func (inventory EdgeInventory) valid(region string) bool {
	ports := func(table map[string]int) bool {
		for host, port := range table {
			if host == "" || port < 1024 || port > 65535 {
				return false
			}
		}
		return true
	}
	if inventory.Web == nil || inventory.Services == nil || !ports(inventory.Web) || !ports(inventory.Postgres) {
		return false
	}
	for _, route := range inventory.Readiness {
		if route.Host == "" || route.Port < 1024 || route.Port > 65535 || len(route.Path) == 0 || route.Path[0] != '/' {
			return false
		}
	}
	return !slices.ContainsFunc(inventory.Nodes, func(node WorkerPeer) bool { return !validPeer(region, peer{node.Node, node.Address}) })
}

func (n *Node) edgeInventorySubject() string {
	return protocol.MeshWorkerPrefix + n.cfg.region + ".edge.inventory"
}

func (n *Node) PublishEdgeInventory(inventory EdgeInventory) error {
	inventory.Nodes = n.RegionalNodes()
	data, err := protocol.EncodeJSON(inventory)
	if err != nil {
		return err
	}
	return n.conn.Publish(n.edgeInventorySubject(), data)
}

func (n *Node) FollowEdgeInventory() func() (EdgeInventory, bool) {
	n.goWork(func() {
		backoff := time.Second
		for {
			subscription, err := n.conn.Subscribe(n.edgeInventorySubject(), func(message *nats.Msg) {
				var inventory EdgeInventory
				if protocol.DecodeStrict(message.Data, &inventory, maxWire) != nil || !inventory.valid(n.cfg.region) {
					return
				}
				n.edgeInventory.Store(&inventory)
			})
			if err == nil {
				<-n.ctx.Done()
				_ = subscription.Unsubscribe()
				return
			}
			slog.WarnContext(n.ctx, "edge inventory unavailable; retrying", "error", err)
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, 30*time.Second)
		}
	})
	return func() (EdgeInventory, bool) {
		inventory := n.edgeInventory.Load()
		if inventory == nil {
			return EdgeInventory{}, false
		}
		return *inventory, true
	}
}
