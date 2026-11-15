package mesh

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const (
	edgeInventoryRefresh  = time.Hour
	edgeInventoryLifetime = 24 * time.Hour
	edgeInventorySkew     = 5 * time.Minute
	edgeInventoryFile     = "edge-inventory.json"
)

type EdgeRoute struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
}

type EdgeInventory struct {
	Region     string            `json:"region"`
	Generation uint64            `json:"generation"`
	Issued     time.Time         `json:"issued"`
	Web        map[string]int    `json:"web"`
	Postgres   map[string]int    `json:"postgres,omitempty"`
	Services   map[string]string `json:"services"`
	Readiness  []EdgeRoute       `json:"readiness,omitempty"`
	Nodes      []WorkerPeer      `json:"nodes,omitempty"`
	ProofRef   string            `json:"proof_ref,omitempty"`
}

type signedEdgeInventory struct {
	Publisher string `json:"publisher"`
	SPKI      []byte `json:"spki"`
	Inventory []byte `json:"inventory"`
	Signature []byte `json:"signature"`
}

type edgePublication struct {
	content    []byte
	signed     []byte
	generation uint64
	issued     time.Time
}

func EdgeInventoryPublisher(region string) string { return "ts-" + region + "-1" }

func (inventory EdgeInventory) valid(region string) bool {
	ports := func(table map[string]int) bool {
		for host, port := range table {
			if host == "" || port < 1024 || port > 65535 {
				return false
			}
		}
		return true
	}
	if inventory.Region != region || inventory.Generation == 0 || inventory.Issued.IsZero() ||
		inventory.Web == nil || inventory.Services == nil || !ports(inventory.Web) || !ports(inventory.Postgres) {
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

func (n *Node) PublishEdgeInventory(state string, inventory EdgeInventory) error {
	inventory.Nodes = n.RegionalNodes()
	inventory.Region, inventory.Generation, inventory.Issued = n.cfg.region, 0, time.Time{}
	content, err := protocol.EncodeJSON(inventory)
	if err != nil {
		return err
	}
	n.edgePublishMu.Lock()
	defer n.edgePublishMu.Unlock()
	last := n.edgePublished
	if last == nil || !bytes.Equal(last.content, content) || time.Since(last.issued) > edgeInventoryRefresh {
		now := time.Now().UTC()
		generation := uint64(now.UnixNano())
		if last != nil {
			generation = max(generation, last.generation+1)
		}
		inventory.Generation, inventory.Issued = generation, now
		payload, err := protocol.EncodeJSON(inventory)
		if err != nil {
			return err
		}
		spki, signature, err := nodelist.Sign(state, payload)
		if err != nil {
			return err
		}
		signed, err := protocol.EncodeJSON(signedEdgeInventory{Publisher: EdgeInventoryPublisher(n.cfg.region), SPKI: spki, Inventory: payload, Signature: signature})
		if err != nil {
			return err
		}
		last = &edgePublication{content: content, signed: signed, generation: generation, issued: now}
		n.edgePublished = last
	}
	return n.conn.Publish(n.edgeInventorySubject(), last.signed)
}

func (n *Node) verifyEdgeInventory(state string, data []byte) (EdgeInventory, error) {
	var signed signedEdgeInventory
	if err := protocol.DecodeTolerant(data, &signed, maxWire); err != nil {
		return EdgeInventory{}, err
	}
	if signed.Publisher != EdgeInventoryPublisher(n.cfg.region) {
		return EdgeInventory{}, errors.New("edge inventory publisher is not the region's manager")
	}
	list, err := nodelist.Read(state)
	if err != nil {
		return EdgeInventory{}, err
	}
	if err := list.Verify(signed.Publisher, n.cfg.region, signed.SPKI, signed.Inventory, signed.Signature); err != nil {
		return EdgeInventory{}, err
	}
	var inventory EdgeInventory
	if err := protocol.DecodeTolerant(signed.Inventory, &inventory, maxWire); err != nil {
		return EdgeInventory{}, err
	}
	if !inventory.valid(n.cfg.region) {
		return EdgeInventory{}, errors.New("edge inventory is invalid")
	}
	if inventory.Issued.After(time.Now().Add(edgeInventorySkew)) {
		return EdgeInventory{}, errors.New("edge inventory is issued in the future")
	}
	return inventory, nil
}

func (n *Node) acceptEdgeInventory(state string, data []byte) error {
	inventory, err := n.verifyEdgeInventory(state, data)
	n.edgeFollowMu.Lock()
	defer n.edgeFollowMu.Unlock()
	if err != nil {
		if err.Error() != n.edgeRefused {
			slog.WarnContext(n.ctx, "edge inventory refused", "error", err)
			n.edgeRefused = err.Error()
		}
		return err
	}
	n.edgeRefused = ""
	if current := n.edgeInventory.Load(); current != nil && inventory.Generation <= current.Generation {
		return errors.New("edge inventory generation is not newer")
	}
	if err := writePrivate(filepath.Join(state, edgeInventoryFile), data); err != nil {
		slog.WarnContext(n.ctx, "edge inventory not persisted", "error", err)
	}
	n.edgeInventory.Store(&inventory)
	return nil
}

func (n *Node) FollowEdgeInventory(state string) func() (EdgeInventory, bool) {
	if data, err := os.ReadFile(filepath.Join(state, edgeInventoryFile)); err == nil {
		if inventory, err := n.verifyEdgeInventory(state, data); err == nil {
			n.edgeInventory.Store(&inventory)
		} else {
			slog.WarnContext(n.ctx, "persisted edge inventory refused", "error", err)
		}
	}
	if _, err := n.conn.Subscribe(n.edgeInventorySubject(), func(message *nats.Msg) { _ = n.acceptEdgeInventory(state, message.Data) }); err != nil {
		slog.WarnContext(n.ctx, "edge inventory subscription unavailable", "error", err)
	}
	return func() (EdgeInventory, bool) {
		inventory := n.edgeInventory.Load()
		if inventory == nil || time.Since(inventory.Issued) > edgeInventoryLifetime {
			return EdgeInventory{}, false
		}
		return *inventory, true
	}
}
