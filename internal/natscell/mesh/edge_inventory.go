package mesh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
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

type SignedEdgeInventory struct {
	Inventory   []byte   `json:"inventory"`
	Certificate [][]byte `json:"certificate"`
	Signature   []byte   `json:"signature"`
}

type carriedEdgeInventory struct {
	Publisher string `json:"publisher"`
	SPKI      []byte `json:"spki"`
	Inventory []byte `json:"inventory"`
}

type followedEdgeInventory struct {
	EdgeInventory
	publisher string
	signed    []byte
}

type edgePublication struct {
	content    []byte
	signed     []byte
	generation uint64
	issued     time.Time
}

func EdgeInventoryMessage(payload []byte) []byte {
	return append([]byte("TS-EDGE-INVENTORY-V1\x00"), payload...)
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
		chain, signature, err := swarmruntime.SignRegional(state, EdgeInventoryMessage(payload))
		if err != nil {
			return err
		}
		signed, err := protocol.EncodeJSON(SignedEdgeInventory{Inventory: payload, Certificate: chain, Signature: signature})
		if err != nil {
			return err
		}
		last = &edgePublication{content: content, signed: signed, generation: generation, issued: now}
		n.edgePublished = last
	}
	return n.conn.Publish(n.edgeInventorySubject(), last.signed)
}

func (n *Node) decodeEdgeInventory(payload []byte) (EdgeInventory, error) {
	var inventory EdgeInventory
	if err := protocol.DecodeTolerant(payload, &inventory, maxWire); err != nil {
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

func (n *Node) verifyEdgeInventory(state string, data []byte) (followedEdgeInventory, error) {
	var signed SignedEdgeInventory
	if err := protocol.DecodeTolerant(data, &signed, maxWire); err != nil {
		return followedEdgeInventory{}, err
	}
	publisher, err := swarmruntime.VerifyRegionalManager(state, signed.Certificate, EdgeInventoryMessage(signed.Inventory), signed.Signature)
	if err != nil {
		return followedEdgeInventory{}, err
	}
	inventory, err := n.decodeEdgeInventory(signed.Inventory)
	if err != nil {
		return followedEdgeInventory{}, err
	}
	return followedEdgeInventory{EdgeInventory: inventory, publisher: publisher, signed: data}, nil
}

func (n *Node) carriedEdgeInventory(data []byte) (followedEdgeInventory, error) {
	var carried carriedEdgeInventory
	if err := protocol.DecodeTolerant(data, &carried, maxWire); err != nil {
		return followedEdgeInventory{}, err
	}
	if carried.Publisher != "ts-"+n.cfg.region+"-1" || len(carried.SPKI) == 0 {
		return followedEdgeInventory{}, errors.New("persisted edge inventory is not a carried regional inventory")
	}
	inventory, err := n.decodeEdgeInventory(carried.Inventory)
	if err != nil {
		return followedEdgeInventory{}, err
	}
	return followedEdgeInventory{EdgeInventory: inventory, signed: data}, nil
}

func (n *Node) acceptEdgeInventory(state string, data []byte) error {
	inventory, err := n.verifyEdgeInventory(state, data)
	n.edgeFollowMu.Lock()
	defer n.edgeFollowMu.Unlock()
	if err != nil {
		n.edgeRefusals.Add(1)
		if err.Error() != n.edgeRefused {
			slog.WarnContext(n.ctx, "edge inventory refused", "error", err)
			n.edgeRefused = err.Error()
		}
		return err
	}
	n.edgeRefused = ""
	if current, ok := n.edgeInventories[inventory.publisher]; ok && inventory.Generation <= current.Generation {
		return errors.New("edge inventory generation is not newer")
	}
	if newest, ok := n.selectEdgeInventory(state); !ok || inventory.Generation > newest.Generation {
		if err := writePrivate(filepath.Join(state, edgeInventoryFile), data); err != nil {
			slog.WarnContext(n.ctx, "edge inventory not persisted", "error", err)
		}
	}
	n.edgeInventories[inventory.publisher] = inventory
	n.selectEdgeInventory(state)
	return nil
}

func (n *Node) selectEdgeInventory(state string) (followedEdgeInventory, bool) {
	managers := swarmruntime.RegionManagers(state)
	var selected followedEdgeInventory
	found := false
	for publisher, inventory := range n.edgeInventories {
		if publisher != "" && !slices.Contains(managers, publisher) || time.Since(inventory.Issued) > edgeInventoryLifetime {
			continue
		}
		if !found || inventory.Generation > selected.Generation {
			selected, found = inventory, true
		}
	}
	if found {
		n.edgeInventory.Store(&selected.EdgeInventory)
		n.edgePublisher.Store(&selected.publisher)
	} else {
		n.edgeInventory.Store(nil)
		n.edgePublisher.Store(nil)
	}
	return selected, found
}

func (n *Node) FollowEdgeInventory(state string) func() (EdgeInventory, bool) {
	n.edgeFollowMu.Lock()
	n.edgeInventories = map[string]followedEdgeInventory{}
	if data, err := os.ReadFile(filepath.Join(state, edgeInventoryFile)); err == nil {
		inventory, err := n.verifyEdgeInventory(state, data)
		if err != nil {
			var carryErr error
			if inventory, carryErr = n.carriedEdgeInventory(data); carryErr != nil {
				slog.WarnContext(n.ctx, "persisted edge inventory refused", "error", err)
			}
			err = carryErr
		}
		if err == nil {
			n.edgeInventories[inventory.publisher] = inventory
			n.selectEdgeInventory(state)
		}
	}
	n.edgeFollowMu.Unlock()
	if _, err := n.conn.Subscribe(n.edgeInventorySubject(), func(message *nats.Msg) { _ = n.acceptEdgeInventory(state, message.Data) }); err != nil {
		slog.WarnContext(n.ctx, "edge inventory subscription unavailable", "error", err)
	}
	return func() (EdgeInventory, bool) {
		n.edgeFollowMu.Lock()
		defer n.edgeFollowMu.Unlock()
		inventory, ok := n.selectEdgeInventory(state)
		return inventory.EdgeInventory, ok
	}
}

func (n *Node) writeEdgeInventoryMetrics(w io.Writer) {
	fmt.Fprintf(w, "ts_orch_mesh_edge_inventory_refused_total %d\n", n.edgeRefusals.Load())
	if publisher := n.edgePublisher.Load(); publisher != nil {
		fmt.Fprintf(w, "ts_orch_mesh_edge_inventory_publisher{node=%q} 1\n", *publisher)
	}
}
