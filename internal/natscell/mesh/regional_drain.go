package mesh

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

type regionalDrainer func(context.Context, string) error

type drainRequest struct {
	Node string `json:"node"`
	Task string `json:"task"`
}
type drainReply struct {
	Error string `json:"error,omitempty"`
}

// RegionalNodes returns only this region's authenticated, admitted serving nodes.
func (n *Node) RegionalNodes() []WorkerPeer {
	nodes := n.joinedWorkers()
	if address, err := n.cfg.address(); err == nil {
		nodes = append([]WorkerPeer{{Node: n.cfg.server, Address: address}}, nodes...)
	}
	return nodes
}

// SetRegionalDrainer binds the founder's ingress drain implementation.
func (n *Node) SetRegionalDrainer(drain func(context.Context, string) error) {
	fn := regionalDrainer(drain)
	n.regionalDrain.Store(&fn)
}

// DrainTask asks the region's founder to withdraw ingress before this task stops.
func (n *Node) DrainTask(ctx context.Context, task string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	data, err := protocol.EncodeJSON(drainRequest{Node: n.cfg.server, Task: task})
	if err != nil {
		return err
	}
	response, err := n.conn.RequestWithContext(ctx, protocol.MeshDrainPrefix+n.cfg.region, data)
	if err != nil {
		return err
	}
	var reply drainReply
	if err := protocol.DecodeStrict(response.Data, &reply, maxWire); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	return nil
}

func (n *Node) handleDrain(m *nats.Msg) {
	var request drainRequest
	if protocol.DecodeStrict(m.Data, &request, maxWire) != nil || request.Task == "" {
		n.respond(m, drainReply{Error: "invalid drain request"})
		return
	}
	admitted := false
	for _, peer := range n.RegionalNodes() {
		admitted = admitted || peer.Node == request.Node
	}
	drain := n.regionalDrain.Load()
	if !admitted || drain == nil {
		n.respond(m, drainReply{Error: "regional ingress drain unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(n.ctx, 2*time.Minute)
	defer cancel()
	var reply drainReply
	if err := (*drain)(ctx, request.Node); err != nil {
		reply.Error = err.Error()
	}
	n.respond(m, reply)
}
