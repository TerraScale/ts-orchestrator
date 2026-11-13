package mesh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	"github.com/nats-io/nats.go"
)

type bootstrapStageKey struct{}
type bootstrapFenceReply struct {
	Job   *rolloutmaintenance.Job `json:"job,omitempty"`
	Error string                  `json:"error,omitempty"`
}

func (n *Node) handleBootstrapFence(m *nats.Msg) {
	var reply bootstrapFenceReply
	if n.cfg.maintenance == nil {
		reply.Error = "executor fence unavailable"
	} else {
		j, err := n.cfg.maintenance.Status(n.ctx)
		reply.Job = j
		if err != nil {
			reply.Error = err.Error()
		}
	}
	n.respond(m, reply)
}

type bootstrapClearRequest struct {
	ID string `json:"id"`
}

// handleBootstrapClear lifts this node's fence only for its own exact verified
// transaction (the store refuses anything else); mesh members alone can ask.
func (n *Node) handleBootstrapClear(m *nats.Msg) {
	var request bootstrapClearRequest
	var reply bootstrapFenceReply
	switch {
	case protocol.DecodeStrict(m.Data, &request, maxWire) != nil || request.ID == "":
		reply.Error = "invalid clear request"
	case n.cfg.maintenance == nil:
		reply.Error = "executor fence unavailable"
	default:
		if err := n.cfg.maintenance.Clear(n.ctx, request.ID); err != nil {
			reply.Error = err.Error()
		}
	}
	n.respond(m, reply)
}

// ClearPeer asks one admitted regional peer to clear its exact verified fence.
func (n *Node) ClearPeer(ctx context.Context, peer, id string) error {
	admitted := false
	for _, p := range n.RegionalNodes() {
		admitted = admitted || p.Node == peer
	}
	if !admitted {
		return errors.New("clear target is not an admitted regional node")
	}
	data, err := protocol.EncodeJSON(bootstrapClearRequest{ID: id})
	if err != nil {
		return err
	}
	response, err := n.conn.RequestWithContext(ctx, protocol.MeshDrainPrefix+n.cfg.region+"."+peer+".clear", data)
	if err != nil {
		return err
	}
	var reply bootstrapFenceReply
	if err = protocol.DecodeStrict(response.Data, &reply, maxWire); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	return nil
}

// stageBootstrap uses only the candidate retained by the existing authenticated
// release handler and the existing service applier. Both regional executors
// must durably fence this exact image and owner epoch before Swarm sees it.
func (n *Node) stageBootstrap(action string, j rolloutmaintenance.Job) error {
	ctx, cancel := context.WithTimeout(n.ctx, rolloutmaintenance.Budget)
	defer cancel()
	if n.cfg.maintenance == nil || n.cfg.applier == nil {
		return errors.New("bootstrap staging requires the fenced regional founder")
	}
	peers := n.RegionalNodes()
	if len(peers) != 2 {
		return errors.New("bootstrap staging requires both admitted regional nodes")
	}
	seen := map[string]bool{}
	for _, peer := range peers {
		response, err := n.conn.RequestWithContext(ctx, protocol.MeshDrainPrefix+n.cfg.region+"."+peer.Node+".fence", nil)
		if err != nil {
			return err
		}
		var reply bootstrapFenceReply
		if err = protocol.DecodeStrict(response.Data, &reply, maxWire); err != nil {
			return err
		}
		held := reply.Job
		if reply.Error != "" || held == nil || held.Member != peer.Node || held.Target.Image != j.Target.Image || held.Owner != j.Owner || held.Epoch != j.Epoch {
			return fmt.Errorf("regional executor %s lacks the exact durable bootstrap fence", peer.Node)
		}
		if held.Member == j.Member && (held.ID != j.ID || held.Source != j.Source) {
			return rolloutmaintenance.ErrFenced
		}
		seen[held.Member] = true
	}
	if !seen[j.Member] || !seen[j.Owner] {
		return rolloutmaintenance.ErrFenced
	}
	candidate, err := n.cfg.maintenance.Candidate(ctx)
	if err != nil {
		return err
	}
	if candidate.Image != j.Target.Image {
		return rolloutmaintenance.ErrFenced
	}
	deployment := &Deployment{Repository: candidate.Repository, RunID: candidate.RunID, RunAttempt: candidate.RunAttempt, Revision: candidate.Revision, Image: candidate.Image, Workflow: candidate.Workflow}
	if err = deployment.Validate(); err != nil {
		return err
	}
	n.mu.Lock()
	current := n.desired["terrabase"]
	before := current.entry()
	if before.Spec == nil {
		n.mu.Unlock()
		return errors.New("TerraBase service is absent")
	}
	if err = current.accepts(deployment); err != nil {
		n.mu.Unlock()
		return err
	}
	spec := *before.Spec
	spec.Image = candidate.Image
	already := before.Spec.Image == candidate.Image && before.Deployment != nil && *before.Deployment == *deployment
	n.mu.Unlock()
	if action == "staged" {
		if !already {
			return errors.New("pinned candidate not staged")
		}
		return nil
	}
	if already {
		return nil
	}
	// Pre-pull before any selected driver starts its 60s stop/start budget.
	if err = n.cfg.applier.PrePull(ctx, spec); err != nil {
		return err
	}
	generation := max(time.Now().UnixNano(), before.Generation+1)
	_, err = n.apply(context.WithValue(ctx, bootstrapStageKey{}, candidate.Image), ApplyRequest{Name: "terrabase", Entry: Entry{Generation: generation, Spec: &spec, Deployment: deployment}})
	return err
}
