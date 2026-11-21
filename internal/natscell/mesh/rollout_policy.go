package mesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
)

const rolloutPolicySubject = StateSubject + ".rollout-policy"

type rolloutPolicyQuery struct {
	Nonce   string   `json:"nonce"`
	Regions []string `json:"regions"`
}

type rolloutPolicy struct {
	Nonce     string   `json:"nonce"`
	Region    string   `json:"region"`
	Receiver  string   `json:"receiver"`
	Receivers []string `json:"receivers"`
	Order     []string `json:"order"`
}

type receiverProof struct {
	receivers []string
	proved    map[string]bool
}

func (n *Node) reportRolloutPolicy(m *nats.Msg) {
	var query rolloutPolicyQuery
	if protocol.DecodeTolerant(m.Data, &query, maxWire) != nil || query.Nonce == "" || !slices.Contains(query.Regions, n.cfg.region) {
		return
	}
	ctx, cancel := context.WithTimeout(n.ctx, stateWait)
	defer cancel()
	a, ok := n.cfg.applier.(swarmApplier)
	if !ok {
		return
	}
	client, close, err := a.control()
	if err != nil {
		return
	}
	defer close()
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return
	}
	var receivers []string
	for _, node := range listed.Nodes {
		if node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager {
			receivers = append(receivers, node.ID)
		}
	}
	if !slices.Contains(receivers, n.cfg.nodeID) {
		return
	}
	slices.Sort(receivers)
	n.respond(m, rolloutPolicy{Nonce: query.Nonce, Region: n.cfg.region, Receiver: n.cfg.nodeID, Receivers: receivers, Order: EnvironmentOf(n.cfg.region).Rollout})
}

func requireRolloutOrder(ctx context.Context, conn *nats.Conn, spec *swarmruntime.ServiceSpec) error {
	region := ConnRegion(conn)
	targets := rolloutOrder(region, spec)
	if len(targets) < 2 {
		return nil
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	query := rolloutPolicyQuery{Nonce: hex.EncodeToString(nonce[:]), Regions: targets}
	payload, err := protocol.EncodeJSON(query)
	if err != nil {
		return err
	}
	order := EnvironmentOf(region).Rollout
	policies := map[string]receiverProof{}
	var blocker string
	err = collect(ctx, conn, rolloutPolicySubject, payload, math.MaxInt, stateWait, func(data []byte) bool {
		var reply rolloutPolicy
		if protocol.DecodeTolerant(data, &reply, maxWire) != nil || reply.Nonce != query.Nonce || !slices.Contains(targets, reply.Region) {
			return true
		}
		if !slices.Equal(reply.Order, order) || !slices.Contains(reply.Receivers, reply.Receiver) || reply.Receiver == "" {
			blocker = fmt.Sprintf("%s receiver %s does not prove rollout order %v", reply.Region, reply.Receiver, order)
			return false
		}
		proof, known := policies[reply.Region]
		if known && !slices.Equal(proof.receivers, reply.Receivers) {
			blocker = fmt.Sprintf("%s managers disagree on the rollout receiver inventory", reply.Region)
			return false
		}
		if !known {
			proof = receiverProof{receivers: reply.Receivers, proved: map[string]bool{}}
			policies[reply.Region] = proof
		}
		proof.proved[reply.Receiver] = true
		return firstUnprovedReceiver(targets, policies) != ""
	})
	if err != nil {
		return err
	}
	if blocker != "" {
		return fmt.Errorf("%s", blocker)
	}
	if missing := firstUnprovedReceiver(targets, policies); missing != "" {
		return fmt.Errorf("%s has no receiver proof for rollout order %v", missing, order)
	}
	return nil
}

func firstUnprovedReceiver(targets []string, policies map[string]receiverProof) string {
	for _, region := range targets {
		proof, ok := policies[region]
		if !ok {
			return region
		}
		for _, receiver := range proof.receivers {
			if !proof.proved[receiver] {
				return region + " receiver " + receiver
			}
		}
	}
	return ""
}
