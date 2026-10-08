package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// A missing leader needs an installed remote controller for confirmation.
func (n *netbirdRollout) orderNodes(nodes []string) []string {
	leader := n.services.controllerNode(n.cell, n.cfg.NATS.Instance)
	rank := func(node string) int {
		if node == leader {
			return 2
		}
		if n.nodes != nil && n.nodes.controllers != nil && n.nodes.controllers(node) {
			return 0
		}
		return 1
	}
	slices.SortFunc(nodes, func(a, b string) int {
		if difference := rank(a) - rank(b); difference != 0 {
			return difference
		}
		return strings.Compare(a, b)
	})
	return nodes
}

func (n *netbirdRollout) healthyRemotePeer(ctx context.Context, peers []string) error {
	last := errors.New("no installed healthy remote controller")
	for _, node := range peers {
		status, err := n.status(ctx, node)
		if err != nil {
			last = err
			continue
		}
		if status.Missing || status.Pending != "" || status.Error != "" {
			continue
		}
		// One unreachable peer must not consume the entire leader deadline.
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = n.healthy(attempt, node, status, time.Time{})
		cancel()
		if err == nil {
			return nil
		}
		last = fmt.Errorf("%s: %w", node, err)
	}
	return fmt.Errorf("NetBird leader cannot reach a healthy controller peer: %w", last)
}
