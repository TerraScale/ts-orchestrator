package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func netbirdAdmittedFence(record network.Record) (*cellspec.ReleaseFence, error) {
	var admitted *cellspec.ReleaseFence
	if err := json.Unmarshal(record.Fence, &admitted, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode admitted NetBird fence: %w", err)
	}
	if admitted == nil {
		return nil, errors.New("NetBird admission has no release fence")
	}
	if err := netbirdOCIAddress(record.OCIAddress); err != nil {
		return nil, err
	}
	return admitted, nil
}

func (n *netbirdRollout) preflightAddresses(ctx context.Context, node string) (*cellspec.ReleaseFence, map[string]string, error) {
	spec, addresses := n.addresses()
	state, err := n.state(ctx)
	if err != nil {
		return nil, nil, err
	}
	record := state.Record
	if record.ID != "" && record.Node == node && record.Phase != "done" && !record.RecoveryComplete && len(record.Fence) > 0 {
		spec, err = netbirdAdmittedFence(record)
		if err != nil {
			return nil, nil, err
		}
		// Only the admitted node keeps its saved address. Peers still come
		// from the current inventory and pass live health/quorum checks.
		addresses[node] = record.OCIAddress
	}
	return spec, addresses, nil
}
