package app

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// ociNodeCompute observes the fleet through the authenticated root transport.
// Every mutation selects an archived signed operation; root derives its effects.
type ociNodeCompute struct{ client *rootoci.Client }

func newOCINodeCompute(client *rootoci.Client) (nodeCompute, error) {
	if client == nil {
		return nil, rootoci.ErrUnavailable
	}
	return &ociNodeCompute{client: client}, nil
}

func (c *ociNodeCompute) Find(ctx context.Context, node string) (nodeInstance, error) {
	instances, err := c.Instances(ctx)
	if err != nil {
		return nodeInstance{}, err
	}
	return findNode(instances, node)
}

func (c *ociNodeCompute) Instances(ctx context.Context) ([]nodeInstance, error) {
	observed, err := c.client.ObserveFleet(ctx)
	if err != nil {
		return nil, err
	}
	var found []nodeInstance
	for _, instance := range observed {
		if instance.State == "TERMINATED" || instance.State == "TERMINATING" {
			continue
		}
		found = append(found, nodeInstance{ID: instance.ID, Name: instance.Node, State: instance.State,
			OCPUs: float32(instance.WholeOCPUs), MemoryGB: float32(instance.MemoryInGBs)})
	}
	return found, nil
}

func (c *ociNodeCompute) ReconcileNodeOperation(ctx context.Context, request rootoci.NodeOperationRequest) (rootoci.NodeOperationReceipt, error) {
	return c.client.ReconcileNodeOperation(ctx, request)
}
