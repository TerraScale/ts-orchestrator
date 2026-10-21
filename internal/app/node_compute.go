package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// The ordinary controller holds only the admitted typed ROOT client.
type ociNodeCompute struct{ client *rootoci.Client }

func newOCINodeCompute(client *rootoci.Client) (nodeCompute, error) {
	if client == nil {
		return nil, rootoci.ErrUnauthorized
	}
	return &ociNodeCompute{client: client}, nil
}

func (c *ociNodeCompute) Prepare(ctx context.Context, request rootoci.NodeMaintenanceRequest) error {
	view, err := c.client.PrepareNodeMaintenance(ctx, request)
	if err != nil {
		return err
	}
	if view.OperationID != request.OperationID || view.RequestSHA256 != request.RequestSHA256 ||
		view.RequestRevision != request.RequestRevision || view.OriginalDeadline.IsZero() || !time.Now().Before(view.OriginalDeadline) {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (c *ociNodeCompute) Find(ctx context.Context, node string) (nodeInstance, error) {
	if ctx.Value(nodeMaintenanceRequestKey{}) != nil {
		request, err := nodeMaintenanceRequest(ctx)
		if err != nil {
			return nodeInstance{}, err
		}
		view, err := c.client.ObserveNodeMaintenance(ctx, request)
		if err != nil {
			return nodeInstance{}, err
		}
		if view.OperationID != request.OperationID || view.RequestSHA256 != request.RequestSHA256 ||
			view.RequestRevision != request.RequestRevision || (view.Node != node && view.From != node) || view.InstanceID == "" {
			return nodeInstance{}, rootoci.ErrUnauthorized
		}
		return nodeInstance{ID: view.InstanceID, Name: node, State: view.State, OCPUs: view.OCPUs, MemoryGB: view.MemoryGB}, nil
	}
	instances, err := c.Instances(ctx)
	if err != nil {
		return nodeInstance{}, err
	}
	return findNode(instances, node)
}

func (c *ociNodeCompute) Instances(ctx context.Context) ([]nodeInstance, error) {
	observed, err := c.client.ObserveNodeMaintenanceNodes(ctx)
	if err != nil {
		return nil, err
	}
	found := make([]nodeInstance, len(observed))
	for index, instance := range observed {
		found[index] = nodeInstance{ID: instance.InstanceID, Name: instance.Node, State: instance.State,
			OCPUs: instance.OCPUs, MemoryGB: instance.MemoryGB}
	}
	return found, nil
}

// Method arguments describe regional progress; only the original signed archive
// selected in the context can choose the ROOT action and its provider target.
func (c *ociNodeCompute) advance(ctx context.Context, step rootoci.NodeMaintenanceStep) (rootoci.NodeMaintenanceView, error) {
	request, err := nodeMaintenanceRequest(ctx)
	if err != nil {
		return rootoci.NodeMaintenanceView{}, err
	}
	view, err := c.client.AdvanceNodeMaintenance(ctx, rootoci.NodeMaintenanceAdvanceRequest{
		NodeMaintenanceRequest: request, Step: step,
	})
	if err != nil {
		return rootoci.NodeMaintenanceView{}, err
	}
	if view.OperationID != request.OperationID || view.RequestSHA256 != request.RequestSHA256 || view.RequestRevision != request.RequestRevision {
		return rootoci.NodeMaintenanceView{}, rootoci.ErrUnauthorized
	}
	return view, nil
}

func (c *ociNodeCompute) Reboot(ctx context.Context, _ string) error {
	_, err := c.advance(ctx, rootoci.NodeMaintenanceReboot)
	return err
}

func (c *ociNodeCompute) Resize(ctx context.Context, _ string, _, _ float32) error {
	_, err := c.advance(ctx, rootoci.NodeMaintenanceResize)
	return err
}

func (c *ociNodeCompute) Rename(ctx context.Context, _, _ string) error {
	_, err := c.advance(ctx, rootoci.NodeMaintenanceRename)
	return err
}

func (c *ociNodeCompute) Backup(ctx context.Context, _, _ string, _ map[string]string, _ string) (string, error) {
	for {
		view, err := c.advance(ctx, rootoci.NodeMaintenanceBackup)
		if err == nil {
			if view.BackupID == "" {
				return "", fmt.Errorf("%w: ROOT returned no available original boot backup", rootoci.ErrPending)
			}
			return view.BackupID, nil
		}
		if !errors.Is(err, rootoci.ErrPending) {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

func (c *ociNodeCompute) Terminate(ctx context.Context, _ string) error {
	_, err := c.advance(ctx, rootoci.NodeMaintenanceTerminate)
	return err
}
