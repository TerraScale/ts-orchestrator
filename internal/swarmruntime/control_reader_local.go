//go:build linux

package swarmruntime

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

// ReadOnlyControlClient exposes the original admitted manager's applied store
// to its privileged local owner. It does not authenticate a socket peer.
func (n *Node) ReadOnlyControlClient(ctx context.Context) (*manager.ControlReader, error) {
	if ctx == nil || n == nil || n.upstream == nil || n.role != "manager" {
		return nil, errors.New("read-only control requires an admitted manager")
	}
	upstream := n.upstream
	manager := upstream.Manager()
	if manager == nil {
		return nil, errors.New("read-only control requires a current manager")
	}
	originalContext := ctx
	admitted, id := n.admission, n.ID()
	valid := func(node *api.Node) bool {
		return admitted.Role == "manager" && node != nil && node.ID == id && node.Role == api.NodeRoleManager &&
			node.Spec.DesiredRole == api.NodeRoleManager && node.Spec.Membership == api.NodeMembershipAccepted &&
			admitted.HostID != "" && admitted.InstanceID != "" && catalog.IsOCIRegion(admitted.Region) &&
			node.Spec.Annotations.Name == admitted.HostID && node.Spec.Annotations.Labels[LabelRegion] == admitted.Region &&
			node.Spec.Annotations.Labels[LabelInstanceID] == admitted.InstanceID && node.Spec.Annotations.Labels[LabelHostRole] == "manager" &&
			node.Spec.Annotations.Labels[LabelExecutionScope] == "platform"
	}
	identity := func(tx store.ReadTx) error {
		if !valid(store.GetNode(tx, id)) {
			return errors.New("read-only control manager identity changed")
		}
		return nil
	}
	epoch, err := manager.Observe(nil, identity)
	if err != nil {
		return nil, err
	}
	epoch.Cancel()
	live := func(ctx context.Context) error {
		if err := errors.Join(ctx.Err(), originalContext.Err()); err != nil {
			return err
		}
		select {
		case <-n.done:
			return errors.New("read-only control manager stopped")
		default:
		}
		if n.upstream != upstream || upstream.Manager() != manager || n.ID() != id || n.admission != admitted {
			return errors.New("read-only control manager replaced")
		}
		return manager.ValidateObservation(epoch)
	}
	validate := func(ctx context.Context) error {
		if err := live(ctx); err != nil {
			return err
		}
		current, err := manager.Observe(nil, identity)
		if err != nil {
			return err
		}
		current.Cancel()
		return live(ctx)
	}
	if err := validate(ctx); err != nil {
		return nil, err
	}
	return manager.ReadOnlyControlClient(validate)
}
