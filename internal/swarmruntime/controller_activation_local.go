//go:build linux

package swarmruntime

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

// controllerActivationControl retains the original local manager and Raft
// epoch. It is available only to its privileged local owner, never a socket.
type controllerActivationControl struct {
	node        *Node
	original    context.Context
	binding     *ControllerHostBinding
	manager     *manager.Manager
	observation *manager.Observation
	reader      *manager.ControlReader
	nodes       []*api.Node
	tasks       []*api.Task
}

func (n *Node) readControllerActivationControl(ctx context.Context, binding *ControllerHostBinding) (*controllerActivationControl, error) {
	if n == nil || binding == nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("controller activation requires the original local manager binding")
	}
	identity := binding.Identity()
	if n.admission.HostID != identity.Slot || n.admission.InstanceID != identity.InstanceID || n.admission.Region != identity.OCIRegion {
		return nil, errors.New("controller activation binding differs from its actual local manager")
	}
	reader, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return nil, err
	}
	control := &controllerActivationControl{node: n, original: ctx, binding: binding, manager: n.upstream.Manager(), reader: reader}
	control.observation, err = control.manager.Observe(nil, func(tx store.ReadTx) error {
		var err error
		control.nodes, err = store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		control.tasks, err = store.FindTasks(tx, store.All)
		return err
	})
	if err != nil {
		return nil, err
	}
	control.observation.Cancel()
	if err := control.guard(ctx); err != nil {
		return nil, err
	}
	return control, nil
}

func (control *controllerActivationControl) guard(ctx context.Context) error {
	if control == nil || control.original == nil || control.node == nil || ctx == nil || ctx.Err() != nil || control.original.Err() != nil ||
		control.node.upstream == nil || control.node.upstream.Manager() != control.manager {
		return errors.New("controller activation local manager changed")
	}
	if err := control.manager.ValidateObservation(control.observation); err != nil {
		return err
	}
	if _, err := control.reader.GetNode(ctx, &api.GetNodeRequest{NodeID: control.node.ID()}); err != nil {
		return err
	}
	_, err := control.binding.currentRegistration(ctx)
	return err
}

func (control *controllerActivationControl) nodesSnapshot() []*api.Node {
	result := make([]*api.Node, len(control.nodes))
	for index, node := range control.nodes {
		result[index] = node.Copy()
	}
	return result
}

func (control *controllerActivationControl) tasksSnapshot() []*api.Task {
	result := make([]*api.Task, len(control.tasks))
	for index, task := range control.tasks {
		result[index] = task.Copy()
	}
	return result
}

func (control *controllerActivationControl) clusterIdentity(ctx context.Context) (*manager.ClusterIdentity, error) {
	return control.reader.ClusterIdentity(ctx)
}

// update retains native validation and CAS. The additional projections can
// only restrict the transaction; they cannot confer activation authority.
func (control *controllerActivationControl) update(ctx context.Context, expected *api.Node, spec *api.NodeSpec, nodes []*api.Node, tasks []*api.Task, taskOwners []string, retirements []*bootstrapstart.ManagerRetirement) (*api.Node, error) {
	if err := control.guard(ctx); err != nil {
		return nil, err
	}
	guard := func(tx store.ReadTx) error {
		if ctx.Err() != nil || control.original.Err() != nil {
			return errors.New("controller activation original context ended")
		}
		for _, retired := range retirements {
			if !retired.Valid(time.Now()) {
				return errors.New("controller activation original retirement expired")
			}
		}
		managers, err := store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		managerCount := 0
		for _, node := range managers {
			if node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager {
				managerCount++
			}
		}
		expectedManagers := 0
		for _, node := range nodes {
			if node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager {
				expectedManagers++
			}
			current := store.GetNode(tx, node.ID)
			if current == nil || current.Meta.Version != node.Meta.Version {
				return errors.New("controller activation manager projection changed")
			}
		}
		if managerCount != expectedManagers {
			return errors.New("controller activation manager set changed")
		}
		for _, task := range tasks {
			current := store.GetTask(tx, task.ID)
			if current == nil || current.Meta.Version != task.Meta.Version || current.NodeID != task.NodeID || current.Status.State != task.Status.State {
				return errors.New("controller activation captured execution changed or disappeared")
			}
		}
		for _, owner := range taskOwners {
			current, err := store.FindTasks(tx, store.ByNodeID(owner))
			if err != nil {
				return err
			}
			captured := 0
			for _, task := range tasks {
				if task.NodeID == owner {
					captured++
				}
			}
			if len(current) != captured {
				return errors.New("controller activation old execution set changed")
			}
		}
		// A task added on another manager or worker is also execution evidence;
		// checking only the drained owners would miss that concurrent owner.
		currentTasks, err := store.FindTasks(tx, store.All)
		if err != nil {
			return err
		}
		currentAuthTasks := 0
		for _, task := range currentTasks {
			if task.ServiceAnnotations.Labels[LabelRole] == "ts-auth" {
				currentAuthTasks++
			}
		}
		capturedAuthTasks := 0
		for _, task := range control.tasks {
			if task.ServiceAnnotations.Labels[LabelRole] != "ts-auth" {
				continue
			}
			capturedAuthTasks++
			current := store.GetTask(tx, task.ID)
			if current == nil || current.Meta.Version != task.Meta.Version || current.NodeID != task.NodeID {
				return errors.New("controller activation TSAuth execution changed or disappeared")
			}
		}
		if currentAuthTasks != capturedAuthTasks {
			return errors.New("controller activation TSAuth execution set changed")
		}
		return nil
	}
	if err := ociclient.CheckRequestGuard(ctx); err != nil {
		return nil, err
	}
	response, err := control.manager.UpdateNodeAtObservation(ctx, control.observation, expected,
		&api.UpdateNodeRequest{NodeID: expected.ID, NodeVersion: &expected.Meta.Version, Spec: spec}, guard)
	if err != nil {
		return nil, err
	}
	return response.Node, control.guard(ctx)
}
