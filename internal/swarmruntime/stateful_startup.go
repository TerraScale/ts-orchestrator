package swarmruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// InitializeStateful binds only after StartAcceptedWorker returns its actual
// joined identity. Earlier DATA assignments fail closed and need replacement.
func (e *Executor) InitializeStateful(ctx context.Context, agent *host.Agent, instanceID string, node *Node, roots trust.Keyring, evidence releasechannel.Location, stateRoot string) error {
	if e == nil || ctx == nil || ctx.Err() != nil || agent == nil || node == nil || node.upstream == nil || node.role != "container" ||
		node.workerDirectory == "" || stateRoot != filepath.Join(node.workerDirectory, "execution") || os.Geteuid() != 0 {
		return execution.ErrUnsafe
	}
	nodeID := node.ID()
	if nodeID == "" {
		return execution.ErrUnsafe
	}
	wire, err := os.ReadFile(filepath.Join(node.stateDir, "admission.json"))
	var admitted admittedIdentity
	if err != nil || json.Unmarshal(wire, &admitted, json.RejectUnknownMembers(true)) != nil || admitted.InstanceID != instanceID || admitted.Role != "container" {
		return execution.ErrUnsafe
	}
	var enrolled struct {
		Worker    hostenroll.SwarmWorker
		Transport []byte
	}
	wire, err = os.ReadFile(filepath.Join(node.workerDirectory, "enrollment.json"))
	if err != nil || json.Unmarshal(wire, &enrolled, json.RejectUnknownMembers(true)) != nil || enrolled.Worker.Validate(time.Now().UTC()) != nil ||
		enrolled.Worker.RegistrationID != admitted.HostID || enrolled.Worker.InstanceID != instanceID || enrolled.Worker.Region != admitted.Region || enrolled.Worker.Role != admitted.Role {
		return execution.ErrUnsafe
	}
	identity, err := agent.RuntimeWorkerIdentity(instanceID, nodeID)
	if err != nil || entityid.Derive("host", identity.Identity().Cell, identity.Identity().HostNode) != admitted.HostID || identity.Identity().Cell != enrolled.Worker.Cell {
		return errors.Join(execution.ErrUnsafe, err)
	}
	if _, _, err := node.nodeSigningKey(); err != nil {
		return err
	}
	for {
		e.mu.Lock()
		bound, configured := e.stateful != nil, e.functionNodeID
		ready := e.registry != nil && e.containerMaterial != nil
		e.mu.Unlock()
		if bound || !ready {
			return execution.ErrUnsafe
		}
		if configured != "" {
			if configured != nodeID {
				return execution.ErrUnsafe
			}
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return err
	}
	session, err := execution.NewWorkerSessionFromAgent(agent, instanceID, nodeID, e.client)
	if err != nil {
		return err
	}
	if err := session.BindRuntimeStopSigner(node); err != nil {
		return err
	}
	source, err := execution.NewSource(session, execution.RuntimeObserver{Client: e.client}, roots, evidence, stateRoot)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.BindStateful(source)
}
