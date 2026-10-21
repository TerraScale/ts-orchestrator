package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const nodeUsage = `Usage: ts-orch node <command> --config OPERATOR_JSON [flags]

  status                                        Print every node's latest operation and every node out of rotation
  drain    --node N                             Take the node out of every load balancer set and keep it out
  undrain  --node N                             Return a drained node once it serves
  reboot   --node N                             Drain, reboot the instance, check it serves, return it
  resize   --node N --ocpus C --memory-gb M     Drain, resize the instance (OCI restarts it), check, return it
  add      --node N                             Create a granted node's missing backends out of rotation, check, return them
  retire   --node N                             Drain a node without replicas or a controller, remove its backends,
                                                back its boot volume up (kept 7 days) and terminate its instance
  rename   --node N --new-name M                Drain N, rename its instance, boot volume and hostname to M, reboot it,
                                                re-enroll its host as M, move its roles, check, return it; the cell
                                                spec must grant M at N's address first (service grant-host)

The authority leader runs one operation at a time. It refuses one that would
leave a load balancer set with fewer healthy backends than its min_serving.
--wait D waits up to D for the operation to finish; every command prints the
leader's reply as JSON. Use these commands, never the oci CLI, to change a
cell's servers or load balancer backends.
`

// runNode maps ts-orch node <command> to the operator command, which owns
// the controller connection.
func runNode(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, nodeUsage)
		return err
	}
	if !slices.Contains([]string{"status", nodeOpDrain, nodeOpUndrain, nodeOpReboot, nodeOpResize, nodeOpAdd, nodeOpRetire,
		nodeOpRename}, args[0]) {
		return fmt.Errorf("unknown node command %q", args[0])
	}
	return runOperator(ctx, append([]string{"node-" + args[0]}, args[1:]...), output)
}

// operatorNode sends one node request to the authority leader and, with
// wait, polls the operation until it is done or failed.
func operatorNode(ctx context.Context, cfg Config, runtime *natscell.Runtime, command string, request nodeOpRequest,
	wait time.Duration, output io.Writer,
) error {
	kind := nodeOpSubmitKind
	if command == "status" {
		if request != (nodeOpRequest{}) {
			return errors.New("node status takes no --node, --ocpus or --memory-gb")
		}
		kind = nodeOpStatusKind
	} else if request.Node == "" {
		return fmt.Errorf("node %s requires --node", command)
	}
	if command != "status" {
		request.Op = command
	}
	reply, err := requestNode(ctx, cfg, runtime, kind, request)
	if err != nil || wait <= 0 || reply.Operation == nil {
		if err == nil {
			err = printJSON(output, reply)
		}
		return err
	}
	id := reply.Operation.ID
	deadline := time.Now().Add(wait)
	for {
		status, err := requestNode(ctx, cfg, runtime, nodeOpStatusKind, nodeOpRequest{})
		if err != nil {
			return err
		}
		for _, op := range status.Operations {
			if op.Node != request.Node || op.ID != id || op.active() {
				continue
			}
			if err := printJSON(output, nodeOpReply{Operation: &op}); err != nil {
				return err
			}
			if op.State == nodeOpFailed {
				return fmt.Errorf("node %s %s failed: %s", op.Node, op.Op, op.Reason)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("node %s %s did not finish within %s; see ts-orch node status", request.Node, command, wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func requestNode(ctx context.Context, cfg Config, runtime *natscell.Runtime, kind string, request nodeOpRequest,
) (nodeOpReply, error) {
	if kind == nodeOpSubmitKind {
		request.ExecutionDeadline = time.Now().UTC().Add(nodeOperationExecutionLifetime)
	}
	encoded, err := protocol.EncodeJSON(request)
	if err != nil {
		return nodeOpReply{}, err
	}
	data, err := requestLeader(ctx, cfg, runtime, kind, "node", encoded)
	if err != nil {
		return nodeOpReply{}, err
	}
	var reply nodeOpReply
	if err := protocol.DecodeStrict(data, &reply, 1<<20); err != nil {
		return nodeOpReply{}, fmt.Errorf("decode node reply: %w", err)
	}
	if reply.Error != "" {
		return nodeOpReply{}, errors.New(reply.Error)
	}
	return reply, nil
}
