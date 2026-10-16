package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const rolloutUsage = `Usage: ts-orch rollout <command> --config OPERATOR_JSON [flags]

  status                                   Print the desired release, recent generations and the leader's rollout
  publish  --receipt F [--delegation F]    Make a signed release the cell's next generation
  pause                                    Start no further rollout; one in flight still finishes
  resume                                   Undo pause, and retry the rollback of a frozen rollout
  rollback --to GEN                        Publish GEN's release again as a new generation and stop the rollout in flight

Upload the binary first with ts-orch operator artifact-push. Every command
prints the leader's reply as JSON.
`

// runRollout maps ts-orch rollout <command> to the operator command, which
// owns the controller connection.
func runRollout(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, rolloutUsage)
		return err
	}
	if !slices.Contains([]string{"status", "publish", "pause", "resume", "rollback"}, args[0]) {
		return fmt.Errorf("unknown rollout command %q", args[0])
	}
	return runOperator(ctx, append([]string{"rollout-" + args[0]}, args[1:]...), output)
}

// operatorRollout sends one rollout request to the authority leader and
// prints its reply.
func operatorRollout(ctx context.Context, cfg Config, runtime *natscell.Runtime, command string, payload any,
	output io.Writer,
) error {
	encoded, err := protocol.EncodeJSON(payload)
	if err != nil {
		return err
	}
	data, err := requestLeader(ctx, cfg, runtime, "rollout."+command, "rollout", encoded)
	if err != nil {
		return err
	}
	var reply rolloutReply
	if err := protocol.DecodeStrict(data, &reply, 1<<20); err != nil {
		return fmt.Errorf("decode rollout reply: %w", err)
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	return printJSON(output, reply)
}

// rolloutPayload builds the request of one rollout command from its flags.
func rolloutPayload(command, receiptPath, delegationPath string, to uint64) (any, error) {
	if command != "publish" && (receiptPath != "" || delegationPath != "") || command != "rollback" && to != 0 {
		return nil, fmt.Errorf("rollout %s does not take --receipt, --delegation or --to", command)
	}
	switch command {
	case "publish":
		if receiptPath == "" {
			return nil, errors.New("rollout publish requires --receipt [--delegation]")
		}
		request := rolloutPublishRequest{}
		var err error
		if request.Receipt, err = readBoundedConfigFile(receiptPath); err != nil {
			return nil, err
		}
		if delegationPath != "" {
			if request.Delegation, err = readBoundedConfigFile(delegationPath); err != nil {
				return nil, err
			}
		}
		return request, nil
	case "rollback":
		if to == 0 {
			return nil, errors.New("rollout rollback requires --to GEN")
		}
		return rolloutRollbackRequest{To: to}, nil
	}
	return struct{}{}, nil
}
