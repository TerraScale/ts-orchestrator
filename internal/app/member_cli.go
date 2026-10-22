package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/grpclog"
)

const memberCLIUsage = `usage:
  ts-orch member ls                List the hosts of this region's cluster
  ts-orch member leave <hostname>  Drain a worker, wait for its tasks to stop, remove it
`

// RunMemberCLI lists and removes the hosts of the region's SwarmKit cluster
// from its manager's control socket (root).
func RunMemberCLI(ctx context.Context, args []string, output io.Writer) error {
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))
	return explain(runMemberCLI(ctx, args, output, singleHostState))
}

func runMemberCLI(ctx context.Context, args []string, output io.Writer, state string) error {
	var run func(context.Context, api.ControlClient) error
	switch {
	case len(args) == 1 && args[0] == "ls":
		run = func(ctx context.Context, client api.ControlClient) error {
			members, err := swarmruntime.ListMembers(ctx, client)
			if err != nil {
				return err
			}
			table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
			fmt.Fprintln(table, "HOSTNAME\tROLE\tSTATUS\tAVAILABILITY\tADDRESS")
			for _, m := range members {
				fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", m.Hostname, m.Role, m.State, m.Availability, m.Address)
			}
			return table.Flush()
		}
	case len(args) == 2 && args[0] == "leave":
		run = func(ctx context.Context, client api.ControlClient) error {
			if err := swarmruntime.LeaveMember(ctx, client, args[1]); err != nil {
				return err
			}
			_, err := fmt.Fprintf(output, "%s drained and removed; terminate it or clear its state before it starts again\n", args[1])
			return err
		}
	default:
		_, err := io.WriteString(output, memberCLIUsage)
		if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
			return err
		}
		return errors.Join(err, errors.New("unknown member command"))
	}
	client, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute) // leave waits up to 5 min for tasks to stop
	defer cancel()
	return run(ctx, client)
}
