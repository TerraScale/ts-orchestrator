package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/grpclog"
)

const memberCLIUsage = `usage:
  ts-orch member ls                  List the managers and workers of this region's cluster
  ts-orch member promote             On the leader, promote eligible workers to three managers
  ts-orch member leave <hostname>    On the leader, preserve quorum, drain and remove a host
  ts-orch member drain <hostname>     Run no task on a worker; it stays joined
  ts-orch member activate <hostname>  Let a worker run its region's per-node services again
`

// RunMemberCLI lists and removes the hosts of the region's SwarmKit cluster
// from its manager's control socket (root).
func RunMemberCLI(ctx context.Context, args []string, output io.Writer) error {
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))
	return explain(runMemberCLI(ctx, args, output, singleHostState))
}

func runMemberCLI(ctx context.Context, args []string, output io.Writer, state string) error {
	var run func(context.Context, api.ControlClient) error
	var membershipChange bool
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
	case len(args) == 1 && args[0] == "promote":
		membershipChange = true
		run = func(ctx context.Context, client api.ControlClient) error {
			nodeID, err := swarmruntime.SingleHostNodeID(ctx, state)
			if err != nil {
				return err
			}
			watchClient, conn, err := swarmruntime.DialSingleHost(state)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := swarmruntime.PromoteManagers(ctx, watchClient, api.NewWatchClient(conn), nodeID); err != nil {
				return err
			}
			return runMemberCLI(ctx, []string{"ls"}, output, state)
		}
	case len(args) == 2 && args[0] == "leave":
		membershipChange = true
		run = func(ctx context.Context, client api.ControlClient) error {
			nodeID, err := swarmruntime.SingleHostNodeID(ctx, state)
			if err != nil {
				return err
			}
			listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
			if err != nil {
				return err
			}
			if !swarmruntime.IsLeader(listed.Nodes, nodeID) {
				return errors.New("membership changes must run on the Raft leader")
			}
			if err := swarmruntime.LeaveMember(ctx, client, args[1]); err != nil {
				return err
			}
			_, err = fmt.Fprintf(output, "%s drained and removed; terminate it or clear its state before it starts again\n", args[1])
			return err
		}
	case len(args) == 2 && (args[0] == "drain" || args[0] == "activate"):
		availability := map[string]api.NodeSpec_Availability{"drain": api.NodeAvailabilityDrain, "activate": api.NodeAvailabilityActive}[args[0]]
		run = func(ctx context.Context, client api.ControlClient) error {
			if err := swarmruntime.SetMemberAvailability(ctx, client, args[1], availability); err != nil {
				return err
			}
			_, err := fmt.Fprintf(output, "%s %s\n", args[1], strings.ToLower(availability.String()))
			return err
		}
	default:
		_, err := io.WriteString(output, memberCLIUsage)
		if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
			return err
		}
		return errors.Join(err, errors.New("unknown member command"))
	}
	if membershipChange {
		lock, err := os.OpenFile(filepath.Join(state, "membership.lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		defer lock.Close()
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return fmt.Errorf("another membership change is in progress: %w", err)
		}
		defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
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
