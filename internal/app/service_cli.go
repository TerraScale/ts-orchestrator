package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/grpclog"
)

// singleHostState is the `ts-orch single-host` state directory.
const singleHostState = "/var/lib/ts-orch"

const serviceCLIUsage = `usage:
  ts-orch service apply -f <spec.json>
  ts-orch service ls
  ts-orch service rm <name>
  ts-orch service ps <name>
  ts-orch service logs [-f] <name>
  ts-orch service inspect <name>
`

// RunServiceCLI manages services declared by deploy/m1/services/*.json: apply
// and rm reach every ordered region over the mesh; ls shows this host.
func RunServiceCLI(ctx context.Context, args []string, output io.Writer) error {
	// SwarmKit routes gRPC transport chatter to stderr; RPC errors are returned.
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))
	return explain(runServiceCLI(ctx, args, output, singleHostState))
}

func runServiceCLI(ctx context.Context, args []string, output io.Writer, state string) error {
	if len(args) != 0 && slices.Contains([]string{"ps", "logs", "inspect"}, args[0]) {
		return runServiceOps(ctx, args, output, state)
	}
	// The 30s RPC bound below does not cover WaitServiceSpec, which bounds itself.
	outer := ctx
	var run func(context.Context, api.ControlClient) error
	switch {
	case len(args) == 3 && args[0] == "apply" && args[1] == "-f":
		data, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		var spec swarmruntime.ServiceSpec
		if err := protocol.DecodeStrict(data, &spec, 64<<10); err != nil {
			return fmt.Errorf("decode %s: %w", args[2], err)
		}
		run = func(ctx context.Context, client api.ControlClient) error {
			service, err := swarmruntime.ApplyServiceSpec(ctx, client, spec)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(output, "applied %s (%s) version %d on this host only\n", spec.Name, service.ID, service.Meta.Version.Index); err != nil {
				return err
			}
			// A new task that is not ready in time rolls back; the previous spec keeps serving.
			rollout, err := swarmruntime.WaitServiceSpec(outer, client, service, nil)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(output, "%s running in %dms, ready in %dms\n", spec.Name, rollout.Running.Milliseconds(), rollout.Ready.Milliseconds())
			return err
		}
		if done, err := meshRequest(state, func(conn *nats.Conn) error { return mesh.Apply(ctx, conn, spec, output) }); done {
			return err
		}
	case len(args) == 1 && args[0] == "ls":
		run = func(ctx context.Context, client api.ControlClient) error {
			rows, err := swarmruntime.ListServiceSpecs(ctx, client)
			if err != nil {
				return err
			}
			table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
			fmt.Fprintln(table, "NAME\tREPLICAS\tIMAGE")
			for _, row := range rows {
				fmt.Fprintf(table, "%s\t%d/%d running\t%s\n", row.Name, row.Running, row.Replicas, row.Image)
			}
			return table.Flush()
		}
	case len(args) == 2 && args[0] == "rm":
		run = func(ctx context.Context, client api.ControlClient) error {
			if err := swarmruntime.RemoveServiceSpec(ctx, client, args[1]); err != nil {
				return err
			}
			_, err := fmt.Fprintf(output, "removed %s on this host only\n", args[1])
			return err
		}
		if done, err := meshRequest(state, func(conn *nats.Conn) error { return mesh.Remove(ctx, conn, args[1], output) }); done {
			return err
		}
	default:
		_, err := io.WriteString(output, serviceCLIUsage)
		if len(args) == 0 || strings.HasPrefix(args[0], "-h") || args[0] == "--help" || args[0] == "help" {
			return err
		}
		return errors.Join(err, errors.New("unknown service command"))
	}
	client, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return run(ctx, client)
}

// meshRequest runs one global service change through this host's mesh node.
// A host whose mesh never started (no client token: not in an OCI region with
// Vault, such as a CI runner) is not done and changes only its own services.
func meshRequest(state string, request func(*nats.Conn) error) (bool, error) {
	conn, err := mesh.Connect(state)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	defer conn.Close()
	return true, request(conn)
}
