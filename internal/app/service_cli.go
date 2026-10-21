package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
)

// singleHostControlSocket is the SwarmKit control API of `ts-orch single-host`
// (node state dir /var/lib/ts-orch); only root can open it.
const singleHostControlSocket = "/var/lib/ts-orch/control.sock"

const serviceCLIUsage = `usage:
  ts-orch service apply -f <spec.json>
  ts-orch service ls
  ts-orch service rm <name>
`

// RunServiceCLI manages single-host services declared by deploy/m1/services/*.json.
func RunServiceCLI(ctx context.Context, args []string, output io.Writer) error {
	// SwarmKit routes gRPC transport chatter to stderr; RPC errors are returned.
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))
	return runServiceCLI(ctx, args, output, singleHostControlSocket)
}

func runServiceCLI(ctx context.Context, args []string, output io.Writer, socket string) error {
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
			_, err = fmt.Fprintf(output, "applied %s (%s) version %d\n", spec.Name, service.ID, service.Meta.Version.Index)
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
			_, err := fmt.Fprintf(output, "removed %s\n", args[1])
			return err
		}
	default:
		_, err := io.WriteString(output, serviceCLIUsage)
		if len(args) == 0 || strings.HasPrefix(args[0], "-h") || args[0] == "--help" || args[0] == "help" {
			return err
		}
		return errors.Join(err, errors.New("unknown service command"))
	}
	// The manager serves its node TLS identity on the socket; root-only socket
	// permissions, not the certificate, authorize this client (as SwarmKit's own).
	conn, err := grpc.NewClient("passthrough:///single-host-control", grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return run(ctx, api.NewControlClient(conn))
}
