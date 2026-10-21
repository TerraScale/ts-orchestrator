package mesh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

// Connect opens the root CLI's connection to this host's mesh node.
func Connect(state string) (*nats.Conn, error) {
	token, err := os.ReadFile(filepath.Join(state, "mesh", "client.token"))
	if err != nil {
		return nil, fmt.Errorf("mesh is not running on this host: %w", err)
	}
	return nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", LocalPort), nats.Token(strings.TrimSpace(string(token))))
}

// noReply marks a region that did not answer in time.
const noReply = "no reply"

// Apply sends spec to every ordered region as a new generation and prints
// one line per region. It fails when a targeted region failed or did not reply.
func Apply(ctx context.Context, conn *nats.Conn, spec swarmruntime.ServiceSpec, output io.Writer) error {
	return printApply(output)(applySpec(ctx, conn, spec, applyWait))
}

// Remove deletes name in every ordered region.
func Remove(ctx context.Context, conn *nats.Conn, name string, output io.Writer) error {
	if !serviceName.MatchString(name) {
		return errors.New("service name must match ^[a-z][a-z0-9-]{0,62}$")
	}
	return printApply(output)(send(ctx, conn, ApplyRequest{Name: name, Entry: Entry{Generation: time.Now().UnixNano()}}, applyWait))
}

func applySpec(ctx context.Context, conn *nats.Conn, spec swarmruntime.ServiceSpec, wait time.Duration) ([]Reply, error) {
	if err := validEntry(spec.Name, Entry{Generation: 1, Spec: &spec}); err != nil {
		return nil, err
	}
	return send(ctx, conn, ApplyRequest{Name: spec.Name, Entry: Entry{Generation: time.Now().UnixNano(), Spec: &spec}}, wait)
}

// send returns one row per ordered region; it fails when a targeted region
// failed or did not reply.
func send(ctx context.Context, conn *nats.Conn, request ApplyRequest, wait time.Duration) ([]Reply, error) {
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		return nil, err
	}
	regions := Regions()
	replies := map[string]Reply{}
	if err := collect(ctx, conn, ApplySubject, payload, len(regions), wait, func(data []byte) bool {
		var reply Reply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			replies[reply.Region] = reply
		}
		return true
	}); err != nil {
		return nil, err
	}
	var rows []Reply
	var failed, succeeded []string
	for _, region := range regions {
		reply, ok := replies[region]
		if !ok {
			reply = Reply{Region: region, Error: noReply}
		}
		rows = append(rows, reply)
		if reply.Error == "" {
			succeeded = append(succeeded, region)
		} else if request.Entry.Spec == nil || len(request.Entry.Spec.Regions) == 0 || slices.Contains(request.Entry.Spec.Regions, region) {
			failed = append(failed, region)
		}
	}
	if len(failed) != 0 {
		return rows, fmt.Errorf("%s failed in %s; succeeded in [%s]", request.Name, strings.Join(failed, ", "), strings.Join(succeeded, ", "))
	}
	return rows, nil
}

func printApply(output io.Writer) func([]Reply, error) error {
	return func(rows []Reply, failed error) error {
		if rows == nil {
			return failed
		}
		table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "REGION\tRESULT\tREADY")
		for _, row := range rows {
			switch row.Error {
			case "":
				fmt.Fprintf(table, "%s\t%s\t%dms\n", row.Region, row.Result, row.ElapsedMS)
			case noReply:
				fmt.Fprintf(table, "%s\tNO REPLY\t-\n", row.Region)
			default:
				fmt.Fprintf(table, "%s\tERROR %s\t-\n", row.Region, row.Error)
			}
		}
		return errors.Join(table.Flush(), failed)
	}
}

// Ping prints every region that answers on the mesh with its round trip, and
// fails when an ordered region is missing.
func Ping(ctx context.Context, conn *nats.Conn, wait time.Duration, output io.Writer) error {
	rows, failed := ping(ctx, conn, wait)
	if rows == nil {
		return failed
	}
	table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "REGION\tSERVER\tRTT")
	for _, row := range rows {
		if row.Error == "" {
			fmt.Fprintf(table, "%s\t%s\t%dms\n", row.Region, row.Server, row.ElapsedMS)
		} else {
			fmt.Fprintf(table, "%s\t-\tNO REPLY\n", row.Region)
		}
	}
	return errors.Join(table.Flush(), failed)
}

// ping returns one row per ordered region, ElapsedMS being its round trip.
func ping(ctx context.Context, conn *nats.Conn, wait time.Duration) ([]Reply, error) {
	sent := time.Now()
	answers := map[string]Reply{}
	if err := collect(ctx, conn, PingSubject, nil, len(Regions()), wait, func(data []byte) bool {
		var reply Reply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			reply.ElapsedMS = time.Since(sent).Milliseconds()
			answers[reply.Region] = reply
		}
		return true
	}); err != nil {
		return nil, err
	}
	var rows []Reply
	var missing []string
	for _, region := range Regions() {
		reply, ok := answers[region]
		if !ok {
			reply = Reply{Region: region, Error: noReply}
			missing = append(missing, region)
		}
		rows = append(rows, reply)
	}
	if len(missing) != 0 {
		return rows, fmt.Errorf("no reply from %s", strings.Join(missing, ", "))
	}
	return rows, nil
}

// RunCLI is `ts-orch mesh ping`.
func RunCLI(ctx context.Context, args []string, state string, output io.Writer) error {
	if len(args) != 1 || args[0] != "ping" {
		_, err := io.WriteString(output, "usage:\n  ts-orch mesh ping\n")
		if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
			return err
		}
		return errors.Join(err, errors.New("unknown mesh command"))
	}
	conn, err := Connect(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	return Ping(ctx, conn, 5*time.Second, output)
}
