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

// Apply sends spec to every ordered region as a new generation and prints
// one line per region. It fails when a targeted region failed or did not reply.
func Apply(ctx context.Context, conn *nats.Conn, spec swarmruntime.ServiceSpec, output io.Writer) error {
	if err := validEntry(spec.Name, Entry{Generation: 1, Spec: &spec}); err != nil {
		return err
	}
	return send(ctx, conn, ApplyRequest{Name: spec.Name, Entry: Entry{Generation: time.Now().UnixNano(), Spec: &spec}}, applyWait, output)
}

// Remove deletes name in every ordered region.
func Remove(ctx context.Context, conn *nats.Conn, name string, output io.Writer) error {
	if !serviceName.MatchString(name) {
		return errors.New("service name must match ^[a-z][a-z0-9-]{0,62}$")
	}
	return send(ctx, conn, ApplyRequest{Name: name, Entry: Entry{Generation: time.Now().UnixNano()}}, applyWait, output)
}

func send(ctx context.Context, conn *nats.Conn, request ApplyRequest, wait time.Duration, output io.Writer) error {
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		return err
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
		return err
	}
	table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "REGION\tRESULT\tREADY")
	var failed, succeeded []string
	for _, region := range regions {
		targeted := request.Entry.Spec == nil || len(request.Entry.Spec.Regions) == 0 || slices.Contains(request.Entry.Spec.Regions, region)
		reply, ok := replies[region]
		switch {
		case !ok:
			fmt.Fprintf(table, "%s\tNO REPLY\t-\n", region)
		case reply.Error != "":
			fmt.Fprintf(table, "%s\tERROR %s\t-\n", region, reply.Error)
		default:
			fmt.Fprintf(table, "%s\t%s\t%dms\n", region, reply.Result, reply.ElapsedMS)
			succeeded = append(succeeded, region)
			continue
		}
		if targeted {
			failed = append(failed, region)
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if len(failed) != 0 {
		return fmt.Errorf("%s failed in %s; succeeded in [%s]", request.Name, strings.Join(failed, ", "), strings.Join(succeeded, ", "))
	}
	return nil
}

// Ping prints every region that answers on the mesh with its round trip, and
// fails when an ordered region is missing.
func Ping(ctx context.Context, conn *nats.Conn, wait time.Duration, output io.Writer) error {
	sent := time.Now()
	type answer struct {
		Reply
		rtt time.Duration
	}
	answers := map[string]answer{}
	if err := collect(ctx, conn, PingSubject, nil, len(Regions()), wait, func(data []byte) bool {
		var reply Reply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			answers[reply.Region] = answer{reply, time.Since(sent)}
		}
		return true
	}); err != nil {
		return err
	}
	table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "REGION\tSERVER\tRTT")
	var missing []string
	for _, region := range Regions() {
		if a, ok := answers[region]; ok {
			fmt.Fprintf(table, "%s\t%s\t%dms\n", region, a.Server, a.rtt.Milliseconds())
		} else {
			fmt.Fprintf(table, "%s\t-\tNO REPLY\n", region)
			missing = append(missing, region)
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if len(missing) != 0 {
		return fmt.Errorf("no reply from %s", strings.Join(missing, ", "))
	}
	return nil
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
