package mesh

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
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
	deadline := time.Now().Add(10 * time.Second)
	for {
		token, err := os.ReadFile(filepath.Join(state, "mesh", "client.token"))
		if err != nil {
			return nil, fmt.Errorf("mesh is not running on this host: %w", err)
		}
		conn, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", LocalPort), nats.Token(strings.TrimSpace(string(token))))
		// ts-orch may be restarting (a release install): wait for its listener.
		if err == nil || time.Now().After(deadline) {
			return conn, err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// noReply marks a region that did not answer in time.
const noReply = "no reply"

// Apply sends spec to every ordered region as a new generation and prints
// one line per region. It fails when a targeted region failed or did not reply.
// With holdAfter, the regions after it hold the previous generation (a canary)
// until Resume.
func Apply(ctx context.Context, conn *nats.Conn, spec swarmruntime.ServiceSpec, holdAfter string, output io.Writer) error {
	return printApply(output)(applySpec(ctx, conn, spec, holdAfter, applyWait))
}

// Resume re-applies name's held spec without its hold, so the rollout goes on
// past the canary region.
func Resume(ctx context.Context, conn *nats.Conn, name string, output io.Writer) error {
	entries, err := desiredStates(ctx, conn)
	if err != nil {
		return err
	}
	current := entries[name].entry()
	if current.Spec == nil || current.HoldAfter == "" {
		return fmt.Errorf("%s has no held rollout", name)
	}
	return printApply(output)(applySpec(ctx, conn, *current.Spec, "", applyWait))
}

// Remove deletes name in every ordered region.
func Remove(ctx context.Context, conn *nats.Conn, name string, output io.Writer) error {
	if !serviceName.MatchString(name) {
		return errors.New("service name must match ^[a-z][a-z0-9-]{0,62}$")
	}
	return printApply(output)(send(ctx, conn, ApplyRequest{Name: name, Entry: Entry{Generation: time.Now().UnixNano()}}, applyWait))
}

// applySpec rolls spec out region by region. When a targeted region fails,
// the later ones never apply and every region gets the previous spec back,
// unless a newer apply replaced this one meanwhile.
func applySpec(ctx context.Context, conn *nats.Conn, spec swarmruntime.ServiceSpec, holdAfter string, wait time.Duration) ([]Reply, error) {
	if err := validEntry(spec.Name, Entry{Generation: 1, Spec: &spec, HoldAfter: holdAfter}); err != nil {
		return nil, err
	}
	entries, err := desiredStates(ctx, conn)
	if err != nil {
		return nil, err
	}
	before := entries[spec.Name].entry()
	generation := max(time.Now().UnixNano(), before.Generation+1)
	rows, failed := send(ctx, conn, ApplyRequest{Name: spec.Name, Entry: Entry{Generation: generation, Spec: &spec, HoldAfter: holdAfter}}, max(wait, rolloutWait(&spec)))
	if failed == nil || before.Spec == nil {
		return rows, failed
	}
	if current, err := desiredStates(ctx, conn); err != nil || current[spec.Name].entry().Generation != generation {
		return rows, errors.Join(failed, errors.New("not rolled back: a newer apply replaced it"), err)
	}
	back, err := send(ctx, conn, ApplyRequest{Name: spec.Name, ExpectedGeneration: generation, Entry: Entry{Generation: max(time.Now().UnixNano(), generation+1), Spec: before.Spec}}, max(rollbackWait, regionWindow(before.Spec)))
	if err != nil {
		return append(rows, back...), errors.Join(failed, fmt.Errorf("rollback to %s: %w", before.Spec.Image, err))
	}
	return append(rows, back...), errors.Join(failed, errors.New("rolled back to "+before.Spec.Image))
}

// gather publishes a request and returns the regions it expects (the seeds
// plus every region a reply names) and each one's reply, once all replied or
// wait elapsed. rtt stamps each reply's ElapsedMS with its round trip.
func gather(ctx context.Context, conn *nats.Conn, subject string, payload []byte, wait time.Duration, rtt bool) ([]string, map[string]Reply, error) {
	sent := time.Now()
	regions, replies := Regions(), map[string]Reply{}
	err := collect(ctx, conn, subject, payload, math.MaxInt, wait, func(data []byte) bool {
		var reply Reply
		if protocol.DecodeTolerant(data, &reply, maxWire) != nil {
			return true
		}
		if rtt {
			reply.ElapsedMS = time.Since(sent).Milliseconds()
		}
		replies[reply.Region] = reply
		pending := false
		for _, region := range slices.Concat(regions, reply.Regions) {
			if !slices.Contains(regions, region) {
				regions = append(regions, region)
			}
			_, ok := replies[region]
			pending = pending || !ok
		}
		return pending
	})
	return regions, replies, err
}

// send returns one row per known region; it fails when a targeted region
// failed or did not reply.
func send(ctx context.Context, conn *nats.Conn, request ApplyRequest, wait time.Duration) ([]Reply, error) {
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		return nil, err
	}
	regions, replies, err := gather(ctx, conn, ApplySubject, payload, wait, false)
	if err != nil {
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
		fmt.Fprintln(table, "REGION\tRESULT\tREADY\tPHASES")
		for _, row := range rows {
			switch row.Error {
			case "":
				fmt.Fprintf(table, "%s\t%s\t%dms\t%s\n", row.Region, row.Result, row.ElapsedMS, cmp.Or(row.Phases, "-"))
			case noReply:
				fmt.Fprintf(table, "%s\tNO REPLY\t-\t-\n", row.Region)
			default:
				fmt.Fprintf(table, "%s\tERROR %s\t-\t-\n", row.Region, row.Error)
			}
		}
		return errors.Join(table.Flush(), failed)
	}
}

// Ping prints every region that answers on the mesh with its round trip, and
// fails when a known region is missing.
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

// ping returns one row per known region, ElapsedMS being its round trip.
func ping(ctx context.Context, conn *nats.Conn, wait time.Duration) ([]Reply, error) {
	regions, answers, err := gather(ctx, conn, PingSubject, nil, wait, true)
	if err != nil {
		return nil, err
	}
	var rows []Reply
	var missing []string
	for _, region := range regions {
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
