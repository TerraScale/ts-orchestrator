package regionhealth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const (
	checkEvery = 10 * time.Second
	statusWait = 2 * time.Second
	maxReply   = 64 << 10
)

// Run checks this host every 10 s until ctx ends, warns on every state
// change, and answers MeshHealthSubject once this host's mesh node is up.
// Without a mesh only the local checks run.
func Run(ctx context.Context, state string) {
	server, _ := os.Hostname()
	var latest atomic.Pointer[Report]
	var conn *nats.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	previous := StateOK
	tick := time.NewTicker(checkEvery)
	defer tick.Stop()
	for {
		report := check(ctx, state)
		report.Server = server
		latest.Store(&report)
		if report.State != previous {
			slog.WarnContext(ctx, "region health changed", "from", previous, "to", report.State, "reasons", strings.Join(report.Reasons, "; "))
			previous = report.State
		}
		if conn == nil || conn.IsClosed() {
			// The mesh writes its token once it starts; until then this retries every tick.
			if conn, _ = mesh.Connect(state); conn != nil {
				// A gateway server's cluster name is its region.
				if err := serve(conn, conn.ConnectedClusterName(), func() Report { return *latest.Load() }); err != nil {
					slog.WarnContext(ctx, "region health responder failed", "error", err)
					conn.Close()
					conn = nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// serve answers MeshHealthSubject as region with the latest report.
func serve(conn *nats.Conn, region string, latest func() Report) error {
	_, err := conn.Subscribe(protocol.MeshHealthSubject, func(m *nats.Msg) {
		report := latest()
		report.Region = region
		data, err := protocol.EncodeJSON(report)
		if err == nil {
			err = m.Respond(data)
		}
		if err != nil {
			slog.Warn("region health reply failed", "error", err)
		}
	})
	if err != nil {
		return err
	}
	return conn.Flush()
}

// Ask collects every region's report over the mesh within statusWait.
func Ask(ctx context.Context, conn *nats.Conn) (map[string]Report, error) {
	return ask(ctx, conn, len(mesh.Regions()), statusWait)
}

// ask collects one report per region until want arrived or wait elapsed.
func ask(ctx context.Context, conn *nats.Conn, want int, wait time.Duration) (map[string]Report, error) {
	inbox := conn.NewRespInbox()
	sub, err := conn.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := conn.PublishRequest(protocol.MeshHealthSubject, inbox, nil); err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	reports := map[string]Report{}
	for len(reports) < want {
		m, err := sub.NextMsgWithContext(waitCtx)
		if err != nil {
			break
		}
		var report Report
		if protocol.DecodeTolerant(m.Data, &report, maxReply) == nil {
			reports[report.Region] = report
		}
	}
	return reports, ctx.Err()
}

// write prints one line per region and fails when any is not ok.
func write(output io.Writer, regions []string, reports map[string]Report) error {
	var bad []string
	for _, region := range regions {
		line := region + ": unreachable"
		report, ok := reports[region]
		if ok {
			line = region + ": " + report.State
			if len(report.Reasons) != 0 {
				line += " (" + strings.Join(report.Reasons, "; ") + ")"
			}
		}
		if !ok || report.State != StateOK {
			bad = append(bad, region)
		}
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
	}
	if len(bad) != 0 {
		return fmt.Errorf("not ok: %s", strings.Join(bad, ", "))
	}
	return nil
}

// RunCLI is `ts-orch status`: every region's health over the mesh, or this
// host's as `local` when it has no mesh.
func RunCLI(ctx context.Context, args []string, state string, output io.Writer) error {
	if len(args) != 0 {
		_, err := io.WriteString(output, "usage:\n  ts-orch status\n")
		if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
			return err
		}
		return errors.Join(err, errors.New("status accepts no arguments"))
	}
	conn, err := mesh.Connect(state)
	if errors.Is(err, fs.ErrNotExist) {
		return write(output, []string{"local"}, map[string]Report{"local": check(ctx, state)})
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	regions := mesh.Regions()
	reports, err := ask(ctx, conn, len(regions), statusWait)
	if err != nil {
		return err
	}
	return write(output, regions, reports)
}
