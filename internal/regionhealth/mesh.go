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
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
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
		report := releaseDegraded(check(ctx, state), state)
		report.Server = server
		hosts, err := HostVersions(ctx, state, "")
		report.Hosts = hosts
		if err != nil {
			report.HostError = "host revision inventory unavailable"
		}
		if err := report.readRollout(state); err != nil {
			slog.WarnContext(ctx, "pull rollout record unreadable", "error", err)
		}
		latest.Store(&report)
		if report.State != previous {
			slog.WarnContext(ctx, "region health changed", "from", previous, "to", report.State, "reasons", strings.Join(report.Reasons, "; "))
			previous = report.State
		}
		if conn == nil || conn.IsClosed() {
			// The mesh writes its token once it starts; until then this retries every tick.
			if conn, _ = mesh.Connect(state); conn != nil {
				if err := Serve(conn, func() Report { return *latest.Load() }); err != nil {
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

func Serve(conn *nats.Conn, latest func() Report) error {
	region, _, _ := strings.Cut(conn.ConnectedServerName(), ".")
	if region == "" {
		return errors.New("mesh server has no region identity")
	}
	_, err := conn.QueueSubscribe(protocol.MeshHealthSubject, region, func(m *nats.Msg) {
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

func ask(ctx context.Context, conn *nats.Conn, want int, wait time.Duration) (map[string]Report, error) {
	return collect(ctx, conn, protocol.MeshHealthSubject, want, wait, func(r Report) string { return r.Region })
}

func collect[T any](ctx context.Context, conn *nats.Conn, subject string, want int, wait time.Duration, region func(T) string) (map[string]T, error) {
	inbox := conn.NewRespInbox()
	sub, err := conn.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := conn.PublishRequest(subject, inbox, nil); err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	replies := map[string]T{}
	for len(replies) < want {
		m, err := sub.NextMsgWithContext(waitCtx)
		if err != nil {
			break
		}
		var reply T
		if protocol.DecodeTolerant(m.Data, &reply, maxReply) == nil {
			replies[region(reply)] = reply
		}
	}
	return replies, ctx.Err()
}

// write prints one line per region and fails when any is not ok.
func write(output io.Writer, regions []string, reports map[string]Report, reconcile map[string]Reconcile) error {
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
		if report.HostError != "" {
			line += "\n  " + report.HostError
		}
		if report.Rollout != nil {
			line += "\n  " + report.Rollout.String()
		}
		if result, ok := reconcile[region]; ok {
			for _, reconcile := range result.lines() {
				line += "\n  " + reconcile
			}
		}
		for _, host := range report.Hosts {
			line += fmt.Sprintf("\n  host %s: revision %s", host.Host, host.Version)
			if host.Refusal != nil {
				line += fmt.Sprintf("; refused %s run %s attempt %s: %s", host.Refusal.SHA, host.Refusal.RunID, host.Refusal.RunAttempt, host.Refusal.Reason)
			}
			if host.Error != "" {
				line += "; " + host.Error
			}
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
	if len(args) > 0 && args[0] == "revision" {
		return revisionCLI(ctx, args[1:], state, output)
	}
	if len(args) != 0 {
		_, err := io.WriteString(output, "usage:\n  ts-orch status\n  ts-orch status revision <published 40-hex revision>\n")
		if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
			return err
		}
		return errors.Join(err, errors.New("status accepts no arguments"))
	}
	conn, err := mesh.Connect(state)
	if errors.Is(err, fs.ErrNotExist) {
		report := releaseDegraded(check(ctx, state), state)
		report.Hosts, err = HostVersions(ctx, state, "")
		if err != nil {
			report.HostError = "host revision inventory unavailable"
		}
		if err := report.readRollout(state); err != nil {
			report.Reasons = append(report.Reasons, err.Error())
		}
		return write(output, []string{"local"}, map[string]Report{"local": report}, nil)
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
	reconcile, err := askReconcile(ctx, conn)
	if err != nil {
		return err
	}
	return write(output, regions, reports, reconcile)
}

func releaseDegraded(report Report, state string) Report {
	record, err := releasepush.ReadDegraded(state)
	if err != nil {
		report.Reasons = append(report.Reasons, "release degraded record unreadable: "+err.Error())
		return report
	}
	if record == nil {
		return report
	}
	for _, worker := range record.Skipped {
		report.Reasons = append(report.Reasons, fmt.Sprintf("release %s run %s skipped down worker %s: %s", record.SHA, record.RunID, worker.Host, worker.Reason))
	}
	if len(record.Skipped) != 0 && report.State == StateOK {
		report.State = StateDegraded
	}
	return report
}

func HostVersions(ctx context.Context, state, region string) ([]releasepush.HostVersion, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	control, close, err := swarmruntime.DialControl(state)
	if err != nil {
		return nil, err
	}
	defer close.Close()
	listed, err := control.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	conn, err := mesh.Connect(state)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if region == "" {
		region, _, _ = strings.Cut(conn.ConnectedServerName(), ".")
	}
	return releasepush.ReadHostVersions(ctx, conn, region, listed.Nodes), nil
}

func (r *Report) readRollout(state string) error {
	rollout, err := pullrelease.Read(state)
	r.Rollout = rollout
	if rollout != nil && rollout.Phase == pullrelease.PhaseStalled {
		r.Reasons = append(r.Reasons, rollout.Reason)
		if r.State == StateOK {
			r.State = StateDegraded
		}
	}
	return err
}
