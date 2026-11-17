package regionhealth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

type Reconcile struct {
	Region string                   `json:"region"`
	Error  string                   `json:"error,omitempty"`
	Kinds  []ociresource.KindStatus `json:"kinds,omitempty"`
}

func ServeReconcile(ctx context.Context, state string, latest func() (Reconcile, bool)) {
	tick := time.NewTicker(checkEvery)
	defer tick.Stop()
	var conn *nats.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	for {
		if conn == nil || conn.IsClosed() {
			if conn, _ = mesh.Connect(state); conn != nil {
				if err := serveReconcile(conn, latest); err != nil {
					slog.WarnContext(ctx, "OCI reconcile status responder failed", "error", err)
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

func serveReconcile(conn *nats.Conn, latest func() (Reconcile, bool)) error {
	region, _, _ := strings.Cut(conn.ConnectedServerName(), ".")
	if region == "" {
		return errors.New("mesh server has no region identity")
	}
	if _, err := conn.Subscribe(protocol.MeshReconcileSubject, func(m *nats.Msg) {
		report, leader := latest()
		if !leader {
			return
		}
		report.Region = region
		data, err := protocol.EncodeJSON(report)
		if err == nil {
			err = m.Respond(data)
		}
		if err != nil {
			slog.Warn("OCI reconcile status reply failed", "error", err)
		}
	}); err != nil {
		return err
	}
	return conn.Flush()
}

func askReconcile(ctx context.Context, conn *nats.Conn) (map[string]Reconcile, error) {
	return collect(ctx, conn, protocol.MeshReconcileSubject, len(mesh.Regions()), statusWait, func(r Reconcile) string { return r.Region })
}

func (r Reconcile) lines() []string {
	if r.Error != "" {
		return []string{"reconcile: changes nothing: " + r.Error}
	}
	var out []string
	for _, k := range r.Kinds {
		line := fmt.Sprintf("reconcile %s: %s", k.Kind, k.Result)
		if !k.LastRun.IsZero() {
			line += fmt.Sprintf("; last run %s (%s, %d changes)", k.LastRun.UTC().Format(time.RFC3339), k.Duration.Round(time.Millisecond), k.Changes)
		}
		if !k.LastSuccess.IsZero() {
			line += "; last success " + k.LastSuccess.UTC().Format(time.RFC3339)
		}
		line += fmt.Sprintf("; %d errors", k.Errors)
		if k.Running {
			line += "; running"
		}
		out = append(out, line)
	}
	return out
}

func PrintReconcile(ctx context.Context, state string, output io.Writer) error {
	conn, err := mesh.Connect(state)
	if err != nil {
		_, err := fmt.Fprintf(output, "reconcile loop: not visible here (%v); ts-orch status on a node shows each region leader's last result per kind\n", err)
		return err
	}
	defer conn.Close()
	results, err := askReconcile(ctx, conn)
	if err != nil {
		return err
	}
	for _, region := range mesh.Regions() {
		result, ok := results[region]
		lines := result.lines()
		if !ok {
			lines = []string{"reconcile: no leader answered"}
		}
		for _, line := range lines {
			if _, err := fmt.Fprintf(output, "%s %s\n", region, line); err != nil {
				return err
			}
		}
	}
	return nil
}
