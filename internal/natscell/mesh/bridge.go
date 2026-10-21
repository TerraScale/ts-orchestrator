package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

// Bridge serves the multi-region workflow's ts.release.mesh.* requests
// (releasepush.Handler.Mesh) on this host's mesh node, as the root CLI does.
func Bridge(state string) func(ctx context.Context, op string, spec json.RawMessage) (json.RawMessage, error) {
	return func(ctx context.Context, op string, spec json.RawMessage) (json.RawMessage, error) {
		conn, err := Connect(state)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		return bridge(ctx, conn, op, spec)
	}
}

// bridge returns the rows as JSON together with the failure, so CI sees
// which regions answered.
func bridge(ctx context.Context, conn *nats.Conn, op string, spec json.RawMessage) (json.RawMessage, error) {
	var rows []Reply
	var failed error
	switch op {
	case "ping":
		rows, failed = ping(ctx, conn, 5*time.Second)
	case "apply":
		var service swarmruntime.ServiceSpec
		if err := protocol.DecodeStrict(spec, &service, 64<<10); err != nil {
			return nil, err
		}
		// Shorter than the release handler's 2 min, so a missing region still yields rows.
		rows, failed = applySpec(ctx, conn, service, applyWait-5*time.Second)
	default:
		return nil, errors.New("unknown mesh request " + op)
	}
	if rows == nil {
		return nil, failed
	}
	data, err := protocol.EncodeJSON(rows)
	return data, errors.Join(failed, err)
}
