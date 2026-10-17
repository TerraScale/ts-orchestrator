package app

import (
	"context"
	"fmt"
	"net"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
)

const rootBrokerSourceSocket = "/run/terrascale-orchestrator/broker-source.sock"
const rootBrokerSourceMaxPreface = 256

type rootBrokerSourcePreface struct {
	Command     string `json:"command"`
	QuerySHA256 string `json:"query_sha256"`
}

func serveRootBrokerSourceTransport(parent context.Context, conn *net.UnixConn, registry *rootBrokerSourceChildren) {
	if parent == nil || parent.Err() != nil || conn == nil || registry == nil {
		return
	}
	child, err := registry.lookup(conn)
	if err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(parent, earlier(child.deadline, registry.deadline))
	defer cancel()
	stopChild := context.AfterFunc(child.ctx, cancel)
	defer stopChild()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil || child.guard(ctx) != nil {
		return
	}
	// Read exactly the bounded preface; following bytes belong to native NATS.
	wire, err := rootociwire.ReadBoundedFrame(conn, rootBrokerSourceMaxPreface)
	var preface rootBrokerSourcePreface
	if err != nil || protocol.DecodeStrict(wire, &preface, rootBrokerSourceMaxPreface) != nil ||
		preface.Command != child.command || preface.QuerySHA256 != fmt.Sprintf("%x", child.querySHA256) || child.guard(ctx) != nil {
		return
	}
	_ = child.servePublic(ctx, conn)
}
