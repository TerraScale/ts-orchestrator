package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

// TerraBaseInternalPort is TerraBase's private listener, bound only on this
// host's NetBird address; ts-auth and ts-dashboard reach it as
// http://127.0.0.1:8081, which this edge serves.
const TerraBaseInternalPort = 8081

var terrabaseLoopback = net.JoinHostPort("127.0.0.1", strconv.Itoa(TerraBaseInternalPort))

// terrabaseHandoffWait bounds a loopback dial across a TerraBase stop-first
// rollout, which has no other region to fail over to: on 2026-10-26 shutdown
// to ready took 21 s (gru), 24 s (sjc) and 30 s (fra); 60 s is 2x the slowest.
const terrabaseHandoffWait = 60 * time.Second

// terrabaseInternal is the address TerraBase's private listener binds.
func terrabaseInternal() (string, error) {
	ip, err := mesh.NetBirdAddress()
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip, strconv.Itoa(TerraBaseInternalPort)), nil
}

// terrabaseBindError names the host shortcut that held 127.0.0.1:8081 before
// ts-orch served it, so the operator knows what to remove.
func terrabaseBindError(err error) error {
	if !errors.Is(err, syscall.EADDRINUSE) {
		return err
	}
	return fmt.Errorf("%w: another process holds %s; if it is the fr1-terrabase-loopback host shortcut, run "+
		"`systemctl disable --now fr1-terrabase-loopback.socket fr1-terrabase-loopback.service` and delete both units; "+
		"ts-orch binds the port within 5 s", err, terrabaseLoopback)
}

// serveTerraBase relays each loopback connection to target. A dial during a
// TerraBase stop-first handoff waits up to wait for the new task (refused
// dials sent nothing, so retrying them is safe); past it the client is closed.
func serveTerraBase(ln net.Listener, target func() (string, error), wait time.Duration) error {
	slots := make(chan struct{}, maxPostgresConns)
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				relayTerraBase(conn, target, wait)
			}()
		default:
			conn.Close()
		}
	}
}

func relayTerraBase(client net.Conn, target func() (string, error), wait time.Duration) {
	defer client.Close()
	address, err := target()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	backend, err := dialHandoffWithin(ctx, "tcp", address, wait)
	cancel()
	if err != nil {
		return
	}
	defer backend.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(backend, client)
		closeWrite(backend)
		close(done)
	}()
	_, _ = io.Copy(client, backend)
	closeWrite(client)
	<-done
}

// closeWrite passes one side's EOF on while the other side may still answer.
func closeWrite(conn net.Conn) {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
}
