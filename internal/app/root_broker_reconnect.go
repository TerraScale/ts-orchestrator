package app

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
)

type rootBrokerReconnectResponse struct {
	Count int    `json:"count"`
	Error string `json:"error,omitzero"`
}

func (broker *rootBrokerRuntime) serveReconnect(parent context.Context, conn *net.UnixConn) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	peer, err := nativerootoci.PeerCredential(conn)
	if err != nil {
		return
	}
	lease, err := broker.authority.authorizeRuntime(ctx, peer)
	if err != nil {
		return
	}
	ctx, cancelLease := context.WithDeadline(ctx, lease.Deadline)
	defer cancelLease()
	stopLease := context.AfterFunc(lease.Context, cancelLease)
	defer stopLease()
	ctx, cancelOriginal := broker.operationContext(ctx)
	defer cancelOriginal()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return
	}
	closeBound := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer closeBound()
	wire, err := nativerootoci.ReadBoundedFrame(conn, nativerootoci.MaxFrameBytes)
	if err != nil || !bytes.Equal(wire, []byte("{}")) {
		return
	}
	stopPeer := watchRootBrokerPeer(conn, cancel)
	defer stopPeer()
	guard := func() error {
		if ctx.Err() != nil || lease.Context.Err() != nil || broker.guard(ctx) != nil {
			return rootoci.ErrUnauthorized
		}
		current, err := broker.authority.authorizeRuntime(ctx, peer)
		if err != nil || current.Context != lease.Context || current.Deadline != lease.Deadline || current.Binding != lease.Binding {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	if guard() != nil {
		return
	}
	account, err := broker.runtime.ReadControllerAccount(ctx)
	if err != nil || account.Account != broker.runtime.CellAccount() || guard() != nil {
		return
	}
	count, err := broker.runtime.ReconnectInterRegion(ctx)
	response := rootBrokerReconnectResponse{Count: count}
	if err != nil {
		response.Error = rootBrokerErrorCode(err)
	}
	current, readErr := broker.runtime.ReadControllerAccount(ctx)
	if readErr != nil || current.Account != account.Account || current.JWT != account.JWT || guard() != nil {
		return
	}
	wire, err = json.Marshal(response)
	if err == nil && guard() == nil {
		_ = nativerootoci.WriteBoundedFrame(conn, wire, nativerootoci.MaxFrameBytes)
	}
}

func reconnectRootBroker(parent context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	connection, err := new(net.Dialer).DialContext(ctx, "unix", rootBrokerReconnectSocket)
	if err != nil {
		return 0, err
	}
	defer connection.Close()
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, rootoci.ErrUnauthorized
	}
	peer, err := rootociwire.PeerCredential(conn)
	if err != nil || peer.UID != 0 || peer.GID != 0 {
		return 0, rootoci.ErrUnauthorized
	}
	binding, err := rootBrokerPeerBinding(conn, rootBrokerReconnectSocket)
	if err != nil {
		return 0, err
	}
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return 0, rootoci.ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if rootociwire.WriteBoundedFrame(conn, []byte("{}"), rootBrokerObservationMaxFrame) != nil {
		return 0, rootoci.ErrUnavailable
	}
	wire, err := rootociwire.ReadBoundedFrame(conn, rootBrokerObservationMaxFrame)
	if err != nil {
		return 0, err
	}
	response, err := decodeRootBrokerReconnectResponse(wire)
	if err != nil {
		return 0, err
	}
	current, err := rootBrokerPeerBinding(conn, rootBrokerReconnectSocket)
	if err != nil || current != binding || ctx.Err() != nil {
		return 0, rootoci.ErrUnauthorized
	}
	if response.Error != "" {
		return response.Count, rootoci.ErrUnavailable
	}
	return response.Count, nil
}

func decodeRootBrokerReconnectResponse(wire []byte) (rootBrokerReconnectResponse, error) {
	var fields map[string]jsontext.Value
	if json.Unmarshal(wire, &fields) != nil || len(fields) < 1 || len(fields) > 2 {
		return rootBrokerReconnectResponse{}, rootoci.ErrUnavailable
	}
	count, found := fields["count"]
	if !found || bytes.Equal(count, []byte("null")) {
		return rootBrokerReconnectResponse{}, rootoci.ErrUnavailable
	}
	var response rootBrokerReconnectResponse
	if json.Unmarshal(wire, &response, json.RejectUnknownMembers(true)) != nil || response.Count < 0 {
		return rootBrokerReconnectResponse{}, rootoci.ErrUnavailable
	}
	if _, found := fields["error"]; found && response.Error == "" {
		return rootBrokerReconnectResponse{}, rootoci.ErrUnavailable
	}
	return response, nil
}
