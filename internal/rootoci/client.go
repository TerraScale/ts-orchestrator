package rootoci

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"golang.org/x/sys/unix"
)

type Client struct {
	expected      Expectations
	mu            sync.Mutex
	serverBinding string
}

func NewClient(expected Expectations) *Client { return &Client{expected: expected} }

func (client *Client) Inventory(ctx context.Context) (InventoryObservation, error) {
	var result InventoryObservation
	err := client.invoke(ctx, OperationInventory, struct{}{}, &result)
	return result, err
}
func (client *Client) ObserveLocalInstance(ctx context.Context) (bootstrapstart.InstanceObservation, error) {
	var result bootstrapstart.InstanceObservation
	err := client.invoke(ctx, OperationObserveLocalInstance, struct{}{}, &result)
	return result, err
}
func (client *Client) ObserveFleet(ctx context.Context) ([]oci.Instance, error) {
	var result []oci.Instance
	err := client.invoke(ctx, OperationObserveFleet, struct{}{}, &result)
	return result, err
}
func (client *Client) Costs(ctx context.Context) (ocicost.Report, error) {
	var result ocicost.Report
	err := client.invoke(ctx, OperationCosts, struct{}{}, &result)
	return result, err
}
func (client *Client) ObserveImage(ctx context.Context, request ImageRequest) (ImageObservation, error) {
	var result ImageObservation
	err := client.invoke(ctx, OperationObserveImage, request, &result)
	return result, err
}
func (client *Client) ReleaseChannel(ctx context.Context) (ChannelObservation, error) {
	var result ChannelObservation
	err := client.invoke(ctx, OperationReleaseChannel, struct{}{}, &result)
	return result, err
}
func (client *Client) ReconcileFoundation(ctx context.Context, request ReconcileFoundationRequest) (FoundationReceipt, error) {
	var result FoundationReceipt
	err := client.invoke(ctx, OperationReconcileFoundation, request, &result)
	return result, err
}
func (client *Client) EnsureSource(ctx context.Context, request SourceRequest) (SourceReceipt, error) {
	var result SourceReceipt
	err := client.invoke(ctx, OperationEnsureSource, request, &result)
	return result, err
}
func (client *Client) DeliverControllerGeneration(ctx context.Context, request DeliverControllerGenerationRequest) (SecretDeliveryReceipt, error) {
	var result SecretDeliveryReceipt
	err := client.invoke(ctx, OperationDeliverControllerGeneration, request, &result)
	return result, err
}

func (client *Client) AuthorizeNetBirdIntent(ctx context.Context, request NetBirdIntentRequest) (NetBirdIntentReceipt, error) {
	var result NetBirdIntentReceipt
	err := client.invoke(ctx, OperationAuthorizeNetBirdIntent, request, &result)
	return result, err
}

func (client *Client) invoke(parent context.Context, operation Operation, request, destination any) error {
	if client == nil || parent == nil || !validExpectations(client.expected) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	payload, err := json.Marshal(request)
	if err != nil {
		return ErrInvalid
	}
	wire, err := json.Marshal(wireRequest{Version: 1, Operation: operation, Expected: client.expected, Payload: payload})
	if err != nil || len(wire) > maxFrameBytes {
		return ErrInvalid
	}
	connection, err := new(net.Dialer).DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return ErrUnavailable
	}
	defer connection.Close()
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		return ErrUnauthorized
	}
	peer, err := nativerootoci.PeerCredential(socket)
	if err != nil || peer.UID != 0 || peer.GID != 0 || peer.PID < 2 {
		return ErrUnauthorized
	}
	binding, err := rootServerBinding(peer)
	if err != nil || !client.pinServer(binding) {
		return ErrUnauthorized
	}
	deadline, _ := ctx.Deadline()
	if socket.SetDeadline(deadline) != nil {
		return ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	if err := nativerootoci.WriteBoundedFrame(socket, wire, maxFrameBytes); err != nil {
		return outcomeError(operation)
	}
	reply, err := nativerootoci.ReadBoundedFrame(socket, maxFrameBytes)
	if err != nil {
		return outcomeError(operation)
	}
	var response wireResponse
	if json.Unmarshal(reply, &response, json.RejectUnknownMembers(true)) != nil || response.Version != 1 ||
		response.Operation != operation {
		return outcomeError(operation)
	}
	currentBinding, err := rootServerBinding(peer)
	if err != nil || currentBinding != binding {
		return outcomeError(operation)
	}
	if err := statusError(response.Status); err != nil {
		return err
	}
	if len(response.Payload) == 0 || json.Unmarshal(response.Payload, destination, json.RejectUnknownMembers(true)) != nil {
		return outcomeError(operation)
	}
	return nil
}

func (client *Client) pinServer(binding string) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.serverBinding == "" {
		client.serverBinding = binding
	}
	return client.serverBinding == binding
}

func (client *Client) transportBinding() string {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.serverBinding
}

func rootServerBinding(peer nativerootoci.Peer) (string, error) {
	for _, path := range []string{"/run", "/run/terrascale-orchestrator"} {
		var stat unix.Stat_t
		if unix.Lstat(path, &stat) != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
			return "", ErrUnauthorized
		}
	}
	var socket unix.Stat_t
	if unix.Lstat(SocketPath, &socket) != nil || socket.Uid != 0 || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Mode&0o7777 != 0o660 {
		return "", ErrUnauthorized
	}
	start, parent, cgroup, err := processKernelIdentity(peer.PID)
	if err != nil {
		return "", ErrUnauthorized
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%s:%d:%d:%d", peer.PID, start, cgroup, parent, socket.Dev, socket.Ino)))), nil
}

func outcomeError(operation Operation) error {
	if operation.ReadOnly() || operation == OperationObservePoolChild {
		return ErrUnavailable
	}
	return errors.Join(ErrUnavailable, ErrOutcomeUnknown)
}
