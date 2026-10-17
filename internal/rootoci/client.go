package rootoci

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
)

type Client struct {
	expected      Expectations
	mu            sync.Mutex
	serverBinding string
	root          *rootClient
	closed        bool
	pin           rootociwire.Pin
}

type rootClient struct {
	service *Service
	call    Call
	cancel  context.CancelFunc
}

// RootClient retains this root process and the original finite bootstrap call.
// Domain backends still derive actual signed phase authority for every effect.
func (service *Service) RootClient(ctx context.Context) (*Client, error) {
	if service == nil || !validBackends(service.backends) {
		return nil, ErrInvalid
	}
	call, err := RootCall(ctx)
	if err != nil {
		return nil, err
	}
	witness, err := CaptureProcess(os.Getpid())
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithDeadline(ctx, call.Deadline())
	call.state.ctx = bounded
	call.state.witness = witness
	context.AfterFunc(bounded, func() { _ = witness.Close() })
	if call.Guard(bounded) != nil {
		cancel()
		return nil, ErrUnauthorized
	}
	client := &Client{root: &rootClient{service: service, call: call, cancel: cancel}}
	binding := fmt.Sprintf("%x", sha256.Sum256([]byte(witness.Binding()+"\x00"+call.SessionBindingSHA256())))
	client.pinServer(binding)
	return client, nil
}

func (client *Client) Close() error {
	if client == nil {
		return nil
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.closed = true
	_ = client.pin.Close()
	if client.root != nil {
		client.root.cancel()
	}
	return nil
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
	if client.isClosed() {
		return ErrUnauthorized
	}
	if client.root != nil {
		return client.invokeRoot(ctx, wireRequest{Version: 1, Operation: operation, Expected: client.expected, Payload: payload}, destination)
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
	if client.pin.Verify(socket) != nil {
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
	if client.pin.Verify(socket) != nil {
		return outcomeError(operation)
	}
	if err := statusError(response.Status); err != nil {
		return err
	}
	if len(response.Payload) == 0 || json.Unmarshal(response.Payload, destination, json.RejectUnknownMembers(true)) != nil {
		return outcomeError(operation)
	}
	if ctx.Err() != nil || client.isClosed() {
		return outcomeError(operation)
	}
	return nil
}

func (client *Client) pinServer(binding string) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return false
	}
	if client.serverBinding == "" {
		client.serverBinding = binding
	}
	return client.serverBinding == binding
}

func (client *Client) transportBinding() string {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return ""
	}
	if client.root == nil {
		return client.pin.Binding()
	}
	return client.serverBinding
}

func (client *Client) isClosed() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.closed
}

func (client *Client) invokeRoot(ctx context.Context, request wireRequest, destination any) error {
	root := client.root
	if root == nil || root.call.Guard(ctx) != nil || client.isClosed() {
		return ErrUnauthorized
	}
	bounded, cancel := context.WithDeadline(ctx, root.call.Deadline())
	defer cancel()
	stop := context.AfterFunc(root.call.state.ctx, cancel)
	defer stop()
	state := *root.call.state
	state.operation, state.expected = request.Operation, request.Expected
	call := Call{state: &state}
	if !root.service.validRequest(request) {
		return ErrInvalid
	}
	result, err := root.service.dispatch(bounded, call, request)
	if err != nil {
		if !request.Operation.observationOnly() {
			err = errors.Join(err, ErrOutcomeUnknown)
		}
		return statusError(errorStatus(err))
	}
	if call.Guard(bounded) != nil {
		if !request.Operation.observationOnly() {
			return errors.Join(ErrUnauthorized, ErrOutcomeUnknown)
		}
		return ErrUnauthorized
	}
	wire, err := json.Marshal(result)
	if err != nil || len(wire) > maxFrameBytes || json.Unmarshal(wire, destination, json.RejectUnknownMembers(true)) != nil {
		return outcomeError(request.Operation)
	}
	if call.Guard(bounded) != nil {
		if !request.Operation.observationOnly() {
			return errors.Join(ErrUnauthorized, ErrOutcomeUnknown)
		}
		return ErrUnauthorized
	}
	return nil
}

func outcomeError(operation Operation) error {
	if operation.observationOnly() {
		return ErrUnavailable
	}
	return errors.Join(ErrUnavailable, ErrOutcomeUnknown)
}
