package rootvolumeclient

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
)

var ErrUnverified = errors.New("retained volume lacks current authenticated root observation")

// Client has no selectable endpoint, SDK credentials or generic RPC method.
type Client struct {
	expected Expectations
	server   *rootociwire.Pin
}

func New(expected Expectations, server *rootociwire.Pin) (*Client, error) {
	if server == nil || expected.Cell != "" && !bounded(expected.Cell, 256) || expected.OperationID != "" && !bounded(expected.OperationID, 256) ||
		expected.GrantSHA256 != "" && !digest(expected.GrantSHA256) {
		return nil, ErrUnverified
	}
	return &Client{expected: expected, server: server}, nil
}

type wireRequest struct {
	Version   uint64         `json:"version"`
	Operation string         `json:"operation"`
	Expected  Expectations   `json:"expected"`
	Payload   jsontext.Value `json:"payload"`
}

type wireResponse struct {
	Version   uint64         `json:"version"`
	Operation string         `json:"operation"`
	Status    string         `json:"status"`
	Payload   jsontext.Value `json:"payload,omitempty"`
}

func (c *Client) invoke(parent context.Context, operation string, request, destination any) error {
	if c == nil || parent == nil || operation != InspectOperation && operation != TerminatedOperation {
		return ErrUnverified
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	payload, err := json.Marshal(request)
	if err != nil {
		return ErrUnverified
	}
	wire, err := json.Marshal(wireRequest{Version: 1, Operation: operation, Expected: c.expected, Payload: payload})
	if err != nil || len(wire) > 16<<10 {
		return ErrUnverified
	}
	connection, err := new(net.Dialer).DialContext(ctx, "unix", rootociwire.SocketPath)
	if err != nil {
		return ErrUnverified
	}
	defer connection.Close()
	socket, ok := connection.(*net.UnixConn)
	if !ok || c.server.Verify(socket) != nil {
		return ErrUnverified
	}
	deadline, _ := ctx.Deadline()
	if socket.SetDeadline(deadline) != nil {
		return ErrUnverified
	}
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	if rootociwire.WriteBoundedFrame(socket, wire, 16<<10) != nil {
		return ErrUnverified
	}
	reply, err := rootociwire.ReadBoundedFrame(socket, 16<<10)
	if err != nil || c.server.Verify(socket) != nil || ctx.Err() != nil {
		return ErrUnverified
	}
	var response wireResponse
	if json.Unmarshal(reply, &response, json.RejectUnknownMembers(true)) != nil || response.Version != 1 ||
		response.Operation != operation || response.Status != "ok" || len(response.Payload) == 0 ||
		json.Unmarshal(response.Payload, destination, json.RejectUnknownMembers(true)) != nil {
		return ErrUnverified
	}
	return nil
}

type VerifiedMount struct {
	view    MountObservation
	client  *Client
	binding string
}

func (c *Client) InspectVolumeMount(ctx context.Context, request InspectRequest) (VerifiedMount, error) {
	if !request.Valid() || request.Original != nil {
		return VerifiedMount{}, ErrUnverified
	}
	view, err := c.mount(ctx, request)
	if err != nil {
		return VerifiedMount{}, err
	}
	return VerifiedMount{view: view, client: c, binding: c.server.Binding()}, nil
}

func (c *Client) mount(ctx context.Context, request InspectRequest) (MountObservation, error) {
	var view MountObservation
	if err := c.invoke(ctx, InspectOperation, request, &view); err != nil {
		return view, err
	}
	if !view.valid(time.Now()) || view.Pins != request.Pins || view.PredecessorID != request.PredecessorID ||
		request.Original != nil && view.Authority != *request.Original ||
		c.expected.GrantSHA256 != "" && view.Authority.GrantSHA256 != c.expected.GrantSHA256 {
		return MountObservation{}, ErrUnverified
	}
	return view, nil
}

func (p VerifiedMount) View() MountObservation { return p.view }
func (p VerifiedMount) IsVerified() bool {
	return p.client != nil && p.binding != "" && p.client.server.Binding() == p.binding && p.view.valid(time.Now())
}
func (p VerifiedMount) Revalidate(ctx context.Context) error {
	if ctx == nil || !p.IsVerified() {
		return ErrUnverified
	}
	ctx, cancel := context.WithDeadline(ctx, p.view.Authority.Deadline)
	defer cancel()
	current, err := p.client.mount(ctx, InspectRequest{Pins: p.view.Pins, PredecessorID: p.view.PredecessorID, Original: &p.view.Authority})
	if err != nil {
		return err
	}
	if !p.IsVerified() || current.BootDescriptorSHA256 != p.view.BootDescriptorSHA256 {
		return ErrUnverified
	}
	return nil
}

type VerifiedTerminated struct {
	view    TerminatedObservation
	client  *Client
	binding string
}

func (c *Client) ObserveTerminatedInstance(ctx context.Context, request TerminatedRequest) (VerifiedTerminated, error) {
	if !request.Valid() || request.Original != nil {
		return VerifiedTerminated{}, ErrUnverified
	}
	view, err := c.terminated(ctx, request)
	if err != nil {
		return VerifiedTerminated{}, err
	}
	return VerifiedTerminated{view: view, client: c, binding: c.server.Binding()}, nil
}

func (c *Client) terminated(ctx context.Context, request TerminatedRequest) (TerminatedObservation, error) {
	var view TerminatedObservation
	if err := c.invoke(ctx, TerminatedOperation, request, &view); err != nil {
		return view, err
	}
	if !view.valid(time.Now()) || view.InstanceID != request.InstanceID ||
		request.Original != nil && view.Authority != *request.Original ||
		c.expected.Cell != "" && view.Region != c.expected.Cell ||
		c.expected.GrantSHA256 != "" && view.Authority.GrantSHA256 != c.expected.GrantSHA256 {
		return TerminatedObservation{}, ErrUnverified
	}
	return view, nil
}

func (p VerifiedTerminated) View() TerminatedObservation { return p.view }
func (p VerifiedTerminated) IsVerified() bool {
	return p.client != nil && p.binding != "" && p.client.server.Binding() == p.binding && p.view.valid(time.Now())
}
func (p VerifiedTerminated) Revalidate(ctx context.Context) error {
	if ctx == nil || !p.IsVerified() {
		return ErrUnverified
	}
	ctx, cancel := context.WithDeadline(ctx, p.view.Authority.Deadline)
	defer cancel()
	current, err := p.client.terminated(ctx, TerminatedRequest{InstanceID: p.view.InstanceID, Original: &p.view.Authority})
	if err != nil {
		return err
	}
	current.ObservedAt = p.view.ObservedAt
	if !p.IsVerified() || current != p.view {
		return ErrUnverified
	}
	return nil
}
