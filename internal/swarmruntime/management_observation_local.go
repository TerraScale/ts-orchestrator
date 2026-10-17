//go:build linux

package swarmruntime

import (
	"context"
	"crypto/rand"
	"errors"
	"io"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type localManagementObservationSource struct {
	server   *managementObservationServer
	validate func(context.Context) error
}

// LocalManagementObservation exposes scoped read-only history to the privileged
// local manager owner, like ControlClient. It is not Unix socket authentication.
func (n *Node) LocalManagementObservation(ctx context.Context, environment string) (ManagementObservationClient, error) {
	if n == nil || environment == "" {
		return ManagementObservationClient{}, errors.New("local observation requires a manager and environment")
	}
	client, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return ManagementObservationClient{}, err
	}
	region := n.admission.Region
	validate := func(ctx context.Context) error {
		_, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: n.ID()})
		return err
	}
	return ManagementObservationClient{local: &localManagementObservationSource{
		server:   &managementObservationServer{node: n, scope: &managementServer{region: region, environment: environment}, epoch: rand.Text()},
		validate: validate,
	}}, nil
}

type localManagementObservationStream struct {
	ctx      context.Context
	messages chan *wrapperspb.BytesValue
	done     chan struct{}
	err      error
}

func (s *localManagementObservationStream) RecvMsg(message any) error {
	encoded, ok := message.(*wrapperspb.BytesValue)
	if !ok {
		return errors.New("invalid local observation receiver")
	}
	finished := func() error {
		if s.err != nil {
			return s.err
		}
		return io.EOF
	}
	select {
	case <-s.done:
		return finished()
	default:
	}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case <-s.done:
		return finished()
	case value := <-s.messages:
		select {
		case <-s.done:
			return finished()
		default:
		}
		encoded.Value = value.Value
		return nil
	}
}

func (c ManagementObservationClient) observeLocal(ctx context.Context, resume *ManagementObservationCursor) (*ManagementObservationStream, error) {
	if err := c.local.validate(ctx); err != nil {
		return nil, err
	}
	request := observationRequest{}
	if resume != nil {
		request.Resume = new(*resume)
	}
	sourceCtx, cancel := context.WithCancel(ctx)
	local := &localManagementObservationStream{ctx: ctx, messages: make(chan *wrapperspb.BytesValue, 1), done: make(chan struct{})}
	go func() {
		defer cancel()
		local.err = c.local.server.observeSource(sourceCtx, request, c.local.validate, func(message *wrapperspb.BytesValue) error {
			select {
			case local.messages <- message:
				return nil
			case <-sourceCtx.Done():
				return sourceCtx.Err()
			}
		})
		close(local.done)
	}()
	result := &ManagementObservationStream{stream: local}
	if resume != nil {
		result.last = request.Resume.Version
		result.expected = request.Resume
	}
	return result, nil
}
