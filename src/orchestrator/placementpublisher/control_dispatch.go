package placementpublisher

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func DrainHostSubject(identity string) (string, error) {
	subject, err := HostSubject(identity)
	if err != nil {
		return "", err
	}
	return subject[:len(subject)-len("stage")] + "drain", nil
}

type DrainTarget interface {
	Drain(context.Context, string, *pb.PlacementDrainRequest) (*pb.PlacementDrainResponse, error)
	Principal() string
	ServerIdentity() string
}

func (target *RemoteTarget) controlRequest(ctx context.Context, subject, id string, request proto.Message) ([]byte, error) {
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(acceptanceDispatch{OperationID: id, ServerIdentity: target.serverIdentity, Principal: target.principal, Request: raw})
	if err != nil || len(payload) > maximumDispatchBytes {
		return nil, ErrInvalidConfig
	}
	ctx, cancel := context.WithTimeout(ctx, target.timeout)
	defer cancel()
	message, err := target.connection.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return nil, err
	}
	if message == nil || len(message.Data) > maximumDispatchBytes {
		return nil, ErrInvalidConfig
	}
	var reply dispatchReply
	if json.Unmarshal(message.Data, &reply, json.RejectUnknownMembers(true)) != nil {
		return nil, ErrInvalidConfig
	}
	if reply.Code != 0 {
		if reply.Code < 1 || reply.Code > 16 || len(reply.Receipt) != 0 {
			return nil, ErrInvalidConfig
		}
		return nil, status.Error(codes.Code(reply.Code), "host control request refused")
	}
	return reply.Receipt, nil
}
func (target *RemoteTarget) Drain(ctx context.Context, id string, request *pb.PlacementDrainRequest) (*pb.PlacementDrainResponse, error) {
	prepared, err := tbep.DrainBinding(id, request)
	if err != nil {
		return nil, err
	}
	subject, err := DrainHostSubject(target.serverIdentity)
	if err != nil {
		return nil, err
	}
	raw, err := target.controlRequest(ctx, subject, id, request)
	if err != nil {
		return nil, err
	}
	response := new(pb.PlacementDrainResponse)
	if proto.Unmarshal(raw, response) != nil {
		return nil, ErrInvalidConfig
	}
	if err := tbep.ValidateDrainReceipt(response, prepared, target.serverIdentity); err != nil {
		return nil, err
	}
	return response, nil
}

// startControlBridge supplies bounded exact-host dispatch for signed fence and
// signed readiness exchanges. It never interprets missing evidence as success.
func startControlBridge(ctx context.Context, connection *nats.Conn, subject, identity, principal string, handle func(context.Context, string, []byte) (proto.Message, error)) (*AcceptanceHostBridge, error) {
	if ctx == nil || !authenticatedConnection(connection) || !validIdentity(identity) || !validIdentity(principal) || handle == nil {
		return nil, ErrInvalidConfig
	}
	subscription, err := connection.SubscribeSync(subject)
	if err != nil {
		return nil, err
	}
	if err := subscription.SetPendingLimits(8, 2*maximumDispatchBytes); err != nil {
		subscription.Unsubscribe()
		return nil, err
	}
	if err := connection.FlushWithContext(ctx); err != nil {
		subscription.Unsubscribe()
		return nil, err
	}
	if connection.LastError() != nil {
		subscription.Unsubscribe()
		return nil, errors.New("placement publisher: control subscription denied")
	}
	lifetime, cancel := context.WithCancel(ctx)
	bridge := &AcceptanceHostBridge{cancel: cancel, subscription: subscription, done: make(chan struct{})}
	go func() {
		defer close(bridge.done)
		defer subscription.Unsubscribe()
		for lifetime.Err() == nil {
			message, err := subscription.NextMsgWithContext(lifetime)
			if err != nil {
				return
			}
			reply := dispatchReply{Code: int32(codes.InvalidArgument)}
			var dispatch acceptanceDispatch
			if len(message.Data) <= maximumDispatchBytes && json.Unmarshal(message.Data, &dispatch, json.RejectUnknownMembers(true)) == nil && dispatch.ServerIdentity == identity && dispatch.Principal == principal {
				bounded, cancel := context.WithTimeout(lifetime, time.Minute)
				result, err := handle(bounded, dispatch.OperationID, dispatch.Request)
				cancel()
				if err != nil {
					reply.Code = int32(status.Code(err))
				} else if result != nil {
					reply.Receipt, err = (proto.MarshalOptions{Deterministic: true}).Marshal(result)
					if err == nil {
						reply.Code = 0
					}
				}
			}
			payload, err := json.Marshal(reply)
			if err == nil && message.Reply != "" && len(payload) <= maximumDispatchBytes {
				_ = message.Respond(payload)
			}
		}
	}()
	return bridge, nil
}
func StartDrainHostBridge(ctx context.Context, connection *nats.Conn, target DrainTarget) (*AcceptanceHostBridge, error) {
	if target == nil {
		return nil, ErrInvalidConfig
	}
	subject, err := DrainHostSubject(target.ServerIdentity())
	if err != nil {
		return nil, err
	}
	return startControlBridge(ctx, connection, subject, target.ServerIdentity(), target.Principal(), func(ctx context.Context, id string, raw []byte) (proto.Message, error) {
		request := new(pb.PlacementDrainRequest)
		if proto.Unmarshal(raw, request) != nil {
			return nil, ErrInvalidConfig
		}
		prepared, err := tbep.DrainBinding(id, request)
		if err != nil {
			return nil, err
		}
		receipt, err := target.Drain(ctx, id, request)
		if err != nil {
			return nil, err
		}
		if err := tbep.ValidateDrainReceipt(receipt, prepared, target.ServerIdentity()); err != nil {
			return nil, err
		}
		return receipt, nil
	})
}
