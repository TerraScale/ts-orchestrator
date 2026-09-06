package placementpublisher

import (
	"context"
	"encoding/json/v2"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func AcceptedHostSubject(identity string) (string, error) {
	subject, err := HostSubject(identity)
	if err != nil {
		return "", err
	}
	return subject[:len(subject)-len("stage")] + "accept", nil
}

type AcceptanceTarget interface {
	Accept(context.Context, string, *pb.PlacementControlServiceAcceptRequest) (*pb.PlacementControlServiceAcceptResponse, error)
	Principal() string
	ServerIdentity() string
}
type acceptanceDispatch struct {
	OperationID, ServerIdentity, Principal string
	Request                                []byte
}

func (target *RemoteTarget) Accept(ctx context.Context, id string, request *pb.PlacementControlServiceAcceptRequest) (*pb.PlacementControlServiceAcceptResponse, error) {
	expected, err := tbep.AcceptanceBinding(id, request)
	if err != nil {
		return nil, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(acceptanceDispatch{OperationID: id, ServerIdentity: target.serverIdentity, Principal: target.principal, Request: encoded})
	if err != nil || len(payload) > maximumDispatchBytes {
		return nil, ErrInvalidConfig
	}
	subject, err := AcceptedHostSubject(target.serverIdentity)
	if err != nil {
		return nil, err
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
		return nil, status.Error(codes.Code(reply.Code), "host refused accepted placement proof")
	}
	receipt := new(pb.PlacementControlServiceAcceptResponse)
	if proto.Unmarshal(reply.Receipt, receipt) != nil {
		return nil, ErrInvalidConfig
	}
	if err := tbep.ValidateAcceptanceReceipt(receipt, expected); err != nil {
		return nil, err
	}
	return receipt, nil
}

type AcceptanceHostBridge struct {
	cancel       context.CancelFunc
	subscription *nats.Subscription
	done         chan struct{}
	once         sync.Once
}

func StartAcceptanceHostBridge(ctx context.Context, connection *nats.Conn, target AcceptanceTarget) (*AcceptanceHostBridge, error) {
	if ctx == nil || !authenticatedConnection(connection) || target == nil || !validIdentity(target.Principal()) {
		return nil, ErrInvalidConfig
	}
	subject, err := AcceptedHostSubject(target.ServerIdentity())
	if err != nil {
		return nil, err
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
		return nil, errors.New("placement publisher: accepted proof subscription denied")
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
			if len(message.Data) <= maximumDispatchBytes && json.Unmarshal(message.Data, &dispatch, json.RejectUnknownMembers(true)) == nil && dispatch.ServerIdentity == target.ServerIdentity() && dispatch.Principal == target.Principal() {
				request := new(pb.PlacementControlServiceAcceptRequest)
				if proto.Unmarshal(dispatch.Request, request) == nil {
					expected, err := tbep.AcceptanceBinding(dispatch.OperationID, request)
					if err == nil {
						bounded, cancel := context.WithTimeout(lifetime, time.Minute)
						receipt, err := target.Accept(bounded, dispatch.OperationID, request)
						cancel()
						if err != nil {
							reply.Code = int32(status.Code(err))
						} else if tbep.ValidateAcceptanceReceipt(receipt, expected) == nil {
							reply.Receipt, err = (proto.MarshalOptions{Deterministic: true}).Marshal(receipt)
							if err == nil {
								reply.Code = 0
							}
						}
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
func (bridge *AcceptanceHostBridge) Completion() <-chan struct{} { return bridge.done }
func (bridge *AcceptanceHostBridge) Close() error {
	if bridge == nil {
		return nil
	}
	bridge.once.Do(func() { bridge.cancel(); _ = bridge.subscription.Unsubscribe() })
	<-bridge.done
	return nil
}

var _ AcceptanceTarget = (*RemoteTarget)(nil)
