package placementpublisher

import (
	"context"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func ReadinessHostSubject(identity string) (string, error) {
	subject, err := HostSubject(identity)
	if err != nil {
		return "", err
	}
	return subject[:len(subject)-len("stage")] + "readiness", nil
}

type ReadinessTarget interface {
	Readiness(context.Context, *pb.PlacementControlServiceReadinessRequest) (*pb.PlacementControlServiceReadinessResponse, error)
	Principal() string
	ServerIdentity() string
}

func (target *RemoteTarget) Readiness(ctx context.Context, request *pb.PlacementControlServiceReadinessRequest) (*pb.PlacementControlServiceReadinessResponse, error) {
	if err := tbep.ValidateReadinessRequest(request); err != nil {
		return nil, err
	}
	subject, err := ReadinessHostSubject(target.serverIdentity)
	if err != nil {
		return nil, err
	}
	raw, err := target.controlRequest(ctx, subject, request.OperationId, request)
	if err != nil {
		return nil, err
	}
	response := new(pb.PlacementControlServiceReadinessResponse)
	if proto.Unmarshal(raw, response) != nil {
		return nil, ErrInvalidConfig
	}
	if err := tbep.ValidateReadinessEnvelope(response); err != nil {
		return nil, err
	}
	return response, nil
}
func StartReadinessHostBridge(ctx context.Context, connection *nats.Conn, target ReadinessTarget) (*AcceptanceHostBridge, error) {
	if target == nil {
		return nil, ErrInvalidConfig
	}
	subject, err := ReadinessHostSubject(target.ServerIdentity())
	if err != nil {
		return nil, err
	}
	return startControlBridge(ctx, connection, subject, target.ServerIdentity(), target.Principal(), func(ctx context.Context, id string, raw []byte) (proto.Message, error) {
		request := new(pb.PlacementControlServiceReadinessRequest)
		if proto.Unmarshal(raw, request) != nil || id != request.OperationId {
			return nil, ErrInvalidConfig
		}
		if err := tbep.ValidateReadinessRequest(request); err != nil {
			return nil, err
		}
		response, err := target.Readiness(ctx, request)
		if err != nil {
			return nil, err
		}
		if err := tbep.ValidateReadinessEnvelope(response); err != nil {
			return nil, err
		}
		return response, nil
	})
}
