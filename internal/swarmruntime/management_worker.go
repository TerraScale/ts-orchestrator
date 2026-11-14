//go:build linux

package swarmruntime

import (
	"context"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const workerPrepareMethod = "/terrascale.swarmruntime.WorkerManagement/Prepare"
const workerAdmitMethod = "/terrascale.swarmruntime.WorkerManagement/Admit"
const workerAuditMethod = "/terrascale.swarmruntime.WorkerManagement/Audit"
const workerReadMembershipMethod = "/terrascale.swarmruntime.WorkerManagement/ReadMembership"

type workerMembershipRequest struct {
	NodeID string `json:"node_id"`
}

type workerAdmitRequest struct {
	Query   WorkerRegistrationQuery     `json:"query"`
	Binding hostenroll.SwarmNodeBinding `json:"binding"`
}

type workerManagementRPC interface {
	Prepare(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	Admit(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	Audit(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	ReadMembership(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
}
type workerManagementServer struct{ node *Node }

func (s *workerManagementServer) Prepare(ctx context.Context, request *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	var query WorkerRegistrationQuery
	if err := protocol.DecodeStrict(request.Value, &query, 128<<10); err != nil {
		return nil, denied()
	}
	if query.Swarm != nil {
		return nil, denied()
	}
	wire, err := s.node.PrepareEnrolledWorker(ctx, query)
	if err != nil {
		return nil, err
	}
	return &wrapperspb.BytesValue{Value: wire}, nil
}
func (s *workerManagementServer) Admit(ctx context.Context, request *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	var admission workerAdmitRequest
	if err := protocol.DecodeStrict(request.Value, &admission, 128<<10); err != nil {
		return nil, denied()
	}
	if admission.Query.Swarm != nil {
		return nil, denied()
	}
	if err := s.node.AdmitEnrolledWorker(ctx, admission.Query, admission.Binding); err != nil {
		return nil, err
	}
	return new(wrapperspb.BytesValue), nil
}
func (s *workerManagementServer) Audit(ctx context.Context, request *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	var query struct{}
	if err := protocol.DecodeStrict(request.Value, &query, 128<<10); err != nil {
		return nil, denied()
	}
	if err := s.node.AuditWorkerMembership(ctx); err != nil {
		return nil, err
	}
	return new(wrapperspb.BytesValue), nil
}
func (s *workerManagementServer) ReadMembership(ctx context.Context, request *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	var query workerMembershipRequest
	if err := protocol.DecodeStrict(request.Value, &query, 128<<10); err != nil {
		return nil, denied()
	}
	if len(query.NodeID) != 25 || strings.Trim(query.NodeID, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
		return nil, denied()
	}
	proof, err := s.node.ReadWorkerMembership(ctx, query.NodeID)
	if err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(proof.Info())
	if err != nil {
		return nil, err
	}
	return &wrapperspb.BytesValue{Value: wire}, nil
}
func registerWorkerManagement(server *grpc.Server, node *Node) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "terrascale.swarmruntime.WorkerManagement",
		HandlerType: (*workerManagementRPC)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Audit", Handler: func(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(wrapperspb.BytesValue)
				if err := decode(request); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, request any) (any, error) {
					return service.(workerManagementRPC).Audit(ctx, request.(*wrapperspb.BytesValue))
				}
				if interceptor == nil {
					return handler(ctx, request)
				}
				return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: service, FullMethod: workerAuditMethod}, handler)
			}},
			{MethodName: "ReadMembership", Handler: func(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(wrapperspb.BytesValue)
				if err := decode(request); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, request any) (any, error) {
					return service.(workerManagementRPC).ReadMembership(ctx, request.(*wrapperspb.BytesValue))
				}
				if interceptor == nil {
					return handler(ctx, request)
				}
				return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: service, FullMethod: workerReadMembershipMethod}, handler)
			}},
			{MethodName: "Prepare", Handler: func(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(wrapperspb.BytesValue)
				if err := decode(request); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, request any) (any, error) {
					return service.(workerManagementRPC).Prepare(ctx, request.(*wrapperspb.BytesValue))
				}
				if interceptor == nil {
					return handler(ctx, request)
				}
				return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: service, FullMethod: workerPrepareMethod}, handler)
			}},
			{MethodName: "Admit", Handler: func(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(wrapperspb.BytesValue)
				if err := decode(request); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, request any) (any, error) {
					return service.(workerManagementRPC).Admit(ctx, request.(*wrapperspb.BytesValue))
				}
				if interceptor == nil {
					return handler(ctx, request)
				}
				return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: service, FullMethod: workerAdmitMethod}, handler)
			}},
		},
	}, &workerManagementServer{node: node})
}
