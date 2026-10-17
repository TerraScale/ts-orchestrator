//go:build linux

package swarmruntime

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const managementObservationMethod = "/terrascale.swarmruntime.ManagementObservation/Observe"
const observationMessageLimit = 16 << 20

// ManagementObservationCursor names an actual applied transaction and its
// authenticated source lifetime. ServerEpoch only invalidates old sessions;
// continuity comes from complete Raft replay, never from this random identity.
type ManagementObservationCursor struct {
	Version     uint64 `json:"version"`
	NodeID      string `json:"node_id"`
	ClusterID   string `json:"cluster_id"`
	ServerEpoch string `json:"server_epoch"`
	Term        uint64 `json:"term"`
	Leader      uint64 `json:"leader"`
}

// ManagementObservationMessage has exactly one populated payload. A stream
// starts with Snapshot, replays transactions, sends ReplayThrough even when
// quiet, and then delivers live transactions. Any error invalidates continuity.
type ManagementObservationMessage struct {
	Cursor        ManagementObservationCursor
	Snapshot      *api.StoreSnapshot
	Transaction   *api.WatchMessage
	ReplayThrough *api.Version
}

type observationRequest struct {
	Resume *ManagementObservationCursor `json:"resume,omitempty"`
}

type observationWire struct {
	Cursor        ManagementObservationCursor `json:"cursor"`
	Snapshot      []byte                      `json:"snapshot,omitempty"`
	Transaction   []byte                      `json:"transaction,omitempty"`
	ReplayThrough *uint64                     `json:"replay_through,omitempty"`
}

type ManagementObservationClient struct {
	conn  *grpc.ClientConn
	local *localManagementObservationSource
}

type ManagementObservationStream struct {
	stream   interface{ RecvMsg(any) error }
	source   ManagementObservationCursor
	last     uint64
	through  uint64
	phase    uint8
	expected *ManagementObservationCursor
}

// DialManagementClients shares one authenticated Unix connection; its closer
// belongs to the caller. The old DialManagement API remains available.
func DialManagementClients(ctx context.Context, accepted bootstrapstart.AcceptedIdentity) (api.ControlClient, ManagementObservationClient, string, io.Closer, error) {
	binding, err := acceptedBinding(accepted)
	if err != nil {
		return nil, ManagementObservationClient{}, "", nil, err
	}
	control, id, conn, err := dialManagementAt(ctx, managementSocket, 0, binding)
	if err != nil {
		return nil, ManagementObservationClient{}, "", nil, err
	}
	return control, ManagementObservationClient{conn: conn}, id, conn, nil
}

func (c ManagementObservationClient) Observe(ctx context.Context, resume *ManagementObservationCursor) (*ManagementObservationStream, error) {
	if c.local != nil {
		return c.observeLocal(ctx, resume)
	}
	if c.conn == nil {
		return nil, errors.New("management observation connection unavailable")
	}
	wire, err := protocol.EncodeJSON(observationRequest{Resume: resume})
	if err != nil {
		return nil, err
	}
	stream, err := c.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, managementObservationMethod, grpc.MaxCallRecvMsgSize(observationMessageLimit))
	if err != nil {
		return nil, err
	}
	if err := stream.SendMsg(&wrapperspb.BytesValue{Value: wire}); err != nil {
		_ = stream.CloseSend()
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	result := &ManagementObservationStream{stream: stream}
	if resume != nil {
		result.last = resume.Version
		result.expected = new(*resume)
	}
	return result, nil
}

func sameObservationSource(a, b ManagementObservationCursor) bool {
	a.Version, b.Version = 0, 0
	return a == b
}

func (s *ManagementObservationStream) Recv() (ManagementObservationMessage, error) {
	var encoded wrapperspb.BytesValue
	if err := s.stream.RecvMsg(&encoded); err != nil {
		return ManagementObservationMessage{}, err
	}
	var wire observationWire
	if err := protocol.DecodeStrict(encoded.Value, &wire, observationMessageLimit); err != nil {
		return ManagementObservationMessage{}, err
	}
	result := ManagementObservationMessage{Cursor: wire.Cursor}
	if wire.Cursor.NodeID == "" || wire.Cursor.ClusterID == "" || wire.Cursor.ServerEpoch == "" || wire.Cursor.Term == 0 || wire.Cursor.Leader == 0 || wire.Cursor.Version == 0 {
		return result, errors.New("management observation has no exact source")
	}
	payloads := 0
	if len(wire.Snapshot) != 0 {
		payloads++
		result.Snapshot = new(api.StoreSnapshot)
		if err := result.Snapshot.Unmarshal(wire.Snapshot); err != nil {
			return result, err
		}
	}
	if len(wire.Transaction) != 0 {
		payloads++
		result.Transaction = new(api.WatchMessage)
		if err := result.Transaction.Unmarshal(wire.Transaction); err != nil {
			return result, err
		}
	}
	if wire.ReplayThrough != nil {
		payloads++
		result.ReplayThrough = &api.Version{Index: *wire.ReplayThrough}
	}
	if payloads != 1 || s.phase != 0 && !sameObservationSource(s.source, wire.Cursor) {
		return result, errors.New("management observation payload or source changed")
	}
	switch {
	case result.Snapshot != nil:
		if s.phase != 0 || wire.Cursor.Version < s.last || s.expected != nil && !sameObservationSource(*s.expected, wire.Cursor) {
			return result, errors.New("management observation snapshot is out of order")
		}
		s.source, s.through, s.phase = wire.Cursor, wire.Cursor.Version, 1
	case result.ReplayThrough != nil:
		if s.phase != 1 || result.ReplayThrough.Index != s.through || wire.Cursor.Version != s.through {
			return result, errors.New("management observation replay boundary is out of order")
		}
		s.last, s.phase = s.through, 2
	case result.Transaction != nil:
		version := result.Transaction.Version
		if s.phase == 0 || version == nil || version.Index != wire.Cursor.Version || version.Index <= s.last || s.phase == 1 && version.Index > s.through {
			return result, errors.New("management observation transaction is out of order")
		}
		s.last = version.Index
	}
	return result, nil
}

type guardedManagementStream struct {
	grpc.ServerStream
	validate func(context.Context) error
}

func (s guardedManagementStream) SendMsg(message any) error {
	if err := s.validate(s.Context()); err != nil {
		return err
	}
	if err := s.ServerStream.SendMsg(message); err != nil {
		return err
	}
	return s.validate(s.Context())
}

func (s guardedManagementStream) RecvMsg(message any) error {
	if err := s.validate(s.Context()); err != nil {
		return err
	}
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err
	}
	return s.validate(s.Context())
}

func managementStreamInterceptor(uid uint32, cgroup, binding string, refresh func(context.Context) error) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		validate := func(ctx context.Context) error {
			remote, ok := peer.FromContext(ctx)
			if !ok {
				return denied()
			}
			identity, ok := remote.AuthInfo.(unixPeer)
			incoming, _ := metadata.FromIncomingContext(ctx)
			if !ok || verifyPeer(identity, uid, cgroup) != nil || len(incoming.Get(managementBinding)) != 1 || incoming.Get(managementBinding)[0] != binding || refresh(ctx) != nil {
				return denied()
			}
			return nil
		}
		if info.FullMethod != managementObservationMethod {
			return denied()
		}
		if err := validate(stream.Context()); err != nil {
			return err
		}
		if err := handler(srv, guardedManagementStream{stream, validate}); err != nil {
			return status.Error(status.Code(err), "management observation unavailable")
		}
		return nil
	}
}

type managementObservationServer struct {
	node  *Node
	scope *managementServer
	epoch string
}

func registerManagementObservation(server *grpc.Server, node *Node, scope *managementServer) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "terrascale.swarmruntime.ManagementObservation",
		HandlerType: (*interface{ observationService() })(nil),
		Streams: []grpc.StreamDesc{{StreamName: "Observe", ServerStreams: true, Handler: func(srv any, stream grpc.ServerStream) error {
			return srv.(*managementObservationServer).observe(stream)
		}}},
	}, &managementObservationServer{node: node, scope: scope, epoch: rand.Text()})
}

func (*managementObservationServer) observationService() {}

func (s *managementObservationServer) visible(object *api.Object) bool {
	if object == nil {
		return false
	}
	switch {
	case object.GetNode() != nil, object.GetTask() != nil:
		return true
	case object.GetService() != nil:
		return s.scope.scoped(object.GetService().Spec.Annotations)
	case object.GetConfig() != nil:
		return s.scope.floor(&object.GetConfig().Spec)
	}
	return false
}

func (s *managementObservationServer) observe(stream grpc.ServerStream) error {
	guard, ok := stream.(guardedManagementStream)
	if !ok {
		return denied()
	}
	var input wrapperspb.BytesValue
	if err := stream.RecvMsg(&input); err != nil {
		return err
	}
	var request observationRequest
	if err := protocol.DecodeStrict(input.Value, &request, 64<<10); err != nil {
		return denied()
	}
	return s.observeSource(stream.Context(), request, guard.validate, func(message *wrapperspb.BytesValue) error { return stream.SendMsg(message) })
}

func (s *managementObservationServer) observeSource(ctx context.Context, request observationRequest, refresh func(context.Context) error, transmit func(*wrapperspb.BytesValue) error) error {
	manager := s.node.upstream.Manager()
	if manager == nil {
		return status.Error(codes.Unavailable, "manager unavailable")
	}
	var snapshot api.StoreSnapshot
	var clusterID string
	var from *api.Version
	if request.Resume != nil {
		if request.Resume.Version == 0 {
			return denied()
		}
		from = &api.Version{Index: request.Resume.Version}
	}
	observed, err := manager.Observe(from, func(tx store.ReadTx) error {
		var err error
		if snapshot.Nodes, err = store.FindNodes(tx, store.All); err != nil {
			return err
		}
		if snapshot.Tasks, err = store.FindTasks(tx, store.All); err != nil {
			return err
		}
		services, err := store.FindServices(tx, store.All)
		if err != nil {
			return err
		}
		for _, service := range services {
			if s.scope.scoped(service.Spec.Annotations) {
				snapshot.Services = append(snapshot.Services, service)
			}
		}
		configs, err := store.FindConfigs(tx, store.All)
		if err != nil {
			return err
		}
		for _, config := range configs {
			if s.scope.floor(&config.Spec) {
				snapshot.Configs = append(snapshot.Configs, config)
			}
		}
		clusters, err := store.FindClusters(tx, store.All)
		if err != nil || len(clusters) != 1 {
			return errors.New("observation requires one current cluster")
		}
		clusterID = clusters[0].ID
		return nil
	}, api.EventCreateNode{}, api.EventUpdateNode{}, api.EventDeleteNode{}, api.EventCreateTask{}, api.EventUpdateTask{}, api.EventDeleteTask{}, api.EventCreateService{}, api.EventUpdateService{}, api.EventDeleteService{}, api.EventCreateConfig{}, api.EventUpdateConfig{}, api.EventDeleteConfig{}, state.EventCommit{})
	if err != nil {
		return err
	}
	defer observed.Cancel()
	cursor := ManagementObservationCursor{Version: observed.Version.Index, NodeID: s.node.ID(), ClusterID: clusterID, ServerEpoch: s.epoch, Term: observed.Term, Leader: observed.Leader}
	if request.Resume != nil && !sameObservationSource(*request.Resume, cursor) {
		return status.Error(codes.FailedPrecondition, "observation source epoch changed")
	}
	validate := func() error {
		select {
		case <-observed.Closed:
			return status.Error(codes.OutOfRange, "observation stream lost continuity")
		default:
		}
		if err := refresh(ctx); err != nil {
			return err
		}
		if s.node.upstream.Manager() != manager {
			return errors.New("observation manager replaced")
		}
		return manager.ValidateObservation(observed)
	}
	send := func(message observationWire) error {
		if err := validate(); err != nil {
			return err
		}
		wire, err := protocol.EncodeJSON(message)
		if err != nil {
			return err
		}
		if len(wire) > observationMessageLimit {
			return status.Error(codes.ResourceExhausted, "observation exceeds fixed message bound")
		}
		return sendManagementObservation(ctx, observed.Closed, validate, func() error {
			return transmit(&wrapperspb.BytesValue{Value: wire})
		})
	}
	snapshotWire, err := snapshot.Marshal()
	if err != nil {
		return err
	}
	if err := send(observationWire{Cursor: cursor, Snapshot: snapshotWire}); err != nil {
		return err
	}
	sendTransaction := func(events []*api.WatchMessage_Event, version *api.Version) error {
		if version == nil {
			return errors.New("observation transaction has no applied version")
		}
		wire, err := (&api.WatchMessage{Events: events, Version: version}).Marshal()
		if err != nil {
			return err
		}
		at := cursor
		at.Version = version.Index
		return send(observationWire{Cursor: at, Transaction: wire})
	}
	project := func(event api.Event, historical bool) (*api.WatchMessage_Event, error) {
		message := api.WatchMessageEvent(event)
		if message == nil {
			return nil, nil
		}
		if s.visible(message.Object) {
			if message.OldObject != nil && !s.visible(message.OldObject) {
				message.OldObject = nil
			}
			return message, nil
		}
		if s.visible(message.OldObject) || historical && message.Action == api.WatchActionKindUpdate && (message.Object.GetService() != nil || message.Object.GetConfig() != nil) {
			return nil, status.Error(codes.FailedPrecondition, "observation scope continuity unavailable")
		}
		return nil, nil
	}
	for _, change := range observed.Replay {
		var events []*api.WatchMessage_Event
		for _, action := range change.StoreActions {
			event, err := api.EventFromStoreAction(action, nil)
			if err != nil {
				return err
			}
			message, err := project(event, true)
			if err != nil {
				return err
			}
			if message != nil {
				events = append(events, message)
			}
		}
		if err := sendTransaction(events, &change.Version); err != nil {
			return err
		}
	}
	if err := send(observationWire{Cursor: cursor, ReplayThrough: new(cursor.Version)}); err != nil {
		return err
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var pending []*api.WatchMessage_Event
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := validate(); err != nil {
				return err
			}
		case event, ok := <-observed.Events:
			if !ok {
				return status.Error(codes.OutOfRange, "observation stream lost continuity")
			}
			if commit, ok := event.(state.EventCommit); ok {
				if err := sendTransaction(pending, commit.Version); err != nil {
					return err
				}
				pending = nil
			} else if changed, ok := event.(api.Event); ok {
				message, err := project(changed, false)
				if err != nil {
					return err
				}
				if message != nil {
					pending = append(pending, message)
				}
			} else {
				return errors.New("observation received an unknown event")
			}
		}
	}
}

// Returning the handler closes gRPC's transport stream and releases SendMsg.
// A buffered result lets that one sender exit after overflow or revocation.
func sendManagementObservation(ctx context.Context, closed <-chan struct{}, validate func() error, send func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validate(); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() { result <- send() }()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-closed:
			return status.Error(codes.OutOfRange, "observation stream lost continuity")
		case <-ticker.C:
			if err := validate(); err != nil {
				return err
			}
		case err := <-result:
			if err != nil {
				return err
			}
			return validate()
		}
	}
}
