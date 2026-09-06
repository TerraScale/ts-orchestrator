package placementpublisher

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json/v2"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authbootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

const maximumDispatchBytes = 1 << 20

// HostSubject names exactly one admitted TerraBase identity; no proposal body
// can select a different host or engine endpoint.
func HostSubject(serverIdentity string) (string, error) {
	if !validIdentity(serverIdentity) {
		return "", ErrInvalidConfig
	}
	digest := sha256.Sum256([]byte(serverIdentity))
	return "orch.placement.host." + hex.EncodeToString(digest[:]) + ".stage", nil
}

// HostPermissions belong to a dedicated host NKey on global R3. The host cannot
// publish placement requests, change the intent journal, or subscribe elsewhere.
func HostPermissions(serverIdentity string) (publish, subscribe []string, err error) {
	subject, err := HostSubject(serverIdentity)
	if err != nil {
		return nil, nil, err
	}
	identity, bootstrap, err := authbootstrap.HostSubjects(serverIdentity)
	if err != nil {
		return nil, nil, err
	}
	return []string{"_INBOX.>"}, []string{subject, identity, bootstrap}, nil
}

func authenticatedConnection(connection *nats.Conn) bool {
	if connection == nil || !connection.IsConnected() || !connection.AuthRequired() {
		return false
	}
	options := connection.Opts
	if options.Nkey == "" || options.SignatureCB == nil || options.AllowReconnect || options.ReconnectBufSize >= 0 || options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify || options.TLSConfig.RootCAs == nil || (len(options.TLSConfig.Certificates) == 0 && options.TLSConfig.GetClientCertificate == nil && options.TLSCertCB == nil) {
		return false
	}
	state, err := connection.TLSConnectionState()
	return err == nil && state.HandshakeComplete && state.Version >= tls.VersionTLS13 && len(state.VerifiedChains) > 0
}

type RemoteTarget struct {
	connection     *nats.Conn
	serverIdentity string
	principal      string
	subject        string
	timeout        time.Duration
}

func NewRemoteTarget(connection *nats.Conn, serverIdentity, principal string, timeout time.Duration) (*RemoteTarget, error) {
	subject, err := HostSubject(serverIdentity)
	if err != nil || !authenticatedConnection(connection) || !validIdentity(principal) || timeout <= 0 || timeout > time.Minute {
		return nil, ErrInvalidConfig
	}
	return &RemoteTarget{connection, serverIdentity, principal, subject, timeout}, nil
}
func (target *RemoteTarget) ServerIdentity() string { return target.serverIdentity }
func (target *RemoteTarget) Principal() string      { return target.principal }

type dispatchReply struct {
	Receipt []byte
	Code    int32
}

func (target *RemoteTarget) Stage(ctx context.Context, id string, request *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
	record, err := NewRecord(id, target.serverIdentity, target.principal, request)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(record)
	if err != nil || len(payload) > maximumDispatchBytes {
		return nil, ErrInvalidConfig
	}
	ctx, cancel := context.WithTimeout(ctx, target.timeout)
	defer cancel()
	message, err := target.connection.RequestWithContext(ctx, target.subject, payload)
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
		return nil, status.Error(codes.Code(reply.Code), "host refused placement proposal")
	}
	receipt := new(pb.PlacementProposalResponse)
	if proto.Unmarshal(reply.Receipt, receipt) != nil {
		return nil, ErrInvalidConfig
	}
	if err := tbep.ValidatePlacementReceipt(receipt, request.Proposal); err != nil {
		return nil, err
	}
	return receipt, nil
}

// HostBridge is a control-only global-to-local hop. Its dedicated NATS identity
// admits requests only from the GRU authority publish subject. TBEP still uses
// the exact local orchestrator certificate and verifies the local engine.
type HostBridge struct {
	cancel       context.CancelFunc
	subscription *nats.Subscription
	done         chan struct{}
	once         sync.Once
}

func StartHostBridge(ctx context.Context, connection *nats.Conn, target Target) (*HostBridge, error) {
	if ctx == nil || !authenticatedConnection(connection) || target == nil || !validIdentity(target.Principal()) {
		return nil, ErrInvalidConfig
	}
	subject, err := HostSubject(target.ServerIdentity())
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
	if err := connection.LastError(); err != nil {
		_ = subscription.Unsubscribe()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	bridge := &HostBridge{cancel: cancel, subscription: subscription, done: make(chan struct{})}
	go func() {
		defer close(bridge.done)
		defer subscription.Unsubscribe()
		for lifetime.Err() == nil {
			message, err := subscription.NextMsgWithContext(lifetime)
			if err != nil {
				return
			}
			reply := dispatchReply{Code: int32(codes.InvalidArgument)}
			var record Record
			if len(message.Data) <= maximumDispatchBytes && json.Unmarshal(message.Data, &record, json.RejectUnknownMembers(true)) == nil && record.ServerIdentity == target.ServerIdentity() && record.Principal == target.Principal() && len(record.Receipt) == 0 {
				request, err := decodeRecord(record)
				if err == nil {
					receipt, err := target.Stage(lifetime, record.OperationID, request)
					if err != nil {
						reply.Code = int32(status.Code(err))
					} else if tbep.ValidatePlacementReceipt(receipt, request.Proposal) == nil {
						reply.Receipt, err = (proto.MarshalOptions{Deterministic: true}).Marshal(receipt)
						if err == nil {
							reply.Code = 0
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
func (bridge *HostBridge) Completion() <-chan struct{} { return bridge.done }
func (bridge *HostBridge) Close() error {
	if bridge == nil {
		return nil
	}
	bridge.once.Do(func() { bridge.cancel(); _ = bridge.subscription.Unsubscribe() })
	<-bridge.done
	return nil
}

var _ Target = (*RemoteTarget)(nil)
