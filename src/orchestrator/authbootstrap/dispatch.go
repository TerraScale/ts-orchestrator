package authbootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

const maximumDispatchBytes = 64 << 10

func HostSubjects(identity string) (identitySubject, bootstrapSubject string, err error) {
	if !validIdentity(identity) {
		return "", "", ErrInvalid
	}
	digest := sha256.Sum256([]byte(identity))
	prefix := "orch.auth.bootstrap.host." + hex.EncodeToString(digest[:])
	return prefix + ".identity", prefix + ".bootstrap", nil
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
	connection                *nats.Conn
	serverIdentity, principal string
	timeout                   time.Duration
}

func NewRemoteTarget(connection *nats.Conn, identity, principal string, timeout time.Duration) (*RemoteTarget, error) {
	if !authenticatedConnection(connection) || !validIdentity(identity) || !validIdentity(principal) || timeout <= 0 || timeout > time.Minute {
		return nil, ErrInvalid
	}
	return &RemoteTarget{connection, identity, principal, timeout}, nil
}
func (target *RemoteTarget) ServerIdentity() string { return target.serverIdentity }
func (target *RemoteTarget) Principal() string      { return target.principal }

type dispatchRequest struct {
	ServerIdentity string
	Principal      string
	Request        []byte
}
type dispatchReply struct {
	Response []byte
	Code     int32
}

func dispatchCode(err error) codes.Code {
	if errors.Is(err, ErrInvalid) {
		return codes.InvalidArgument
	}
	return status.Code(err)
}

func (target *RemoteTarget) call(ctx context.Context, subject string, request, reply proto.Message) error {
	var data []byte
	var err error
	if request != nil {
		data, err = (proto.MarshalOptions{Deterministic: true}).Marshal(request)
		if err != nil {
			return err
		}
	}
	payload, err := json.Marshal(dispatchRequest{target.serverIdentity, target.principal, data})
	if err != nil || len(payload) > maximumDispatchBytes {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, target.timeout)
	defer cancel()
	message, err := target.connection.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return err
	}
	var response dispatchReply
	if message == nil || len(message.Data) > maximumDispatchBytes || json.Unmarshal(message.Data, &response, json.RejectUnknownMembers(true)) != nil {
		return ErrInvalid
	}
	if response.Code != 0 {
		if response.Code < 1 || response.Code > 16 || len(response.Response) != 0 {
			return ErrInvalid
		}
		return status.Error(codes.Code(response.Code), "host refused auth bootstrap control")
	}
	if proto.Unmarshal(response.Response, reply) != nil || rejectUnknownFields(reply) != nil {
		return ErrInvalid
	}
	return nil
}
func (target *RemoteTarget) Identity(ctx context.Context) (*pb.AuthStorageIdentity, error) {
	subject, _, _ := HostSubjects(target.serverIdentity)
	reply := new(pb.AuthStorageIdentity)
	err := target.call(ctx, subject, nil, reply)
	return reply, err
}
func (target *RemoteTarget) Bootstrap(ctx context.Context, request *pb.AuthGroupBootstrapRequest) (*pb.AuthGroupBootstrapReceipt, error) {
	if request == nil {
		return nil, ErrInvalid
	}
	if err := rejectUnknownFields(request); err != nil {
		return nil, err
	}
	if _, err := CanonicalGrant(request.Grant, false); err != nil {
		return nil, err
	}
	_, subject, _ := HostSubjects(target.serverIdentity)
	reply := new(pb.AuthGroupBootstrapReceipt)
	if err := target.call(ctx, subject, request, reply); err != nil {
		return nil, err
	}
	if err := ValidateReceipt(reply, request, target.serverIdentity); err != nil {
		return nil, err
	}
	return reply, nil
}

// HostBridge accepts only separately authorized control subjects. The broker
// pins publishers to global authority and subscribers to the exact host NKey.
type HostBridge struct {
	cancel        context.CancelFunc
	subscriptions []*nats.Subscription
	done          chan struct{}
	once          sync.Once
}

func StartHostBridge(ctx context.Context, connection *nats.Conn, target Target) (*HostBridge, error) {
	if ctx == nil || !authenticatedConnection(connection) || target == nil || !validIdentity(target.Principal()) {
		return nil, ErrInvalid
	}
	identitySubject, bootstrapSubject, err := HostSubjects(target.ServerIdentity())
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	bridge := &HostBridge{cancel: cancel, done: make(chan struct{})}
	for _, subject := range []string{identitySubject, bootstrapSubject} {
		subscription, err := connection.SubscribeSync(subject)
		if err != nil {
			cancel()
			for _, s := range bridge.subscriptions {
				_ = s.Unsubscribe()
			}
			return nil, err
		}
		bridge.subscriptions = append(bridge.subscriptions, subscription)
		if err := subscription.SetPendingLimits(8, 2*maximumDispatchBytes); err != nil {
			cancel()
			for _, s := range bridge.subscriptions {
				_ = s.Unsubscribe()
			}
			return nil, err
		}
	}
	if err := connection.FlushWithContext(ctx); err != nil {
		cancel()
		for _, s := range bridge.subscriptions {
			_ = s.Unsubscribe()
		}
		return nil, err
	}
	if err := connection.LastError(); err != nil {
		cancel()
		for _, subscription := range bridge.subscriptions {
			_ = subscription.Unsubscribe()
		}
		return nil, err
	}
	var workers sync.WaitGroup
	for index, subscription := range bridge.subscriptions {
		workers.Go(func() {
			defer subscription.Unsubscribe()
			for lifetime.Err() == nil {
				message, err := subscription.NextMsgWithContext(lifetime)
				if err != nil {
					return
				}
				reply := dispatchReply{Code: int32(codes.InvalidArgument)}
				var request dispatchRequest
				if len(message.Data) <= maximumDispatchBytes && json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) == nil && request.ServerIdentity == target.ServerIdentity() && request.Principal == target.Principal() {
					var response proto.Message
					if index == 0 && len(request.Request) == 0 {
						response, err = target.Identity(lifetime)
					} else if index == 1 {
						grant := new(pb.AuthGroupBootstrapRequest)
						err = proto.Unmarshal(request.Request, grant)
						if err == nil {
							err = rejectUnknownFields(grant)
						}
						if err != nil {
							err = ErrInvalid
						}
						if err == nil {
							_, err = CanonicalGrant(grant.Grant, false)
						}
						if err == nil {
							response, err = target.Bootstrap(lifetime, grant)
						}
					} else {
						err = ErrInvalid
					}
					if err != nil {
						reply.Code = int32(dispatchCode(err))
					} else if response != nil {
						reply.Response, err = (proto.MarshalOptions{Deterministic: true}).Marshal(response)
						if err == nil {
							reply.Code = 0
						}
					}
				}
				payload, err := json.Marshal(reply)
				if err == nil && len(payload) <= maximumDispatchBytes && message.Reply != "" {
					_ = message.Respond(payload)
				}
			}
		})
	}
	go func() { workers.Wait(); close(bridge.done) }()
	return bridge, nil
}
func (bridge *HostBridge) Completion() <-chan struct{} { return bridge.done }
func (bridge *HostBridge) Close() error {
	if bridge == nil {
		return nil
	}
	bridge.once.Do(func() {
		bridge.cancel()
		for _, s := range bridge.subscriptions {
			_ = s.Unsubscribe()
		}
	})
	<-bridge.done
	return nil
}
