//go:build linux

package swarmruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/api"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const managementSocket = "/var/lib/terrascale-orchestrator-host/swarm-management.sock"
const managementBinding = "terrascale-accepted-identity"
const managementNodeID = "terrascale-manager-node-id"
const controllerCgroup = "/system.slice/terrascale-orchestrator-controller.service"

// StartManagementServer exposes only controller operations beside the root-owned
// manager. The private upstream control and containerd sockets remain root-only.
func StartManagementServer(ctx context.Context, node *Node, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (io.Closer, error) {
	if os.Geteuid() != 0 || node == nil || reader == nil {
		return nil, errors.New("management requires the root-owned admitted manager")
	}
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	identity := authority.Identity()
	account, err := user.Lookup("terrascale-orchestrator")
	if err != nil {
		return nil, err
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return nil, errors.New("invalid controller service identity")
	}
	binding, err := acceptedBinding(accepted)
	if err != nil {
		return nil, err
	}
	client, err := node.ControlClient(ctx)
	if err != nil {
		return nil, err
	}
	observed, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()})
	if err != nil || observed.Node == nil || observed.Node.Spec.Annotations.Name != identity.Slot || observed.Node.Spec.Annotations.Labels[LabelInstanceID] != identity.InstanceID || observed.Node.Spec.Annotations.Labels[LabelRegion] != strings.ToLower(identity.Cell) || observed.Node.Spec.Annotations.Labels[LabelHostRole] != "manager" {
		return nil, errors.New("management node differs from accepted controller")
	}
	refresh := func(ctx context.Context) error {
		current, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
		if err != nil || current.Identity() != identity {
			return errors.New("current controller authority unavailable")
		}
		return nil
	}
	return startManagementAt(ctx, managementSocket, uint32(uid), uint32(gid), controllerCgroup, binding, node.ID(), strings.ToLower(identity.Cell), identity.Environment, client, refresh)
}

// DialManagement authenticates the root manager over the fixed local socket.
// Its returned connection belongs to the caller; no privileged socket is shared.
func DialManagement(ctx context.Context, accepted bootstrapstart.AcceptedIdentity) (api.ControlClient, string, io.Closer, error) {
	binding, err := acceptedBinding(accepted)
	if err != nil {
		return nil, "", nil, err
	}
	return dialManagementAt(ctx, managementSocket, 0, binding)
}

func acceptedBinding(accepted bootstrapstart.AcceptedIdentity) (string, error) {
	wire, err := bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

type unixPeer struct {
	credentials.CommonAuthInfo
	uid uint32
	pid int32
}

func (unixPeer) AuthType() string { return "unix-peer" }

type unixCredentials struct{ serverUID uint32 }

func (c unixCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix-peer"}
}
func (c unixCredentials) Clone() credentials.TransportCredentials { return c }
func (unixCredentials) OverrideServerName(string) error           { return nil }
func (c unixCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	identity, err := socketPeer(conn)
	return conn, identity, err
}
func (c unixCredentials) ClientHandshake(ctx context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	identity, err := socketPeer(conn)
	if err == nil && (identity.uid != c.serverUID || identity.pid <= 0) {
		err = errors.New("management server identity denied")
	}
	return conn, identity, err
}
func socketPeer(conn net.Conn) (unixPeer, error) {
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return unixPeer{}, errors.New("management requires Unix transport")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return unixPeer{}, err
	}
	var cred *unix.Ucred
	var readErr error
	err = raw.Control(func(fd uintptr) { cred, readErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err = errors.Join(err, readErr); err != nil {
		return unixPeer{}, err
	}
	return unixPeer{SecurityLevel: credentials.PrivacyAndIntegrity, uid: cred.Uid, pid: cred.Pid}, nil
}
func verifyPeer(identity unixPeer, uid uint32, cgroup string) error {
	if identity.uid != uid || identity.pid <= 0 {
		return errors.New("management peer identity denied")
	}
	if cgroup != "" {
		wire, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", identity.pid))
		if err != nil {
			return err
		}
		admitted := false
		for line := range strings.SplitSeq(strings.TrimSpace(string(wire)), "\n") {
			if strings.HasSuffix(line, ":"+cgroup) {
				admitted = true
			}
		}
		if !admitted {
			return errors.New("management peer service denied")
		}
	}
	return nil
}

type managementServer struct {
	api.UnimplementedControlServer
	client              api.ControlClient
	region, environment string
}
type managementListener struct {
	server   *grpc.Server
	listener net.Listener
	stop     func() bool
	once     sync.Once
	lock     *flock.Flock
}

func (s *managementListener) Close() error {
	s.once.Do(func() {
		if s.stop != nil {
			s.stop()
		}
		s.server.Stop()
		_ = s.listener.Close()
		if s.lock != nil {
			_ = s.lock.Unlock()
		}
	})
	return nil
}
func startManagementAt(ctx context.Context, path string, uid, gid uint32, cgroup, binding, nodeID, region, environment string, client api.ControlClient, refresh func(context.Context) error) (io.Closer, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	// The caller owns the parent; never replace an existing path or follow a link.
	if !ok || stat.Uid != uint32(os.Geteuid()) || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("management socket parent is writable by another identity")
	}
	lock := flock.New(path + ".lock")
	locked, err := lock.TryLock()
	if err != nil || !locked {
		return nil, errors.New("management socket is already in use")
	}
	ready := false
	defer func() {
		if !ready {
			_ = lock.Unlock()
		}
	}()
	if old, err := os.Lstat(path); err == nil {
		owner, ok := old.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || old.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("management socket path has unexpected ownership or type")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (io.Closer, error) { _ = listener.Close(); return nil, err }
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, int(gid)); err != nil {
			return fail(err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return fail(err)
	}
	server := grpc.NewServer(grpc.Creds(unixCredentials{}), grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "management peer required")
		}
		identity, ok := p.AuthInfo.(unixPeer)
		incoming, _ := metadata.FromIncomingContext(ctx)
		if !ok || verifyPeer(identity, uid, cgroup) != nil || len(incoming.Get(managementBinding)) != 1 || incoming.Get(managementBinding)[0] != binding {
			return nil, status.Error(codes.PermissionDenied, "management identity denied")
		}
		if err := refresh(ctx); err != nil {
			return nil, status.Error(codes.PermissionDenied, "current controller authority unavailable")
		}
		if err := grpc.SetHeader(ctx, metadata.Pairs(managementNodeID, nodeID)); err != nil {
			return nil, err
		}
		switch info.FullMethod {
		case "/docker.swarmkit.v1.Control/GetNode", "/docker.swarmkit.v1.Control/ListNodes", "/docker.swarmkit.v1.Control/UpdateNode", "/docker.swarmkit.v1.Control/GetTask", "/docker.swarmkit.v1.Control/ListTasks", "/docker.swarmkit.v1.Control/GetService", "/docker.swarmkit.v1.Control/ListServices", "/docker.swarmkit.v1.Control/CreateService", "/docker.swarmkit.v1.Control/UpdateService", "/docker.swarmkit.v1.Control/GetConfig", "/docker.swarmkit.v1.Control/ListConfigs", "/docker.swarmkit.v1.Control/CreateConfig", "/docker.swarmkit.v1.Control/UpdateConfig":
		default:
			return nil, denied()
		}
		result, err := handler(ctx, req)
		if err != nil {
			return nil, status.Error(status.Code(err), "management operation failed")
		}
		return result, nil
	}))
	api.RegisterControlServer(server, &managementServer{client: client, region: region, environment: environment})
	serving := &managementListener{server: server, listener: listener, lock: lock}
	serving.stop = context.AfterFunc(ctx, func() { server.Stop(); _ = listener.Close(); _ = lock.Unlock() })
	ready = true
	go func() { _ = server.Serve(listener) }()
	return serving, nil
}
func dialManagementAt(ctx context.Context, path string, serverUID uint32, binding string) (api.ControlClient, string, io.Closer, error) {
	conn, err := grpc.NewClient("passthrough:///swarm-management", grpc.WithTransportCredentials(unixCredentials{serverUID: serverUID}), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(metadata.AppendToOutgoingContext(ctx, managementBinding, binding), method, req, reply, cc, opts...)
	}))
	if err != nil {
		return nil, "", nil, err
	}
	client := api.NewControlClient(conn)
	var headers metadata.MD
	_, err = client.ListNodes(ctx, &api.ListNodesRequest{}, grpc.Header(&headers))
	if err != nil {
		_ = conn.Close()
		return nil, "", nil, err
	}
	ids := headers.Get(managementNodeID)
	if len(ids) != 1 || ids[0] == "" {
		_ = conn.Close()
		return nil, "", nil, errors.New("management manager identity unavailable")
	}
	return client, ids[0], conn, nil
}
func (s *managementServer) scoped(a api.Annotations) bool {
	return a.Labels[LabelRegion] == s.region && a.Labels[LabelEnvironment] == s.environment && entityid.Valid(a.Labels[LabelIntentID]) && intentName.MatchString(a.Labels[LabelRole])
}
func (s *managementServer) floor(spec *api.ConfigSpec) bool {
	if spec == nil || !s.scoped(spec.Annotations) {
		return false
	}
	identity := sha256.Sum256([]byte(s.environment + "/" + s.region + "/" + spec.Annotations.Labels[LabelRole]))
	return spec.Annotations.Name == fmt.Sprintf("ts-release-%x", identity[:16])
}
func denied() error {
	return status.Error(codes.PermissionDenied, "management operation outside admitted scope")
}

func (s *managementServer) GetNode(ctx context.Context, req *api.GetNodeRequest) (*api.GetNodeResponse, error) {
	return s.client.GetNode(ctx, req)
}
func (s *managementServer) ListNodes(ctx context.Context, req *api.ListNodesRequest) (*api.ListNodesResponse, error) {
	return s.client.ListNodes(ctx, req)
}
func (s *managementServer) UpdateNode(ctx context.Context, req *api.UpdateNodeRequest) (*api.UpdateNodeResponse, error) {
	if req.Spec == nil {
		return nil, denied()
	}
	current, err := s.client.GetNode(ctx, &api.GetNodeRequest{NodeID: req.NodeID})
	if err != nil {
		return nil, err
	}
	if req.Spec.DesiredRole != current.Node.Spec.DesiredRole || req.Spec.Membership != current.Node.Spec.Membership {
		return nil, denied()
	}
	labels := req.Spec.Annotations.Labels
	if labels[LabelRegion] != s.region || labels[LabelInstanceID] == "" || labels[LabelHostRole] == "" {
		return nil, denied()
	}
	if bound := current.Node.Spec.Annotations.Labels[LabelInstanceID]; bound != "" && (bound != labels[LabelInstanceID] || current.Node.Spec.Annotations.Name != req.Spec.Annotations.Name || current.Node.Spec.Annotations.Labels[LabelHostRole] != labels[LabelHostRole]) {
		return nil, denied()
	}
	return s.client.UpdateNode(ctx, req)
}
func (s *managementServer) GetTask(ctx context.Context, req *api.GetTaskRequest) (*api.GetTaskResponse, error) {
	return s.client.GetTask(ctx, req)
}
func (s *managementServer) ListTasks(ctx context.Context, req *api.ListTasksRequest) (*api.ListTasksResponse, error) {
	return s.client.ListTasks(ctx, req)
}
func (s *managementServer) GetService(ctx context.Context, req *api.GetServiceRequest) (*api.GetServiceResponse, error) {
	result, err := s.client.GetService(ctx, req)
	if err == nil && !s.scoped(result.Service.Spec.Annotations) {
		return nil, denied()
	}
	return result, err
}
func (s *managementServer) ListServices(ctx context.Context, req *api.ListServicesRequest) (*api.ListServicesResponse, error) {
	result, err := s.client.ListServices(ctx, req)
	if err != nil {
		return nil, err
	}
	visible := result.Services[:0]
	for _, service := range result.Services {
		if s.scoped(service.Spec.Annotations) {
			visible = append(visible, service)
		}
	}
	result.Services = visible
	return result, nil
}
func (s *managementServer) CreateService(ctx context.Context, req *api.CreateServiceRequest) (*api.CreateServiceResponse, error) {
	if req.Spec == nil || !s.scoped(req.Spec.Annotations) {
		return nil, denied()
	}
	return s.client.CreateService(ctx, req)
}
func (s *managementServer) UpdateService(ctx context.Context, req *api.UpdateServiceRequest) (*api.UpdateServiceResponse, error) {
	if req.Spec == nil || !s.scoped(req.Spec.Annotations) {
		return nil, denied()
	}
	current, err := s.GetService(ctx, &api.GetServiceRequest{ServiceID: req.ServiceID})
	if err != nil {
		return nil, err
	}
	for _, key := range []string{LabelIntentID, LabelRole, LabelRegion, LabelEnvironment} {
		if current.Service.Spec.Annotations.Labels[key] != req.Spec.Annotations.Labels[key] {
			return nil, denied()
		}
	}
	return s.client.UpdateService(ctx, req)
}
func (s *managementServer) GetConfig(ctx context.Context, req *api.GetConfigRequest) (*api.GetConfigResponse, error) {
	result, err := s.client.GetConfig(ctx, req)
	if err == nil && !s.floor(&result.Config.Spec) {
		return nil, denied()
	}
	return result, err
}
func (s *managementServer) ListConfigs(ctx context.Context, req *api.ListConfigsRequest) (*api.ListConfigsResponse, error) {
	result, err := s.client.ListConfigs(ctx, req)
	if err != nil {
		return nil, err
	}
	visible := result.Configs[:0]
	for _, config := range result.Configs {
		if s.floor(&config.Spec) {
			visible = append(visible, config)
		}
	}
	result.Configs = visible
	return result, nil
}
func (s *managementServer) CreateConfig(ctx context.Context, req *api.CreateConfigRequest) (*api.CreateConfigResponse, error) {
	if !s.floor(req.Spec) {
		return nil, denied()
	}
	return s.client.CreateConfig(ctx, req)
}
func (s *managementServer) UpdateConfig(ctx context.Context, req *api.UpdateConfigRequest) (*api.UpdateConfigResponse, error) {
	if !s.floor(req.Spec) {
		return nil, denied()
	}
	current, err := s.GetConfig(ctx, &api.GetConfigRequest{ConfigID: req.ConfigID})
	if err != nil {
		return nil, err
	}
	if current.Config.Spec.Annotations.Name != req.Spec.Annotations.Name || !bytes.Equal(current.Config.Spec.Data, req.Spec.Data) {
		return nil, denied()
	}
	for _, key := range []string{LabelIntentID, LabelRole, LabelRegion, LabelEnvironment} {
		if current.Config.Spec.Annotations.Labels[key] != req.Spec.Annotations.Labels[key] {
			return nil, denied()
		}
	}
	return s.client.UpdateConfig(ctx, req)
}
