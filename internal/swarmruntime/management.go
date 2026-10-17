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
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/gofrs/flock"
	"github.com/gogo/protobuf/proto"
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

// StatefulServiceAuthorizer derives the exact current signed service in root.
// The unprivileged socket caller cannot supply its readers or a cached seal.
// The callback runs synchronously once and must not be retained.
type StatefulServiceAuthorizer interface {
	WithStatefulService(context.Context, *api.ServiceSpec, func(context.Context) error) error
}

// ManagementPeerPID returns the kernel-authenticated Unix peer for root's exact
// process witness. RPC payloads cannot construct this private credential type.
func ManagementPeerPID(ctx context.Context) (int32, error) {
	if admitted, _ := ctx.Value(managementAdmission{}).(bool); !admitted {
		return 0, denied()
	}
	remote, ok := peer.FromContext(ctx)
	if !ok {
		return 0, denied()
	}
	identity, ok := remote.AuthInfo.(unixPeer)
	if !ok || identity.pid <= 0 {
		return 0, denied()
	}
	return identity.pid, nil
}

type managementAdmission struct{}

// StartManagementServer exposes only controller operations beside the root-owned
// manager. The private upstream control and containerd sockets remain root-only.
func StartManagementServer(ctx context.Context, node *Node, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity, stateful StatefulServiceAuthorizer) (io.Closer, error) {
	if os.Geteuid() != 0 || node == nil || reader == nil || stateful == nil {
		return nil, errors.New("management requires the root-owned admitted manager")
	}
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	identity := authority.Identity()
	region := authority.Anchor().Anchor().OCIRegion
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
	if err != nil || observed.Node == nil || observed.Node.Spec.Annotations.Name != identity.Slot || observed.Node.Spec.Annotations.Labels[LabelInstanceID] != identity.InstanceID || observed.Node.Spec.Annotations.Labels[LabelRegion] != region || observed.Node.Spec.Annotations.Labels[LabelHostRole] != "manager" {
		return nil, errors.New("management node differs from accepted controller")
	}
	refresh := func(ctx context.Context) error {
		current, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
		if err != nil || current.Identity() != identity || current.Anchor().Anchor().OCIRegion != region {
			return errors.New("current controller authority unavailable")
		}
		return nil
	}
	return startManagementAt(ctx, managementSocket, uint32(uid), uint32(gid), controllerCgroup, binding, node, region, identity.Environment, client, refresh, stateful)
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
	stateful            StatefulServiceAuthorizer
}
type managementListener struct{ close func() }

func (s *managementListener) Close() error { s.close(); return nil }
func startManagementAt(ctx context.Context, path string, uid, gid uint32, cgroup, binding string, node *Node, region, environment string, client api.ControlClient, refresh func(context.Context) error, stateful StatefulServiceAuthorizer) (io.Closer, error) {
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
		if err := grpc.SetHeader(ctx, metadata.Pairs(managementNodeID, node.ID())); err != nil {
			return nil, err
		}
		switch info.FullMethod {
		case "/docker.swarmkit.v1.Control/ListClusters", workerPrepareMethod, workerAdmitMethod, workerAuditMethod, workerReadMembershipMethod, "/docker.swarmkit.v1.Control/GetNode", "/docker.swarmkit.v1.Control/ListNodes", "/docker.swarmkit.v1.Control/UpdateNode", "/docker.swarmkit.v1.Control/GetTask", "/docker.swarmkit.v1.Control/ListTasks", "/docker.swarmkit.v1.Control/GetService", "/docker.swarmkit.v1.Control/ListServices", "/docker.swarmkit.v1.Control/CreateService", "/docker.swarmkit.v1.Control/UpdateService", "/docker.swarmkit.v1.Control/RemoveService", "/docker.swarmkit.v1.Control/GetConfig", "/docker.swarmkit.v1.Control/ListConfigs", "/docker.swarmkit.v1.Control/CreateConfig", "/docker.swarmkit.v1.Control/UpdateConfig":
		default:
			return nil, denied()
		}
		result, err := handler(context.WithValue(ctx, managementAdmission{}, true), req)
		if err != nil {
			return nil, status.Error(status.Code(err), "management operation failed")
		}
		if err := refresh(ctx); err != nil {
			return nil, status.Error(codes.PermissionDenied, "current controller authority changed")
		}
		return result, nil
	}), grpc.StreamInterceptor(managementStreamInterceptor(uid, cgroup, binding, refresh)))
	scope := &managementServer{client: client, region: region, environment: environment, stateful: stateful}
	api.RegisterControlServer(server, scope)
	registerManagementObservation(server, node, scope)
	registerWorkerManagement(server, node)
	stop := context.AfterFunc(ctx, func() { server.Stop(); _ = listener.Close(); _ = lock.Unlock() })
	serving := &managementListener{close: sync.OnceFunc(func() { stop(); server.Stop(); _ = listener.Close(); _ = lock.Unlock() })}
	ready = true
	go func() { _ = server.Serve(listener) }()
	return serving, nil
}
func dialManagementAt(ctx context.Context, path string, serverUID uint32, binding string) (api.ControlClient, string, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient("passthrough:///swarm-management", grpc.WithTransportCredentials(unixCredentials{serverUID: serverUID}), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(metadata.AppendToOutgoingContext(ctx, managementBinding, binding), method, req, reply, cc, opts...)
	}), grpc.WithStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(metadata.AppendToOutgoingContext(ctx, managementBinding, binding), desc, cc, method, opts...)
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
	if spec == nil || spec.Templating != nil || !s.scoped(spec.Annotations) || !validIntentLabels(spec.Annotations.Labels) {
		return false
	}
	sequence, err := strconv.ParseUint(spec.Annotations.Labels["terrascale.release-sequence"], 10, 64)
	if err != nil || sequence == 0 {
		return false
	}
	labels := spec.Annotations.Labels
	if strings.HasPrefix(spec.Annotations.Name, "ts-worker-family-") {
		migration := labels[labelReleaseMigration]
		digest, err := hex.DecodeString(migration)
		if labels[LabelRole] != "function-worker" || err != nil || len(digest) != sha256.Size || migration != strings.ToLower(migration) {
			return false
		}
		identity := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s/%d", migration, labels[LabelRole], s.environment, sequence)))
		return spec.Annotations.Name == fmt.Sprintf("ts-worker-family-%x", identity[:16])
	}
	scope := s.environment + "/" + s.region + "/" + labels[LabelRole]
	if architecture := labels[labelReleaseArchitecture]; architecture != "" {
		if labels[LabelRole] != "function-worker" || architecture != "arm64" && architecture != "amd64" {
			return false
		}
		scope += "/" + architecture
	}
	identity := sha256.Sum256([]byte(scope))
	return spec.Annotations.Name == fmt.Sprintf("ts-release-%x", identity[:16])
}
func denied() error {
	return status.Error(codes.PermissionDenied, "management operation outside admitted scope")
}

func validIntentLabels(labels map[string]string) bool {
	stored, hasGeneration := labels[LabelIntentGeneration]
	fingerprint, hasFingerprint := labels[labelIntentFingerprint]
	if !hasGeneration && !hasFingerprint {
		return true
	}
	generation, err := strconv.ParseUint(stored, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != stored {
		return false
	}
	digest, err := hex.DecodeString(fingerprint)
	return err == nil && len(digest) == sha256.Size && fingerprint == strings.ToLower(fingerprint)
}

func retainsIntentGeneration(before, after map[string]string) bool {
	if !validIntentLabels(before) || !validIntentLabels(after) {
		return false
	}
	generation, _ := strconv.ParseUint(after[LabelIntentGeneration], 10, 64)
	return checkIntentGeneration(before, ServiceIntent{Generation: generation, intentFingerprint: after[labelIntentFingerprint]}) == nil
}

func (s *managementServer) GetNode(ctx context.Context, req *api.GetNodeRequest) (*api.GetNodeResponse, error) {
	return s.client.GetNode(ctx, req)
}
func (s *managementServer) ListNodes(ctx context.Context, req *api.ListNodesRequest) (*api.ListNodesResponse, error) {
	return s.client.ListNodes(ctx, req)
}
func (s *managementServer) UpdateNode(ctx context.Context, req *api.UpdateNodeRequest) (*api.UpdateNodeResponse, error) {
	if req.Spec == nil || req.Spec.Availability != api.NodeAvailabilityPause {
		return nil, denied()
	}
	current, err := s.client.GetNode(ctx, &api.GetNodeRequest{NodeID: req.NodeID})
	if err != nil {
		return nil, err
	}
	if req.Spec.DesiredRole != current.Node.Spec.DesiredRole || req.Spec.Membership != current.Node.Spec.Membership {
		return nil, denied()
	}
	labels := current.Node.Spec.Annotations.Labels
	if labels[LabelRegion] != s.region || labels[LabelInstanceID] == "" || !proto.Equal(&current.Node.Spec.Annotations, &req.Spec.Annotations) {
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
func (s *managementServer) managedService(spec *api.ServiceSpec) bool {
	if spec == nil || !s.scoped(spec.Annotations) || !validIntentLabels(spec.Annotations.Labels) || spec.GetReplicated() == nil || spec.GetReplicated().Replicas > autoscale.MaxReplicas || len(spec.Networks) != 0 {
		return false
	}
	placement := spec.Task.Placement
	if placement == nil || len(placement.Platforms) != 1 || placement.Platforms[0] == nil || placement.Platforms[0].OS != "linux" || (placement.Platforms[0].Architecture != "arm64" && placement.Platforms[0].Architecture != "amd64") {
		return false
	}
	constraints := []string{"node.labels." + LabelRegion + "==" + s.region, "node.labels." + LabelExecutionScope + "==platform"}
	if spec.Annotations.Labels[LabelRole] == "function-worker" {
		constraints[1] = "node.labels." + LabelExecutionScope + "==tenant"
		constraints = append(constraints, "node.labels."+LabelHostRole+"==wasm")
	}
	if spec.Annotations.Labels[LabelRole] == "ts-auth" {
		constraints = append(constraints, "node.role==manager")
		if placement.MaxReplicas != 1 {
			return false
		}
	}
	if !slices.Equal(placement.Constraints, constraints) {
		return false
	}
	if spec.Endpoint != nil && (spec.Endpoint.Mode != api.ResolutionModeDNSRoundRobin || len(spec.Endpoint.Ports) > 1) {
		return false
	}
	_, err := DecodeContainer(&api.Task{ID: "validation", ServiceID: "validation", Spec: spec.Task, ServiceAnnotations: spec.Annotations, Endpoint: &api.Endpoint{Spec: spec.Endpoint}})
	return err == nil
}

func (s *managementServer) CreateService(ctx context.Context, req *api.CreateServiceRequest) (*api.CreateServiceResponse, error) {
	if s.managedService(req.Spec) {
		return s.client.CreateService(ctx, req)
	}
	var result *api.CreateServiceResponse
	err := s.withStatefulService(ctx, req.Spec, func(effectCtx context.Context) error {
		var err error
		result, err = s.client.CreateService(effectCtx, req)
		return err
	})
	if err == nil && result == nil {
		return nil, denied()
	}
	return result, err
}
func (s *managementServer) UpdateService(ctx context.Context, req *api.UpdateServiceRequest) (*api.UpdateServiceResponse, error) {
	stateful := statefulService(req.Spec)
	if !s.managedService(req.Spec) && !stateful {
		return nil, denied()
	}
	current, err := s.GetService(ctx, &api.GetServiceRequest{ServiceID: req.ServiceID})
	if err != nil {
		return nil, err
	}
	if stateful != statefulService(&current.Service.Spec) {
		return nil, denied()
	}
	if stateful {
		if req.Rollback != api.UpdateServiceRequest_NONE || req.Spec.Annotations.Name != current.Service.Spec.Annotations.Name {
			return nil, denied()
		}
		for _, key := range []string{"terrascale.database-id", "terrascale.partition-id", "terrascale.member-id"} {
			if req.Spec.Annotations.Labels[key] != current.Service.Spec.Annotations.Labels[key] {
				return nil, denied()
			}
		}
	}
	effective := req.Spec
	switch req.Rollback {
	case api.UpdateServiceRequest_NONE:
		if !retainsIntentGeneration(current.Service.Spec.Annotations.Labels, effective.Annotations.Labels) {
			return nil, denied()
		}
	case api.UpdateServiceRequest_PREVIOUS:
		effective = current.Service.PreviousSpec
	default:
		return nil, denied()
	}
	if !stateful && !s.managedService(effective) {
		return nil, denied()
	}
	for _, key := range []string{LabelIntentID, LabelRole, LabelRegion, LabelEnvironment} {
		if current.Service.Spec.Annotations.Labels[key] != effective.Annotations.Labels[key] {
			return nil, denied()
		}
	}
	if stateful {
		var result *api.UpdateServiceResponse
		err := s.withStatefulService(ctx, effective, func(effectCtx context.Context) error {
			var err error
			result, err = s.client.UpdateService(effectCtx, req)
			return err
		})
		if err == nil && result == nil {
			return nil, denied()
		}
		return result, err
	}
	return s.client.UpdateService(ctx, req)
}

func statefulService(spec *api.ServiceSpec) bool {
	return spec != nil && spec.Annotations.Labels[LabelRole] == "terrabase" && spec.Annotations.Labels["terrascale.stateful"] == "true"
}

func (s *managementServer) withStatefulService(ctx context.Context, spec *api.ServiceSpec, effect func(context.Context) error) error {
	if !statefulService(spec) || !s.scoped(spec.Annotations) || !validIntentLabels(spec.Annotations.Labels) || s.stateful == nil {
		return denied()
	}
	called := false
	invalid := false
	var effectErr error
	err := s.stateful.WithStatefulService(ctx, spec, func(effectCtx context.Context) error {
		if called {
			invalid = true
			return denied()
		}
		called = true
		if effectCtx == nil || effectCtx.Err() != nil {
			invalid = true
			return denied()
		}
		effectErr = effect(effectCtx)
		return effectErr
	})
	if !called || invalid {
		return denied()
	}
	if effectErr != nil {
		return effectErr
	}
	return err
}
func (s *managementServer) RemoveService(ctx context.Context, req *api.RemoveServiceRequest) (*api.RemoveServiceResponse, error) {
	current, err := s.GetService(ctx, &api.GetServiceRequest{ServiceID: req.ServiceID})
	if err != nil {
		return nil, err
	}
	if !s.managedService(&current.Service.Spec) {
		return nil, denied()
	}
	return s.client.RemoveService(ctx, req)
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
	if !s.floor(req.Spec) || strings.HasPrefix(req.Spec.Annotations.Name, "ts-worker-family-") {
		return nil, denied()
	}
	current, err := s.GetConfig(ctx, &api.GetConfigRequest{ConfigID: req.ConfigID})
	if err != nil {
		return nil, err
	}
	if current.Config.Spec.Annotations.Name != req.Spec.Annotations.Name || !bytes.Equal(current.Config.Spec.Data, req.Spec.Data) {
		return nil, denied()
	}
	before, after := current.Config.Spec.Annotations.Labels, req.Spec.Annotations.Labels
	if !retainsIntentGeneration(before, after) {
		return nil, denied()
	}
	for key := range after {
		if _, exists := before[key]; !exists && key != LabelIntentGeneration && key != labelIntentFingerprint {
			return nil, denied()
		}
	}
	for key, value := range before {
		if _, exists := after[key]; !exists {
			return nil, denied()
		}
		switch key {
		case "terrascale.release-sequence", "terrascale.release-fingerprint", "terrascale.release-baseline", LabelIntentGeneration, labelIntentFingerprint:
		default:
			if after[key] != value {
				return nil, denied()
			}
		}
	}
	previous, err := strconv.ParseUint(before["terrascale.release-sequence"], 10, 64)
	if err != nil || previous == 0 {
		return nil, denied()
	}
	next, err := strconv.ParseUint(after["terrascale.release-sequence"], 10, 64)
	if err != nil || next < previous || next == previous && after["terrascale.release-fingerprint"] != before["terrascale.release-fingerprint"] {
		return nil, denied()
	}
	return s.client.UpdateConfig(ctx, req)
}
