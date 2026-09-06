// Package tbep observes the same-host TerraBase process over its private contract.
// Observation is not evidence of replication durability or lifecycle completion.
package tbep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// Config must come from the admitted host's identity and database scope.
// Endpoint is a literal loopback IP and port. ServerIdentity is the exact
// admitted TerraBase SPIFFE identity, never a trust-domain wildcard.
type Config struct {
	Endpoint       string
	ServerIdentity string
	Certificate    tls.Certificate
	Roots          *x509.CertPool
	Tenant         string
	Project        string
	Database       string
	Timeout        time.Duration
}

type Client struct {
	conn        *grpc.ClientConn
	maintenance pb.MaintenanceServiceClient
	lifecycle   pb.LifecycleControlServiceClient
	scope       metadata.MD
	principal   string
	timeout     time.Duration
}

// New configures a lazy connection. Only a successful Observe proves contact.
// The wrapper exposes no mutations and disables service-config retries.
func New(config Config) (*Client, error) {
	return newClient(config, true)
}

func newClient(config Config, databaseScope bool) (*Client, error) {
	host, port, err := net.SplitHostPort(config.Endpoint)
	if err != nil {
		return nil, errors.New("TBEP endpoint must be a loopback IP and port")
	}
	ip := net.ParseIP(host)
	portNumber, portErr := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("TBEP endpoint must be a loopback IP and port")
	}
	if !validIdentity(config.ServerIdentity) {
		return nil, errors.New("TBEP server identity must be an exact SPIFFE URI")
	}
	if config.Timeout <= 0 || config.Timeout > time.Minute {
		return nil, errors.New("TBEP timeout must be positive and at most one minute")
	}
	if config.Roots == nil || len(config.Roots.Subjects()) == 0 || len(config.Certificate.Certificate) == 0 || config.Certificate.PrivateKey == nil {
		return nil, errors.New("TBEP requires client certificate, private key, and trusted roots")
	}
	leaf, err := x509.ParseCertificate(config.Certificate.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 || !validIdentity(leaf.URIs[0].String()) {
		return nil, errors.New("TBEP client certificate must have exactly one SPIFFE URI SAN")
	}
	principal := leaf.URIs[0].String()
	for _, item := range []struct {
		value string
		limit int
	}{{principal, 128}, {config.Tenant, 64}, {config.Project, 255}, {config.Database, 255}} {
		if !databaseScope && item.value == "" {
			continue
		}
		if !validMetadata(item.value, item.limit) {
			return nil, errors.New("TBEP scope must contain bounded nonempty printable ASCII metadata")
		}
	}
	// SPIFFE uses URI SANs, not DNS SANs. VerifyConnection performs chain,
	// server usage, validity, and sole exact URI checks instead of DNS matching.
	roots := config.Roots.Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{config.Certificate}, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
			return errors.New("TBEP requires TLS 1.3 and a server certificate")
		}
		peer := state.PeerCertificates[0]
		if len(peer.URIs) != 1 || peer.URIs[0].String() != config.ServerIdentity {
			return errors.New("TBEP server SPIFFE identity differs from admitted host")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := peer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return err
	}}
	conn, err := grpc.NewClient("passthrough:///"+config.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		// Dial the admitted literal directly; proxy environment and resolver
		// configuration cannot redirect a host-local control connection.
		return (&net.Dialer{}).DialContext(ctx, "tcp", config.Endpoint)
	}), grpc.WithDisableRetry(), grpc.WithDisableServiceConfig(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(512*1024), grpc.MaxCallSendMsgSize(512*1024)))
	if err != nil {
		return nil, fmt.Errorf("configure TBEP transport: %w", err)
	}
	scope := metadata.Pairs("x-tb-principal", principal)
	if databaseScope {
		scope.Append("x-tb-tenant", config.Tenant)
		scope.Append("x-tb-project", config.Project)
		scope.Append("x-tb-database", config.Database)
	}
	return &Client{conn: conn, maintenance: pb.NewMaintenanceServiceClient(conn), lifecycle: pb.NewLifecycleControlServiceClient(conn), scope: scope, principal: principal, timeout: config.Timeout}, nil
}

// LifecycleAssignment is the complete accepted placement envelope supplied by
// the GRU placement journal. The signature is forwarded unchanged to TBEP.
type LifecycleAssignment struct {
	Environment, Tenant, Project, Database, Region, Member string
	PlacementRevision, AuthorityEpoch                      uint64
	AuthorityLease                                         string
	AuthoritySignature                                     []byte
	OperationGrant                                         []byte
}

func (c *Client) lifecycleRequest(a LifecycleAssignment, operation string) (*pb.LifecycleControlRequest, error) {
	if c == nil || c.lifecycle == nil || !validMetadata(operation, 128) || len(a.AuthoritySignature) == 0 || len(a.OperationGrant) == 0 {
		return nil, errors.New("TBEP lifecycle request is incomplete")
	}
	return &pb.LifecycleControlRequest{Context: &pb.LifecycleControlContext{
		Environment: a.Environment, Tenant: a.Tenant, Project: a.Project, Database: a.Database,
		Region: a.Region, Member: a.Member, PlacementRevision: a.PlacementRevision,
		AuthorityEpoch: a.AuthorityEpoch, AuthorityLease: a.AuthorityLease,
		AuthoritySignature: append([]byte(nil), a.AuthoritySignature...),
		OperationGrant:     append([]byte(nil), a.OperationGrant...),
	}, OperationId: operation}, nil
}

func (c *Client) lifecycleCall(ctx context.Context, request *pb.LifecycleControlRequest, call func(context.Context, *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error)) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, c.scope)
	response, err := call(ctx, request)
	if err != nil {
		return err
	}
	if response.GetOperationId() != request.GetOperationId() || response.GetStatus() != pb.LifecycleStatus_LIFECYCLE_STATUS_APPLIED && response.GetStatus() != pb.LifecycleStatus_LIFECYCLE_STATUS_ALREADY_APPLIED {
		return fmt.Errorf("TBEP lifecycle operation %q was not applied: %s", request.GetOperationId(), response.GetDetail())
	}
	return nil
}

// RestoreToTarget invokes the authenticated native restore operation. The
// target assignment is carried in the accepted placement context; source and
// recovery facts are explicit so a caller cannot silently restore a different
// point or owner.
func (c *Client) RestoreToTarget(ctx context.Context, a LifecycleAssignment, operation, sourceOwner, sourceDatabase, recoveryPointID, recoveryPointDigest, targetOwner, targetDatabase, journalCut string, restoreEpoch uint64, expectedPlacement []string, provider pb.RestoreProvider) (*pb.LifecycleControlResponse, error) {
	if !validOwner(sourceOwner) || !validMetadata(sourceDatabase, 255) || !validMetadata(recoveryPointID, 255) || len(recoveryPointDigest) != 64 || !validOwner(targetOwner) || !validMetadata(targetDatabase, 255) || !validMetadata(journalCut, 255) || restoreEpoch == 0 || (provider != pb.RestoreProvider_RESTORE_PROVIDER_OCI && provider != pb.RestoreProvider_RESTORE_PROVIDER_TIGRIS) {
		return nil, errors.New("TBEP restore request is incomplete")
	}
	r, err := c.lifecycleRequest(a, operation)
	if err != nil {
		return nil, err
	}
	request := &pb.RestoreToTargetRequest{Context: r.Context, OperationId: r.OperationId, SourceOwner: sourceOwner, SourceDatabase: sourceDatabase, RecoveryPointId: recoveryPointID, RecoveryPointDigest: recoveryPointDigest, TargetOwner: targetOwner, TargetDatabase: targetDatabase, JournalCut: journalCut, RestoreEpoch: restoreEpoch, Provider: provider}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, c.scope)
	response, err := c.lifecycle.RestoreToTarget(ctx, request)
	if err != nil {
		return nil, err
	}
	want, got := slices.Clone(expectedPlacement), slices.Clone(response.GetPlacement())
	slices.Sort(want)
	slices.Sort(got)
	if response.GetOperationId() != operation || response.GetRecoveryPointId() != recoveryPointID || response.GetRecoveryPointDigest() != recoveryPointDigest || !slices.Equal(want, got) || !slices.Contains(got, a.Region) || (response.GetStatus() != pb.LifecycleStatus_LIFECYCLE_STATUS_APPLIED && response.GetStatus() != pb.LifecycleStatus_LIFECYCLE_STATUS_ALREADY_APPLIED) {
		return nil, fmt.Errorf("TBEP restore operation %q was not applied: %s", operation, response.GetDetail())
	}
	return response, nil
}

func validOwner(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && validMetadata(parts[0], 64) && validMetadata(parts[1], 255) && !strings.Contains(parts[0], "/") && !strings.Contains(parts[1], "/")
}

// RestoreStats reads facts from the admitted restored target. The member
// computes these facts; callers never synthesize them from the request.
func (c *Client) RestoreStats(ctx context.Context, a LifecycleAssignment, operation, targetOwner, targetDatabase, journalCut string, restoreEpoch uint64) (*pb.RestoreStatsResponse, error) {
	if !validMetadata(targetOwner, 255) || !validMetadata(targetDatabase, 255) || !validMetadata(journalCut, 255) || restoreEpoch == 0 {
		return nil, errors.New("TBEP restore stats request is incomplete")
	}
	r, err := c.lifecycleRequest(a, operation)
	if err != nil {
		return nil, err
	}
	request := &pb.RestoreStatsRequest{Context: r.Context, OperationId: operation, TargetOwner: targetOwner, TargetDatabase: targetDatabase, JournalCut: journalCut, RestoreEpoch: restoreEpoch}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	response, err := c.lifecycle.RestoreStats(metadata.NewOutgoingContext(ctx, c.scope), request)
	if err != nil {
		return nil, err
	}
	if response.GetOperationId() != operation || response.GetTargetOwner() != targetOwner || response.GetTargetDatabase() != targetDatabase || response.GetJournalCut() != journalCut || response.GetRowCount() < 0 || response.GetChecksum() == "" {
		return nil, errors.New("TBEP restore stats response is unbound or incomplete")
	}
	return response, nil
}

// EnsureSnapshot invokes the authenticated native snapshot operation.
func (c *Client) EnsureSnapshot(ctx context.Context, a LifecycleAssignment, operation string) error {
	r, err := c.lifecycleRequest(a, operation)
	if err != nil {
		return err
	}
	return c.lifecycleCall(ctx, r, func(ctx context.Context, req *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.lifecycle.EnsureSnapshot(ctx, req)
	})
}

// VerifySnapshotPlacement verifies the accepted placement before snapshot visibility.
func (c *Client) VerifySnapshotPlacement(ctx context.Context, a LifecycleAssignment, operation string) error {
	r, err := c.lifecycleRequest(a, operation)
	if err != nil {
		return err
	}
	return c.lifecycleCall(ctx, r, func(ctx context.Context, req *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.lifecycle.VerifySnapshotPlacement(ctx, req)
	})
}

// CloseDatabase closes serving while retaining the same database identity.
func (c *Client) CloseDatabase(ctx context.Context, a LifecycleAssignment, operation string) error {
	r, err := c.lifecycleRequest(a, operation)
	if err != nil {
		return err
	}
	return c.lifecycleCall(ctx, r, func(ctx context.Context, req *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.lifecycle.CloseDatabase(ctx, req)
	})
}

// StopNativeBackup stops only the selected database backup stream.
func (c *Client) StopNativeBackup(ctx context.Context, a LifecycleAssignment, operation string) error {
	r, err := c.lifecycleRequest(a, operation)
	if err != nil {
		return err
	}
	return c.lifecycleCall(ctx, r, func(ctx context.Context, req *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.lifecycle.StopNativeBackup(ctx, req)
	})
}

// Reactivate resumes the same retained database.
func (c *Client) Reactivate(ctx context.Context, a LifecycleAssignment, operation string) error {
	r, err := c.lifecycleRequest(a, operation)
	if err != nil {
		return err
	}
	return c.lifecycleCall(ctx, r, func(ctx context.Context, req *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.lifecycle.Reactivate(ctx, &pb.LifecycleReactivateRequest{Request: req})
	})
}

// DeleteOwnedData deletes only data owned by this member after authority validation.
func (c *Client) DeleteOwnedData(ctx context.Context, a LifecycleAssignment, operation string) error {
	r, err := c.lifecycleRequest(a, operation)
	if err != nil {
		return err
	}
	return c.lifecycleCall(ctx, r, func(ctx context.Context, req *pb.LifecycleControlRequest) (*pb.LifecycleControlResponse, error) {
		return c.lifecycle.DeleteOwnedData(ctx, req)
	})
}

func validMetadata(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func validIdentity(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && u.Hostname() == u.Host && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" && u.Path != "" && u.String() == value && validMetadata(value, 128)
}

// Observation preserves separate RPC results; these are sequential samples,
// not an atomic snapshot, placement acceptance, or a backup readiness receipt.
type Observation struct {
	Health   *pb.MaintenanceServiceSupervisionHealthResponse
	Topology *pb.MaintenanceServiceTopologyReadResponse
	Admin    *pb.MaintenanceServiceAdminStatusResponse
	CatchUp  *pb.MaintenanceServiceCatchUpStatusResponse
}

// Observe has one deadline for the complete operation and replaces inherited
// outgoing metadata so a caller cannot add duplicate or foreign scope values.
// Any unavailable RPC or invalid closed vocabulary fails the whole sample.
func (c *Client) Observe(ctx context.Context) (Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, c.scope.Copy())
	health, err := c.maintenance.SupervisionHealth(ctx, &pb.MaintenanceServiceSupervisionHealthRequest{})
	if err != nil {
		return Observation{}, fmt.Errorf("TBEP supervision health: %w", err)
	}
	if health.State < pb.HealthState_HEALTH_STATE_STARTING || health.State > pb.HealthState_HEALTH_STATE_STOPPED {
		return Observation{}, errors.New("TBEP health returned unknown state")
	}
	topology, err := c.maintenance.TopologyRead(ctx, &pb.MaintenanceServiceTopologyReadRequest{})
	if err != nil {
		return Observation{}, fmt.Errorf("TBEP topology: %w", err)
	}
	// A pending control listener can honestly report no engine topology. Its
	// unknown cluster and registry values never establish serving readiness.
	pending := !topology.EngineTopologyAvailable && health.State != pb.HealthState_HEALTH_STATE_SERVING
	unknownCluster := topology.ClusterMode == pb.ClusterMode_CLUSTER_MODE_UNSPECIFIED && pending
	if topology.Binding != pb.BindingKind_BINDING_KIND_NETWORK_MTLS || (!unknownCluster && topology.ClusterMode < pb.ClusterMode_CLUSTER_MODE_STANDALONE) || topology.ClusterMode > pb.ClusterMode_CLUSTER_MODE_BACKUP || len(topology.Subsystems) > 16 {
		return Observation{}, errors.New("TBEP topology returned invalid binding, cluster mode, or subsystem count")
	}
	for _, subsystem := range topology.Subsystems {
		if !validMetadata(subsystem, 128) {
			return Observation{}, errors.New("TBEP topology returned invalid subsystem")
		}
	}
	admin, err := c.maintenance.AdminStatus(ctx, &pb.MaintenanceServiceAdminStatusRequest{})
	if err != nil {
		return Observation{}, fmt.Errorf("TBEP admin status: %w", err)
	}
	if !validMetadata(admin.RegistryVersion, 128) && !(pending && admin.RegistryVersion == "") {
		return Observation{}, errors.New("TBEP admin status returned invalid registry version")
	}
	catchup, err := c.maintenance.CatchUpStatus(ctx, &pb.MaintenanceServiceCatchUpStatusRequest{})
	if err != nil {
		return Observation{}, fmt.Errorf("TBEP catchup status: %w", err)
	}
	if err := validateCatchUp(catchup); err != nil {
		return Observation{}, err
	}
	return Observation{Health: health, Topology: topology, Admin: admin, CatchUp: catchup}, nil
}

func (c *Client) Close() error { return c.conn.Close() }
