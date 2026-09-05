package tbep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

const serverIdentity = "spiffe://terrascale.test/region/GRU/host/a/terrabase"
const clientIdentity = "spiffe://terrascale.test/region/GRU/host/a/orchestrator"

type testCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TBEP test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return testCA{cert, key, roots}
}
func (ca testCA) issue(t *testing.T, identities []string, usage x509.ExtKeyUsage, expired bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if expired {
		template.NotAfter = time.Now().Add(-time.Minute)
	}
	for _, identity := range identities {
		u, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = append(template.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type maintenanceServer struct {
	pb.UnimplementedMaintenanceServiceServer
	calls   atomic.Int32
	delay   bool
	unknown bool
	reject  bool
}

func (s *maintenanceServer) SupervisionHealth(ctx context.Context, _ *pb.MaintenanceServiceSupervisionHealthRequest) (*pb.MaintenanceServiceSupervisionHealthResponse, error) {
	s.calls.Add(1)
	if s.delay {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	if s.reject {
		return nil, status.Error(codes.Unavailable, "unavailable")
	}
	state := pb.HealthState_HEALTH_STATE_SERVING
	if s.unknown {
		state = 99
	}
	return &pb.MaintenanceServiceSupervisionHealthResponse{State: state, FramesServed: 42}, nil
}
func (s *maintenanceServer) TopologyRead(context.Context, *pb.MaintenanceServiceTopologyReadRequest) (*pb.MaintenanceServiceTopologyReadResponse, error) {
	s.calls.Add(1)
	return &pb.MaintenanceServiceTopologyReadResponse{Binding: pb.BindingKind_BINDING_KIND_NETWORK_MTLS, ClusterMode: pb.ClusterMode_CLUSTER_MODE_STANDALONE, Subsystems: []string{"engine"}, EngineTopologyAvailable: false}, nil
}
func (s *maintenanceServer) AdminStatus(context.Context, *pb.MaintenanceServiceAdminStatusRequest) (*pb.MaintenanceServiceAdminStatusResponse, error) {
	s.calls.Add(1)
	return &pb.MaintenanceServiceAdminStatusResponse{RegistryVersion: "1.0"}, nil
}

func startServer(t *testing.T, ca testCA, cert tls.Certificate, version uint16, implementation *maintenanceServer) Config {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{cert}, ClientCAs: ca.roots, ClientAuth: tls.RequireAndVerifyClientCert})), grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		for key, want := range map[string]string{"x-tb-principal": clientIdentity, "x-tb-tenant": "tenant", "x-tb-project": "project", "x-tb-database": "database"} {
			got := md.Get(key)
			if len(got) != 1 || got[0] != want {
				return nil, status.Error(codes.PermissionDenied, "scope mismatch")
			}
		}
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no peer")
		}
		auth, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(auth.State.PeerCertificates[0].URIs) != 1 || auth.State.PeerCertificates[0].URIs[0].String() != clientIdentity {
			return nil, status.Error(codes.Unauthenticated, "identity mismatch")
		}
		if _, ok := ctx.Deadline(); !ok {
			return nil, status.Error(codes.InvalidArgument, "missing deadline")
		}
		return handler(ctx, req)
	}))
	pb.RegisterMaintenanceServiceServer(server, implementation)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return Config{Endpoint: listener.Addr().String(), ServerIdentity: serverIdentity, Certificate: ca.issue(t, []string{clientIdentity}, x509.ExtKeyUsageClientAuth, false), Roots: ca.roots, Tenant: "tenant", Project: "project", Database: "database", Timeout: time.Second}
}

func TestObserveMTLSScopeAndRawState(t *testing.T) {
	ca := newTestCA(t)
	server := &maintenanceServer{}
	config := startServer(t, ca, ca.issue(t, []string{serverIdentity}, x509.ExtKeyUsageServerAuth, false), tls.VersionTLS13, server)
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-tb-tenant", "foreign", "x-tb-tenant", "duplicate"))
	observed, err := client.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Health.State != pb.HealthState_HEALTH_STATE_SERVING || observed.Topology.EngineTopologyAvailable || observed.Admin.RegistryVersion != "1.0" || server.calls.Load() != 3 {
		t.Fatalf("unexpected observation: %+v; calls %d", observed, server.calls.Load())
	}
}

func TestObserveRejectsUnauthenticatedHost(t *testing.T) {
	for _, scenario := range []string{"other-host", "multiple-identities", "untrusted-ca", "expired", "client-only-usage", "tls12", "untrusted-client"} {
		t.Run(scenario, func(t *testing.T) {
			ca := newTestCA(t)
			issuer := ca
			identities := []string{serverIdentity}
			usage := x509.ExtKeyUsageServerAuth
			version := uint16(tls.VersionTLS13)
			switch scenario {
			case "other-host":
				identities = []string{strings.Replace(serverIdentity, "/host/a/", "/host/b/", 1)}
			case "multiple-identities":
				identities = append(identities, clientIdentity)
			case "untrusted-ca":
				issuer = newTestCA(t)
			case "client-only-usage":
				usage = x509.ExtKeyUsageClientAuth
			case "tls12":
				version = tls.VersionTLS12
			}
			server := &maintenanceServer{}
			config := startServer(t, ca, issuer.issue(t, identities, usage, scenario == "expired"), version, server)
			if scenario == "untrusted-client" {
				config.Certificate = newTestCA(t).issue(t, []string{clientIdentity}, x509.ExtKeyUsageClientAuth, false)
			}
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.Observe(context.Background()); err == nil {
				t.Fatal("accepted unauthenticated server")
			}
			if server.calls.Load() != 0 {
				t.Fatal("request reached unauthenticated host")
			}
		})
	}
}

func TestObserveDeadlineAndNoRetry(t *testing.T) {
	for _, scenario := range []string{"deadline", "caller-cancel", "unknown-state", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			ca := newTestCA(t)
			server := &maintenanceServer{delay: scenario == "deadline", unknown: scenario == "unknown-state", reject: scenario == "unavailable"}
			config := startServer(t, ca, ca.issue(t, []string{serverIdentity}, x509.ExtKeyUsageServerAuth, false), tls.VersionTLS13, server)
			config.Timeout = 100 * time.Millisecond
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "caller-cancel" {
				cancel()
			}
			before := time.Now()
			_, err = client.Observe(ctx)
			if err == nil {
				t.Fatal("accepted failed sample")
			}
			if time.Since(before) > time.Second {
				t.Fatal("deadline not enforced")
			}
			if scenario == "deadline" && status.Code(err) != codes.DeadlineExceeded {
				t.Fatalf("deadline code: %v", err)
			}
			if scenario == "caller-cancel" {
				if server.calls.Load() != 0 {
					t.Fatal("canceled request reached server")
				}
			} else if server.calls.Load() != 1 {
				t.Fatalf("retried rejected observation: %d", server.calls.Load())
			}
		})
	}
}

func TestConfigRejectsRemoteAndInvalidScope(t *testing.T) {
	ca := newTestCA(t)
	base := Config{Endpoint: "127.0.0.1:50051", ServerIdentity: serverIdentity, Certificate: ca.issue(t, []string{clientIdentity}, x509.ExtKeyUsageClientAuth, false), Roots: ca.roots, Tenant: "tenant", Project: "project", Database: "database", Timeout: time.Second}
	for _, endpoint := range []string{"10.0.0.1:50051", "localhost:50051", "127.0.0.1:0", "dns:///remote:50051", "[::1]:65536"} {
		config := base
		config.Endpoint = endpoint
		if client, err := New(config); err == nil {
			client.Close()
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	for _, scope := range []string{"", "duplicate\nmetadata", strings.Repeat("t", 65)} {
		config := base
		config.Tenant = scope
		if client, err := New(config); err == nil {
			client.Close()
			t.Fatal("accepted invalid scope")
		}
	}
}
