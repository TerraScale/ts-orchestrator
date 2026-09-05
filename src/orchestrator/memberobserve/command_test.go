package memberobserve

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestObserveMemberConfigRejectsAmbiguity(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `{"endpoint":"a","endpoint":"b"}`, `{"Endpoint":"a"}`, `{"endpoint":123}`, `{"endpoint":null}`, `{"unknown":"private-secret"}`} {
		if _, err := parseObservationConfig([]byte(input)); err == nil {
			t.Fatalf("accepted invalid config %s", input)
		}
	}
	complete := `{"endpoint":"127.0.0.1:50051","serverIdentity":"spiffe://test/host/a/terrabase","tenant":"tenant","project":"project","database":"database","timeout":"5s","certificateFile":"client.pem","privateKeyFile":"key.pem","trustBundleFile":"ca.pem"}`
	if _, err := parseObservationConfig([]byte(complete)); err != nil {
		t.Fatal(err)
	}
	if _, err := parseObservationConfig([]byte(complete + ` {}`)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
}

type observedMemberServer struct {
	pb.UnimplementedMaintenanceServiceServer
}

func (observedMemberServer) SupervisionHealth(context.Context, *pb.MaintenanceServiceSupervisionHealthRequest) (*pb.MaintenanceServiceSupervisionHealthResponse, error) {
	return &pb.MaintenanceServiceSupervisionHealthResponse{State: pb.HealthState_HEALTH_STATE_DRAINING, FramesServed: 17}, nil
}
func (observedMemberServer) TopologyRead(context.Context, *pb.MaintenanceServiceTopologyReadRequest) (*pb.MaintenanceServiceTopologyReadResponse, error) {
	return &pb.MaintenanceServiceTopologyReadResponse{Binding: pb.BindingKind_BINDING_KIND_NETWORK_MTLS, ClusterMode: pb.ClusterMode_CLUSTER_MODE_STANDALONE, EngineTopologyAvailable: false}, nil
}
func (observedMemberServer) AdminStatus(context.Context, *pb.MaintenanceServiceAdminStatusRequest) (*pb.MaintenanceServiceAdminStatusResponse, error) {
	return &pb.MaintenanceServiceAdminStatusResponse{RegistryVersion: "1.0", Scopes: 2}, nil
}

func TestObserveMemberExecuteRealMTLS(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(identity string, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		uri, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(usage) + 10), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{uri}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	}
	serverIdentity := "spiffe://test/GRU/host/a/terrabase"
	clientIdentity := "spiffe://test/GRU/host/a/orchestrator"
	serverPEM, serverKey := issue(serverIdentity, x509.ExtKeyUsageServerAuth)
	serverCert, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})), grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		for key, value := range map[string]string{"x-tb-principal": clientIdentity, "x-tb-tenant": "tenant", "x-tb-project": "project", "x-tb-database": "database"} {
			if got := md.Get(key); len(got) != 1 || got[0] != value {
				return nil, status.Error(codes.PermissionDenied, "scope mismatch")
			}
		}
		return next(ctx, req)
	}))
	pb.RegisterMaintenanceServiceServer(server, observedMemberServer{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	dir := t.TempDir()
	certPEM, keyPEM := issue(clientIdentity, x509.ExtKeyUsageClientAuth)
	for name, data := range map[string][]byte{"client.pem": certPEM, "key.pem": keyPEM, "ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	configuration := map[string]string{"endpoint": listener.Addr().String(), "serverIdentity": serverIdentity, "tenant": "tenant", "project": "project", "database": "database", "timeout": "2s", "certificateFile": "client.pem", "privateKeyFile": "key.pem", "trustBundleFile": "ca.pem"}
	data, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "observe.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(context.Background(), []string{"observe-member", "--config", path}, &output); err != nil {
		t.Fatal(err)
	}
	var facts memberObservationFacts
	if err := json.Unmarshal(output.Bytes(), &facts); err != nil {
		t.Fatal(err)
	}
	if facts.ServerIdentity != serverIdentity || facts.Health.State != "HEALTH_STATE_DRAINING" || facts.Health.FramesServed != 17 || facts.Topology.EngineTopologyAvailable || facts.Admin.Scopes != 2 || facts.ObservedAt.IsZero() {
		t.Fatalf("unexpected reported facts: %+v", facts)
	}
	if strings.Contains(output.String(), "PRIVATE KEY") || strings.Contains(output.String(), "ready") {
		t.Fatal("output leaked a secret or claimed readiness")
	}
	// Configuration failures stay actionable without quoting file paths or PEM.
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte("private-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	err = Run(context.Background(), []string{"observe-member", "--config", path}, &output)
	if err == nil || !strings.Contains(err.Error(), "matching PEM") || strings.Contains(err.Error(), "private-secret") || output.Len() != 0 {
		t.Fatalf("invalid key error: %v", err)
	}
}

func TestObservationFilesRejectSpecialFilesAndBounds(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("oversized"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readObservationFile(file, 4); err == nil {
		t.Fatal("accepted oversized file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readObservationFile(link, 100); err == nil {
		t.Fatal("followed credential symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readObservationFile(fifo, 100); err == nil {
		t.Fatal("accepted FIFO")
	}
}
