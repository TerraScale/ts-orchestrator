package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

type rotationStateCluster struct {
	servers       []*natsserver.Server
	options       []*natsserver.Options
	tls           *tls.Config
	root          string
	key           nkeys.KeyPair
	public        string
	sessionKey    nkeys.KeyPair
	sessionPublic string
}

func newRotationStateCluster(t *testing.T) *rotationStateCluster {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rotation-state-unit"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	userKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	public, err := userKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	cluster := &rotationStateCluster{key: userKey, public: public, root: t.TempDir(), tls: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}}
	sessionKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	sessionPublic, err := sessionKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	cluster.sessionKey, cluster.sessionPublic = sessionKey, sessionPublic
	plan, err := control.GlobalNatsPermissionsCreate("gru", control.GlobalNatsRoleGlobalAuthority)
	if err != nil {
		t.Fatal(err)
	}
	permissions := &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: plan.Publish}, Subscribe: &natsserver.SubjectPermission{Allow: plan.Subscribe}}
	t.Cleanup(cluster.stop)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstClusterPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	route, _ := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", firstClusterPort))
	for index := 0; index < 3; index++ {
		options := &natsserver.Options{ServerName: fmt.Sprintf("rotation-%d", index), Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(cluster.root, fmt.Sprint(index)), NoLog: true, NoSigs: true, SystemAccount: "$SYS", Accounts: []*natsserver.Account{natsserver.NewAccount("$SYS")}, Nkeys: []*natsserver.NkeyUser{{Nkey: public}, {Nkey: sessionPublic, Permissions: permissions}}, TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}, Cluster: natsserver.ClusterOpts{Name: "rotation-state", Host: "127.0.0.1", Port: -1}}
		if index == 0 {
			options.Cluster.Port = firstClusterPort
		}
		if route != nil {
			options.Routes = []*url.URL{route}
		}
		server, err := natsserver.NewServer(options)
		if err != nil {
			t.Fatal(err)
		}
		cluster.servers = append(cluster.servers, server)
		server.Start()
		if !server.ReadyForConnections(5 * time.Second) {
			t.Fatal("real NATS cluster listener did not start")
		}
		options.Port = server.Addr().(*net.TCPAddr).Port
		options.Cluster.Port = server.ClusterAddr().Port
		if route == nil {
			route, _ = url.Parse("nats-route://" + server.ClusterAddr().String())
		}
		cluster.options = append(cluster.options, options)
	}
	t.Cleanup(cluster.stop)
	return cluster
}
func (cluster *rotationStateCluster) stop() {
	for _, server := range cluster.servers {
		server.Shutdown()
	}
	for _, server := range cluster.servers {
		server.WaitForShutdown()
	}
}
func (cluster *rotationStateCluster) connect(t *testing.T) *nats.Conn {
	t.Helper()
	connection, err := nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", cluster.options[0].Port), nats.Secure(cluster.tls.Clone()), nats.Nkey(cluster.public, cluster.key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}
func rotationTestLease(epoch int64, candidate string) authority.RegionalAuthorityLeaseDocument {
	return authority.RegionalAuthorityLeaseDocument{SchemaVersion: 1, AuthorityId: "global", Epoch: epoch, CandidateId: candidate, LeaseId: fmt.Sprintf("lease-%d", epoch), IssuedAt: time.Now().UTC(), DurationMilliseconds: 60000}
}
func putRotationTestLease(t *testing.T, ctx context.Context, store jetstream.KeyValue, lease authority.RegionalAuthorityLeaseDocument) {
	t.Helper()
	data, _ := json.Marshal(lease)
	if _, err := store.Put(ctx, "authority.global", data); err != nil {
		t.Fatal(err)
	}
}
func openRotationTestLeaseStore(t *testing.T, ctx context.Context, connection *nats.Conn, create bool) jetstream.KeyValue {
	t.Helper()
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	setupCtx, stopSetup := context.WithTimeout(ctx, 45*time.Second)
	defer stopSetup()
	var store jetstream.KeyValue
	var lastErr error
	for setupCtx.Err() == nil {
		attemptCtx, stopAttempt := context.WithTimeout(setupCtx, 3*time.Second)
		if create {
			store, err = js.CreateKeyValue(attemptCtx, jetstream.KeyValueConfig{Bucket: "ORCH_LEADERS", History: 1, Storage: jetstream.FileStorage, Replicas: 3, MaxBytes: 8 << 20})
		} else {
			store, err = js.KeyValue(attemptCtx, "ORCH_LEADERS")
		}
		if err == nil {
			var stream jetstream.Stream
			stream, err = js.Stream(attemptCtx, "KV_ORCH_LEADERS")
			if err == nil {
				var info *jetstream.StreamInfo
				info, err = stream.Info(attemptCtx)
				if err == nil && !rotationTestQuorumReady(info) {
					err = fmt.Errorf("R3 leader and both current replicas are not ready")
				}
			}
		}
		stopAttempt()
		if err == nil {
			return store
		}
		lastErr = err
		select {
		case <-setupCtx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("rotation fixture R3 readiness timed out: %v (last observation: %v)", setupCtx.Err(), lastErr)
	return nil
}

func rotationTestQuorumReady(info *jetstream.StreamInfo) bool {
	if info == nil || info.Config.Replicas != 3 || info.Cluster == nil || info.Cluster.Leader == "" || len(info.Cluster.Replicas) != 2 {
		return false
	}
	for _, replica := range info.Cluster.Replicas {
		if replica == nil || !replica.Current || replica.Offline {
			return false
		}
	}
	return true
}

func (cluster *rotationStateCluster) sessionConnect(ctx context.Context) (*nats.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", cluster.options[0].Port), nats.Secure(cluster.tls.Clone()), nats.Nkey(cluster.sessionPublic, cluster.sessionKey.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1), nats.Timeout(time.Second))
}
