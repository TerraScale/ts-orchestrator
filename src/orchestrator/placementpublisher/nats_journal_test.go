package placementpublisher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/jsontext"
	"encoding/json/v2"
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
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

type placementJournalCluster struct {
	servers []*natsserver.Server
	options []*natsserver.Options
	tls     *tls.Config
	root    string
	key     nkeys.KeyPair
	public  string
}

func newPlacementJournalCluster(t *testing.T) *placementJournalCluster {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "placement-journal-unit"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
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
	cluster := &placementJournalCluster{key: userKey, public: public, root: t.TempDir(), tls: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}}
	t.Cleanup(cluster.stop)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstClusterPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	route, _ := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", firstClusterPort))
	for index := 0; index < 3; index++ {
		options := &natsserver.Options{ServerName: fmt.Sprintf("placement-%d", index), Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(cluster.root, fmt.Sprint(index)), NoLog: true, NoSigs: true, SystemAccount: "$SYS", Accounts: []*natsserver.Account{natsserver.NewAccount("$SYS")}, Nkeys: []*natsserver.NkeyUser{{Nkey: public}}, TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}, Cluster: natsserver.ClusterOpts{Name: "placement-journal", Host: "127.0.0.1", Port: -1}}
		if index == 0 {
			options.Cluster.Port = firstClusterPort
		}
		if route != nil {
			options.Routes = []*url.URL{route}
		}
		// Keep restart metadata separate from options owned by the running server.
		server, err := natsserver.NewServer(options.Clone())
		if err != nil {
			t.Fatal(err)
		}
		cluster.servers = append(cluster.servers, server)
		server.Start()
		if !server.ReadyForConnections(30 * time.Second) {
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
func (cluster *placementJournalCluster) stop() {
	for _, server := range cluster.servers {
		server.Shutdown()
	}
	for _, server := range cluster.servers {
		server.WaitForShutdown()
	}
}
func (cluster *placementJournalCluster) restart(t *testing.T) {
	t.Helper()
	cluster.stop()
	cluster.servers = nil
	for _, options := range cluster.options {
		// Keep restart metadata separate from options owned by the running server.
		server, err := natsserver.NewServer(options.Clone())
		if err != nil {
			t.Fatal(err)
		}
		server.Start()
		if !server.ReadyForConnections(30 * time.Second) {
			t.Fatal("NATS restart failed")
		}
		cluster.servers = append(cluster.servers, server)
	}
}
func (cluster *placementJournalCluster) connect(t *testing.T) *nats.Conn {
	t.Helper()
	connection, err := nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", cluster.options[0].Port), nats.Secure(cluster.tls.Clone()), nats.Nkey(cluster.public, cluster.key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}
func placementLease(epoch int64, candidate string) authority.RegionalAuthorityLeaseDocument {
	return authority.RegionalAuthorityLeaseDocument{SchemaVersion: 1, AuthorityId: "global", Epoch: epoch, CandidateId: candidate, LeaseId: fmt.Sprintf("lease-%d", epoch), IssuedAt: time.Now().UTC(), DurationMilliseconds: 60000}
}
func putPlacementLease(t *testing.T, ctx context.Context, store jetstream.KeyValue, lease authority.RegionalAuthorityLeaseDocument) {
	t.Helper()
	data, _ := json.Marshal(lease)
	if _, err := store.Put(ctx, "authority.global", data); err != nil {
		t.Fatal(err)
	}
}
func openPlacementLeaseStore(t *testing.T, ctx context.Context, connection *nats.Conn, create bool) jetstream.KeyValue {
	t.Helper()
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	var store jetstream.KeyValue
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, time.Second)
		if create {
			store, err = js.CreateKeyValue(attemptCtx, jetstream.KeyValueConfig{Bucket: "ORCH_LEADERS", History: 1, Storage: jetstream.FileStorage, Replicas: 3, MaxBytes: 8 << 20})
		} else {
			store, err = js.KeyValue(attemptCtx, "ORCH_LEADERS")
		}
		attemptCancel()
		if err == nil {
			return store
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}
func newPlacementJournalClient(t *testing.T, connection *nats.Conn, epoch uint64, candidate string) *NATSJournal {
	t.Helper()
	journal, err := NewNATSJournal(NATSJournalConfig{Connection: connection, CandidateID: candidate, AuthorityEpoch: epoch, LeaseID: fmt.Sprintf("lease-%d", epoch)})
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestNATSPlacementJournalRestartFencingAndUnknownOutcome(t *testing.T) {
	cluster := newPlacementJournalCluster(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	connection := cluster.connect(t)
	store := openPlacementLeaseStore(t, ctx, connection, true)
	const candidate = "global-controller-gru-one"
	putPlacementLease(t, ctx, store, placementLease(1, candidate))
	journal := newPlacementJournalClient(t, connection, 1, candidate)
	target := newFakeTarget()
	publisher, err := New(journal, target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	if err := publisher.Accept(ctx, "op-1", request); err != nil {
		t.Fatal(err)
	}
	target.unknown = true
	if _, err := publisher.Reconcile(ctx); err == nil {
		t.Fatal("lost response treated as success")
	}
	replacement := testRequest()
	replacement.Proposal.Generation++
	replacement.Proposal.Epoch++
	if err := publisher.Accept(ctx, "op-2", replacement); err == nil {
		t.Fatal("unresolved intent replaced")
	}
	connection.Close()
	cluster.restart(t)
	connection = cluster.connect(t)
	store = openPlacementLeaseStore(t, ctx, connection, false)
	journal = newPlacementJournalClient(t, connection, 1, candidate)
	publisher, err = New(journal, target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.Reconcile(ctx)
	if err != nil || result.Revision != 1 || target.effects != 1 {
		t.Fatalf("retry result=%v effects=%d error=%v", result, target.effects, err)
	}
	if err := publisher.Accept(ctx, "op-2", replacement); err == nil {
		t.Fatal("wrong expected revision accepted")
	}
	replacement.ExpectedRevision = 1
	if err := publisher.Accept(ctx, "op-2", replacement); err != nil {
		t.Fatal(err)
	}
	putPlacementLease(t, ctx, store, placementLease(2, "global-controller-gru-two"))
	if _, err := publisher.Reconcile(ctx); err == nil {
		t.Fatal("old global controller dispatched")
	}
	if target.effects != 1 {
		t.Fatal("fenced dispatch reached engine")
	}
	successor := newPlacementJournalClient(t, connection, 2, "global-controller-gru-two")
	publisher, err = New(successor, target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	result, err = publisher.Reconcile(ctx)
	if err != nil || result.Revision != 2 {
		t.Fatalf("successor result=%v error=%v", result, err)
	}
	// Server-acknowledged messages arriving after lease expiry cannot replace the
	// accepted state, even when history=1 has discarded the preceding value.
	accepted, err := successor.Load(ctx, target.ServerIdentity())
	if err != nil {
		t.Fatal(err)
	}
	prior, _ := json.Marshal(placementJournalState{Hosts: map[string]Record{accepted.ServerIdentity: accepted}})
	invalid := placementJournalState{}
	invalid.Hosts = map[string]Record{}
	expired := placementLease(2, "global-controller-gru-two")
	expired.IssuedAt = time.Now().Add(-time.Minute)
	expired.DurationMilliseconds = 1
	payload, _ := json.Marshal(struct {
		SchemaVersion int
		Lease         authority.RegionalAuthorityLeaseDocument
		LeaseRevision uint64
		State         placementJournalState
		PriorState    jsontext.Value
	}{SchemaVersion: 1, Lease: expired, LeaseRevision: 1, State: invalid, PriorState: prior})
	jetStream, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jetStream.Publish(ctx, placementStateSubject, payload); err != nil {
		t.Fatal(err)
	}
	recovered, err := successor.Load(ctx, target.ServerIdentity())
	if err != nil || recovered.OperationID != "op-2" {
		t.Fatalf("late commit erased accepted intent: %v %v", recovered, err)
	}
	for _, server := range cluster.servers[1:] {
		server.Shutdown()
		server.WaitForShutdown()
	}
	outage, outageCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer outageCancel()
	if _, err := successor.Load(outage, target.ServerIdentity()); err == nil {
		t.Fatal("minority returned authoritative intent")
	}
}
