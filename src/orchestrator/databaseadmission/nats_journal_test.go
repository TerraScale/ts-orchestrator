package databaseadmission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"errors"
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
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

type admissionJournalCluster struct {
	servers []*natsserver.Server
	options []*natsserver.Options
	tls     *tls.Config
	root    string
	key     nkeys.KeyPair
	public  string
}

func newAdmissionJournalCluster(t *testing.T) *admissionJournalCluster {
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
	cluster := &admissionJournalCluster{key: userKey, public: public, root: t.TempDir(), tls: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}}
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
func (cluster *admissionJournalCluster) stop() {
	for _, server := range cluster.servers {
		server.Shutdown()
	}
	for _, server := range cluster.servers {
		server.WaitForShutdown()
	}
}
func (cluster *admissionJournalCluster) restart(t *testing.T) {
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
		if !server.ReadyForConnections(5 * time.Second) {
			t.Fatal("NATS restart failed")
		}
		cluster.servers = append(cluster.servers, server)
	}
}
func (cluster *admissionJournalCluster) connect(t *testing.T) *nats.Conn {
	t.Helper()
	connection, err := nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", cluster.options[0].Port), nats.Secure(cluster.tls.Clone()), nats.Nkey(cluster.public, cluster.key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}
func admissionLease(epoch int64, candidate string) authority.RegionalAuthorityLeaseDocument {
	return authority.RegionalAuthorityLeaseDocument{SchemaVersion: 1, AuthorityId: "global", Epoch: epoch, CandidateId: candidate, LeaseId: fmt.Sprintf("lease-%d", epoch), IssuedAt: time.Now().UTC(), DurationMilliseconds: 60000}
}
func putAdmissionLease(t *testing.T, ctx context.Context, store jetstream.KeyValue, lease authority.RegionalAuthorityLeaseDocument) {
	t.Helper()
	data, _ := json.Marshal(lease)
	if _, err := store.Put(ctx, "authority.global", data); err != nil {
		t.Fatal(err)
	}
}
func openAdmissionLeaseStore(t *testing.T, ctx context.Context, connection *nats.Conn, create bool) jetstream.KeyValue {
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
func newAdmissionJournalClient(t *testing.T, connection *nats.Conn, epoch uint64, candidate string) *NATSJournal {
	t.Helper()
	journal, err := NewNATSJournal(NATSJournalConfig{Connection: connection, CandidateID: candidate, AuthorityEpoch: epoch, LeaseID: fmt.Sprintf("lease-%d", epoch)})
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestNATSAdmissionJournalRestartAndAuthorityFencing(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	connection := cluster.connect(t)
	store := openAdmissionLeaseStore(t, ctx, connection, true)
	const candidate = "global-controller-gru-one"
	putAdmissionLease(t, ctx, store, admissionLease(1, candidate))
	journal := newAdmissionJournalClient(t, connection, 1, candidate)
	record := journalFixture(t)
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	key := ScopeKey(record.Request)
	revision, err := journal.Save(ctx, key, 0, record)
	if err != nil || revision != 1 {
		t.Fatalf("accept revision=%d err=%v", revision, err)
	}
	lifecycleRevision, resources, err := journal.LifecycleResources(ctx)
	if err != nil || lifecycleRevision != 1 || len(resources) != 1 || resources[0].DatabaseID != record.DatabaseID {
		t.Fatalf("create/inventory not atomic: %d %+v %v", lifecycleRevision, resources, err)
	}
	route := databaselifecycle.Event{Identity: resources[0].Identity, OperationID: "initial-routing", Kind: "streams", At: record.CreatedAt, Streams: []databaselifecycle.Stream{{Region: "GRU", Partition: "root", Epoch: 1, StartedAt: record.CreatedAt}}}
	if err := journal.ApplyLifecycle(ctx, route); err != nil {
		t.Fatal(err)
	}
	closed, err := journal.FreezeInventory(ctx, record.Request.TenantID, record.CreatedAt, record.CreatedAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Ignore the create response and reconstruct both the process and R3 servers.
	cluster.restart(t)
	connection = cluster.connect(t)
	store = openAdmissionLeaseStore(t, ctx, connection, false)
	putAdmissionLease(t, ctx, store, admissionLease(2, "global-controller-gru-two"))
	stale := newAdmissionJournalClient(t, connection, 1, candidate)
	if _, _, err := stale.Load(ctx, key); !errors.Is(err, ErrEpochFenced) {
		t.Fatalf("old authority read: %v", err)
	}
	successor := newAdmissionJournalClient(t, connection, 2, "global-controller-gru-two")
	recovered, found, err := successor.Load(ctx, key)
	if err != nil || !found || recovered.DatabaseID != record.DatabaseID || recovered.Revision != 1 || !ImmutableEqual(recovered, record) {
		t.Fatalf("recovery found=%v err=%v record=%+v", found, err, recovered)
	}
	replayed, err := successor.FreezeInventory(ctx, record.Request.TenantID, closed.Start, closed.End)
	if err != nil || replayed.Digest != closed.Digest || replayed.Revision != closed.Revision {
		t.Fatalf("lost closed inventory: %+v %v", replayed, err)
	}
	recovered.State = "keys_provisioned"
	recovered.Wrapped = journalWrapped(recovered)
	recovered.Revision, err = successor.Save(ctx, key, recovered.Revision, recovered)
	if err != nil {
		t.Fatal(err)
	}
	restarted := newAdmissionJournalClient(t, connection, 2, "global-controller-gru-two")
	loaded, _, err := restarted.Load(ctx, key)
	if err != nil || loaded.Wrapped[0].Ciphertext != recovered.Wrapped[0].Ciphertext {
		t.Fatalf("lost ciphertext: %v", err)
	}
	// A same-candidate/same-epoch replacement lease still fences the old client.
	replacement := admissionLease(2, "global-controller-gru-two")
	replacement.LeaseId = "different-live-lease"
	putAdmissionLease(t, ctx, store, replacement)
	if _, err := restarted.Save(ctx, key, loaded.Revision, loaded); !errors.Is(err, ErrEpochFenced) {
		t.Fatalf("stale exact lease wrote: %v", err)
	}
	live, err := NewNATSJournal(NATSJournalConfig{Connection: connection, CandidateID: replacement.CandidateId, AuthorityEpoch: uint64(replacement.Epoch), LeaseID: replacement.LeaseId})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.List(ctx); err != nil {
		t.Fatal(err)
	}
	for _, server := range cluster.servers[1:] {
		server.Shutdown()
		server.WaitForShutdown()
	}
	outage, outageCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer outageCancel()
	if _, err := live.List(outage); err == nil {
		t.Fatal("minority served authoritative operations")
	}
}
