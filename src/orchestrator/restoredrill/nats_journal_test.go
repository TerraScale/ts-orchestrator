package restoredrill

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

type restoreJournalCluster struct {
	servers []*natsserver.Server
	options []*natsserver.Options
	tls     *tls.Config
	root    string
	key     nkeys.KeyPair
	public  string
}

func newRestoreJournalCluster(t *testing.T) *restoreJournalCluster {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "restore-journal-unit"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
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
	cluster := &restoreJournalCluster{key: userKey, public: public, root: t.TempDir(), tls: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}}
	t.Cleanup(cluster.stop)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstClusterPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	route, _ := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", firstClusterPort))
	for index := 0; index < 3; index++ {
		options := &natsserver.Options{ServerName: fmt.Sprintf("restore-%d", index), Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(cluster.root, fmt.Sprint(index)), NoLog: true, NoSigs: true, SystemAccount: "$SYS", Accounts: []*natsserver.Account{natsserver.NewAccount("$SYS")}, Nkeys: []*natsserver.NkeyUser{{Nkey: public}}, TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}, Cluster: natsserver.ClusterOpts{Name: "restore-journal", Host: "127.0.0.1", Port: -1}}
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
func (cluster *restoreJournalCluster) stop() {
	for _, server := range cluster.servers {
		server.Shutdown()
	}
	for _, server := range cluster.servers {
		server.WaitForShutdown()
	}
}
func (cluster *restoreJournalCluster) restart(t *testing.T) {
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
func (cluster *restoreJournalCluster) connect(t *testing.T) *nats.Conn {
	t.Helper()
	connection, err := nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", cluster.options[0].Port), nats.Secure(cluster.tls.Clone()), nats.Nkey(cluster.public, cluster.key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}
func restoreLease(epoch int64, candidate string) authority.RegionalAuthorityLeaseDocument {
	return authority.RegionalAuthorityLeaseDocument{SchemaVersion: 1, AuthorityId: "global", Epoch: epoch, CandidateId: candidate, LeaseId: fmt.Sprintf("lease-%d", epoch), IssuedAt: time.Now().UTC(), DurationMilliseconds: 60000}
}
func putRestoreLease(t *testing.T, ctx context.Context, store jetstream.KeyValue, lease authority.RegionalAuthorityLeaseDocument) {
	t.Helper()
	data, _ := json.Marshal(lease)
	if _, err := store.Put(ctx, "authority.global", data); err != nil {
		t.Fatal(err)
	}
}
func openRestoreLeaseStore(t *testing.T, ctx context.Context, connection *nats.Conn, create bool) jetstream.KeyValue {
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
func newRestoreJournalClient(t *testing.T, connection *nats.Conn, epoch uint64, candidate string) *NATSJournal {
	t.Helper()
	journal, err := NewNATSJournal(NATSJournalConfig{Connection: connection, CandidateID: candidate, AuthorityEpoch: epoch, LeaseID: fmt.Sprintf("lease-%d", epoch)})
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestNATSRestoreJournalRestartEpochCASAndMinorityOutage(t *testing.T) {
	cluster := newRestoreJournalCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection := cluster.connect(t)
	store := openRestoreLeaseStore(t, ctx, connection, true)
	const candidate = "global-controller-gru-one"
	putRestoreLease(t, ctx, store, restoreLease(1, candidate))
	journal := newRestoreJournalClient(t, connection, 1, candidate)
	facts := JournalFacts{JournalCut: "immutable-source-cut-7", Checksum: "actual-fixture-checksum", RowCount: 42}
	if err := journal.RecordFacts(ctx, "database", facts); err != nil {
		t.Fatal(err)
	}
	epoch, err := journal.ClaimRestoreEpoch(ctx, "database", "run-1/database")
	if err != nil || epoch != 1 {
		t.Fatalf("claim=%d error=%v", epoch, err)
	}
	item := ItemRecord{Key: "run-1/database", RunID: "run-1", DatabaseID: "database", RestoreEpoch: epoch, Expected: facts, Status: ItemRunning, StartedAt: time.Now().UTC()}
	if err := journal.SaveItem(ctx, item); err != nil {
		t.Fatal(err)
	}
	run := RunRecord{ID: "run-1", ScheduledAt: time.Now().UTC(), StartedAt: item.StartedAt, Status: RunRunning, DatabaseIDs: []string{"database"}, Items: []ItemRecord{item}}
	if err := journal.SaveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	cluster.restart(t)
	connection = cluster.connect(t)
	store = openRestoreLeaseStore(t, ctx, connection, false)
	// A new object and restarted servers must recover durable bytes, not maps
	// retained by the old adapter or the old JetStream processes.
	journal = newRestoreJournalClient(t, connection, 1, candidate)
	loaded, found, err := journal.LoadRun(ctx, run.ID)
	if err != nil || !found || len(loaded.Items) != 1 || loaded.Items[0].RestoreEpoch != 1 {
		t.Fatalf("restart run: %+v %v %v", loaded, found, err)
	}
	loadedFacts, err := journal.Facts(ctx, "database", "item")
	if err != nil || loadedFacts != facts {
		t.Fatalf("restart facts: %+v %v", loadedFacts, err)
	}
	again, err := journal.ClaimRestoreEpoch(ctx, "database", item.Key)
	if err != nil || again != 1 {
		t.Fatalf("idempotent claim=%d %v", again, err)
	}
	second, err := journal.ClaimRestoreEpoch(ctx, "database", "run-2/database")
	if err != nil || second != 2 {
		t.Fatalf("next claim=%d %v", second, err)
	}
	if current, err := journal.RestoreEpochCurrent(ctx, "database", 1); err != nil || current {
		t.Fatalf("stale restore epoch current=%v %v", current, err)
	}
	item.Status = ItemSucceeded
	if err := journal.SaveItem(ctx, item); !errors.Is(err, ErrRestoreEpochFenced) {
		t.Fatalf("stale item writer accepted: %v", err)
	}
	// A lease transition and journal publication share one stream sequence.
	// The exact pre-transition snapshot cannot be published after takeover.
	snapshot, err := journal.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a real in-flight publication reaching JetStream after expiry.
	// History=1 removes the previous value, so recovery must be self-contained.
	shortLease := restoreLease(1, candidate)
	shortLease.DurationMilliseconds = 150
	putRestoreLease(t, ctx, store, shortLease)
	lateSnapshot, err := journal.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prior, _ := json.Marshal(lateSnapshot.state)
	var proposed restoreJournalState
	if err := json.Unmarshal(prior, &proposed); err != nil {
		t.Fatal(err)
	}
	delete(proposed.Runs, run.ID)
	lateEnvelope := restoreJournalEnvelope{SchemaVersion: 1, Lease: lateSnapshot.lease, LeaseRevision: lateSnapshot.leaseRevision, State: proposed, PriorState: prior}
	latePayload, _ := json.Marshal(lateEnvelope)
	time.Sleep(time.Until(shortLease.IssuedAt.Add(200 * time.Millisecond)))
	if _, err := journal.js.Publish(ctx, restoreStateSubject, latePayload, jetstream.WithExpectLastSequence(lateSnapshot.sequence)); err != nil {
		t.Fatal(err)
	}
	const successor = "global-controller-gru-two"
	putRestoreLease(t, ctx, store, restoreLease(2, successor))
	if _, err := journal.js.Publish(ctx, restoreStateSubject, []byte("invalid-old-writer"), jetstream.WithExpectStream(restoreJournalStream), jetstream.WithExpectLastSequence(snapshot.sequence)); err == nil {
		t.Fatal("same-stream lease CAS did not fence old snapshot")
	}
	if err := journal.RecordFacts(ctx, "database", facts); !errors.Is(err, ErrRestoreEpochFenced) {
		t.Fatalf("old authority wrote after takeover: %v", err)
	}
	journal = newRestoreJournalClient(t, connection, 2, successor)
	if _, found, err := journal.LoadItem(ctx, item.Key); err != nil || !found {
		t.Fatalf("new authority lost history: %v %v", found, err)
	}
	if restored, found, err := journal.LoadRun(ctx, run.ID); err != nil || !found || restored.ID != run.ID {
		t.Fatalf("late commit erased prior valid run with history=1: %+v %v %v", restored, found, err)
	}
	healed, err := journal.snapshot(ctx)
	if err != nil || healed.recovered {
		t.Fatalf("successor did not durably heal late commit: %+v %v", healed, err)
	}
	large := RunRecord{ID: "large-bounded-run", StartedAt: time.Now().UTC(), Status: RunFailed, Error: strings.Repeat("x", 440<<10)}
	if err := journal.SaveRun(ctx, large); err != nil {
		t.Fatal(err)
	}
	large.Error = strings.Repeat("y", 440<<10)
	if err := journal.SaveRun(ctx, large); err != nil {
		t.Fatal(err)
	}
	if loaded, found, err := journal.LoadRun(ctx, large.ID); err != nil || !found || loaded.Error != large.Error {
		t.Fatalf("bounded 880KiB envelope failed base64 MSG.GET readback: %v %v", found, err)
	}
	cluster.servers[1].Shutdown()
	cluster.servers[2].Shutdown()
	cluster.servers[1].WaitForShutdown()
	cluster.servers[2].WaitForShutdown()
	outageCtx, outageCancel := context.WithTimeout(context.Background(), time.Second)
	defer outageCancel()
	if _, _, err := journal.LoadRun(outageCtx, run.ID); err == nil {
		t.Fatal("minority outage returned cached journal success")
	}
}

func TestNATSRestoreJournalConcurrentClaimsAndExpiredAuthority(t *testing.T) {
	cluster := newRestoreJournalCluster(t)
	connection := cluster.connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	store := openRestoreLeaseStore(t, ctx, connection, true)
	for _, mode := range []string{"unverified-tls", "reconnect-buffer"} {
		clientTLS := cluster.tls.Clone()
		options := []nats.Option{nats.Secure(clientTLS), nats.Nkey(cluster.public, cluster.key.Sign)}
		if mode == "unverified-tls" {
			clientTLS.InsecureSkipVerify = true
			options = append(options, nats.NoReconnect(), nats.ReconnectBufSize(-1))
		}
		unsafeConnection, err := nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", cluster.options[0].Port), options...)
		if err != nil {
			t.Fatal("negative fixture failed to establish intended transport")
		}
		_, err = NewNATSJournal(NATSJournalConfig{Connection: unsafeConnection, CandidateID: "global-controller-gru-concurrent", AuthorityEpoch: 1, LeaseID: "lease-1"})
		unsafeConnection.Close()
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("accepted unsafe %s transport: %v", mode, err)
		}
	}
	const candidate = "global-controller-gru-concurrent"
	putRestoreLease(t, ctx, store, restoreLease(1, candidate))
	one := newRestoreJournalClient(t, connection, 1, candidate)
	two := newRestoreJournalClient(t, connection, 1, candidate)
	var wg sync.WaitGroup
	wg.Add(2)
	epochs := make(chan uint64, 2)
	errs := make(chan error, 2)
	for index, journal := range []*NATSJournal{one, two} {
		go func(index int, journal *NATSJournal) {
			defer wg.Done()
			epoch, err := journal.ClaimRestoreEpoch(ctx, "database", fmt.Sprintf("claim-%d", index))
			epochs <- epoch
			errs <- err
		}(index, journal)
	}
	wg.Wait()
	close(epochs)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uint64]bool{}
	for epoch := range epochs {
		seen[epoch] = true
	}
	if !seen[1] || !seen[2] || len(seen) != 2 {
		t.Fatalf("concurrent claims lost CAS: %v", seen)
	}
	future := restoreLease(1, candidate)
	future.IssuedAt = time.Now().Add(time.Second)
	putRestoreLease(t, ctx, store, future)
	stream, err := one.js.Stream(ctx, restoreJournalStream)
	if err != nil {
		t.Fatal(err)
	}
	before, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := one.ClaimRestoreEpoch(ctx, "database", "future"); !errors.Is(err, ErrRestoreEpochFenced) {
		t.Fatalf("future lease admitted mutation: %v", err)
	}
	after, err := stream.Info(ctx)
	if err != nil || after.State.LastSeq != before.State.LastSeq {
		t.Fatalf("future lease wrote barrier or state: %v", err)
	}
	expired := restoreLease(1, candidate)
	expired.IssuedAt = time.Now().Add(-time.Minute)
	expired.DurationMilliseconds = 1000
	putRestoreLease(t, ctx, store, expired)
	if _, err := one.ClaimRestoreEpoch(ctx, "database", "expired"); !errors.Is(err, ErrRestoreEpochFenced) {
		t.Fatalf("expired authority claimed epoch: %v", err)
	}
}

func TestNATSRestoreJournalRequiresExactLeaseID(t *testing.T) {
	cluster := newRestoreJournalCluster(t)
	connection := cluster.connect(t)
	ctx := context.Background()
	store := openRestoreLeaseStore(t, ctx, connection, true)
	lease := restoreLease(1, "global-controller-gru-leaseid")
	putRestoreLease(t, ctx, store, lease)
	if _, err := NewNATSJournal(NATSJournalConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: 1}); err == nil {
		t.Fatal("missing lease ID accepted")
	}
	journal := newRestoreJournalClient(t, connection, 1, lease.CandidateId)
	facts := JournalFacts{JournalCut: "cut-1", Checksum: "checksum-1", RowCount: 1}
	if err := journal.RecordFacts(ctx, "database", facts); err != nil {
		t.Fatal(err)
	}
	lease.IssuedAt = time.Now().UTC()
	putRestoreLease(t, ctx, store, lease)
	if _, err := journal.Facts(ctx, "database", "item"); err != nil {
		t.Fatalf("same-lease renewal rejected: %v", err)
	}
	lease.LeaseId = "replacement-lease"
	putRestoreLease(t, ctx, store, lease)
	if _, err := journal.Facts(ctx, "database", "item"); err == nil {
		t.Fatal("same candidate and epoch with changed lease ID accepted")
	}
}
