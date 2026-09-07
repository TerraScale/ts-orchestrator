package testnats

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"fmt"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"testing"
	"time"
)

type Cluster struct {
	Servers []*natsserver.Server
	Options []*natsserver.Options
	TLS     *tls.Config
	Root    string
	Key     nkeys.KeyPair
	Public  string
}

func New(t *testing.T) *Cluster {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "testnats"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	user, _ := nkeys.CreateUser()
	pub, _ := user.PublicKey()
	c := &Cluster{Key: user, Public: pub, Root: t.TempDir(), TLS: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	route, _ := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", port))
	for i := 0; i < 3; i++ {
		o := &natsserver.Options{ServerName: fmt.Sprintf("testnats-%d", i), Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(c.Root, fmt.Sprint(i)), NoLog: true, NoSigs: true, SystemAccount: "$SYS", Accounts: []*natsserver.Account{natsserver.NewAccount("$SYS")}, Nkeys: []*natsserver.NkeyUser{{Nkey: pub}}, TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}, Cluster: natsserver.ClusterOpts{Name: "testnats", Host: "127.0.0.1", Port: -1}}
		if i == 0 {
			o.Cluster.Port = port
		}
		if route != nil {
			o.Routes = []*url.URL{route}
		}
		s, _ := natsserver.NewServer(o.Clone())
		s.Start()
		if !s.ReadyForConnections(5 * time.Second) {
			t.Fatal("NATS start failed")
		}
		o.Port = s.Addr().(*net.TCPAddr).Port
		o.Cluster.Port = s.ClusterAddr().Port
		if route == nil {
			route, _ = url.Parse("nats-route://" + s.ClusterAddr().String())
		}
		c.Servers = append(c.Servers, s)
		c.Options = append(c.Options, o)
	}
	t.Cleanup(c.Stop)
	return c
}
func (c *Cluster) Stop() {
	for _, s := range c.Servers {
		s.Shutdown()
	}
	for _, s := range c.Servers {
		s.WaitForShutdown()
	}
}
func (c *Cluster) Connect(t *testing.T) *nats.Conn {
	t.Helper()
	n, err := nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", c.Options[0].Port), nats.Secure(c.TLS.Clone()), nats.Nkey(c.Public, c.Key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	return n
}
func (c *Cluster) Restart(t *testing.T) {
	c.Stop()
	c.Servers = nil
	for _, o := range c.Options {
		s, err := natsserver.NewServer(o.Clone())
		if err != nil {
			t.Fatal(err)
		}
		s.Start()
		if !s.ReadyForConnections(5 * time.Second) {
			t.Fatal("NATS restart failed")
		}
		c.Servers = append(c.Servers, s)
	}
}
func (c *Cluster) StopNodes(indices ...int) {
	for _, i := range indices {
		if i >= 0 && i < len(c.Servers) {
			c.Servers[i].Shutdown()
			c.Servers[i].WaitForShutdown()
		}
	}
}
func OpenLeaseStore(t *testing.T, ctx context.Context, connection *nats.Conn, create bool) jetstream.KeyValue {
	t.Helper()
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	var store jetstream.KeyValue
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, cancel := context.WithTimeout(ctx, time.Second)
		if create {
			store, err = js.CreateKeyValue(c, jetstream.KeyValueConfig{Bucket: "ORCH_LEADERS", History: 1, Storage: jetstream.FileStorage, Replicas: 3, MaxBytes: 8 << 20})
		} else {
			store, err = js.KeyValue(c, "ORCH_LEADERS")
		}
		cancel()
		if err == nil {
			return store
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}
func Lease(epoch int64, candidate string) authority.RegionalAuthorityLeaseDocument {
	return authority.RegionalAuthorityLeaseDocument{SchemaVersion: 1, AuthorityId: "global", Epoch: epoch, CandidateId: candidate, LeaseId: fmt.Sprintf("lease-%d", epoch), IssuedAt: time.Now().UTC(), DurationMilliseconds: 60000}
}
func PutLease(t *testing.T, ctx context.Context, store jetstream.KeyValue, lease authority.RegionalAuthorityLeaseDocument) {
	b, _ := json.Marshal(lease)
	if _, err := store.Put(ctx, "authority.global", b); err != nil {
		t.Fatal(err)
	}
}
