package nodeauthority_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"testing"
	"time"
)

func authenticatedConnections(t *testing.T) (*nats.Conn, *nats.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(usage x509.ExtKeyUsage) tls.Certificate {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(usage) + 2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}
	}
	clientKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, err := clientKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	nodePublic, err := nodeKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, MaxPayload: 4 << 20, JetStream: true, StoreDir: t.TempDir(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{issue(x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, Nkeys: []*server.NkeyUser{{Nkey: clientPublic}, {Nkey: nodePublic}}})
	if err != nil {
		t.Fatal(err)
	}
	go instance.Start()
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS not ready")
	}
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	connect := func(pair nkeys.KeyPair, public string) *nats.Conn {
		certificate := issue(x509.ExtKeyUsageClientAuth)
		options := []nats.Option{nats.Nkey(public, pair.Sign), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}}), nats.NoReconnect()}
		{
			// Match ts-node's file loader: nats.ClientCert installs TLSCertCB rather
			// than populating the caller-visible TLSConfig.Certificates slice.
			dir := t.TempDir()
			keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
				t.Fatal(err)
			}
			options = []nats.Option{nats.Nkey(public, pair.Sign), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}), nats.ClientCert(certPath, keyPath), nats.NoReconnect()}
		}
		connection, err := nats.Connect(instance.ClientURL(), options...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(connection.Close)
		return connection
	}
	return connect(clientKey, clientPublic), connect(nodeKey, nodePublic)
}

func TestRealFileTLSSenderAndReceiverFencesStaleLease(t *testing.T) {
	controller, node := authenticatedConnections(t)
	if node.Opts.TLSCertCB == nil || controller.Opts.TLSCertCB == nil || len(node.Opts.TLSConfig.Certificates) != 0 || len(controller.Opts.TLSConfig.Certificates) != 0 {
		t.Fatal("receiver fixture did not use production file TLS callback")
	}
	js, err := jetstream.New(node)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateKeyValue(context.Background(), jetstream.KeyValueConfig{Bucket: "AUTHORITY", History: 5})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := security.NewCommandSignatureVerifierFromKeys([]security.CommandSignatureTrustKey{{KeyID: signer.PublicKeyID(), Algorithm: security.CommandSignatureAlgorithm, PublicKeySPKI: spki}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := nodeauthority.NewRegionalCommandAuthorizer(nodeauthority.CommandAuthorityConfig{Connection: node, NodeID: "gru-1", Bucket: "AUTHORITY", Trust: trust, SignerCandidates: map[string]string{signer.PublicKeyID(): "gru-controller-one"}})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := nodeauthority.NewEpochStore(directory, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lease := authority.RegionalAuthorityLeaseDocument{SchemaVersion: 1, AuthorityId: "gru-regional", Epoch: 7, CandidateId: "gru-controller-one", LeaseId: "lease-seven", IssuedAt: time.Now().Add(-time.Second), DurationMilliseconds: 60000}
	put := func() {
		data, _ := json.Marshal(lease)
		if _, err := kv.Put(context.Background(), "authority.regional", data); err != nil {
			t.Fatal(err)
		}
	}
	put()
	var mutations atomic.Int32
	captured := make(chan []byte, 8)
	nodeID, _ := hostagent.NewNodeId("gru-1")
	subject, _ := hostagent.NodeDrainSubject(nodeID)
	_, err = node.Subscribe(subject, func(message *nats.Msg) {
		captured <- append([]byte(nil), message.Data...)
		authorized, err := verifier.Authorize(context.Background(), message.Subject, message.Data)
		if err == nil {
			err = store.Admit(authorized)
		}
		if err != nil {
			data, _ := json.Marshal(hostagent.NewCommandEnvelopeError("authority refused"))
			_ = message.Respond(data)
			return
		}
		mutations.Add(1)
		var command hostagent.DrainCommand
		_ = json.Unmarshal(authorized.Command, &command)
		receipt, _ := hostagent.NewDrainReceipt(command.CommandId, "gru-1", command.Drain, command.Drain, "")
		data, _ := json.Marshal(receipt)
		_ = message.Respond(data)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = node.Flush(); err != nil {
		t.Fatal(err)
	}
	client, err := hostcontrol.New(hostcontrol.Config{Region: "GRU", SigningKey: signer, Connection: controller, ResolveHost: func(context.Context, string) (hostcontrol.Host, error) {
		return hostcontrol.Host{NodeID: nodeID, Region: "GRU", Architecture: runtimeplan.HostArchitectureX64}, nil
	}, Authorize: func(context.Context, hostcontrol.Host) error { return nil }, CommandAuthority: func(ctx context.Context, _ hostcontrol.Host) (delivery.RegionalCommandAuthority, error) {
		value, _, err := nodeauthority.ReadRegionalCommandLease(ctx, controller, "AUTHORITY")
		return delivery.RegionalCommandAuthority{AuthorityID: value.AuthorityId, Epoch: value.Epoch, DesiredGeneration: 1, CandidateID: value.CandidateId, LeaseID: value.LeaseId, IssuedAt: value.IssuedAt, ExpiresAt: value.IssuedAt.Add(time.Duration(value.DurationMilliseconds) * time.Millisecond)}, err
	}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SetDrain(context.Background(), "gru-1", "drain-seven", true); err != nil {
		t.Fatal(err)
	}
	old := <-captured
	if mutations.Load() != 1 {
		t.Fatal("valid command did not reach receiver")
	}
	lease.Epoch = 8
	lease.LeaseId = "lease-eight"
	put()
	if _, err := client.SetDrain(context.Background(), "gru-1", "drain-eight", true); err != nil {
		t.Fatal(err)
	}
	<-captured
	if _, err := verifier.Authorize(context.Background(), subject, old); err == nil {
		t.Fatal("delayed stale lease accepted")
	}
	envelope, err := protocol.DecodeCommandEnvelope(old)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload = protocol.OpaquePayloadCopyFrom([]byte(`{}`))
	bad, err := protocol.EncodeCommandEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Authorize(context.Background(), subject, bad); err == nil {
		t.Fatal("tampered payload accepted")
	}
	if err := kv.Delete(context.Background(), "authority.regional"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := nodeauthority.ReadRegionalCommandLease(context.Background(), node, "AUTHORITY"); err == nil {
		t.Fatal("deleted authority accepted")
	}
	if mutations.Load() != 2 {
		t.Fatal("refused request mutated host")
	}
}

func TestEpochFloorSurvivesRestartAndRefusesSecondOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := nodeauthority.NewEpochStore(dir, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	if second, err := nodeauthority.NewEpochStore(dir, "gru-1"); err == nil {
		second.Close()
		t.Fatal("second receiver owns same journal")
	}
	command := nodeauthority.CommandAuthorization{NodeID: "gru-1", AuthorityID: "gru-regional", Epoch: 9, CandidateID: "controller-nine", LeaseID: "lease-nine"}
	if err := store.Admit(command); err != nil {
		t.Fatal(err)
	}
	if err := store.Admit(command); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = nodeauthority.NewEpochStore(dir, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	command.Epoch = 8
	if err := store.Admit(command); err == nil {
		t.Fatal("persisted epoch regressed")
	}
	command.Epoch = 9
	command.CandidateID = "other"
	if err := store.Admit(command); err == nil {
		t.Fatal("same epoch changed holder")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authority-epoch.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if next, err := nodeauthority.NewEpochStore(dir, "gru-1"); err == nil {
		next.Close()
		t.Fatal("corrupt epoch floor accepted")
	}
}

func TestLeaderReadLargeValueAndMissingTombstone(t *testing.T) {
	connection, _ := authenticatedConnections(t)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateKeyValue(context.Background(), jetstream.KeyValueConfig{Bucket: "LARGE"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := nodeauthority.ReadLeaderKV(context.Background(), connection, "LARGE", "missing"); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	// Server fixture sets a 4 MiB payload limit; full delivery values include
	// base64 expansion in the ordinary leader-read response.
	data := []byte(strings.Repeat("v", (2<<20)+(16<<10)))
	if _, err := kv.Put(context.Background(), "value", data); err != nil {
		t.Fatal(err)
	}
	observed, _, err := nodeauthority.ReadLeaderKV(context.Background(), connection, "LARGE", "value")
	if err != nil || string(observed) != string(data) {
		t.Fatalf("large value read: %v", err)
	}
	if err := kv.Delete(context.Background(), "value"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := nodeauthority.ReadLeaderKV(context.Background(), connection, "LARGE", "value"); !errors.Is(err, jetstream.ErrKeyDeleted) {
		t.Fatalf("deleted key: %v", err)
	}
}
