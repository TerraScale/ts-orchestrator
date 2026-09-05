package hostcontrol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/nats-io/nats.go"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/security"
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
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{issue(x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, Nkeys: []*server.NkeyUser{{Nkey: clientPublic}, {Nkey: nodePublic}}})
	if err != nil {
		t.Fatal(err)
	}
	go instance.Start()
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS not ready")
	}
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	connect := func(pair nkeys.KeyPair, public string) *nats.Conn {
		connection, err := nats.Connect(instance.ClientURL(), nats.Nkey(public, pair.Sign), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{issue(x509.ExtKeyUsageClientAuth)}}), nats.NoReconnect())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(connection.Close)
		return connection
	}
	return connect(clientKey, clientPublic), connect(nodeKey, nodePublic)
}
func testClient(t *testing.T, connection *nats.Conn, authorize func(context.Context, Host) error) *Client {
	t.Helper()
	if authorize == nil {
		authorize = func(context.Context, Host) error { return nil }
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{SigningKey: signer, CommandAuthority: func(context.Context, Host) (delivery.RegionalCommandAuthority, error) {
		now := time.Now()
		return delivery.RegionalCommandAuthority{AuthorityID: "gru-regional", Epoch: 1, DesiredGeneration: 1, CandidateID: "gru-controller-test", LeaseID: "lease-test", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, nil
	}, Region: "GRU", Connection: connection, ResolveHost: func(_ context.Context, host string) (Host, error) {
		if host != "gru-1" {
			return Host{}, errors.New("not admitted")
		}
		node, _ := hostagent.NewNodeId(host)
		return Host{NodeID: node, Region: "GRU", Architecture: runtimeplan.HostArchitectureX64}, nil
	}, Authorize: authorize, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func subscribe(t *testing.T, node *nats.Conn, subject string, handler func(*nats.Msg)) {
	t.Helper()
	subscription, err := node.Subscribe(subject, func(message *nats.Msg) {
		if !strings.HasSuffix(message.Subject, ".drain-status") {
			envelope, err := protocol.DecodeCommandEnvelope(message.Data)
			if err != nil {
				t.Error(err)
				return
			}
			var binding nodeauthority.SignedNodeCommand
			if json.Unmarshal(envelope.Payload.Bytes(), &binding) != nil || binding.Subject != message.Subject || binding.NodeID != "gru-1" {
				t.Error("unsigned or mismatched host request")
				return
			}
			copy := *message
			copy.Data = binding.Command
			message = &copy
		}
		handler(message)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := node.Flush(); err != nil {
		t.Fatal(err)
	}
}
func respondJSON(message *nats.Msg, value any) {
	data, _ := json.Marshal(value)
	_ = message.Respond(data)
}
func statusFacts(commandID string) hostagent.NodeStatusReport {
	return hostagent.NodeStatusReport{CommandId: commandID, NodeId: "gru-1", State: hostagent.NodeStateDraining, Quiesced: true, Facts: hostagent.HostFacts{State: hostagent.NodeStateDraining, TsNodeVersion: "dev", ManifestSha256: strings.Repeat("a", 64), Components: []hostagent.ComponentFact{}}}
}

func TestClientUsesAuthenticatedCommandsAndFreshStatus(t *testing.T) {
	connection, node := authenticatedConnections(t)
	var authorizations atomic.Int32
	client := testClient(t, connection, func(context.Context, Host) error { authorizations.Add(1); return nil })
	id, _ := hostagent.NewNodeId("gru-1")
	drain, _ := hostagent.NodeDrainSubject(id)
	subscribe(t, node, drain, func(message *nats.Msg) {
		var command hostagent.DrainCommand
		_ = json.Unmarshal(message.Data, &command)
		receipt, _ := hostagent.NewDrainReceipt(command.CommandId, "gru-1", command.Drain, command.Drain, "")
		respondJSON(message, receipt)
	})
	for _, draining := range []bool{true, false} {
		commandID := "drain-begin"
		if !draining {
			commandID = "drain-release"
		}
		if _, err := client.SetDrain(context.Background(), "gru-1", commandID, draining); err != nil {
			t.Fatal(err)
		}
	}
	statusSubject, _ := hostagent.NodeDrainStatusSubject(id)
	ids := make(chan string, 2)
	subscribe(t, node, statusSubject, func(message *nats.Msg) {
		var request hostagent.NodeStatusRequest
		_ = json.Unmarshal(message.Data, &request)
		ids <- request.CommandId
		respondJSON(message, statusFacts(request.CommandId))
	})
	for range 2 {
		report, err := client.Status(context.Background(), "gru-1")
		if err != nil || !report.Quiesced {
			t.Fatalf("status %+v: %v", report, err)
		}
	}
	if first, second := <-ids, <-ids; first == second {
		t.Fatal("status reused identity")
	}
	if authorizations.Load() != 4 {
		t.Fatalf("mutation authorization count %d", authorizations.Load())
	}
	deploySubject, _ := hostagent.NodeDeploySubject(id)
	subscribe(t, node, deploySubject, func(message *nats.Msg) {
		var command hostagent.DeployCommand
		_ = json.Unmarshal(message.Data, &command)
		receipt, _ := hostagent.NewDeployReceipt(command.CommandId, "gru-1", true, command.Version, "")
		respondJSON(message, receipt)
	})
	if _, err := client.Deploy(context.Background(), "gru-1", "deploy-one", "terrabase", "1.0"); err != nil {
		t.Fatal(err)
	}
	rollbackSubject, _ := hostagent.NodeRollbackSubject(id)
	subscribe(t, node, rollbackSubject, func(message *nats.Msg) {
		var command hostagent.RollbackCommand
		_ = json.Unmarshal(message.Data, &command)
		receipt, _ := hostagent.NewDeployReceipt(command.CommandId, "gru-1", true, "0.9", "")
		respondJSON(message, receipt)
	})
	if _, err := client.Rollback(context.Background(), "gru-1", "rollback-one", "terrabase", "0.9"); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsForeignMalformedAndRefusedReceipts(t *testing.T) {
	for _, scenario := range []string{"foreign-host", "foreign-command", "rejected", "wrong-version", "duplicate", "null", "unknown", "envelope-error"} {
		t.Run(scenario, func(t *testing.T) {
			connection, node := authenticatedConnections(t)
			client := testClient(t, connection, nil)
			id, _ := hostagent.NewNodeId("gru-1")
			subject, _ := hostagent.NodeDeploySubject(id)
			subscribe(t, node, subject, func(message *nats.Msg) {
				receipt := hostagent.DeployReceipt{CommandId: "deploy-one", NodeId: "gru-1", Accepted: true, Current: "1.0", Detail: ""}
				switch scenario {
				case "foreign-host":
					receipt.NodeId = "sfo-1"
				case "foreign-command":
					receipt.CommandId = "other"
				case "rejected":
					receipt.Accepted = false
				case "wrong-version":
					receipt.Current = "2.0"
				case "envelope-error":
					respondJSON(message, hostagent.NewCommandEnvelopeError("refused"))
					return
				}
				data, _ := json.Marshal(receipt)
				switch scenario {
				case "duplicate":
					data = []byte(strings.Replace(string(data), `"accepted":true`, `"accepted":false,"accepted":true`, 1))
				case "null":
					data = []byte(strings.Replace(string(data), `"accepted":true`, `"accepted":null`, 1))
				case "unknown":
					data = append(data[:len(data)-1], []byte(`,"extra":true}`)...)
				}
				_ = message.Respond(data)
			})
			if _, err := client.Deploy(context.Background(), "gru-1", "deploy-one", "terrabase", "1.0"); err == nil {
				t.Fatal("accepted invalid receipt")
			}
		})
	}
}
func TestClientRefusesUnknownHostLostAuthorityAndIndeterminateRetry(t *testing.T) {
	connection, node := authenticatedConnections(t)
	var calls atomic.Int32
	id, _ := hostagent.NewNodeId("gru-1")
	subject, _ := hostagent.NodeDrainSubject(id)
	subscribe(t, node, subject, func(*nats.Msg) { calls.Add(1) })
	client := testClient(t, connection, func(context.Context, Host) error { return errors.New("fence lost") })
	if _, err := client.SetDrain(context.Background(), "gru-1", "drain-one", true); err == nil {
		t.Fatal("lost fence accepted")
	}
	if _, err := client.SetDrain(context.Background(), "sfo-1", "drain-one", true); err == nil {
		t.Fatal("unknown host accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized command published")
	}
	client = testClient(t, connection, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.SetDrain(ctx, "gru-1", "drain-one", true); err == nil {
		t.Fatal("missing reply accepted")
	}
	if calls.Load() != 1 {
		t.Fatalf("indeterminate command retried %d times", calls.Load())
	}
}
func TestClientManifestReceiptMustMatchExactDigest(t *testing.T) {
	connection, node := authenticatedConnections(t)
	client := testClient(t, connection, nil)
	id, _ := hostagent.NewNodeId("gru-1")
	subject, _ := hostagent.NodeApplyManifestSubject(id)
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{}}
	var wrong atomic.Bool
	subscribe(t, node, subject, func(message *nats.Msg) {
		var command hostmanifest.ApplyManifestCommand
		_ = json.Unmarshal(message.Data, &command)
		digest, _ := hostmanifest.HostManifestSha256(command.Manifest)
		if wrong.Load() {
			digest = strings.Repeat("b", 64)
		}
		receipt, _ := hostagent.NewManifestReceipt(command.CommandId, "gru-1", true, digest, "")
		respondJSON(message, receipt)
	})
	if _, err := client.ApplyManifest(context.Background(), "gru-1", "manifest-one", strings.Repeat("a", 64), manifest); err != nil {
		t.Fatal(err)
	}
	wrong.Store(true)
	if _, err := client.ApplyManifest(context.Background(), "gru-1", "manifest-two", strings.Repeat("a", 64), manifest); err == nil {
		t.Fatal("wrong manifest digest accepted")
	}
}

func TestClientRefusesCrossRegionBeforePublication(t *testing.T) {
	connection, node := authenticatedConnections(t)
	source := testClient(t, connection, nil)
	config := source.config
	config.Region = "SFO"
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	var publications atomic.Int32
	subscribe(t, node, "ts.orch.v1.gru.agent.*.command.*", func(*nats.Msg) { publications.Add(1) })
	if _, err := client.SetDrain(context.Background(), "gru-1", "cross-region", true); err == nil {
		t.Fatal("cross-region command accepted")
	}
	if publications.Load() != 0 {
		t.Fatal("cross-region command published")
	}
}
