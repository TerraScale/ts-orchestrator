package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

type identityRekeyCLIFixture struct {
	directory      string
	now            time.Time
	key            ed25519.PrivateKey
	roots          trust.Keyring
	checkpoint     identityrekey.AcceptedIdentityCheckpoint
	expected       identityrekey.CheckpointExpectation
	observed       identityrekey.HostStateObservation
	plan           identityrekey.HostStateHandoffPlan
	reset          authority.IdentityReset
	target         authority.IdentityResetTarget
	accepted       bootstrapstart.AcceptedIdentity
	journal        bootstrapstart.IdentityRekeyJournal
	checkpointWire []byte
}

func newIdentityRekeyCLIFixture(t *testing.T) *identityRekeyCLIFixture {
	t.Helper()
	f := &identityRekeyCLIFixture{directory: t.TempDir(), now: time.Now().UTC().Truncate(time.Second)}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	f.roots, err = trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("root.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	writeFixture(t, f.path("root.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	chainWire, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("roots.json"), chainWire, 0o644)
	nkey := func(operator bool) string {
		var pair nkeys.KeyPair
		var err error
		if operator {
			pair, err = nkeys.CreateOperator()
		} else {
			pair, err = nkeys.CreateAccount()
		}
		if err != nil {
			t.Fatal(err)
		}
		defer pair.Wipe()
		public, err := pair.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return public
	}
	f.checkpoint = identityrekey.AcceptedIdentityCheckpoint{SchemaVersion: 1,
		OperationID: entityid.New(), DeploymentID: entityid.New(), ClusterID: entityid.New(),
		Cell: "GRU", Environment: "canary", SeedSlot: "controller-a", MaterialGenerationSHA256: digest([]byte("material generation")),
		Broker: identityrekey.BrokerIdentity{Operator: nkey(true), SystemAccount: nkey(false), CellAccount: nkey(false),
			HostSigner: nkey(false), RoleSigner: nkey(false)}}
	for i := range 3 {
		slot := fmt.Sprintf("controller-%c", 'a'+i)
		purposes := map[string]bootstrap.SecretPurpose{
			"operator.jwt": bootstrap.SecretRegionalShared, "system.jwt": bootstrap.SecretRegionalShared,
			"cell.jwt": bootstrap.SecretRegionalShared, "system.creds": bootstrap.SecretRegionalShared,
			"ca.pem": bootstrap.SecretRegionalShared, "route-password": bootstrap.SecretRegionalShared,
			"ticket.pub": bootstrap.SecretRegionalShared, "ticket.key": bootstrap.SecretRegionalShared,
			"host-nats-issuer.seed": bootstrap.SecretHostIssuer, "host-tls-issuer-cert.pem": bootstrap.SecretHostIssuer,
			"host-tls-issuer-key.pem": bootstrap.SecretHostIssuer, slot + ".creds": bootstrap.SecretController,
			slot + "-tls-cert.pem": bootstrap.SecretController, slot + "-tls-key.pem": bootstrap.SecretController,
			slot + "-response.key": bootstrap.SecretController,
		}
		var references []bootstrap.SecretReference
		for _, name := range slices.Sorted(maps.Keys(purposes)) {
			ref := bootstrap.SecretReference{Purpose: purposes[name], SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1." + slot,
				VersionNumber: 1, MaxBytes: 64 << 10, TargetFile: name, SHA256: digest([]byte(name))}
			if ref.Purpose == bootstrap.SecretController {
				ref.Slot = slot
			}
			references = append(references, ref)
		}
		f.checkpoint.Slots = append(f.checkpoint.Slots, identityrekey.SlotBinding{Slot: slot,
			PreviousAcceptanceSHA256: digest([]byte("opaque old acceptance")),
			PreviousMaterialSHA256:   map[string]string{"installed": digest([]byte("old material chain")), "durable": digest([]byte("old material chain"))},
			InstanceOCID:             fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.controller%d", i),
			ImageOCID:                "ocid1.image.oc1.sa-saopaulo-1.current", PrimaryVNICOCID: fmt.Sprintf("ocid1.vnic.oc1.sa-saopaulo-1.controller%d", i),
			PrimaryPrivateIP: fmt.Sprintf("10.251.0.%d", i+11),
			Binary:           identityrekey.BinaryPin{SHA256: digest([]byte("binary")), Size: 4096, Architecture: "amd64"},
			ConfigSHA256: map[string]string{"controller.json": digest([]byte("config")), "placement.json": digest([]byte("placement")),
				"oci-region.json": digest([]byte("region")), "oci-region-intent.json": digest([]byte("intent"))},
			LaunchMaterialSHA256: map[string]string{"host-enrollment-public.json": digest([]byte("enrollment")),
				"operator-ssh-key.pub": digest([]byte("SSH")), "managed-host-image-receipt.json": digest([]byte("image")),
				"managed-host-image-delegation.json": digest([]byte("image grant"))},
			MaterialReferences: references,
			Store: identityrekey.StoreIdentity{Directory: "/var/lib/terrascale-orchestrator-controller/nats", ServerName: fmt.Sprintf("gru-1-ctl-%d", i+1),
				RaftNodeID: fmt.Sprintf("NODE000%d", i), ServerNameSHA256: digest([]byte(fmt.Sprintf("gru-1-ctl-%d\n", i+1))),
				NodeIdentitySHA256: digest([]byte(fmt.Sprintf("existing node %d", i)))}})
	}
	f.expected = identityrekey.CheckpointExpectation{OperationID: f.checkpoint.OperationID, DeploymentID: f.checkpoint.DeploymentID,
		ClusterID: f.checkpoint.ClusterID, Environment: f.checkpoint.Environment, Cell: f.checkpoint.Cell,
		SeedSlot: f.checkpoint.SeedSlot, MaterialGenerationSHA256: f.checkpoint.MaterialGenerationSHA256,
		Broker: f.checkpoint.Broker, Slot: f.checkpoint.Slots[0]}
	writeFixture(t, f.path("expected.json"), mustEncodePayload(t, f.expected), 0o644)
	writeFixture(t, f.path("checkpoint-candidate.json"), mustEncodePayload(t, f.checkpoint), 0o644)
	checkpointEnvelope, err := identityrekey.IssueAcceptedIdentityCheckpoint(f.checkpoint, f.now, f.now.Add(24*time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	f.checkpointWire = encodeEnvelope(t, checkpointEnvelope)
	writeFixture(t, f.path("checkpoint.json"), f.checkpointWire, 0o644)
	checkpoint, err := identityrekey.VerifyAcceptedIdentityCheckpoint(f.checkpointWire, f.roots, trust.RootChain{Version: 1}, f.expected, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.accepted, err = bootstrapstart.AcceptedIdentityFromCheckpoint(checkpoint, "controller-a", f.now)
	if err != nil {
		t.Fatal(err)
	}
	acceptedWire, err := bootstrapstart.EncodeAcceptedIdentity(f.accepted)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("accepted.json"), acceptedWire, 0o644)
	responseKey := func() string {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(public)
	}
	f.observed = identityrekey.HostStateObservation{OperationID: f.expected.OperationID, DeploymentID: f.expected.DeploymentID,
		ClusterID: f.expected.ClusterID, Cell: f.expected.Cell, Environment: f.expected.Environment, CheckpointSHA256: checkpoint.Fingerprint(),
		EpochFloor: 7, Epoch: 8, PreviousResponseKey: responseKey(), ResponseKey: responseKey(),
		AgentsStoppedAt: f.now.Add(-time.Minute), ObservedAt: f.now.Add(-time.Second)}
	f.observed.Preconditions = []identityrekey.HostStatePrecondition{{Bucket: "TS_HOST_STATE", Key: "retirement-cutover." + strings.ToLower(f.expected.Cell)}}
	f.plan, err = identityrekey.BuildHostStateHandoffPlan(f.observed, f.now)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("observation.json"), mustEncodePayload(t, f.observed), 0o644)
	writeFixture(t, f.path("host-candidate.json"), mustEncodePayload(t, f.plan), 0o644)
	hostEnvelope, err := identityrekey.SignHostStateHandoffPlan(f.plan, f.now, f.now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	hostWire := encodeEnvelope(t, hostEnvelope)
	writeFixture(t, f.path("host-plan.json"), hostWire, 0o644)
	hostPlan, err := identityrekey.VerifyHostStateHandoffPlan(hostEnvelope, f.roots, f.observed, f.now)
	if err != nil {
		t.Fatal(err)
	}
	values := [][]byte{[]byte("replacement service set"), chainWire, []byte("replacement material chain")}
	f.reset = authority.IdentityReset{Version: 1, OperationID: f.expected.OperationID, DeploymentID: f.expected.DeploymentID,
		ClusterID: f.expected.ClusterID, Scope: "gru", Environment: f.expected.Environment, CheckpointSHA256: checkpoint.Fingerprint(),
		HostStatePlanSHA256: hostPlan.Fingerprint(), LastSequence: 1, PreviousSequence: 1,
		PreviousSHA256: digest(identityRekeyOldLease), EpochFloor: 7, Epoch: 8}
	for i, destination := range [][2]string{{"TS_SERVICE_SET", "current"}, {"TS_TRUST_ROOTS", "chain"}, {"TS_TRUST_ROOTS", "material-generations"}} {
		f.reset.Records = append(f.reset.Records, authority.IdentityResetRecord{Action: authority.IdentityResetReplaceKV,
			Bucket: destination[0], Key: destination[1], SHA256: digest(values[i])})
	}
	f.reset.Records = append(f.reset.Records, hostPlan.IdentityResetRecords()...)
	values = append(values, hostPlan.Values()...)
	writeFixture(t, f.path("reset-candidate.json"), mustEncodePayload(t, f.reset), 0o644)
	resetEnvelope, err := authority.SignIdentityReset(f.reset, f.now, f.now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	f.target = authority.IdentityResetTarget{OperationID: f.reset.OperationID, DeploymentID: f.reset.DeploymentID,
		ClusterID: f.reset.ClusterID, Scope: f.reset.Scope, Environment: f.reset.Environment, CheckpointSHA256: f.reset.CheckpointSHA256,
		HostStatePlanSHA256: f.reset.HostStatePlanSHA256, Replicas: 1}
	roots, err := trust.VerifyRootChain(f.roots, trust.ChainIdentity{DeploymentID: f.expected.DeploymentID, Cell: "gru", Environment: f.expected.Environment}, trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.journal = bootstrapstart.IdentityRekeyJournal{Version: 1, AcceptedWire: acceptedWire, PreviousMaterialSHA256: maps.Clone(f.expected.Slot.PreviousMaterialSHA256),
		PreviousAcceptanceSHA256: f.expected.Slot.PreviousAcceptanceSHA256, CheckpointWire: f.checkpointWire,
		ResetWire: encodeEnvelope(t, resetEnvelope), HostPlanWire: hostWire, HostObservation: f.observed,
		RootChainWire: chainWire, GenesisSHA256: trust.RootSetDigest(f.roots), RootHead: roots.Head, Replicas: 1, Values: values}
	writeFixture(t, f.path("journal.json"), mustEncodePayload(t, f.journal), 0o644)
	return f
}

func (f *identityRekeyCLIFixture) path(name string) string { return filepath.Join(f.directory, name) }

func (f *identityRekeyCLIFixture) signArgs(candidate string) []string {
	return []string{"--candidate", f.path(candidate), "--expectation", f.path("expected.json"),
		"--root-key", f.path("root.pem"), "--root-chain", f.path("roots.json"), "--signing-key", f.path("root.key"),
		"--out", f.path("signed.json"), "--valid-for", "1h"}
}

func TestIdentityRekeyRootSigningExactV1(t *testing.T) {
	for _, kind := range []string{"checkpoint", "host", "reset"} {
		t.Run(kind, func(t *testing.T) {
			f := newIdentityRekeyCLIFixture(t)
			c := command{ctx: t.Context(), output: io.Discard}
			args := f.signArgs(kind + "-candidate.json")
			var commandName string
			switch kind {
			case "checkpoint":
				commandName = "sign-accepted-identity-checkpoint"
			case "host":
				commandName = "sign-host-state-handoff-plan"
				args = append(args, "--checkpoint", f.path("checkpoint.json"), "--observation", f.path("observation.json"))
			case "reset":
				commandName = "sign-identity-reset"
				args = append(args, "--checkpoint", f.path("checkpoint.json"), "--observation", f.path("observation.json"),
					"--host-plan", f.path("host-plan.json"), "--replicas", "1")
			}
			if err := c.runAt(append([]string{commandName}, args...), f.now); err != nil {
				t.Fatal(err)
			}
			wire, err := os.ReadFile(f.path("signed.json"))
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.DecodeEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "checkpoint":
				_, err = identityrekey.VerifyAcceptedIdentityCheckpoint(wire, f.roots, trust.RootChain{Version: 1}, f.expected, f.now)
			case "host":
				_, err = identityrekey.VerifyHostStateHandoffPlan(envelope, f.roots, f.observed, f.now)
			case "reset":
				var reset authority.IdentityReset
				reset, err = authority.VerifyIdentityReset(envelope, f.roots, f.target, f.now)
				if reset.LastSequence != f.reset.LastSequence || reset.PreviousSequence != f.reset.PreviousSequence || reset.PreviousSHA256 != f.reset.PreviousSHA256 {
					t.Fatal("signer changed the reviewed predecessor")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

var identityRekeyOldLease = []byte(`{"version":1,"scope":"gru","candidate_id":"old-controller","owner_id":"old-owner","epoch":7}`)

func identityRekeyTestBroker(t *testing.T) (*natscell.Runtime, jetstream.Stream, natscell.Config) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "material")
	_, err := bootstrapmaterial.Generate(directory, bootstrapmaterial.Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru",
		DeploymentID: entityid.New(), ClusterID: entityid.New(), SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
		Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.10"}, {Name: "controller-b", PrivateIP: "10.251.0.11"}, {Name: "controller-c", PrivateIP: "10.251.0.12"}}}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(directory, name) }
	tlsFiles := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path("controller-a-tls-cert.pem"), KeyFile: path("controller-a-tls-key.pem")}
	// Port -1 has the broker bind a free port itself. A port picked here and
	// closed again could be taken by another socket before the broker binds it.
	cfg := natscell.Config{Cell: "gru", Instance: "controller-a", Replicas: 1, ClientRole: "controller", CredentialsFile: path("controller-a.creds"), TLS: tlsFiles,
		Embedded: &natscell.Embedded{StoreDir: t.TempDir(), Host: "127.0.0.1", Port: -1, TLS: tlsFiles, RouteTLS: tlsFiles,
			OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"), CellJWTFile: path("cell.jwt"),
			SystemCredentialsFile: path("system.creds"), TicketPublicKeyFile: path("ticket.pub"), BrokerIDs: []string{"controller-a"}}}
	runtime, err := natscell.Start(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if err := runtime.Bridge().OpenUntil(1, runtime.InitialCellJWT(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, bucket := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_STATE"} {
		if _, err := runtime.JetStream().CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, Storage: jetstream.FileStorage, Replicas: 1}); err != nil {
			t.Fatal(err)
		}
	}
	stream, err := runtime.JetStream().CreateStream(t.Context(), jetstream.StreamConfig{Name: authority.ControlStreamName,
		Subjects: []string{protocol.ControlStreamSubject()}, Retention: jetstream.LimitsPolicy,
		MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
		Storage: jetstream.FileStorage, Replicas: 1, DenyDelete: true, DenyPurge: true,
		Metadata: map[string]string{"terrascale-contract": "authority-log-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.JetStream().Publish(t.Context(), protocol.Control("gru", "lease"), identityRekeyOldLease); err != nil {
		t.Fatal(err)
	}
	return runtime, stream, cfg
}

// The old bridge can close after the durable write, before its reply reaches
// the caller. The executor must report uncertainty rather than publish again.
type identityRekeyDisconnect struct {
	jetstream.JetStream
	conn      *nats.Conn
	publishes int
}

func (js *identityRekeyDisconnect) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	js.publishes++
	if _, err := js.JetStream.PublishMsg(ctx, msg, opts...); err != nil {
		return nil, err
	}
	js.conn.Close()
	return nil, nats.ErrConnectionClosed
}

func TestIdentityRekeyPrecommitDisconnectDoesNotDuplicateReset(t *testing.T) {
	f := newIdentityRekeyCLIFixture(t)
	runtime, _, cfg := identityRekeyTestBroker(t)
	certificate, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(cfg.TLS.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture has no TLS roots")
	}
	credentials, err := os.ReadFile(cfg.CredentialsFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nkeys.ParseDecoratedUserNKey(credentials)
	clear(credentials)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	key.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := nats.Connect(runtime.URL(), nats.UserCredentials(cfg.CredentialsFile),
		nats.CustomInboxPrefix(protocol.InboxPrefix("gru", public)), nats.IgnoreDiscoveredServers(),
		nats.SetCustomDialer(&tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots,
			Certificates: []tls.Certificate{certificate}, ServerName: "controller-a"}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	disconnected := &identityRekeyDisconnect{JetStream: js, conn: conn}
	envelope, err := trust.DecodeEnvelope(f.journal.ResetWire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ResetIdentityLease(t.Context(), disconnected, envelope, f.roots, f.target, f.now); !errors.Is(err, authority.ErrOutcomeUnknown) {
		t.Fatalf("lost old bridge reply must remain uncertain: %v", err)
	}
	if disconnected.publishes != 1 {
		t.Fatalf("retried through closed bridge: %d publishes", disconnected.publishes)
	}
	sequence, err := authority.ResetIdentityLease(t.Context(), runtime.JetStream(), envelope, f.roots, f.target, f.now)
	if err != nil || sequence != 2 {
		t.Fatalf("held broker readback did not recognize exact barrier: %d %v", sequence, err)
	}
}
