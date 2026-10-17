//go:build fixturetest

package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

type installedControllerHostFixture struct {
	installed *installedControllerFixture
	process   *installedManagerProcess
	sdk       *bootstrapstart.ControllerSDKAcquisitionFixture
	brokers   []*natscell.Runtime
	control   *authority.Runtime
	hosts     *host.Controller
	agent     *host.Agent
	transport hostenroll.WorkerTransport
	session   context.Context
}

// Every source is produced inside this finite installed namespace. The actual
// child exists before its witness determines the regional runtime candidate.
func newInstalledControllerHostFixture(t *testing.T, ctx context.Context) *installedControllerHostFixture {
	t.Helper()
	installed := newInstalledControllerFixture(t)
	process := newInstalledManagerProcess(t, ctx, installed)
	sdk := bootstrapstart.NewControllerSDKAcquisitionFixture(t, ctx, installed.Bootstrap)
	if err := sdk.InstallChildSource(); err != nil {
		t.Fatal(err)
	}
	brokers, configs := startInstalledControllerBrokers(t, ctx, installed)
	var seed *natscell.Runtime
	for index, cfg := range configs {
		if cfg.Instance == installed.Config.NATS.Instance {
			seed = brokers[index]
		}
	}
	if seed == nil {
		t.Fatal("actual installed seed is absent from its broker set")
	}
	candidate := entityid.Derive("controller-runtime", process.witness.Binding())
	control, err := authority.Start(ctx, seed.JetStream(), authority.Config{
		DeploymentID: installed.Bootstrap.Accepted.DeploymentID, Scope: configs[0].Cell, CandidateID: candidate, Replicas: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	private, public, err := brokerTicketKeys(installed.Config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(private) })
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	gateCtx, stopGates := context.WithCancel(ctx)
	t.Cleanup(stopGates)
	for index, cfg := range configs {
		if _, err := startBrokerGate(gateCtx, Config{NATS: cfg}, brokers[index], control,
			installed.Bootstrap.Accepted.DeploymentID, candidate, private, public, clock); err != nil {
			t.Fatal("open actual original broker admission", err)
		}
	}
	waitBrokerGateStatus(t, ctx, brokers, func(status natscell.BridgeStatus) bool { return status.Open && status.ClaimSequence > 0 })
	grant := cellspec.HostGrant{Node: "gru-1-ctl-3", Controller: installed.Bootstrap.Accepted.Slot,
		PrivateIP: installed.Bootstrap.Accepted.PrimaryPrivateIP, Roles: []string{"ts-auth"}, Environment: installed.Bootstrap.Accepted.Environment}
	specWire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema,
		Identity:   cellspec.Identity{DeploymentID: installed.Bootstrap.Accepted.DeploymentID, Cell: configs[0].Cell, Environment: grant.Environment},
		Generation: 1, RequiresBinary: 17, HostGrants: []cellspec.HostGrant{grant}},
		nil, installed.Bootstrap.Roots, time.Now().UTC(), time.Hour, installed.Bootstrap.Root)
	if err != nil {
		t.Fatal(err)
	}
	services, err := newSpecRegistry(installed.Config, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := services.open(ctx, seed.JetStream(), 3); err != nil {
		t.Fatal(err)
	}
	if err := services.roots.open(ctx, seed.JetStream(), 3); err != nil {
		t.Fatal(err)
	}
	rootWire, err := os.ReadFile(bootstrapstart.RootChainFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services.roots.kv.Create(ctx, rootChainKey, rootWire); err != nil {
		t.Fatal(err)
	}
	if _, err := services.kv.Create(ctx, cellSpecKey, specWire); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: releasechannel.Bucket, Replicas: 3}); err != nil {
		t.Fatal(err)
	}
	artifacts, err := seed.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket, Replicas: 3})
	if err != nil {
		t.Fatal(err)
	}
	responseKey, err := readPrivateKey(installed.Config.Controller.ResponseKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(responseKey) })
	hosts, err := host.NewController(ctx, host.ControllerConfig{Cell: configs[0].Cell, Conn: seed.Conn(), JS: seed.JetStream(), Artifacts: artifacts,
		ResponseKey: responseKey, StateReplicas: 3, HostMutations: control,
		AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard})
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(hostKey) })
	hostUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hostUser.Wipe)
	hostNKey, err := hostUser.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := hostboot.Static(configs[0].Cell, installed.Bootstrap.Accepted.Cell, grant.Node)
	descriptorWire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	request := hostenroll.Request{SchemaVersion: 1, Operation: "enroll", InstanceID: installed.Bootstrap.Accepted.InstanceOCID,
		Descriptor: string(descriptorWire), IdentityPublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: hostNKey,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Nonce:  base64.StdEncoding.EncodeToString(nonce), IssuedAt: time.Now().UTC()}
	if err := request.Sign(hostKey); err != nil {
		t.Fatal(err)
	}
	requestWire, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := hostenroll.ParseCSR(request.CSRPEM)
	if err != nil {
		t.Fatal(err)
	}
	descriptorDigest, err := descriptor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	grants, err := hostenroll.OpenGrantStore(ctx, seed.JetStream(), 3)
	if err != nil {
		t.Fatal(err)
	}
	claimed, revision, err := grants.Claim(ctx, hostenroll.Grant{SchemaVersion: 1, InstanceID: request.InstanceID,
		CreateKey: entityid.New(), DescriptorSHA256: descriptorDigest, Request: requestWire})
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{Cell: configs[0].Cell, Node: grant.Node, Environment: grant.Environment, Roles: grant.Roles,
		Generation: 1, PublicKey: request.IdentityPublicKey, NATSUserPublicKey: request.NATSUserPublicKey,
		Capacity: host.Capacity{CPU: 2, MemoryBytes: 16 << 30, DiskBytes: 64 << 30}}
	receipt, err := hosts.Register(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(installed.Config.NATS.TLS.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	c := installed.Config.Controller
	issuer, err := hostenroll.LoadIssuer(configs[0].Cell, installed.Record.Public.CellAccountNKey,
		c.HostNATSIssuerSeedFile, c.HostTLSIssuerKeyFile, c.HostTLSIssuerCertFile, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.NATSKey.Wipe()
	cellWire, err := os.ReadFile(installed.Config.NATS.Embedded.CellJWTFile)
	if err != nil || issuer.ValidateAccountScope(string(cellWire)) != nil {
		t.Fatal("generated host issuer scope changed", err)
	}
	issuedJWT, chain, expires, err := issuer.Issue(request, csr, grant.Node, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	response := hostenroll.Response{SchemaVersion: 1, Operation: request.Operation, InstanceID: request.InstanceID, Node: descriptor.Node,
		DescriptorSHA256: descriptorDigest, RequestSHA256: hostenroll.RequestSHA256(requestWire), Nonce: request.Nonce,
		RegistrationReceipt: receipt, Roles: registration.Roles, NATSUserJWT: issuedJWT, TLSCertificatePEM: string(chain), ExpiresAt: expires}
	if err := response.Sign(responseKey); err != nil {
		t.Fatal(err)
	}
	responseWire, err := protocol.EncodeJSON(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Finish(ctx, claimed, revision, responseWire); err != nil {
		t.Fatal(err)
	}
	transport := hostenroll.WorkerTransport{Request: requestWire, Response: responseWire}
	completed, _, err := hostenroll.ReadCurrentGrant(ctx, seed.JetStream(), request.InstanceID)
	if err != nil || !completed.MatchesCompletedWorkerEnrollment(transport) {
		t.Fatal("public enrollment producers did not retain the exact completed request and response", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	certificate, err := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("original generated broker CA is invalid")
	}
	dialer := &jetStreamObserverDialer{Dialer: &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}}
	conn, err := nats.Connect(seed.URL(), nats.UserJWT(func() (string, error) { return issuedJWT, nil }, hostUser.Sign),
		nats.CustomInboxPrefix(protocol.InboxPrefix(configs[0].Cell, hostNKey)), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	session, stopSession := context.WithCancel(ctx)
	hostsDone := make(chan struct{})
	var hostsErr error
	go func() { hostsErr = hosts.Run(session); close(hostsDone) }()
	t.Cleanup(func() { stopSession(); <-hostsDone })
	select {
	case <-hosts.Ready():
	case <-hostsDone:
		t.Fatal("actual host controller stopped before initialization", hostsErr)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	ready := make(chan struct{})
	agent, err := host.NewAgent(host.AgentConfig{Cell: registration.Cell, Node: registration.Node, Environment: registration.Environment,
		Roles: registration.Roles, Conn: conn, Identity: hostKey, NATSUserPublicKey: hostNKey,
		ControllerPublicKey: responseKey.Public().(ed25519.PublicKey), InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t),
		WorkloadIdentity: testHostWorkloadIdentity(), ClockCheck: controllerClockCheck(clock), Initialized: func() { close(ready) }})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan struct{})
	var agentErr error
	go func() { agentErr = agent.RunSession(session); close(agentDone) }()
	t.Cleanup(func() { stopSession(); <-agentDone })
	select {
	case <-ready:
	case <-agentDone:
		t.Fatal("actual sole ownhost Agent stopped before initialization", agentErr)
	case <-ctx.Done():
		t.Fatal("actual sole ownhost Agent did not initialize", ctx.Err())
	}
	return &installedControllerHostFixture{installed: installed, process: process, sdk: sdk,
		brokers: brokers, control: control, hosts: hosts, agent: agent, transport: transport, session: session}
}
