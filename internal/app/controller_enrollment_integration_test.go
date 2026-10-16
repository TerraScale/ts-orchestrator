//go:build fixturetest

package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// This lower boundary composes public enrollment/CAS producers, current ordered
// registration, the SDK-backed recipient verifier and the issued-credential Agent.
// It does not run the HTTP handler, service child, production binding or native
// execution; the manager stays paused and its deferred providers stay closed.
func TestControllerEnrollmentIssuedCredentialsAndCurrentRecipient(t *testing.T) {
	if os.Getenv("TS_CONTROLLER_ENROLLMENT_NAMESPACE") != "1" {
		runControllerEnrollmentNamespace(t)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	auth := newAuthenticatedNATS(t, "gru")
	responsePublic, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(responseKey)
	ca, err := os.ReadFile(auth.tls.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	clientBundle, issuer, _ := testHostEnrollmentTLSMaterial(t, responsePublic)
	delegate, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer delegate.Wipe()
	delegatePublic, err := delegate.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer.CellAccount, issuer.NATSKey = auth.cellID, delegate
	// The fixture's existing server CA and enrollment client CA are separate;
	// both are trusted only in this temporary broker, outside host installation.
	if err := os.WriteFile(auth.tls.CAFile, append(bytes.Clone(ca), []byte(clientBundle.CAPEM)...), 0o600); err != nil {
		t.Fatal(err)
	}
	operatorKey, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	defer operatorKey.Wipe()
	operatorPublic, err := operatorKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	systemWire, err := os.ReadFile(auth.systemFile)
	if err != nil {
		t.Fatal(err)
	}
	systemClaim, err := jwt.DecodeAccountClaims(string(systemWire))
	if err != nil {
		t.Fatal(err)
	}
	operatorClaim := jwt.NewOperatorClaims(operatorPublic)
	operatorClaim.SystemAccount = systemClaim.Subject
	operatorJWT, err := operatorClaim.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	systemJWT, err := systemClaim.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	cellClaim, err := jwt.DecodeAccountClaims(auth.cellJWT)
	if err != nil {
		t.Fatal(err)
	}
	cellClaim.SigningKeys.AddScopedSigner(bootstrapmaterial.HostScope("gru", delegatePublic))
	auth.cellJWT, err = cellClaim.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string]string{auth.operatorFile: operatorJWT, auth.systemFile: systemJWT, auth.cellFile: auth.cellJWT} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := issuer.ValidateAccountScope(auth.cellJWT); err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU", Environment: "production",
		ControllerEndpoints: []string{"10.44.0.11:8443", "10.44.0.12:8443", "10.44.0.10:8443"},
		NATSURLs:            []string{"tls://10.44.0.11:4222", "tls://10.44.0.12:4222", "tls://10.44.0.10:4222"},
		CAPEM:               string(ca), ControllerResponsePublicKey: base64.StdEncoding.EncodeToString(responsePublic), CellAccountNKey: auth.cellID,
		InstallRoot: hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot, ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot,
		WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID}
	enrollment, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	roleSigner, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	rolePublic, err := roleSigner.PublicKey()
	roleSigner.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	broker := identityrekey.BrokerIdentity{Operator: operatorPublic, SystemAccount: systemClaim.Subject,
		CellAccount: auth.cellID, HostSigner: delegatePublic, RoleSigner: rolePublic}
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(root)
	foundation, grantWire, intent := managerStartupFoundation(t, root)
	fixture := bootstrapstart.NewControllerManagerStartupFixture(t, enrollment, broker, root, foundation)
	foundations := managerStartupFoundationResolver(t, fixture, grantWire, intent)
	vaultClient, bundles := managerStartupVault(t)
	admitted, err := swarmruntime.ReadAcceptedManagerAdmission(ctx, fixture.Reader, fixture.Accepted)
	if err != nil {
		t.Fatal(err)
	}
	if admitted.HostID != "controller-c" || admitted.Role != "manager" || admitted.InstanceID != fixture.Instance.InstanceOCID {
		t.Fatalf("accepted manager admission lost signed seed identity: %+v", admitted)
	}
	source := &managedRuntimeHost{reader: fixture.Reader, accepted: fixture.Accepted.Clone()}
	executor := &managerStartupExecutor{Executor: new(swarmruntime.Executor)}
	if err := executor.BindContainerMaterial(admitted, source); err != nil {
		t.Fatal(err)
	}
	if err := executor.SetRegistryResolver(source.registryResolver); err != nil {
		t.Fatal(err)
	}
	assertClosed := func() {
		t.Helper()
		material, err := source.CurrentContainerMaterial(ctx, swarmruntime.ContainerTaskBinding{})
		if err == nil || len(material.Files) != 0 {
			t.Fatal("deferred manager material became available without completed ownhost binding")
		}
		resolver, err := source.registryResolver(ctx, nil, nil)
		if err == nil || resolver != nil {
			t.Fatal("deferred manager registry became available without completed ownhost binding")
		}
	}
	assertClosed()
	node, err := swarmruntime.StartAcceptedNodeFixture(ctx, filepath.Join(t.TempDir(), "manager"), fixture.Reader, fixture.Accepted,
		foundations, vaultClient, bundles, executor, fixture.Observer, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := node.Stop(stopCtx); err != nil {
			t.Error(err)
		}
	})
	if err := setManagedRuntimeAvailability(ctx, node, admitted, api.NodeAvailabilityPause); err != nil {
		t.Fatal(err)
	}
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()})
	if err != nil || current.Node == nil || current.Node.Spec.Availability != api.NodeAvailabilityPause {
		t.Fatal("actual manager was not paused before enrollment", err)
	}
	runtime, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{}})
	if err != nil {
		t.Fatal(err)
	}
	control, err := authority.Start(ctx, runtime.JetStream(), authority.Config{DeploymentID: fixture.Accepted.DeploymentID,
		Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	artifacts, err := runtime.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: runtime.Conn(), JS: runtime.JetStream(), Artifacts: artifacts,
		ResponseKey: responseKey, StateReplicas: 1, HostMutations: control, AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard})
	if err != nil {
		t.Fatal(err)
	}
	grant := cellspec.HostGrant{Node: "ts-gru-c", Controller: "controller-c", PrivateIP: "10.44.0.10",
		Roles: []string{"ts-auth"}, Environment: "production"}
	signedSpec, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema,
		Identity:   cellspec.Identity{DeploymentID: fixture.Accepted.DeploymentID, Cell: "gru", Environment: fixture.Accepted.Environment},
		Generation: 1, RequiresBinary: 17, HostGrants: []cellspec.HostGrant{grant}},
		nil, fixture.Roots, time.Now().UTC(), time.Hour, root)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(hostKey)
	hostUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer hostUser.Wipe()
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
	descriptor := hostboot.Static("gru", "GRU", grant.Node)
	descriptorWire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	request := hostenroll.Request{SchemaVersion: 1, Operation: "enroll", InstanceID: fixture.Instance.InstanceOCID,
		Descriptor: string(descriptorWire), IdentityPublicKey: base64.StdEncoding.EncodeToString(hostPublic),
		NATSUserPublicKey: hostNKey, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Nonce: base64.StdEncoding.EncodeToString(nonce), IssuedAt: time.Now().UTC()}
	if err := request.Sign(hostKey); err != nil {
		t.Fatal(err)
	}
	requestWire, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	request, descriptor, err = hostenroll.ParseRequest(requestWire, time.Now().UTC())
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
	grants, err := hostenroll.OpenGrantStore(ctx, runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	claimed, claimRevision, err := grants.Claim(ctx, hostenroll.Grant{SchemaVersion: 1, InstanceID: request.InstanceID,
		CreateKey: entityid.New(), DescriptorSHA256: descriptorDigest, Request: requestWire})
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{Cell: "gru", Node: grant.Node, Environment: grant.Environment, Roles: grant.Roles, Generation: 1,
		PublicKey: request.IdentityPublicKey, NATSUserPublicKey: request.NATSUserPublicKey,
		Capacity: host.Capacity{CPU: 2, MemoryBytes: 16 << 30, DiskBytes: 64 << 30}}
	receipt, err := hosts.Register(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	issuedJWT, issuedChain, expires, err := issuer.Issue(request, csr, registration.Node, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	response := hostenroll.Response{SchemaVersion: 1, Operation: request.Operation, InstanceID: request.InstanceID,
		Node: descriptor.Node, DescriptorSHA256: descriptorDigest, RequestSHA256: hostenroll.RequestSHA256(requestWire),
		Nonce: request.Nonce, RegistrationReceipt: receipt, Roles: registration.Roles,
		NATSUserJWT: issuedJWT, TLSCertificatePEM: string(issuedChain), ExpiresAt: expires}
	if err := response.Sign(responseKey); err != nil {
		t.Fatal(err)
	}
	responseWire, err := protocol.EncodeJSON(response)
	if err != nil {
		t.Fatal(err)
	}
	response, err = hostenroll.VerifyResponse(responseWire, responsePublic, request, requestWire, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Finish(ctx, claimed, claimRevision, responseWire); err != nil {
		t.Fatal(err)
	}
	completed, completedRevision, err := hostenroll.ReadCurrentGrant(ctx, runtime.JetStream(), request.InstanceID)
	transport := hostenroll.WorkerTransport{Request: requestWire, Response: responseWire}
	if err != nil || completedRevision <= claimRevision || !completed.MatchesCompletedWorkerEnrollment(transport) ||
		!bytes.Equal(completed.Request, requestWire) || !bytes.Equal(completed.Response, responseWire) {
		t.Fatal("public producers did not complete the exact enrollment grant by CAS", err)
	}
	mutations, err := authority.OpenReader(ctx, runtime.JetStream(), "gru")
	if err != nil {
		t.Fatal(err)
	}
	registrations, err := host.NewReader(ctx, host.ReaderConfig{Cell: "gru", Conn: runtime.Conn(), JS: runtime.JetStream(),
		StateReplicas: 1, HostMutations: mutations})
	if err != nil {
		t.Fatal(err)
	}
	query := swarmruntime.WorkerRegistrationQuery{Request: requestWire, Response: responseWire}
	readRecipient := func(query swarmruntime.WorkerRegistrationQuery) (swarmruntime.WorkerRegistrationSnapshot, error) {
		request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, time.Now().UTC())
		if err != nil {
			return swarmruntime.WorkerRegistrationSnapshot{}, err
		}
		response, err := hostenroll.VerifyResponse(query.Response, responsePublic, request, query.Request, descriptor)
		if err != nil {
			return swarmruntime.WorkerRegistrationSnapshot{}, err
		}
		snapshot, err := currentWorkerRegistration(ctx, mutations, registrations, runtime.JetStream(), query, request.InstanceID, descriptor.Node, "gru")
		if err != nil {
			return snapshot, err
		}
		if snapshot.Pending {
			return snapshot, errors.New("controller recipient enrollment is incomplete")
		}
		if err := controllerHostRegistration(query, snapshot, request, descriptor, response, fixture.Accepted); err != nil {
			return snapshot, err
		}
		proof, err := fixture.ReadControllerHostRecipient(ctx, signedSpec, descriptor.Node, request.InstanceID, grant.PrivateIP)
		if err != nil {
			return snapshot, err
		}
		if err := proof.VerifyRegistration(ctx, snapshot.Registration); err != nil {
			return snapshot, err
		}
		confirmed, err := currentWorkerRegistration(ctx, mutations, registrations, runtime.JetStream(), query, request.InstanceID, descriptor.Node, "gru")
		if err != nil {
			return confirmed, err
		}
		before, err := protocol.EncodeJSON(snapshot)
		if err != nil {
			return snapshot, err
		}
		after, err := protocol.EncodeJSON(confirmed)
		if err != nil {
			return confirmed, err
		}
		if !bytes.Equal(before, after) || !proof.Valid(time.Now()) || !time.Now().Before(response.ExpiresAt) {
			return confirmed, errors.New("controller recipient changed during observation")
		}
		return confirmed, nil
	}
	snapshot, err := readRecipient(query)
	if err != nil || snapshot.Sequence != receipt.Revision || snapshot.Registration.Generation != receipt.Generation ||
		snapshot.InstanceID != request.InstanceID || snapshot.RequestSHA256 != response.RequestSHA256 || snapshot.Pending {
		t.Fatal("completed ordered registration lost its exact signed response/grant association", err)
	}
	changed := query
	changedResponse := response
	changedResponse.ExpiresAt = response.ExpiresAt.Add(-time.Minute)
	if err := changedResponse.Sign(responseKey); err != nil {
		t.Fatal(err)
	}
	changed.Response, err = protocol.EncodeJSON(changedResponse)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readRecipient(changed); err == nil {
		t.Fatal("changed response inherited the completed controller enrollment")
	}
	assertClosed()
	t.Log("public Claim/Register/Issue/Sign/Finish producers associate completed grant, ordered registration and SDK-backed recipient")
	hostCtx, stopHosts := context.WithCancel(ctx)
	hostDone := make(chan error, 1)
	go func() { hostDone <- hosts.Run(hostCtx) }()
	hostJoined := false
	defer func() {
		stopHosts()
		if !hostJoined {
			<-hostDone
		}
	}()
	select {
	case <-hosts.Ready():
	case err := <-hostDone:
		hostJoined = true
		t.Fatal("host controller stopped before Agent startup", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	before, err := hosts.ListHosts(ctx)
	if err != nil || len(before) != 1 || !before[0].SessionExpiresAt.IsZero() {
		t.Fatal("unexpected ownhost session before the one Agent", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	clientCertificate, err := tls.X509KeyPair([]byte(response.TLSCertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	brokerRoots, err := bundle.RootCAs()
	if err != nil {
		t.Fatal(err)
	}
	dialer := &jetStreamObserverDialer{Dialer: &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: brokerRoots, Certificates: []tls.Certificate{clientCertificate}}}}
	// Connect directly: auth.config would replace the issued scoped JWT.
	hostConn, err := nats.Connect(runtime.URL(), nats.UserJWT(func() (string, error) { return response.NATSUserJWT, nil }, hostUser.Sign),
		nats.CustomInboxPrefix(protocol.InboxPrefix("gru", hostNKey)), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer hostConn.Close()
	ready := make(chan struct{})
	var initialized atomic.Int32
	agent, err := host.NewAgent(host.AgentConfig{Cell: "gru", Node: registration.Node, Environment: registration.Environment, Roles: registration.Roles,
		Conn: hostConn, Identity: hostKey, NATSUserPublicKey: hostNKey, ControllerPublicKey: responsePublic, Runner: &inMemoryRunner{},
		InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), WorkloadIdentity: testHostWorkloadIdentity(),
		ClockCheck: func() error { return nil }, Initialized: func() { initialized.Add(1); close(ready) }})
	if err != nil {
		t.Fatal(err)
	}
	session, stopSession := context.WithCancel(ctx)
	sessionDone := make(chan error, 1)
	go func() { sessionDone <- agent.RunSession(session) }()
	joined := false
	defer func() {
		stopSession()
		if !joined {
			<-sessionDone
		}
	}()
	select {
	case <-ready:
	case err := <-sessionDone:
		joined = true
		t.Fatal("actual ownhost Agent stopped before its signed session", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	statuses, err := hosts.ListHosts(ctx)
	if err != nil || len(statuses) != 1 || !time.Now().Before(statuses[0].SessionExpiresAt) || initialized.Load() != 1 {
		t.Fatal("one real Agent did not establish exactly one current signed session", err)
	}
	if err := agent.VerifyOwnRegistration(statuses[0].Registration, responsePublic); err != nil {
		t.Fatal(err)
	}
	snapshot, err = readRecipient(query)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.VerifyOwnRegistration(snapshot.Registration, responsePublic); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Disable(ctx, request.InstanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecipient(query); err == nil {
		t.Fatal("disabled enrollment preserved the same current-source recipient")
	}
	assertClosed()
	stopSession()
	select {
	case err := <-sessionDone:
		joined = true
		if !errors.Is(err, context.Canceled) {
			t.Fatal("one Agent did not stop on its session context", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	current, err = client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()})
	if err != nil || current.Node == nil || current.Node.Spec.Availability != api.NodeAvailabilityPause {
		t.Fatal("ownhost session exit stopped or activated the independently owned manager", err)
	}
	assertClosed()
	t.Log("issued-credential Agent verified the same current registration; disabled grant refused; manager paused and providers closed")
}

func runControllerEnrollmentNamespace(t *testing.T) {
	t.Helper()
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const script = `set -eu
"$1" link set lo up
"$1" addr add 10.44.0.10/32 dev lo
TS_CONTROLLER_ENROLLMENT_NAMESPACE=1 GOMAXPROCS=2 exec "$2" -test.v -test.run='^TestControllerEnrollmentIssuedCredentialsAndCurrentRecipient$' -test.timeout=110s
`
	args := []string{unshare, "--net", "--fork", "--kill-child=SIGKILL", "--", "/bin/sh", "-c", script, "ts-controller-enrollment", ip, self}
	if os.Geteuid() != 0 {
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			t.Fatal(err)
		}
		args = append([]string{sudo, "-n"}, args...)
	}
	command := exec.CommandContext(t.Context(), args[0], args[1:]...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated controller enrollment fixture: %v\n%s", err, output)
	}
	t.Log(string(output))
}
