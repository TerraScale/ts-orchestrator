//go:build fixturetest

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

// This is a composition boundary: genuine Gate authority, signed SDK/CAS,
// upstream manager/Raft/Vault and one signed NATS Agent session. HomeIAM, the
// production session wrapper/observer, native execution and material delivery
// remain separate; deferred providers must stay closed throughout this test.
func TestManagedRuntimeReadyBeforeSingleOwnHostSession(t *testing.T) {
	if os.Getenv("TS_MANAGER_STARTUP_NAMESPACE") != "1" {
		runManagerStartupNamespace(t)
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
	operatorWire, err := os.ReadFile(auth.operatorFile)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := jwt.DecodeOperatorClaims(string(operatorWire))
	if err != nil {
		t.Fatal(err)
	}
	systemWire, err := os.ReadFile(auth.systemFile)
	if err != nil {
		t.Fatal(err)
	}
	system, err := jwt.DecodeAccountClaims(string(systemWire))
	if err != nil {
		t.Fatal(err)
	}
	broker := identityrekey.BrokerIdentity{Operator: operator.Subject, SystemAccount: system.Subject, CellAccount: auth.cellID}
	for _, target := range []*string{&broker.HostSigner, &broker.RoleSigner} {
		key, err := nkeys.CreateAccount()
		if err != nil {
			t.Fatal(err)
		}
		*target, err = key.PublicKey()
		key.Wipe()
		if err != nil {
			t.Fatal(err)
		}
	}
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
		t.Fatal("actual manager was not paused before root READY", err)
	}
	notifyPath := filepath.Join(t.TempDir(), "notify.sock")
	notifications, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notifications.Close()
	if err := sdnotify.New(notifyPath, "", "", os.Getpid()).Ready("accepted manager fixture ready"); err != nil {
		t.Fatal(err)
	}
	if err := notifications.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, 256)
	n, _, err := notifications.ReadFromUnix(message)
	if err != nil || !strings.HasPrefix(string(message[:n]), "READY=1\n") {
		t.Fatal("root readiness datagram was not observed before Agent startup", err)
	}
	t.Log("signed controller-c manager and create-once Vault ready before NATS/Agent startup")

	// NATS and its one host Agent begin only after the manager's READY datagram.
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
	hostPublic, hostKey := testEd25519(t, t.TempDir(), "host.key")
	defer clear(hostKey)
	hostNKey, hostSeed := testNKey(t)
	registration := host.Registration{Cell: "gru", Node: "ts-gru-c", Environment: "production", Roles: []string{"ts-auth"}, Generation: 1,
		PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: hostNKey,
		Capacity: host.Capacity{CPU: 2, MemoryBytes: 16 << 30, DiskBytes: 64 << 30}}
	if _, err := hosts.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
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
	hostRuntime, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Instance: "ownhost", URL: runtime.Conn().ConnectedUrl(),
		ClientRole: "host", NKeySeedFile: hostSeed})
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	var initialized atomic.Int32
	agent, err := host.NewAgent(host.AgentConfig{Cell: "gru", Node: registration.Node, Environment: registration.Environment, Roles: registration.Roles,
		Conn: hostRuntime.Conn(), Identity: hostKey, NATSUserPublicKey: hostNKey, ControllerPublicKey: responsePublic, Runner: &inMemoryRunner{},
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
	t.Log("one actual signed Agent session stopped; manager remains live and deferred material/registry stay closed")
}

func runManagerStartupNamespace(t *testing.T) {
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
TS_MANAGER_STARTUP_NAMESPACE=1 GOMAXPROCS=2 exec "$2" -test.v -test.run='^TestManagedRuntimeReadyBeforeSingleOwnHostSession$' -test.timeout=110s
`
	args := []string{unshare, "--net", "--fork", "--kill-child=SIGKILL", "--", "/bin/sh", "-c", script, "ts-manager-startup", ip, self}
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
		t.Fatalf("isolated manager startup fixture: %v\n%s", err, output)
	}
	t.Log(string(output))
}

type managerStartupExecutor struct{ *swarmruntime.Executor }

func (*managerStartupExecutor) Describe(context.Context) (*api.NodeDescription, error) {
	return &api.NodeDescription{Hostname: "oracle-controller-c", Platform: &api.Platform{OS: "linux", Architecture: runtime.GOARCH},
		Resources: &api.Resources{NanoCPUs: 2_000_000_000, MemoryBytes: 16 << 30}}, nil
}
func (*managerStartupExecutor) Controller(*api.Task) (swarmexec.Controller, error) {
	return nil, errors.New("manager startup fixture does not execute tasks")
}

func managerStartupFoundation(t *testing.T, root ed25519.PrivateKey) (bootstrap.FoundationScope, []byte, region.FoundationIntent) {
	t.Helper()
	domain := bootstrap.StorageDomain{Namespace: "namespace-a", LedgerBucket: "ledger-bucket", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger",
		HeadBucket: "head-bucket", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap"}
	intent := region.FoundationIntent{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": "ocid1.tenancy.oc1..test",
		"parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared",
		"resource_ids": map[string]any{"control_compartment": "ocid1.compartment.oc1..control", "vault": "ocid1.vault.oc1.sa-saopaulo-1.control", "key": "ocid1.key.oc1.sa-saopaulo-1.control"}}}
	grant := region.FoundationGrant{InstallationID: entityid.New(), SchemaVersion: 1, Generation: 1, TenancyID: "ocid1.tenancy.oc1..test",
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD",
		MonthlyLimitMinor: 10000, CleanupOwner: "manager-startup-fixture", Regions: []region.FoundationIntent{intent}}
	payload, err := trust.EncodePayload(grant)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	signed, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: bootstrapstart.ControllerManagerStartupDeployment,
		Cell: "GRU", Environment: "production", Role: "foundation", Slot: bootstrapstart.ControllerManagerStartupCluster}, now.Add(-time.Minute), now.Add(30*time.Minute), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	return bootstrap.FoundationScope{InstallationID: grant.InstallationID, DeploymentID: bootstrapstart.ControllerManagerStartupDeployment,
		ClusterID: bootstrapstart.ControllerManagerStartupCluster, TenancyID: grant.TenancyID, OCIRegion: "sa-saopaulo-1",
		StorageDomain: domain, GrantGeneration: 1, GrantSHA256: hex.EncodeToString(digest[:])}, wire, intent
}

func managerStartupFoundationResolver(t *testing.T, fixture *bootstrapstart.ControllerManagerStartupFixture, grant []byte, intent region.FoundationIntent) region.FoundationResolver {
	t.Helper()
	domain := fixture.Anchor.Anchor().StorageDomain
	digest := sha256.Sum256(grant)
	_, err := fixture.Storage.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket),
		ObjectName: new(domain.Prefix + "/foundation-scope-v1.json"), ContentLength: new(int64(len(grant))), PutObjectBody: io.NopCloser(bytes.NewReader(grant)),
		IfNoneMatch: new("*"), OpcSseKmsKeyId: new(domain.HeadKMSKeyOCID), OpcContentSha256: new(base64.StdEncoding.EncodeToString(digest[:]))})
	if err != nil {
		t.Fatal(err)
	}
	footprint, err := region.NewSignedFootprint(fixture.Storage, fixture.Anchor, fixture.Roots, "ocid1.tenancy.oc1..test")
	if err != nil {
		t.Fatal(err)
	}
	store, err := region.NewObjectFoundationStore(fixture.Storage, domain.Namespace, domain.HeadBucket)
	if err != nil {
		t.Fatal(err)
	}
	intentDigest, err := region.FoundationIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record := region.FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1..test",
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Generation: 1,
		IntentDigest: intentDigest, OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now,
		ResourceIDs: map[string]string{"control_compartment": "ocid1.compartment.oc1..control", "vault": "ocid1.vault.oc1.sa-saopaulo-1.control", "key": "ocid1.key.oc1.sa-saopaulo-1.control"}}
	if _, err := store.CompareAndSwap(t.Context(), record, ""); err != nil {
		t.Fatal(err)
	}
	resolver := region.FoundationResolver{Footprint: footprint, Store: store}
	if _, err := resolver.Resolve(t.Context(), "GRU"); err != nil {
		t.Fatal(err)
	}
	return resolver
}

func managerStartupVault(t *testing.T) (*vault.VaultsClient, *secrets.SecretsClient) {
	t.Helper()
	var mu sync.Mutex
	values := make(map[string]string)
	secretID := func(name string) string {
		sum := sha256.Sum256([]byte(name))
		return "ocid1.vaultsecret.oc1.sa-saopaulo-1." + hex.EncodeToString(sum[:])
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned Vault SDK request", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		write := func(body any) {
			if err := json.MarshalWrite(w, body); err != nil {
				t.Error(err)
			}
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets"):
			name := r.URL.Query().Get("name")
			items := []any{}
			if _, ok := values[name]; ok {
				items = append(items, map[string]any{"id": secretID(name), "secretName": name, "lifecycleState": "ACTIVE"})
			}
			write(items)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets"):
			var body struct {
				SecretName    string `json:"secretName"`
				SecretContent struct {
					Content string `json:"content"`
				} `json:"secretContent"`
			}
			if err := json.UnmarshalRead(r.Body, &body); err != nil || body.SecretName == "" || body.SecretContent.Content == "" {
				http.Error(w, "invalid Vault body", 400)
				return
			}
			if _, ok := values[body.SecretName]; ok {
				http.Error(w, `{"code":"Conflict","message":"already exists"}`, 409)
				return
			}
			values[body.SecretName] = body.SecretContent.Content
			write(map[string]any{"id": secretID(body.SecretName), "secretName": body.SecretName, "lifecycleState": "ACTIVE"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "getByName"):
			name := r.URL.Query().Get("secretName")
			value, ok := values[name]
			if !ok {
				http.Error(w, `{"code":"NotFound","message":"absent"}`, 404)
				return
			}
			write(map[string]any{"secretId": secretID(name), "versionNumber": 1, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": value}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/secretbundles/"):
			for name, value := range values {
				if strings.HasSuffix(r.URL.Path, "/"+secretID(name)) && r.URL.Query().Get("versionNumber") == "1" {
					write(map[string]any{"secretId": secretID(name), "versionNumber": 1, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": value}})
					return
				}
			}
			http.Error(w, `{"code":"NotFound","message":"absent version"}`, 404)
		default:
			http.Error(w, "unexpected Vault SDK operation", 404)
		}
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "fixture-fingerprint", string(private), nil)
	management, err := vault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	read, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	management.Host, management.HTTPClient = server.URL, server.Client()
	read.Host, read.HTTPClient = server.URL, server.Client()
	return &management, &read
}
