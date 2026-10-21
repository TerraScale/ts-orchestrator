//go:build linux && fixturetest

package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/runtimefixture"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

// This exercises creation-lineage refusal only; successful worker membership remains unqualified.
func TestWorkerStaticCreationLineageRefusesVaultPublication(t *testing.T) {
	if os.Getenv("TS_OBS_STATIC_LINEAGE_CHILD") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, "-test.run=^TestWorkerStaticCreationLineageRefusesVaultPublication$", "-test.v")
		command.Env = append(os.Environ(), "TS_OBS_STATIC_LINEAGE_CHILD=1")
		command.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
			GidMappingsEnableSetgroups: false,
		}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated static-worker refusal integration: %v\n%s", err, output)
		}
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"/run", "/var/lib"} {
		if err := unix.Mount("tmpfs", directory, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0700"); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "10.0.0.1/32", "dev", "lo"}, {"address", "add", "10.0.0.2/32", "dev", "lo"}} {
		if output, err := exec.CommandContext(t.Context(), "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("private worker network: %v: %s", err, output)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	js := testRolloutJetStream(t)
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	artifacts, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	material := generationtest.New(t, time.Now().UTC().Add(-4*24*time.Hour))
	const environment = "canary"
	responsePublic, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU", Environment: environment,
		ControllerEndpoints: []string{"10.0.0.1:8443", "10.0.0.3:8443", "10.0.0.4:8443"},
		NATSURLs:            []string{"tls://10.0.0.1:4222", "tls://10.0.0.3:4222", "tls://10.0.0.4:4222"},
		CAPEM:               string(material.Files["ca.pem"]), ControllerResponsePublicKey: base64.StdEncoding.EncodeToString(responsePublic),
		CellAccountNKey: material.CellID, WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID,
		InstallRoot: hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot, ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot}
	enrollment, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	current := runtimefixture.New(t, "10.0.0.1", enrollment, material)
	management, bundles, vaultCreates := lineageVault(t)
	socket := lineageContainerd(t, ctx)
	managerExecutor, err := swarmruntime.NewExecutor(socket, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = managerExecutor.Close() })
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.observedworker"
	observer, addressReads := lineageOCIObserver(t)
	manager, err := swarmruntime.StartAcceptedNodeFixture(ctx, t.TempDir(), current.Reader, current.Accepted,
		current.Foundations, management, bundles, managerExecutor, observer, enrollment)
	if err != nil {
		t.Fatal("start manager with current signed authority", err)
	}
	stopNode := func(node *swarmruntime.Node) {
		t.Helper()
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := node.Stop(stopCtx); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { stopNode(manager) })
	hostController, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: js.Conn(), JS: js, Artifacts: artifacts,
		ResponseKey: responseKey, StateReplicas: 1, HostMutations: control, AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard})
	if err != nil {
		t.Fatal(err)
	}
	issuerDirectory := t.TempDir()
	hostSeed, err := material.HostSigner.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(hostSeed)
	for name, data := range map[string][]byte{"host.seed": hostSeed, "host.key": material.Files["host-tls-issuer-key.pem"], "host.cert": material.Files["host-tls-issuer-cert.pem"]} {
		if err := os.WriteFile(filepath.Join(issuerDirectory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	hostIssuer, err := hostenroll.LoadIssuer("gru", material.CellID, filepath.Join(issuerDirectory, "host.seed"), filepath.Join(issuerDirectory, "host.key"), filepath.Join(issuerDirectory, "host.cert"), material.Files["ca.pem"])
	if err != nil {
		t.Fatal(err)
	}
	defer hostIssuer.NATSKey.Wipe()
	if err := hostIssuer.ValidateAccountScope(strings.TrimSpace(string(material.Files["cell.jwt"]))); err != nil {
		t.Fatal(err)
	}

	for _, node := range []string{"gru-pool-wasm-1", "ts-gru-4", "gru-ctl-1", "gru-db-1"} {
		t.Run(node, func(t *testing.T) {
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			user, err := nkeys.CreateUser()
			if err != nil {
				t.Fatal(err)
			}
			defer user.Wipe()
			userID, err := user.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			registration := host.Registration{ID: entityid.Derive("host", "gru", node), Cell: "gru", Node: node, Environment: environment,
				Roles: []string{swarmruntime.FunctionWorkerRole}, Generation: 1, PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: userID}
			receipt, err := hostController.Register(ctx, registration)
			if err != nil {
				t.Fatal(err)
			}
			descriptor := hostboot.Static("gru", "GRU", node)
			descriptorWire, err := descriptor.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			descriptorDigest, err := descriptor.Digest()
			if err != nil {
				t.Fatal(err)
			}
			csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrKey)
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			request := hostenroll.Request{SchemaVersion: 1, Operation: "enroll", InstanceID: instanceID, Descriptor: string(descriptorWire),
				IdentityPublicKey: registration.PublicKey, NATSUserPublicKey: userID, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
				Nonce: base64.StdEncoding.EncodeToString(nonce), IssuedAt: now}
			if err := request.Sign(key); err != nil {
				t.Fatal(err)
			}
			requestWire, err := protocol.EncodeJSON(request)
			if err != nil {
				t.Fatal(err)
			}
			parsedCSR, err := hostenroll.ParseCSR(request.CSRPEM)
			if err != nil {
				t.Fatal(err)
			}
			hostJWT, certificate, expires, err := hostIssuer.Issue(request, parsedCSR, descriptor.Node, now)
			if err != nil {
				t.Fatal(err)
			}
			response := hostenroll.Response{SchemaVersion: 1, Operation: "enroll", InstanceID: instanceID, Node: descriptor.Node,
				DescriptorSHA256: descriptorDigest, RequestSHA256: hostenroll.RequestSHA256(requestWire), Nonce: request.Nonce,
				RegistrationReceipt: receipt, NATSUserJWT: hostJWT, TLSCertificatePEM: string(certificate), ExpiresAt: expires}
			if err := response.Sign(responseKey); err != nil {
				t.Fatal(err)
			}
			responseWire, err := protocol.EncodeJSON(response)
			if err != nil {
				t.Fatal(err)
			}
			before := vaultCreates.Load()
			beforeReads := addressReads.Load()
			if _, err := manager.PrepareEnrolledWorker(ctx, swarmruntime.WorkerRegistrationQuery{Request: requestWire, Response: responseWire}); !errors.Is(err, swarmruntime.ErrWorkerCreationLineagePending) {
				t.Fatalf("genuine signed static enrollment did not stop at creation lineage: %v", err)
			}
			if vaultCreates.Load() != before {
				t.Fatal("unproven static enrollment published worker credentials")
			}
			if addressReads.Load() != beforeReads {
				t.Fatal("unproven static enrollment triggered worker OCI reads")
			}
			client, err := manager.ControlClient(ctx)
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
			if err != nil {
				t.Fatal(err)
			}
			for _, node := range nodes.Nodes {
				if node.Role == api.NodeRoleWorker {
					t.Fatal("unproven static enrollment admitted a worker")
				}
			}
		})
	}
}

func lineageContainerd(t *testing.T, ctx context.Context) string {
	t.Helper()
	binary, err := exec.LookPath("containerd")
	if err != nil {
		t.Fatal("fixture requires the actual containerd binary in PATH", err)
	}
	directory := t.TempDir()
	socket := filepath.Join(directory, "containerd.sock")
	command := exec.CommandContext(ctx, binary, "--root", filepath.Join(directory, "root"), "--state", filepath.Join(directory, "state"), "--address", socket, "--log-level", "error")
	log, err := os.Create(filepath.Join(directory, "containerd.log"))
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
		_ = log.Close()
	})
	for {
		if info, err := os.Stat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			return socket
		}
		select {
		case err := <-done:
			// Preserve a completion result for cleanup after an early exit.
			done <- err
			data, _ := os.ReadFile(log.Name())
			t.Fatalf("actual containerd failed to start: %v\n%s", err, data)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// The HTTP endpoint implements OCI's wire protocol; callers are real signed SDK
// clients and production create-once/current/exact-version Vault functions.
func lineageVault(t *testing.T) (*vault.VaultsClient, *secrets.SecretsClient, *atomic.Int64) {
	t.Helper()
	var mu sync.Mutex
	values := make(map[string]string)
	creates := new(atomic.Int64)
	id := func(name string) string {
		digest := sha256.Sum256([]byte(name))
		return "ocid1.vaultsecret.oc1.sa-saopaulo-1." + hex.EncodeToString(digest[:])
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			http.Error(w, "signed SDK requests required", http.StatusUnauthorized)
			return
		}
		write := func(value any) {
			if err := json.MarshalWrite(w, value); err != nil {
				t.Errorf("Vault HTTP response: %v", err)
			}
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets"):
			name := r.URL.Query().Get("name")
			items := []any{}
			if _, exists := values[name]; exists {
				items = append(items, map[string]any{"id": id(name), "secretName": name, "lifecycleState": "ACTIVE"})
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
				http.Error(w, "invalid OCI protocol request", http.StatusBadRequest)
				return
			}
			if _, exists := values[body.SecretName]; exists {
				w.WriteHeader(http.StatusConflict)
				write(map[string]string{"code": "Conflict", "message": "secret already exists"})
				return
			}
			values[body.SecretName] = body.SecretContent.Content
			creates.Add(1)
			write(map[string]any{"id": id(body.SecretName), "secretName": body.SecretName, "lifecycleState": "ACTIVE"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "getByName"):
			name := r.URL.Query().Get("secretName")
			value, exists := values[name]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				write(map[string]string{"code": "NotFound", "message": "absent"})
				return
			}
			write(map[string]any{"secretId": id(name), "versionNumber": 1, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": value}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/secretbundles/"):
			for name, value := range values {
				if strings.HasSuffix(r.URL.Path, "/"+id(name)) && r.URL.Query().Get("versionNumber") == "1" {
					write(map[string]any{"secretId": id(name), "versionNumber": 1, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": value}})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			write(map[string]string{"code": "NotFound", "message": "exact secret version absent"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(endpoint.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..observation", "ocid1.user.oc1..observation", "sa-saopaulo-1", "fixture-fingerprint", string(private), nil)
	management, err := vault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	read, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	management.Host, management.HTTPClient = endpoint.URL, endpoint.Client()
	read.Host, read.HTTPClient = endpoint.URL, endpoint.Client()
	return &management, &read, creates
}

func lineageOCIObserver(t *testing.T) (*bootstrapstart.OCIInstanceObserver, *atomic.Int64) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..observation", "ocid1.user.oc1..observation", "sa-saopaulo-1", "fixture-fingerprint", keyPEM, nil)
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := bootstrapstart.NewOCIInstanceObserverWithClients(oci.RegionGRU, provider, &compute, &network)
	if err != nil {
		t.Fatal(err)
	}
	reads := new(atomic.Int64)
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		t.Errorf("static worker refusal unexpectedly reached OCI: %s %s", r.Method, r.URL.Path)
		http.Error(w, "creation authority is pending", http.StatusForbidden)
	}))
	t.Cleanup(apiServer.Close)
	compute.Host, network.Host = apiServer.URL, apiServer.URL
	return observer, reads
}
