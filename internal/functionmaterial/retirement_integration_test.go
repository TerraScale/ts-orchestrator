package functionmaterial

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

func TestRetirementUsesConditionalOCIRequestsAndRecoversLostReply(t *testing.T) {
	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	proof := materialProof(t, roots, private, 1)
	natsServer, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go natsServer.Start()
	if !natsServer.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { natsServer.Shutdown(); natsServer.WaitForShutdown() })
	conn, err := nats.Connect(natsServer.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	control, err := authority.Start(t.Context(), js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	epoch := control.Current().Epoch
	if _, err := control.CommitFunctionIntent(t.Context(), epoch, entityid.New(), 0, proof); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{TaskID: strings.Repeat("a", 25), ServiceID: strings.Repeat("b", 25), NodeID: strings.Repeat("c", 25), InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.worker", Region: "sa-saopaulo-1", HostID: entityid.New(), Fingerprint: strings.Repeat("a", 64)}
	expires := time.Now().UTC().Add(3 * time.Second)
	material := storedMaterial{Schema: 1, Binding: binding, TenantID: proof.Claim().TenantID, FunctionID: proof.Claim().FunctionID, EnvelopeSHA256: proof.EnvelopeSHA256(), IntentSequence: 1, AccountSequence: 1, Generation: strings.Repeat("a", 64), ExpiresAt: expires,
		Files: map[string][]byte{"broker.creds": []byte("test-private-credentials"), "broker-ca.pem": []byte("test-ca"), "ingress-cert.pem": []byte("test-cert"), "ingress-key.pem": []byte("test-private-key"), "ingress-ca.pem": []byte("test-issuer")}}
	wire, err := encodeMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.CommitFunctionGrant(t.Context(), epoch, entityid.New(), 0, proof, bindingGrant(binding, sum(wire))); err != nil {
		t.Fatal(err)
	}
	backend := &retirementBackend{target: vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..function", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.function"}, wire: wire}
	ref, err := secretRef(backend.target.VaultID, binding)
	if err != nil {
		t.Fatal(err)
	}
	backend.name = ref.Name
	endpoint := httptest.NewServer(http.HandlerFunc(backend.serve))
	t.Cleanup(endpoint.Close)
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..function", "ocid1.user.oc1..function", binding.Region, "fp", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	vault, err := ocivault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	vault.Host, bundles.Host = endpoint.URL, endpoint.URL
	factory, err := ociclient.New(provider, ociclient.Options{Region: binding.Region, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceVault: {PerSecond: 1000, Burst: 1000}}})
	if err != nil {
		t.Fatal(err)
	}
	factory.Configure(&vault.BaseClient, ociclient.ServiceVault)
	factory.Configure(&bundles.BaseClient, ociclient.ServiceVault)
	controller := Controller{Authority: control, Reader: Reader{Bundles: &bundles, VaultID: backend.target.VaultID}, Target: backend.target}
	unused := func(_ context.Context, actual Binding) error {
		if actual != binding {
			return ErrMaterial
		}
		return nil
	}
	backend.reset()
	retired, err := controller.RetireExpired(t.Context(), &vault, unused)
	_, schedules, _ := backend.observations()
	if err != nil || len(retired) != 0 || schedules != 0 {
		t.Fatalf("unexpired delivery retired: %d, %v", len(retired), err)
	}
	// Commit while the delivery is valid, then let its real expiry pass.
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-time.After(time.Until(expires) + 10*time.Millisecond):
	}
	for _, test := range []struct {
		name          string
		prepare       func()
		denyCall      int
		wantSchedules int
	}{
		{name: "current task remains referenced", denyCall: 1},
		{name: "final observation fails", denyCall: 2},
		{name: "current version changes", prepare: func() { backend.changeBundle = true }},
		{name: "metadata etag changes", prepare: func() { backend.changeMetadata = true }},
		{name: "granted bytes change", prepare: func() { backend.wire = append(append([]byte(nil), wire...), ' ') }},
		{name: "provider schedule fails", prepare: func() { backend.rejectSchedule = true }, wantSchedules: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend.reset()
			backend.mu.Lock()
			backend.wire = wire
			if test.prepare != nil {
				test.prepare()
			}
			backend.mu.Unlock()
			calls := 0
			_, err := controller.RetireExpired(t.Context(), &vault, func(ctx context.Context, actual Binding) error {
				calls++
				if calls == test.denyCall {
					return errors.New("task absence could not be established")
				}
				return unused(ctx, actual)
			})
			state, schedules, _ := backend.observations()
			if err == nil || state != "ACTIVE" || schedules != test.wantSchedules {
				t.Fatalf("unsafe or retried retirement: state=%s schedules=%d error=%v", state, schedules, err)
			}
		})
	}
	backend.reset()
	backend.mu.Lock()
	backend.wire = wire
	backend.loseReply = true
	backend.mu.Unlock()
	retired, err = controller.RetireExpired(t.Context(), &vault, unused)
	_, schedules, reads := backend.observations()
	if err != nil || len(retired) != 1 || schedules != 1 || retired[0].TaskID != binding.TaskID || retired[0].MaterialSHA256 != sum(wire) || !retired[0].ExpiresAt.Equal(expires) || time.Until(retired[0].DeleteAt) < 24*time.Hour {
		t.Fatalf("lost schedule reply was not recovered: count=%d schedules=%d error=%v", len(retired), schedules, err)
	}
	restarted := Controller{Authority: control, Reader: Reader{Bundles: &bundles, VaultID: backend.target.VaultID}, Target: backend.target}
	retired, err = restarted.RetireExpired(t.Context(), &vault, func(context.Context, Binding) error { t.Fatal("pending deletion rechecked task"); return ErrMaterial })
	_, schedules, afterReads := backend.observations()
	if err != nil || len(retired) != 1 || retired[0].TaskID != "" || schedules != 1 || afterReads != reads {
		t.Fatalf("restart replayed deletion or read inaccessible bundle: schedules=%d bundles=%d error=%v", schedules, afterReads, err)
	}
	if _, err := control.ReadFunctionGrant(t.Context(), binding.TaskID); err != nil {
		t.Fatal("retirement removed the audit grant")
	}
	t.Run("interrupted publication without grant", func(t *testing.T) {
		backend.reset()
		orphan := material
		orphan.Binding.TaskID = strings.Repeat("d", 25)
		ref, err := secretRef(backend.target.VaultID, orphan.Binding)
		if err != nil {
			t.Fatal(err)
		}
		orphanWire, err := json.Marshal(orphan)
		if err != nil {
			t.Fatal(err)
		}
		backend.mu.Lock()
		backend.name, backend.wire = ref.Name, orphanWire
		backend.mu.Unlock()
		checks := 0
		retired, err := controller.RetireExpired(t.Context(), &vault, func(_ context.Context, candidate Binding) error {
			checks++
			if candidate != orphan.Binding {
				return ErrMaterial
			}
			return nil
		})
		_, schedules, _ := backend.observations()
		if err != nil || len(retired) != 1 || checks != 2 || schedules != 1 || retired[0].TaskID != orphan.Binding.TaskID {
			t.Fatalf("ungranted orphan not retired safely: count=%d checks=%d schedules=%d error=%v", len(retired), checks, schedules, err)
		}
	})
}

type retirementBackend struct {
	mu                                      sync.Mutex
	target                                  vaultsecret.Target
	name, state                             string
	wire                                    []byte
	deleteAt                                time.Time
	metadataReads, bundleReads, schedules   int
	changeBundle, changeMetadata, loseReply bool
	rejectSchedule                          bool
}

func (backend *retirementBackend) observations() (state string, schedules, bundles int) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.state, backend.schedules, backend.bundleReads
}

func (backend *retirementBackend) reset() {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.state, backend.deleteAt = "ACTIVE", time.Time{}
	backend.metadataReads, backend.bundleReads, backend.schedules = 0, 0, 0
	backend.changeBundle, backend.changeMetadata, backend.loseReply, backend.rejectSchedule = false, false, false, false
}

func (backend *retirementBackend) serve(w http.ResponseWriter, r *http.Request) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(value any) { _ = json.MarshalWrite(w, value) }
	metadata := func() map[string]any {
		result := map[string]any{"id": materialSecretID, "compartmentId": backend.target.CompartmentID, "vaultId": backend.target.VaultID, "secretName": backend.name, "description": "Admitted function task material", "lifecycleState": backend.state, "currentVersionNumber": 1}
		if !backend.deleteAt.IsZero() {
			result["timeOfDeletion"] = backend.deleteAt
		}
		return result
	}
	switch {
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/secrets"):
		if r.URL.Query().Get("compartmentId") != backend.target.CompartmentID || r.URL.Query().Get("vaultId") != backend.target.VaultID || r.URL.Query().Get("limit") != "1000" {
			http.Error(w, "unscoped enumeration", 400)
			return
		}
		write([]any{metadata()})
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/secrets/"+materialSecretID):
		backend.metadataReads++
		etag := "1"
		if backend.changeMetadata && backend.metadataReads > 1 {
			etag = "2"
		}
		w.Header().Set("ETag", etag)
		write(metadata())
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName"):
		backend.bundleReads++
		if backend.state != "ACTIVE" {
			http.Error(w, "bundle unavailable", 403)
			return
		}
		version := 1
		if backend.changeBundle && backend.bundleReads > 1 {
			version = 2
		}
		write(map[string]any{"secretId": materialSecretID, "versionNumber": version, "secretBundleContent": map[string]any{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(backend.wire)}})
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/secrets/"+materialSecretID+"/actions/scheduleDeletion"):
		backend.schedules++
		var request ocivault.ScheduleSecretDeletionDetails
		if json.UnmarshalRead(r.Body, &request) != nil || request.TimeOfDeletion == nil || r.Header.Get("If-Match") != "1" || backend.state != "ACTIVE" {
			http.Error(w, "invalid conditional deletion", 412)
			return
		}
		if backend.rejectSchedule {
			http.Error(w, "unavailable", 500)
			return
		}
		backend.state, backend.deleteAt = "PENDING_DELETION", request.TimeOfDeletion.Time
		if backend.loseReply {
			http.Error(w, "lost accepted response", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, fmt.Sprintf("unknown route %s %s", r.Method, r.URL.Path), 404)
	}
}
