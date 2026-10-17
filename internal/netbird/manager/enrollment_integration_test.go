package manager

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// Actual clients cross NetBird/OCI HTTP and protected escrow/filesystem boundaries.
func TestEnrollmentRecoversCommittedResponsesAndDelivery(t *testing.T) {
	for _, interruption := range []string{"group-response", "key-response", "vault-response", "before-key-dispatch", "vault-epoch-loss"} {
		t.Run(interruption, func(t *testing.T) {
			root := t.TempDir()
			groupPath := filepath.Join(root, "groups.json")
			keyPath, vaultPath := filepath.Join(root, "upstream.json"), filepath.Join(root, "vault.json")
			const keyValue = "884B8BCF-16BC-4D2C-8A3F-AE5F8B6B3BA3"
			const secretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.test.enrollment"
			var interrupted atomic.Bool
			var groupsCreated, keysCreated, vaultsCreated atomic.Int32
			var vaultAttempts atomic.Int32
			var term atomic.Uint64
			term.Store(1)
			managerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Token "+testPAT {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				keys := readEnrollmentJSON[[]apiSetupKey](t, keyPath)
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/groups":
					groups := readEnrollmentJSON[[]apiGroup](t, groupPath)
					if groups == nil {
						groups = []apiGroup{}
					}
					writeEnrollmentJSON(t, w, groups)
				case r.Method == http.MethodPost && r.URL.Path == "/api/groups":
					var request groupRequest
					if err := json.UnmarshalRead(r.Body, &request); err != nil || request.Name != "gru-servers" || len(request.Peers) != 0 || len(request.Resources) != 0 {
						t.Error("invalid genesis server group")
						w.WriteHeader(400)
						return
					}
					groupsCreated.Add(1)
					persistEnrollmentJSON(t, groupPath, []apiGroup{{ID: "servers", Name: request.Name, Issued: "api"}})
					if interruption == "group-response" && interrupted.CompareAndSwap(false, true) {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					writeEnrollmentJSON(t, w, created{ID: "servers"})
				case r.Method == http.MethodGet && r.URL.Path == "/api/setup-keys":
					if keys == nil {
						keys = []apiSetupKey{}
					}
					writeEnrollmentJSON(t, w, keys)
				case r.Method == http.MethodPost && r.URL.Path == "/api/setup-keys":
					var request setupKeyRequest
					if err := json.UnmarshalRead(r.Body, &request); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					id := fmt.Sprintf("key-%d", keysCreated.Add(1))
					keys = append(keys, apiSetupKey{ID: id, Name: request.Name, Type: request.Type,
						State: "valid", Valid: true, AutoGroups: request.AutoGroups})
					persistEnrollmentJSON(t, keyPath, keys)
					if interruption == "key-response" && interrupted.CompareAndSwap(false, true) {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					writeEnrollmentJSON(t, w, map[string]string{"id": id, "key": keyValue})
				case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/setup-keys/"):
					var request struct {
						Revoked bool `json:"revoked"`
					}
					if err := json.UnmarshalRead(r.Body, &request); err != nil || !request.Revoked {
						t.Errorf("invalid targeted revocation: %v", err)
					}
					id := strings.TrimPrefix(r.URL.Path, "/api/setup-keys/")
					for i := range keys {
						if keys[i].ID == id {
							keys[i].Revoked, keys[i].Valid, keys[i].State = true, false, "revoked"
						}
					}
					persistEnrollmentJSON(t, keyPath, keys)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected NetBird request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			t.Cleanup(managerServer.Close)
			factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
				stored := readEnrollmentJSON[map[string]any](t, vaultPath)
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "secretbundles/actions/getByName"):
					if stored == nil {
						w.WriteHeader(http.StatusNotFound)
						writeEnrollmentJSON(t, w, map[string]string{"code": "SecretNotFound", "message": "absent"})
						return
					}
					writeEnrollmentJSON(t, w, map[string]any{"secretId": secretID, "versionNumber": 1,
						"secretBundleContent": map[string]string{"contentType": "BASE64", "content": stored["content"].(string)}})
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets"):
					items := []map[string]any{}
					if stored != nil {
						items = append(items, map[string]any{"id": secretID, "secretName": stored["name"], "lifecycleState": "ACTIVE"})
					}
					writeEnrollmentJSON(t, w, items)
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets"):
					vaultAttempts.Add(1)
					if interruption == "vault-epoch-loss" && interrupted.CompareAndSwap(false, true) {
						term.Add(1)
						w.WriteHeader(http.StatusServiceUnavailable)
						writeEnrollmentJSON(t, w, map[string]string{"code": "Unavailable", "message": "authority lost before retry"})
						return
					}
					var request struct {
						SecretName    string `json:"secretName"`
						SecretContent struct {
							Content string `json:"content"`
						} `json:"secretContent"`
					}
					if err := json.UnmarshalRead(r.Body, &request); err != nil {
						t.Error(err)
						return
					}
					if r.Header.Get("opc-retry-token") == "" {
						t.Error("Vault create lacks retry identity")
					}
					decoded, err := base64.StdEncoding.DecodeString(request.SecretContent.Content)
					if err != nil || string(decoded) != keyValue {
						t.Error("Vault delivery differs from escrow")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					vaultsCreated.Add(1)
					persistEnrollmentJSON(t, vaultPath, map[string]any{"name": request.SecretName, "content": request.SecretContent.Content})
					if interruption == "vault-response" && interrupted.CompareAndSwap(false, true) {
						w.WriteHeader(http.StatusBadRequest)
						writeEnrollmentJSON(t, w, map[string]string{"code": "Interrupted", "message": "response lost after commit"})
						return
					}
					writeEnrollmentJSON(t, w, map[string]string{"id": secretID})
				default:
					t.Errorf("unexpected Vault request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
			if err != nil {
				t.Fatal(err)
			}
			factory.Configure(&management.BaseClient, ociclient.ServiceVault)
			management.Host = endpoint
			bundles, err := vaultsecret.SecretsClient(factory)
			if err != nil {
				t.Fatal(err)
			}
			bundles.Host = endpoint
			vault := EnrollmentVault{Target: vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..control", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.enrollment", KeyID: "ocid1.key.oc1.sa-saopaulo-1.enrollment"}, Management: management, Bundles: bundles, Name: "gru-1-netbird-setup-key"}
			stateDir := filepath.Join(root, "protected", "enrollment")
			reconcile := func() (EnrollmentResult, error) {
				api, err := NewAPI(managerServer.URL, testPAT)
				if err != nil {
					return EnrollmentResult{}, err
				}
				defer api.Close()
				expected := term.Load()
				api.beforeWrite = func() error {
					if interruption == "before-key-dispatch" && groupsCreated.Load() > 0 && interrupted.CompareAndSwap(false, true) {
						term.Add(1)
					}
					if term.Load() != expected {
						return errAuthorityLost
					}
					return nil
				}
				return ReconcileServerEnrollment(t.Context(), api, GRU(), stateDir, vault, EnrollmentAuthority{Check: func() error {
					if term.Load() != expected {
						return errAuthorityLost
					}
					return nil
				}, Quiesce: func(context.Context) error { return nil }})
			}
			first, firstErr := reconcile()
			if interruption != "vault-response" && firstErr == nil {
				t.Fatalf("interruption claimed success: %+v", first)
			}
			if interruption == "vault-epoch-loss" && vaultAttempts.Load() != 1 {
				t.Fatalf("SDK redispatched a Vault write after authority loss: %d attempts", vaultAttempts.Load())
			}
			result, err := reconcile()
			if err != nil || result.SecretID != secretID || result.KeyID == "" {
				t.Fatalf("restart did not recover delivery: %+v %v", result, err)
			}
			wantCreates := int32(1)
			if interruption == "key-response" {
				wantCreates = 2
			}
			if groupsCreated.Load() != 1 || keysCreated.Load() != wantCreates || vaultsCreated.Load() != 1 {
				t.Fatalf("duplicate credentials: keys=%d vaults=%d", keysCreated.Load(), vaultsCreated.Load())
			}
			again, err := reconcile()
			if err != nil || again != result || keysCreated.Load() != wantCreates || vaultsCreated.Load() != 1 {
				t.Fatalf("delivered identity changed: %+v %v", again, err)
			}
			keys := readEnrollmentJSON[[]apiSetupKey](t, keyPath)
			if interruption == "key-response" && (!keys[0].Revoked || keys[1].Revoked) {
				t.Fatal("orphan recovery revoked the delivered key")
			}
			info, err := os.Stat(filepath.Join(stateDir, "enrollment.json"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("escrow is not protected")
			}
		})
	}
}

func readEnrollmentJSON[T any](t *testing.T, path string) T {
	t.Helper()
	var value T
	wire, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return value
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func persistEnrollmentJSON(t *testing.T, path string, value any) {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeEnrollmentJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.MarshalWrite(w, value); err != nil {
		t.Error(err)
	}
}
