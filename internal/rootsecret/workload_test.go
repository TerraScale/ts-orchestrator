//go:build linux

package rootsecret

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

func TestWorkloadMaterialRejectsUnsealedAdmissions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root dispatcher admission requires root")
	}
	call, err := rootoci.RootCall(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	service := MaterialService{
		AdmitContainer: func(context.Context, rootoci.Call, host.ContainerMaterialEvidence) (containermaterial.Admission, error) {
			return containermaterial.Admission{}, nil
		},
		AdmitGeneration: func(context.Context, rootoci.Call, string) (containermaterial.GenerationAdmission, error) {
			return containermaterial.GenerationAdmission{}, nil
		},
	}
	if result, err := service.MaterializeContainer(t.Context(), call, rootoci.MaterializeContainerRequest{}); !errors.Is(err, ErrDelivery) || len(result.Values) != 0 {
		t.Fatal("zero delivery proof was accepted", err)
	}
	if result, err := service.ObserveContainerGeneration(t.Context(), call, rootoci.ObserveContainerGenerationRequest{}); !errors.Is(err, ErrDelivery) || len(result.Values) != 0 {
		t.Fatal("zero generation proof was accepted", err)
	}
}

func TestCurrentMetadataNeverReadsBundles(t *testing.T) {
	const id = "ocid1.vaultsecret.oc1.sa-saopaulo-1.owned"
	reference := vaultsecret.Ref{Vault: "ocid1.vault.oc1.sa-saopaulo-1.owned", Name: "gru-ts-api-password"}
	var mode atomic.Int32
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		expires := time.Now().Add(time.Hour)
		if mode.Load() == 2 {
			expires = time.Now().Add(-time.Second)
		}
		secret := map[string]any{"id": id, "compartmentId": "compartment", "vaultId": reference.Vault, "secretName": reference.Name,
			"lifecycleState": "ACTIVE", "currentVersionNumber": 7, "timeOfCurrentVersionExpiry": expires.UTC().Format(time.RFC3339Nano)}
		if mode.Load() == 1 {
			secret["vaultId"] = "another-vault"
		}
		var response any
		switch {
		case strings.HasSuffix(request.URL.Path, "/secrets"):
			if request.URL.Query().Get("compartmentId") != "compartment" || request.URL.Query().Get("vaultId") != reference.Vault || request.URL.Query().Get("name") != reference.Name {
				t.Error("metadata request lost the signed exact scope")
			}
			response = []any{secret}
		case strings.HasSuffix(request.URL.Path, "/secrets/"+id):
			response = secret
		case strings.HasSuffix(request.URL.Path, "/secrets/"+id+"/versions/7"):
			stage, number := "CURRENT", 7
			if mode.Load() == 3 {
				stage = "PENDING"
			}
			if mode.Load() == 4 {
				number++
			}
			response = map[string]any{"secretId": id, "versionNumber": number, "stages": []string{stage}, "timeOfCurrentVersionExpiry": expires.UTC().Format(time.RFC3339Nano)}
		default:
			t.Error("metadata observation requested secret contents or another operation", request.URL.Path)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.MarshalWrite(writer, response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	client, err := vault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&client.BaseClient, server.URL)
	client.HTTPClient = server.Client()
	value, err := observeCurrentMetadata(t.Context(), &client, "compartment", reference)
	if err != nil || value.ID != id || value.Version != 7 || !time.Now().Before(value.ExpiresAt) || requests.Load() != 3 {
		t.Fatal("exact CURRENT metadata was not observed", err)
	}
	for _, scenario := range []int32{1, 2, 3, 4} {
		mode.Store(scenario)
		if _, err := observeCurrentMetadata(t.Context(), &client, "compartment", reference); !errors.Is(err, ErrDelivery) {
			t.Fatal("invalid metadata was accepted", scenario, err)
		}
	}
	mode.Store(0)
	before := requests.Load()
	client.HTTPClient = credentialDispatcher{next: client.HTTPClient, guard: func() error { return ErrDelivery }}
	if _, err := observeCurrentMetadata(t.Context(), &client, "compartment", reference); !errors.Is(err, ErrDelivery) || requests.Load() != before {
		t.Fatal("revoked metadata admission reached the provider", err)
	}
}
