package ociregion

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

func inventoryProtocolEngine(t *testing.T, handler http.HandlerFunc) *Engine {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := sdkcli.NewClient(factory, server.URL)
	return &Engine{Context: t.Context(), Dependency: func(name string, args []any, kwargs Object) (any, error) {
		if name != "oci" || kwargs["region"] != "sa-saopaulo-1" {
			return nil, fmt.Errorf("unexpected dependency %s %v", name, kwargs)
		}
		words := make([]string, len(args))
		for i, arg := range args {
			words[i] = text(arg)
		}
		wire, handled, err := client.Call(t.Context(), words)
		if err != nil {
			return nil, err
		}
		if !handled {
			return nil, fmt.Errorf("OCI SDK did not handle %v", words)
		}
		return decodeJSON(wire)
	}}
}

func TestImportCurrentObjectHeadThroughOCIProtocol(t *testing.T) {
	for _, scenario := range []string{"versioned", "missing version", "invalid timestamp", "negative bytes", "deleted"} {
		t.Run(scenario, func(t *testing.T) {
			requests := 0
			engine := inventoryProtocolEngine(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodHead || r.URL.Path != "/n/ns/b/images/o/controller.qcow2" || r.Header.Get("Authorization") == "" {
					t.Errorf("unexpected unsigned object request: %s %s", r.Method, r.URL.Path)
				}
				if scenario == "deleted" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("content-length", "500")
				w.Header().Set("version-id", "immutable-v1")
				w.Header().Set("last-modified", "Fri, 16 Oct 2026 12:00:00 GMT")
				switch scenario {
				case "missing version":
					w.Header().Del("version-id")
				case "invalid timestamp":
					w.Header().Set("last-modified", "yesterday")
				case "negative bytes":
					w.Header().Set("content-length", "-1")
				}
			})
			engine.Clock = func() time.Time { return time.Date(2026, 10, 16, 12, 0, 1, 0, time.UTC) }
			head, err := capture(func() Object { return engine.currentHead("ns", "images", "controller.qcow2", "sa-saopaulo-1") })
			if requests != 1 {
				t.Fatalf("object HEAD requests=%d", requests)
			}
			if scenario != "versioned" {
				if err == nil {
					t.Fatalf("admitted unsafe object receipt: %v", head)
				}
				return
			}
			if err != nil || head["version_id"] != "immutable-v1" || head["size"] != int64(500) || head["head_at"] != "2026-10-16T12:00:01+00:00" {
				t.Fatalf("head=%v err=%v", head, err)
			}
		})
	}
}

func TestInventoryScopedImagesThroughOCIProtocol(t *testing.T) {
	for _, billed := range []string{"1", "2", "9007199254740993", "2.0", "2e0", "true", `"2"`, "-1", "0", "null"} {
		t.Run(billed, func(t *testing.T) {
			engine := inventoryProtocolEngine(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/20160918/images" || r.URL.Query().Get("compartmentId") != "ocid1.compartment.oc1..control" {
					t.Errorf("unexpected image inventory request: %s %s", r.Method, r.URL)
				}
				w.Header().Set("content-type", "application/json")
				fmt.Fprintf(w, `[{"id":"ocid1.image.oc1.sa-saopaulo-1.test","compartmentId":"ocid1.compartment.oc1..control","displayName":"qualified","lifecycleState":"AVAILABLE","billableSizeInGBs":%s}]`, billed)
			})
			images, err := capture(func() []any {
				return engine.scopedImages([]any{"sa-saopaulo-1"}, []any{"ocid1.compartment.oc1..control"})
			})
			valid := billed == "1" || billed == "2" || billed == "9007199254740993"
			if !valid {
				if err == nil {
					t.Fatalf("accepted malformed billed size %s: %v", billed, images)
				}
				return
			}
			if err != nil || len(images) != 1 || str(obj(images[0])["billable_size_in_gbs"]) != billed {
				t.Fatalf("images=%v err=%v", images, err)
			}
			if !strings.HasPrefix(text(obj(images[0])["id"]), "ocid1.image.") {
				t.Fatalf("image identity lost: %v", images)
			}
		})
	}
}
