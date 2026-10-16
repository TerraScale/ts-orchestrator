package sdkcli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..t", "ocid1.user.oc1..u", "sa-saopaulo-1", "fp",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := NewClient(factory, server.URL)
	return client
}

func TestHandlersServeCLIShapedData(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/vcns/ocid1.vcn.oc1..v"):
			_, _ = io.WriteString(w, `{"id":"ocid1.vcn.oc1..v","compartmentId":"ocid1.compartment.oc1..c","cidrBlocks":["10.0.0.0/16"],"lifecycleState":"AVAILABLE"}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/o"):
			if r.URL.Query().Get("start") == "" {
				_, _ = io.WriteString(w, `{"objects":[{"name":"a","size":1}],"nextStartWith":"b"}`)
				return
			}
			_, _ = io.WriteString(w, `{"objects":[{"name":"b","size":2}]}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/k"):
			_, _ = io.WriteString(w, `{"id":"k","lifecycleState":"ENABLED"}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/networkLoadBalancers"):
			_, _ = io.WriteString(w, `{"items":[{"id":"ocid1.networkloadbalancer.oc1..n","displayName":"public","lifecycleState":"ACTIVE"}]}`)
		case r.Method == http.MethodHead:
			w.Header().Set("Content-Length", "5")
			w.Header().Set("version-id", "v1")
			w.Header().Set("Last-Modified", "Fri, 02 Oct 2026 12:00:00 GMT")
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"missing"}`)
		}
	})
	ctx := t.Context()
	data, handled, err := client.Call(ctx, []string{"network", "vcn", "get", "--vcn-id", "ocid1.vcn.oc1..v"})
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	var vcn map[string]any
	if err := json.Unmarshal(data, &vcn); err != nil || vcn["compartment-id"] != "ocid1.compartment.oc1..c" || vcn["cidr-blocks"].([]any)[0] != "10.0.0.0/16" {
		t.Fatalf("vcn=%v err=%v", vcn, err)
	}

	data, _, err = client.Call(ctx, []string{"os", "object", "list", "--namespace-name", "n", "--bucket-name", "b", "--fields", "size", "--all"})
	if err != nil {
		t.Fatal(err)
	}
	var objects []map[string]any
	if err := json.Unmarshal(data, &objects); err != nil || len(objects) != 2 || objects[1]["name"] != "b" {
		t.Fatalf("objects=%v err=%v", objects, err)
	}

	data, _, err = client.Call(ctx, []string{"os", "object", "head", "--namespace-name", "n", "--bucket-name", "b", "--name", "k"})
	if err != nil {
		t.Fatal(err)
	}
	var headers map[string]any
	if err := json.Unmarshal(data, &headers); err != nil || headers["version-id"] != "v1" || headers["last-modified"] == nil {
		t.Fatalf("headers=%v err=%v", headers, err)
	}

	data, _, err = client.Call(ctx, []string{"nlb", "network-load-balancer", "list", "--compartment-id", "c", "--all"})
	if err != nil {
		t.Fatal(err)
	}
	var collection map[string][]map[string]any
	if err := json.Unmarshal(data, &collection); err != nil || len(collection["items"]) != 1 ||
		collection["items"][0]["display-name"] != "public" {
		t.Fatalf("collection=%v err=%v", collection, err)
	}

	if _, handled, err := client.Call(ctx, []string{"network", "subnet", "get", "--subnet-id", "missing"}); !handled || err == nil {
		t.Fatalf("missing resource handled=%v err=%v", handled, err)
	}
	if _, handled, err := client.Call(ctx, []string{"network", "vcn", "create", "--compartment-id", "c"}); handled || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("mutation handled=%v err=%v", handled, err)
	}
	// A filter the handler does not apply must never widen the answer.
	if _, handled, err := client.Call(ctx, []string{"network", "vcn", "get", "--vcn-id", "ocid1.vcn.oc1..v",
		"--lifecycle-state", "AVAILABLE"}); handled || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unserved flag handled=%v err=%v", handled, err)
	}
	if _, _, err := client.Call(ctx, []string{"network", "vcn", "get", "--vcn-id", "v", "--region", "us-ashburn-1"}); err == nil {
		t.Fatal("accepted a caller-supplied region flag")
	}
	for _, endpoint := range []string{
		"https://evil.example",
		"https://evil.example/.kms.sa-saopaulo-1.oraclecloud.com",
		"https://x.kms.sa-saopaulo-1.oraclecloud.com.evil.example",
		"https://a.b.kms.sa-saopaulo-1.oraclecloud.com",
		"https://x.kms.sa-saopaulo-1.oraclecloud.com:8443",
		"http://x-management.kms.sa-saopaulo-1.oraclecloud.com",
		"https://x-management.kms.eu-frankfurt-1.oraclecloud.com",
	} {
		if _, _, err := client.Call(ctx, []string{"kms", "management", "key", "get", "--key-id", "k", "--endpoint", endpoint}); err == nil {
			t.Fatalf("accepted KMS endpoint %q outside the region", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://vault-management.kms.sa-saopaulo-1.oraclecloud.com",
		"https://vault-crypto.kms.sa-saopaulo-1.oraclecloud.com",
		"https://vault-management.kms.sa-saopaulo-1.oci.oraclecloud.com",
		"https://vault.management.sa-saopaulo-1.oraclecloud.com",
	} {
		if _, handled, err := client.Call(ctx, []string{"kms", "management", "key", "get", "--key-id", "k", "--endpoint", endpoint}); err != nil || !handled {
			t.Fatalf("regional vault endpoint %q: handled=%v err=%v", endpoint, handled, err)
		}
	}
	for _, endpoint := range []string{
		"https://a.b.management.sa-saopaulo-1.oraclecloud.com",
		"https://vault.management.eu-frankfurt-1.oraclecloud.com",
		"https://vault.management.sa-saopaulo-1.oraclecloud.com.evil.example",
		"https://.management.sa-saopaulo-1.oraclecloud.com",
	} {
		if _, _, err := client.Call(ctx, []string{"kms", "management", "key", "get", "--key-id", "k", "--endpoint", endpoint}); err == nil {
			t.Fatalf("accepted the vault endpoint %q", endpoint)
		}
	}
}

func TestObjectVersionListSendsTheCLIFieldList(t *testing.T) {
	var fields []string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/objectversions") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"missing"}`)
			return
		}
		fields = append(fields, r.URL.Query().Get("fields"))
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("opc-next-page", "p2")
			_, _ = io.WriteString(w, `{"items":[{"name":"a","size":1,"versionId":"v1","storageTier":"Standard"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"items":[{"name":"a","size":2,"versionId":"v2","isDeleteMarker":true}]}`)
	})
	data, handled, err := client.Call(t.Context(), []string{"os", "object", "list-object-versions", "--namespace-name", "n",
		"--bucket-name", "b", "--fields", "name,size,storageTier,archivalState", "--all"})
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	var versions []map[string]any
	if err := json.Unmarshal(data, &versions); err != nil || len(versions) != 2 || versions[0]["storage-tier"] != "Standard" ||
		versions[1]["is-delete-marker"] != true {
		t.Fatalf("versions=%v err=%v", versions, err)
	}
	if len(fields) != 2 || fields[0] != "name,size,storageTier,archivalState" || fields[1] != fields[0] {
		t.Fatalf("fields query=%q", fields)
	}
}

func TestSDKShapeCompatibilityAndCancellation(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("compartmentId") != "compartment" || r.URL.Query().Get("imageId") != "image" {
			t.Errorf("shape compatibility query = %s", r.URL.RawQuery)
		}
		if r.URL.Query().Get("availabilityDomain") == "blocked" {
			<-r.Context().Done()
			return
		}
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("opc-next-page", "second")
			_, _ = io.WriteString(w, `[{"shape":"VM.Standard.A1.Flex","processorDescription":"Ampere Altra","isFlexible":true,"ocpuOptions":{"min":1,"max":80},"memoryOptions":{"minInGBs":1,"maxInGBs":512}}]`)
			return
		}
		_, _ = io.WriteString(w, `[{"shape":"VM.Standard.E4.Flex","processorDescription":"AMD EPYC"}]`)
	})
	args := []string{"compute", "shape", "list", "--compartment-id", "compartment", "--image-id", "image", "--all"}
	wire, handled, err := client.Call(t.Context(), args)
	if err != nil || !handled {
		t.Fatalf("shape compatibility: handled=%v err=%v", handled, err)
	}
	var shapes []map[string]any
	if err := json.Unmarshal(wire, &shapes); err != nil || len(shapes) != 2 || shapes[0]["processor-description"] != "Ampere Altra" || shapes[1]["shape"] != "VM.Standard.E4.Flex" {
		t.Fatalf("shape compatibility = %s, %v", wire, err)
	}
	if shapes[0]["memory-options"].(map[string]any)["max-in-gbs"] != float64(512) {
		t.Fatalf("shape dimensions = %s", wire)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	_, _, err = client.Call(ctx, append(args, "--availability-domain", "blocked"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SDK HTTP cancellation = %v", err)
	}
}

func TestSDKObjectInventoryRejectsMalformedResponses(t *testing.T) {
	for _, wire := range []string{"", `{}`, `{"prefixes":["hidden/"]}`, `{"objects":[] ,"objects":[{"name":"hidden","size":100}]}`, `{"objects":[]} {"objects":[]}`} {
		t.Run(wire, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, wire)
			})
			_, _, err := client.Call(t.Context(), []string{"os", "object", "list", "--namespace-name", "n", "--bucket-name", "b", "--all"})
			if err == nil {
				t.Fatalf("accepted uncounted storage: %s", wire)
			}
		})
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"objects":[]}`)
	})
	wire, _, err := client.Call(t.Context(), []string{"os", "object", "list", "--namespace-name", "n", "--bucket-name", "b", "--all"})
	if err != nil || string(wire) != "[]" {
		t.Fatalf("empty inventory = %s, %v", wire, err)
	}
}
