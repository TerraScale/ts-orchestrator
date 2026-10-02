package sdkcli

import (
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

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestKebabMatchesCLIMemberNames(t *testing.T) {
	for camel, want := range map[string]string{
		"id": "id", "lifecycleState": "lifecycle-state", "compartmentId": "compartment-id", "sizeInGBs": "size-in-gbs",
		"vpusPerGB": "vpus-per-gb", "billableSizeInGBs": "billable-size-in-gbs", "isIpv6Enabled": "is-ipv6-enabled",
		"prohibitPublicIpOnVnic": "prohibit-public-ip-on-vnic", "drgRouteTableId": "drg-route-table-id",
		"ipAddresses": "ip-addresses", "content-length": "content-length",
	} {
		if got := Kebab(camel); got != want {
			t.Errorf("Kebab(%q)=%q want %q", camel, got, want)
		}
	}
}

func TestParseRejectsAmbiguousArguments(t *testing.T) {
	command, err := Parse([]string{"network", "vcn", "get", "--vcn-id", "x"})
	if err != nil || command.Path != "network vcn get" || command.Flags["vcn-id"] != "x" || command.All {
		t.Fatalf("command=%+v err=%v", command, err)
	}
	command, err = Parse([]string{"os", "object", "list", "--all", "--bucket-name", "b"})
	if err != nil || !command.All || command.Flags["bucket-name"] != "b" {
		t.Fatalf("command=%+v err=%v", command, err)
	}
	for _, args := range [][]string{
		{"network", "vcn", "get", "--vcn-id"},
		{"network", "vcn", "get", "--vcn-id", "a", "--vcn-id", "b"},
		{"network", "--vcn-id", "a", "get"},
	} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestRenderPreservesUserKeyedMaps(t *testing.T) {
	vcn := core.Vcn{Id: new("ocid1.vcn.oc1..v"), LifecycleState: core.VcnLifecycleStateAvailable,
		FreeformTags: map[string]string{"CostCenter": "infra"},
		DefinedTags:  map[string]map[string]any{"Oracle-Tags": {"CreatedBy": "someone"}}}
	wire, err := Render(vcn)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if got["lifecycle-state"] != "AVAILABLE" || got["id"] != "ocid1.vcn.oc1..v" {
		t.Fatalf("got=%v", got)
	}
	if got["freeform-tags"].(map[string]any)["CostCenter"] != "infra" ||
		got["defined-tags"].(map[string]any)["Oracle-Tags"].(map[string]any)["CreatedBy"] != "someone" {
		t.Fatalf("user-keyed maps were rewritten: %v", got)
	}
}

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
	return &Client{factory: factory, endpoint: server.URL}
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
	if !kmsEndpointInRegion("https://vault-management.kms.sa-saopaulo-1.oraclecloud.com", "sa-saopaulo-1") {
		t.Fatal("rejected the regional KMS management endpoint")
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

func TestSelectedBackend(t *testing.T) {
	t.Setenv(BackendEnv, "")
	if backend, err := SelectedBackend(); err != nil || backend != BackendAuto {
		t.Fatalf("backend=%v err=%v", backend, err)
	}
	t.Setenv(BackendEnv, "cli")
	if backend, _ := SelectedBackend(); backend != BackendCLI {
		t.Fatal(backend)
	}
	t.Setenv(BackendEnv, "python")
	if _, err := SelectedBackend(); err == nil {
		t.Fatal("accepted an unknown backend")
	}
}

func TestEveryHandlerIsARead(t *testing.T) {
	for path := range handlers {
		words := strings.Fields(path)
		verb := words[len(words)-1]
		if verb != "get" && verb != "list" && verb != "head" && !strings.HasPrefix(verb, "list-") {
			t.Fatalf("handler %q is not a read", path)
		}
	}
}
