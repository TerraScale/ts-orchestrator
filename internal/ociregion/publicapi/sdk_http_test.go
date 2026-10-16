package publicapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// sdkFixture sends signed SDK requests over TLS to a controlled OCI API.
func sdkFixture(t *testing.T, handler http.Handler) *SDKClient {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	original := http.DefaultTransport
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	limits := map[ociclient.Service]ociclient.Limit{}
	for service := range ociclient.DefaultLimits {
		limits[service] = ociclient.Limit{PerSecond: 100000, Burst: 100000}
	}
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	return NewClientWithFactory(factory)
}

// fixtureCamel encodes the simulator's CLI-shaped state as OCI API JSON.
func fixtureCamel(value any, preserve bool) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, member := range value {
			name := key
			if !preserve {
				parts := strings.Split(key, "-")
				for i := 1; i < len(parts); i++ {
					parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
				}
				name = strings.Join(parts, "")
			}
			named := key == "backend-sets" || key == "listeners" || key == "certificates" || key == "hostnames" || key == "rule-sets" || key == "routing-policies"
			if entries, ok := member.(map[string]any); ok && named && !preserve {
				converted := make(map[string]any, len(entries))
				for name, entry := range entries {
					converted[name] = fixtureCamel(entry, false)
				}
				out[name] = converted
			} else {
				out[name] = fixtureCamel(member, preserve || key == "freeform-tags" || key == "defined-tags")
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, member := range value {
			out[i] = fixtureCamel(member, preserve)
		}
		return out
	case []map[string]any:
		out := make([]any, len(value))
		for i, member := range value {
			out[i] = fixtureCamel(member, preserve)
		}
		return out
	default:
		return value
	}
}

func (f *fakeOCI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		f.t.Error("OCI request is unsigned")
		http.Error(w, "unsigned", 401)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) > 0 {
		parts = parts[1:]
	}
	var body map[string]any
	if r.Body != nil {
		wire, _ := io.ReadAll(r.Body)
		if len(wire) > 0 {
			if err := json.Unmarshal(wire, &body); err != nil {
				f.t.Error(err)
				http.Error(w, "invalid JSON", 400)
				return
			}
		}
	}
	var args []string
	var result any
	resource := map[string]string{"internetGateways": "internet-gateway", "routeTables": "route-table", "securityLists": "security-list", "subnets": "subnet", "networkSecurityGroups": "nsg"}
	flag := func(name string, value any) {
		wire, _ := json.Marshal(value)
		if s, ok := value.(string); ok {
			args = append(args, "--"+name, s)
		} else {
			args = append(args, "--"+name, string(wire))
		}
	}
	detailFlags := func() {
		for name, value := range body {
			flag(sdkcli.Kebab(name), value)
		}
	}
	switch {
	case len(parts) > 0 && resource[parts[0]] != "":
		kind := resource[parts[0]]
		switch {
		case len(parts) == 2 && r.Method == http.MethodGet:
			result = f.network[kind]
		case len(parts) == 2 && r.Method == http.MethodPost:
			// NSG rule methods append an action segment and are handled below.
			fallthrough
		default:
			if len(parts) >= 3 {
				args = []string{"network", "nsg", "rules"}
				flagID := parts[1]
				switch parts[len(parts)-1] {
				case "securityRules":
					args = append(args, "list")
					flag("nsg-id", flagID)
				case "addSecurityRules":
					args = append(args, "add")
					flag("nsg-id", flagID)
					flag("security-rules", body["securityRules"])
				case "removeSecurityRules":
					args = append(args, "remove")
					flag("nsg-id", flagID)
					flag("security-rule-ids", body["securityRuleIds"])
				default:
					f.t.Errorf("unexpected NSG URL %s", r.URL)
					http.Error(w, "unexpected", 400)
					return
				}
			} else if r.Method == http.MethodPost {
				args = []string{"network", kind, "create"}
				detailFlags()
			} else {
				args = []string{"network", kind, "list"}
			}
		}
	case len(parts) > 0 && parts[0] == "loadBalancers":
		args = []string{"lb", "load-balancer"}
		switch {
		case len(parts) == 1 && r.Method == http.MethodGet:
			args = append(args, "list")
		case len(parts) == 1 && r.Method == http.MethodPost:
			args = append(args, "create")
			detailFlags()
		case len(parts) == 2 && r.Method == http.MethodGet:
			result = f.balancer
		case len(parts) == 2 && r.Method == http.MethodPut:
			args = append(args, "update")
			flag("load-balancer-id", parts[1])
			flag("freeform-tags", body["freeformTags"])
		case len(parts) >= 3:
			id := parts[1]
			switch parts[2] {
			case "actions":
				args = append(args, "update-shape")
				flag("load-balancer-id", id)
				detailFlags()
			case "certificates":
				args = []string{"lb", "certificate", "create"}
				flag("load-balancer-id", id)
				flag("certificate", body)
			case "backendSets":
				args = []string{"lb", "backend-set", "update"}
				flag("load-balancer-id", id)
				flag("backend-set-name", parts[3])
				flag("details", body)
			case "listeners":
				args = []string{"lb", "listener", "update"}
				flag("load-balancer-id", id)
				flag("listener-name", parts[3])
				flag("details", body)
			case "hostnames":
				args = []string{"lb", "hostname", "update"}
				flag("load-balancer-id", id)
				flag("name", parts[3])
				flag("hostname", body["hostname"])
			case "routingPolicies":
				args = []string{"lb", "routing-policy", "create"}
				flag("load-balancer-id", id)
				detailFlags()
			default:
				f.t.Errorf("unexpected LB URL %s", r.URL)
				http.Error(w, "unexpected", 400)
				return
			}
		}
	case len(parts) > 0 && parts[0] == "secrets":
		args = []string{"vault", "secret"}
		if r.Method == http.MethodGet {
			args = append(args, "list")
		} else if r.Method == http.MethodPost {
			args = append(args, "create-base64")
			for name, value := range body {
				if name != "secretContent" {
					flag(sdkcli.Kebab(name), value)
				}
			}
		} else {
			args = append(args, "update-base64")
			flag("secret-id", parts[1])
		}
		if content, ok := body["secretContent"].(map[string]any); ok {
			flag("secret-content-content", content["content"])
		}
	case len(parts) > 0 && parts[0] == "secretbundles":
		args = []string{"secrets", "secret-bundle", "get"}
		flag("secret-id", parts[1])
	default:
		f.t.Errorf("unexpected OCI request %s %s", r.Method, r.URL)
		http.Error(w, "unexpected", 400)
		return
	}
	if result == nil && args != nil {
		for name, values := range r.URL.Query() {
			if name != "page" {
				flag(sdkcli.Kebab(name), values[0])
			}
		}
		response, err := f.serveCommand(r.Context(), args...)
		if err != nil {
			f.t.Error(err)
			http.Error(w, "fixture failure", 500)
			return
		}
		result = response["data"]
		if len(parts) >= 3 && parts[0] == "networkSecurityGroups" && parts[len(parts)-1] == "addSecurityRules" {
			result = map[string]any{"security-rules": result}
		}
		if r.Method == http.MethodPost && len(parts) == 1 && resource[parts[0]] != "" {
			result = f.network[resource[parts[0]]]
		}
	}
	if len(parts) > 0 && parts[0] == "loadBalancers" && r.Method != http.MethodGet {
		w.Header().Set("opc-work-request-id", "fixture-work-request")
		w.WriteHeader(http.StatusAccepted)
		result = map[string]any{}
	}
	wire, err := json.Marshal(fixtureCamel(result, false))
	if err != nil {
		f.t.Error(err)
		return
	}
	_, _ = fmt.Fprintln(w, string(wire))
}
