package sdkcli

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
)

// NLB backend sets and listeners are keyed by user-defined names: those keys
// stay as written while the schema fields inside are converted, so a
// listener's default-backend-set-name still resolves (#127 12109).
func TestRenderKeepsNLBBackendSetAndListenerNames(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/networkLoadBalancers/n") {
			t.Errorf("unexpected NLB read: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"n","backendSets":{"TerraBaseHTTPS":{"name":"TerraBaseHTTPS","isPreserveSource":true}},"listeners":{"TerraBaseListener":{"name":"TerraBaseListener","defaultBackendSetName":"TerraBaseHTTPS","port":443}},"freeformTags":{"CostCenter":"infra"}}`)
	})
	wire, handled, err := client.Call(t.Context(), []string{"nlb", "network-load-balancer", "get", "--network-load-balancer-id", "n"})
	if err != nil || !handled {
		t.Fatalf("NLB read: handled=%v err=%v", handled, err)
	}
	var got map[string]any
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	sets, _ := got["backend-sets"].(map[string]any)
	set, _ := sets["TerraBaseHTTPS"].(map[string]any)
	if set == nil || set["is-preserve-source"] != true {
		t.Fatalf("backend set names or fields were rewritten: %v", got["backend-sets"])
	}
	listeners, _ := got["listeners"].(map[string]any)
	listener, _ := listeners["TerraBaseListener"].(map[string]any)
	if listener == nil || listener["default-backend-set-name"] != "TerraBaseHTTPS" {
		t.Fatalf("listener names or fields were rewritten: %v", got["listeners"])
	}
	if _, resolves := sets[listener["default-backend-set-name"].(string)]; !resolves {
		t.Fatal("the listener's backend set reference does not resolve")
	}
	if got["freeform-tags"].(map[string]any)["CostCenter"] != "infra" {
		t.Fatalf("user-keyed tags were rewritten: %v", got["freeform-tags"])
	}
}
