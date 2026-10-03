package sdkcli

import (
	"encoding/json/v2"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
)

// NLB backend sets and listeners are keyed by user-defined names: those keys
// stay as written while the schema fields inside are converted, so a
// listener's default-backend-set-name still resolves (#127 12109).
func TestRenderKeepsNLBBackendSetAndListenerNames(t *testing.T) {
	nlb := networkloadbalancer.NetworkLoadBalancer{
		Id: new("ocid1.networkloadbalancer.oc1..n"),
		BackendSets: map[string]networkloadbalancer.BackendSet{
			"TerraBaseHTTPS": {Name: new("TerraBaseHTTPS"), IsPreserveSource: new(true)},
		},
		Listeners: map[string]networkloadbalancer.Listener{
			"TerraBaseListener": {Name: new("TerraBaseListener"), DefaultBackendSetName: new("TerraBaseHTTPS"), Port: new(443)},
		},
		FreeformTags: map[string]string{"CostCenter": "infra"},
	}
	wire, err := Render(nlb)
	if err != nil {
		t.Fatal(err)
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
