package ociregion

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/manager"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

func TestGRURebuildPlanKeepsFreshBindingsAndCSharpPeers(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "oci-region")
	engine := &Engine{}
	plan, err := capture(func() Object { return engine.loadPlan(filepath.Join(root, "plan.json")) })
	if err != nil {
		t.Fatal(err)
	}
	for role, value := range obj(plan["preview_compartment_names"]) {
		if value != "gru-1-"+role {
			t.Fatalf("compartment %s reuses an old cell name: %v", role, value)
		}
	}
	for key, value := range obj(plan["resource_ids"]) {
		if bindings, ok := value.(Object); ok {
			for slot, id := range bindings {
				if id != nil {
					t.Fatalf("%s/%s reuses an existing OCI resource", key, slot)
				}
			}
		} else if value != nil {
			t.Fatalf("%s reuses an existing OCI resource", key)
		}
	}
	if obj(plan["operator_gateway"])["local_peering_gateway_id"] != nil {
		t.Fatal("shared gateway reuses an old LPG")
	}
	if _, err := capture(func() bool { engine.requiredIDs(plan); return true }); err == nil {
		t.Fatal("unbound rebuild passed foundation inspection prerequisites")
	}
	statements, err := RequiredControllerStatements(plan, Object{"key": "fresh-key"}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if !strings.Contains(statement, "dynamic-group gru-1-controllers ") || strings.Contains(statement, "compartment terrascale-") {
			t.Fatalf("IAM grant escaped the fresh cell: %s", statement)
		}
	}
	var profile struct {
		Env map[string]string `json:"env"`
	}
	wire, err := os.ReadFile(filepath.Join(root, "terrabase-gru-1-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Env["TERRABASE_REGION"] != "gru-1" {
		t.Fatal("C# profile must announce region gru-1 outside Development")
	}
	parsed, err := terrabase.ParseProfile(profile.Env)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Peers) != int(number(plan["database_members"])) {
		t.Fatal("C# peer count differs from the regional plan")
	}
	pendingPath := filepath.Join(root, "netbird-gru-1-pending.json")
	if _, err := client.ValidateConfig(pendingPath); err == nil {
		t.Fatal("unbound enrollment template accepted for an image")
	}
	pending, err := ReadJSON(pendingPath, 16*1024, "pending enrollment")
	if err != nil {
		t.Fatal(err)
	}
	names := obj(pending["peer_names"])
	if len(names) != len(manager.GRU().Slots) {
		t.Fatal("pending image peer count differs from NetBird desired state")
	}
	for ip, name := range manager.GRU().PeerNames() {
		if names[ip] != name {
			t.Fatalf("pending image peer at %s differs from NetBird desired state", ip)
		}
	}
	for _, key := range []string{"secret_compartment_id", "setup_key_secret_id", "policy_id"} {
		if obj(plan["netbird"])[key] != nil {
			t.Fatalf("NetBird %s reuses a deleted resource", key)
		}
	}
	for _, slot := range manager.GRU().Slots {
		if slot.Role != "member" {
			continue
		}
		name := manager.GRU().PeerName(slot)
		peer, ok := parsed.Peer(name)
		if !ok || peer.Address.String() != fmt.Sprintf("%s:9443", slot.IP) {
			t.Fatalf("C# member %s differs from its NetBird slot", name)
		}
	}
	for _, value := range arr(plan["hosts"]) {
		host := obj(value)
		if strings.HasPrefix(text(host["slot"]), "member-") && !eq(host["roles"], []any{"host", "terrabase"}) {
			t.Fatal("database host uses the managed Rust role")
		}
	}
}
