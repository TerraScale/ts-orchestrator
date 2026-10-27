package manager

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
)

func TestServerConfigRolloutPreservesLiveServiceAndConverges(t *testing.T) {
	inspection := []byte(`{"spec":{"name":"netbird-server","image":"pinned-image","args":["--config","/var/lib/netbird/config.yaml"],"env":{"NB_SETUP_PAT_ENABLED":"true"},"mounts":[{"source":"/var/lib/ts-data/netbird","target":"/var/lib/netbird"}],"replicas":1,"memoryMiB":4096,"milliCPU":1000,"port":8095,"readyPath":"/api/instance","hostnames":["netbird.terrascale.tech"]}}`)
	wire, changed, err := serverConfigSpec(inspection, []byte("rendered config"))
	if err != nil || !changed {
		t.Fatalf("first config rollout: changed=%v err=%v", changed, err)
	}
	var before, after map[string]jsontext.Value
	var original struct {
		Spec map[string]jsontext.Value `json:"spec"`
	}
	if err := json.Unmarshal(inspection, &original); err != nil {
		t.Fatal(err)
	}
	before = original.Spec
	if err := json.Unmarshal(wire, &after); err != nil {
		t.Fatal(err)
	}
	for key, value := range before {
		if key != "env" && string(after[key]) != string(value) {
			t.Fatalf("rollout changed live %s", key)
		}
	}
	var env map[string]string
	if err := json.Unmarshal(after["env"], &env); err != nil || env["NB_SETUP_PAT_ENABLED"] != "true" || len(env[serverConfigDigest]) != 64 || string(after["regions"]) != `["gru"]` {
		t.Fatal("rollout did not retain environment, set generation and confine placement to GRU")
	}
	next, _ := json.Marshal(map[string]any{"spec": after})
	if _, changed, err := serverConfigSpec(next, []byte("rendered config")); err != nil || changed {
		t.Fatalf("unchanged config rolled again: changed=%v err=%v", changed, err)
	}
	if _, changed, err := serverConfigSpec(next, []byte("new callbacks")); err != nil || !changed {
		t.Fatalf("updated config did not roll: changed=%v err=%v", changed, err)
	}
}

func TestServerConfigRolloutRejectsAnotherService(t *testing.T) {
	for _, inspection := range []string{`{}`, `{"spec":{"name":"terrabase"}}`, `{"spec":{"name":"netbird-server","env":17}}`} {
		if _, _, err := serverConfigSpec([]byte(inspection), []byte("config")); err == nil {
			t.Fatal("accepted invalid server inspection")
		}
	}
}

func TestNetBirdCompanionDetectsInstalledBinaryReplacement(t *testing.T) {
	dir := t.TempDir()
	running, installed := filepath.Join(dir, "running"), filepath.Join(dir, "installed")
	if err := os.WriteFile(running, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(running, installed); err != nil {
		t.Fatal(err)
	}
	if changed, err := differentBinary(running, installed); err != nil || changed {
		t.Fatalf("unchanged binary: changed=%v err=%v", changed, err)
	}
	if err := os.Remove(installed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, []byte("new binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if changed, err := differentBinary(running, installed); err != nil || !changed {
		t.Fatalf("replaced binary: changed=%v err=%v", changed, err)
	}
}
