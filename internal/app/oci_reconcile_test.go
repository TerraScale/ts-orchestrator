package app

import (
	"encoding/json/v2"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
)

func TestOciReconcileConfigDefaultsOffAndValidates(t *testing.T) {
	var cfg ControllerConfig
	if err := json.Unmarshal([]byte(`{"candidate_id":"a"}`), &cfg, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if cfg.OciReconcile != nil || cfg.OciObserveVerifyCacheSeconds != 0 {
		t.Fatal("OCI reconcile or observe cache is on by default")
	}
	wire := `{"oci_observe_verify_cache_seconds":15,"oci_reconcile":{"enabled":true,"interval_seconds":120,"tag_mode":"defined",` +
		`"public_nlb":{"name":"public-api","nlb_id":"ocid1.networkloadbalancer.oc1..n","backend_set":"terrabase-https","port":9465}}}`
	if err := json.Unmarshal([]byte(wire), &cfg, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if interval, err := cfg.OciReconcile.interval(); err != nil || interval != 2*time.Minute {
		t.Fatalf("interval=%v err=%v", interval, err)
	}
	ownership, err := cfg.OciReconcile.ownership("cell-gru")
	if err != nil || ownership.Mode != ociresource.TagModeDefined || ownership.Namespace != "" {
		t.Fatalf("ownership=%+v err=%v", ownership, err)
	}
	for _, seconds := range []int{1, 29, 3601} {
		if _, err := (OciReconcileConfig{IntervalSeconds: seconds}).interval(); err == nil {
			t.Fatalf("accepted interval %d", seconds)
		}
	}
	if _, err := (OciReconcileConfig{TagMode: "adopt-anything"}).ownership("cell-gru"); err == nil {
		t.Fatal("accepted an unknown tag mode")
	}
	if _, err := (OciReconcileConfig{}).ownership("Cell_GRU"); err == nil {
		t.Fatal("accepted an owner that is not a token")
	}
}
