package app

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
)

func TestNetBirdEnrollCommandDispatchRejectsPositionalArguments(t *testing.T) {
	var output bytes.Buffer
	err := Run(t.Context(), []string{"netbird-enroll", "unexpected"}, &output)
	if err == nil || !strings.Contains(err.Error(), "no positional arguments") || output.Len() != 0 {
		t.Fatalf("enrollment command dispatch failed: output=%q error=%v", output.String(), err)
	}
}

func TestNetBirdManagementIsOffUnlessTheAdminPATSecretIsConfigured(t *testing.T) {
	dir := t.TempDir()
	leader := func() bool { return true }
	if loop, reason := netbirdManagementLoop(filepath.Join(dir, "missing.json"), leader); loop != nil || !strings.Contains(reason, "no public") {
		t.Fatalf("missing config: %v %q", loop, reason)
	}
	path := filepath.Join(dir, "netbird.json")
	base := `{"management_url":"https://netbird.terrascale.tech","region":"sa-saopaulo-1","setup_key_secret_id":"ocid1.vaultsecret.oc1.sa-saopaulo-1.setupkey"`
	if err := os.WriteFile(path, []byte(base+`}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if loop, reason := netbirdManagementLoop(path, leader); loop != nil || !strings.Contains(reason, "admin_pat_secret_id") {
		t.Fatalf("config without PAT secret: %v %q", loop, reason)
	}
	withPAT := base + `,"admin_pat_secret_id":"ocid1.vaultsecret.oc1.sa-saopaulo-1.adminpat"`
	// Another cell of the region names other servers: it must not prune gru-1's.
	if err := os.WriteFile(path, []byte(withPAT+`,"peer_names":{"10.251.0.11":"gru-2-ctl-1"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if loop, reason := netbirdManagementLoop(path, leader); loop != nil || !strings.Contains(reason, "cell gru-1") {
		t.Fatalf("other cell: %v %q", loop, reason)
	}
	names, err := json.Marshal(manager.GRU().PeerNames())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(withPAT+`,"peer_names":`+string(names)+`}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if loop, reason := netbirdManagementLoop(path, leader); loop == nil || loop.ManagementURL != "https://netbird.terrascale.tech" {
		t.Fatalf("configured PAT secret: %v %q", loop, reason)
	}
	// Another region's controller must never reconcile, or prune, GRU.
	other := `{"region":"us-sanjose-1","setup_key_secret_id":"ocid1.vaultsecret.oc1.us-sanjose-1.setupkey","admin_pat_secret_id":"ocid1.vaultsecret.oc1.us-sanjose-1.adminpat"}`
	if err := os.WriteFile(path, []byte(other), 0o644); err != nil {
		t.Fatal(err)
	}
	if loop, reason := netbirdManagementLoop(path, leader); loop != nil || !strings.Contains(reason, "region us-sanjose-1") {
		t.Fatalf("other region: %v %q", loop, reason)
	}
}
