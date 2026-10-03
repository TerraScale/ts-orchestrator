package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if err := os.WriteFile(path, []byte(base+`,"admin_pat_secret_id":"ocid1.vaultsecret.oc1.sa-saopaulo-1.adminpat"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if loop, reason := netbirdManagementLoop(path, leader); loop == nil || loop.ManagementURL != "https://netbird.terrascale.tech" {
		t.Fatalf("configured PAT secret: %v %q", loop, reason)
	}
}
