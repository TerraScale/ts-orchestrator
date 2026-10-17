package netbird

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDefaultsAndStrictManagerValidation(t *testing.T) {
	cfg := testConfig()
	cfg.ManagementURL, cfg.Region = "", ""
	normalized, err := loadIntegrationConfig(t, cfg)
	if err != nil || normalized.ManagementURL != DefaultManagementURL || normalized.Region != DefaultRegion {
		t.Fatalf("defaults: %+v %v", normalized, err)
	}
	for _, url := range []string{
		"http://netbird.terrascale.tech", "https://user:password@netbird.terrascale.tech", "https://attacker.invalid",
		DefaultManagementURL + "/api", DefaultManagementURL + "#fragment", DefaultManagementURL + "#",
		DefaultManagementURL + "?token=x", DefaultManagementURL + ":8080", DefaultManagementURL + ":",
	} {
		cfg := testConfig()
		cfg.ManagementURL = url
		if _, err := loadIntegrationConfig(t, cfg); err == nil {
			t.Errorf("accepted management URL %q", url)
		}
	}
	for _, region := range []string{"invalid", "sa-saopaulo-1\n", "/etc/setup-key"} {
		cfg := testConfig()
		cfg.Region = region
		if _, err := loadIntegrationConfig(t, cfg); err == nil {
			t.Errorf("accepted OCI region %q", region)
		}
	}
}

func TestLoadConfigRejectsUnknownDuplicatesSymlinksAndWritableConfig(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "netbird.json")
	wire, err := json.Marshal(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		`{"setup_key_secret_id":"ocid1.vaultsecret.oc1.sa-saopaulo-1.old"}`, `{"setup_key_file":"/etc/private"}`, `{"management_ip":"10.250.10.155"}`, `{"peer_names":{}}`, `{"admin_pat_secret_id":""}`, `{"setup_key_secret_id":"a","setup_key_secret_id":"b"}`, `null`,
	} {
		if err := os.WriteFile(path, []byte(malformed), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted malformed config %s", malformed)
		}
	}
	if err := os.WriteFile(path, wire, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatal("accepted config symlink")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("accepted writable config")
	}
}

func loadIntegrationConfig(t *testing.T, cfg Config) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netbird.json")
	wire, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

func TestEnrollmentRequiresAuthenticatedSetupKeyReader(t *testing.T) {
	if err := Enroll(t.Context(), testConfig(), nil); err == nil {
		t.Fatal("enrollment accepted a missing authenticated reader")
	}
	if _, err := ReadSetupKey(t.Context(), DefaultRegion, "ocid1.vaultsecret.oc1.us-sanjose-1.foreign"); err == nil {
		t.Fatal("enrollment accepted a cross-region runtime secret identity")
	}
}
