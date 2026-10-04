package netbird

import (
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigDefaultsAndStrictManagerValidation(t *testing.T) {
	cfg := testConfig()
	cfg.ManagementURL, cfg.Region = "", ""
	normalized, err := cfg.normalized()
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
		if _, err := cfg.normalized(); err == nil {
			t.Errorf("accepted management URL %q", url)
		}
	}
	for _, ip := range []string{"not-an-ip", "127.0.0.1", "1.1.1.1", "::1", "fe80::1%eth0", "::ffff:10.250.10.155", "10.1.1.1\nnetbird"} {
		cfg := testConfig()
		cfg.ManagementIP = ip
		if _, err := cfg.normalized(); err == nil {
			t.Errorf("accepted management IP %q", ip)
		}
	}
	for _, id := range []string{"", "ocid1.vaultsecret.oc1.eu-frankfurt-1.example", "ocid1.vaultsecret.oc1.sa-saopaulo-1.secret\n", "/etc/setup-key"} {
		cfg := testConfig()
		cfg.SetupKeySecretID = id
		if _, err := cfg.normalized(); err == nil {
			t.Errorf("accepted secret ID %q", id)
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
		`{"setup_key_file":"/etc/private"}`, `{"setup_key_secret_id":"a","setup_key_secret_id":"b"}`, `null`,
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

func TestPeerNamesRequirePrivateIPv4KeysAndUniqueServerNames(t *testing.T) {
	cfg := testConfig()
	cfg.PeerNames = map[string]string{"10.251.0.11": "gru-1-ctl-1", "10.251.0.12": "gru-1-ctl-2", "10.251.0.22": "gru-1-db-2"}
	if _, err := cfg.normalized(); err != nil {
		t.Fatal(err)
	}
	for name, names := range map[string]map[string]string{
		"public address":      {"8.8.8.8": "gru-1-ctl-1"},
		"ipv6 address":        {"fd00::1": "gru-1-ctl-1"},
		"noncanonical":        {"010.251.0.11": "gru-1-ctl-1"},
		"cidr":                {"10.251.0.0/24": "gru-1-ctl-1"},
		"pre-scheme name":     {"10.251.0.11": "gru-controller-a"},
		"unknown region":      {"10.251.0.11": "xyz-1-ctl-1"},
		"uppercase":           {"10.251.0.11": "GRU-1-ctl-1"},
		"dotted":              {"10.251.0.11": "gru.1-ctl-1"},
		"leading hyphen":      {"10.251.0.11": "-gru-1-ctl-1"},
		"trailing hyphen":     {"10.251.0.11": "gru-1-ctl-1-"},
		"empty":               {"10.251.0.11": ""},
		"newline":             {"10.251.0.11": "gru-1\nctl-1"},
		"duplicate peer name": {"10.251.0.11": "gru-1-ctl-1", "10.251.0.12": "gru-1-ctl-1"},
	} {
		cfg := testConfig()
		cfg.PeerNames = names
		if _, err := cfg.normalized(); err == nil {
			t.Errorf("accepted %s peer names %v", name, names)
		}
	}
}

func TestConfigAcceptsOptionalAdminPATSecretInRegion(t *testing.T) {
	cfg := testConfig()
	cfg.AdminPATSecretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.adminpat"
	if _, err := cfg.normalized(); err != nil {
		t.Fatal(err)
	}
	cfg.AdminPATSecretID = "ocid1.vaultsecret.oc1.us-ashburn-1.adminpat"
	if _, err := cfg.normalized(); err == nil || !strings.Contains(err.Error(), "admin_pat_secret_id") {
		t.Fatalf("accepted out-of-region admin PAT secret: %v", err)
	}
}

func TestControllerConfigReportsMissingFile(t *testing.T) {
	if _, err := LoadControllerConfig(filepath.Join(t.TempDir(), "netbird.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing config error = %v", err)
	}
}
