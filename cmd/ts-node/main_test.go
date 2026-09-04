package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ts-node.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseTsNodeArguments(t *testing.T) {
	if path, err := parseTsNodeArguments(nil); err != nil || path != tsNodeDefaultConfigPath {
		t.Fatalf("default rejected: %v %q", err, path)
	}
	if path, err := parseTsNodeArguments([]string{"--config", "/tmp/a.json"}); err != nil || path != "/tmp/a.json" {
		t.Fatalf("config flag rejected: %v %q", err, path)
	}
	if _, err := parseTsNodeArguments([]string{"--node-id", "gru-1"}); err == nil {
		t.Fatal("legacy flags accepted: the cloud-init unit passes no arguments")
	}
	if _, err := parseTsNodeArguments([]string{"--config"}); err == nil {
		t.Fatal("missing value accepted")
	}
}

const minimalConfig = `{
  "nodeId": "gru-1",
  "natsUrl": "nats://127.0.0.1:4222",
  "releasePublicKey": "0000000000000000000000000000000000000000000000000000000000000000"
}`

func TestLoadTsNodeConfigurationAppliesDefaults(t *testing.T) {
	configuration, err := loadTsNodeConfiguration(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatalf("minimal configuration rejected: %v", err)
	}
	if configuration.ManifestPath != tsNodeDefaultManifestPath ||
		configuration.InstallRoot != tsNodeDefaultInstallRoot ||
		configuration.UnitDir != tsNodeDefaultUnitDir ||
		configuration.DataVolumeRoot != tsNodeDefaultDataVolumeRoot ||
		configuration.HeartbeatInterval != tsNodeDefaultHeartbeat ||
		configuration.ReconcileInterval != tsNodeDefaultReconcile {
		t.Fatalf("defaults not applied: %+v", configuration)
	}
}

func TestLoadTsNodeConfigurationRejectsInvalidDocuments(t *testing.T) {
	cases := map[string]string{
		"missing file":        "",
		"empty node id":       strings.Replace(minimalConfig, `"gru-1"`, `""`, 1),
		"missing public key":  strings.Replace(minimalConfig, `"releasePublicKey": "0000000000000000000000000000000000000000000000000000000000000000"`, `"releasePublicKey": ""`, 1),
		"wrong nats scheme":   strings.Replace(minimalConfig, "nats://", "http://", 1),
		"relative path":       strings.Replace(minimalConfig, `"natsUrl"`, `"manifestPath":"relative","natsUrl"`, 1),
		"unknown field":       strings.Replace(minimalConfig, "{\n", `{"ambient":true`+"\n", 1),
		"credentials on nats": strings.Replace(minimalConfig, `"natsUrl"`, `"natsNkeyFile":"/etc/nk","natsUrl"`, 1),
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, contents)
			if _, err := loadTsNodeConfiguration(path); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestLoadTsNodeConfigurationRequiresFullTlsCredentials(t *testing.T) {
	contents := strings.Replace(minimalConfig, "nats://127.0.0.1:4222",
		"tls://nats.gru.internal:4222", 1)
	if _, err := loadTsNodeConfiguration(writeConfig(t, contents)); err == nil {
		t.Fatal("tls:// without credentials accepted")
	}
	contents = strings.Replace(contents, `"natsUrl"`,
		`"natsNkeyFile":"/etc/nk","natsTlsCaFile":"/etc/ca.pem","natsTlsCertFile":"/etc/c.pem","natsTlsKeyFile":"/etc/k.pem","natsUrl"`, 1)
	// The credential files do not exist in the test environment, so the
	// load must fail on resolving them — but not on the credential count.
	if _, err := loadTsNodeConfiguration(writeConfig(t, contents)); err == nil {
		t.Fatal("nonexistent credential files accepted")
	}
}

func TestPositiveDefault(t *testing.T) {
	if positiveDefault(0, time.Second) != time.Second {
		t.Fatal("zero did not fall back")
	}
	if positiveDefault(1500, time.Second) != 1500*time.Millisecond {
		t.Fatal("explicit value ignored")
	}
}
