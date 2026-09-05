package main

import (
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/tsnodebootstrap"
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
	if _, err := parseTsNodeArguments([]string{"--config", "relative.json"}); err == nil {
		t.Fatal("relative configuration path accepted")
	}
}

const minimalConfig = `{
  "nodeId": "gru-1",
  "natsUrl": "nats://127.0.0.1:4222",
 "authorityBucket":"ORCH_GRU_LEADERS",
 "commandTrustKeys":[{"candidateId":"gru-controller-test","publicKeyFile":"/etc/terrascale/command-public.pem"}],
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
		"unclean path":        strings.Replace(minimalConfig, `"natsUrl"`, `"manifestPath":"/etc//manifest.json","natsUrl"`, 1),
		"alternate install":   strings.Replace(minimalConfig, `"natsUrl"`, `"installRoot":"/srv/terrascale","natsUrl"`, 1),
		"alternate unit dir":  strings.Replace(minimalConfig, `"natsUrl"`, `"unitDir":"/tmp/systemd","natsUrl"`, 1),
		"outside data root":   strings.Replace(minimalConfig, `"natsUrl"`, `"dataVolumeRoot":"/srv/terrascale","natsUrl"`, 1),
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

func TestLoadTsNodeConfigurationRejectsNonCanonicalJSON(t *testing.T) {
	cases := map[string]string{
		"top-level null":      `null`,
		"duplicate field":     strings.Replace(minimalConfig, `"nodeId": "gru-1"`, `"nodeId": "gru-2", "nodeId": "gru-1"`, 1),
		"case-variant field":  strings.Replace(minimalConfig, `"nodeId"`, `"NodeId"`, 1),
		"unknown field":       strings.Replace(minimalConfig, `{`, `{"unknown":true,`, 1),
		"null optional field": strings.Replace(minimalConfig, `{`, `{"manifestPath":null,`, 1),
		"trailing document":   minimalConfig + `{}`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTsNodeConfiguration(writeConfig(t, document)); err == nil {
				t.Fatal("non-canonical configuration accepted")
			}
		})
	}
}

func TestLoadTsNodeConfigurationUsesBoundedRegularFile(t *testing.T) {
	oversized := strings.Repeat(" ", tsNodeMaximumConfigBytes+1)
	if _, err := loadTsNodeConfiguration(writeConfig(t, oversized)); err == nil {
		t.Fatal("oversized configuration accepted")
	}
	realPath := writeConfig(t, minimalConfig)
	symlink := filepath.Join(t.TempDir(), "ts-node.json")
	if err := os.Symlink(realPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTsNodeConfiguration(symlink); err == nil {
		t.Fatal("symlinked configuration accepted")
	}
}

func TestProductionDefaultsMatchSharedBootstrapContract(t *testing.T) {
	production := tsnodebootstrap.ProductionConfig()
	if tsNodeDefaultInstallRoot != production.InstallRoot ||
		tsNodeDefaultUnitDir != production.UnitDirectory ||
		tsNodeDefaultDataVolumeRoot != production.DataVolumeRoot {
		t.Fatalf("ts-node defaults drifted from bootstrap: %+v", production)
	}
	if hostagent.UnitName(hostmanifest.TsNodeComponentName) != tsnodebootstrap.UnitName {
		t.Fatalf("self unit = %q, bootstrap unit = %q",
			hostagent.UnitName(hostmanifest.TsNodeComponentName), tsnodebootstrap.UnitName)
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
