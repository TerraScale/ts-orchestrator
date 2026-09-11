package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/runmaterial"
)

const validRunConfig = `{"TS_ORCH_CELL":"gru","TS_ORCH_INSTANCE":"gru-1","TS_ORCH_NATS_URL":"tls://nats.internal:4222","TS_ORCH_REPLICAS":"3","TS_ORCH_PROVIDER":"oci"}`

func TestRunConfigurationStrictParsing(t *testing.T) {
	var base map[string]string
	if err := json.Unmarshal([]byte(validRunConfig), &base); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"duplicate": strings.TrimSuffix(validRunConfig, "}") + `,"TS_ORCH_CELL":"gru"}`,
		"unknown":   strings.TrimSuffix(validRunConfig, "}") + `,"SECRET_CANARY":"sensitive"}`,
		"null":      strings.Replace(validRunConfig, `"gru"`, `null`, 1),
		"number":    strings.Replace(validRunConfig, `"3"`, `3`, 1),
		"array":     `[]`, "missing": `{}`, "trailing": validRunConfig + `{}`,
		"oversize": strings.Repeat(" ", maximumRunConfigurationBytes) + validRunConfig,
	}
	for key, value := range map[string]string{
		"TS_ORCH_CELL": "local", "TS_ORCH_PROVIDER": "local", "TS_ORCH_INSTANCE": " secret ",
		"TS_ORCH_NATS_URL": "tls://token@nats.internal:4222", "TS_ORCH_NATS_TLS_KEY_FILE": "INLINEKEY",
		"TS_ORCH_COMMAND_SIGNING_KEY_FILE":                "-----BEGIN PRIVATE KEY-----",
		"TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE": "/private/obsolete-account.seed",
		"TS_ORCH_CI_RUNNER_NATS_ACCOUNT_PUBLIC_KEY":       "obsolete-account",
		"TS_ORCH_CLOUDFLARE_API_TOKEN":                    "secret", "TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS": "https://token@host:443",
	} {
		modified := map[string]string{}
		for k, v := range base {
			modified[k] = v
		}
		modified[key] = value
		encoded, _ := json.Marshal(modified)
		cases[key] = string(encoded)
	}
	for _, value := range []string{"tls://host:4222?token=secret", "tls://host:4222#secret", "tls://host:4222/secret", "tls://host:4222?"} {
		cases[value] = strings.Replace(validRunConfig, "tls://nats.internal:4222", value, 1)
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseRunConfiguration([]byte(input))
			if err == nil {
				t.Fatal("accepted invalid configuration")
			}
			if strings.Contains(err.Error(), "SECRET_CANARY") || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("error disclosed configuration: %v", err)
			}
		})
	}
	lookup, err := parseRunConfiguration([]byte(validRunConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cell, _ := lookup("TS_ORCH_CELL"); cell != "gru" {
		t.Fatal(cell)
	}
	if _, present := lookup("TS_ORCH_COMMAND_SIGNING_KEY_FILE"); present {
		t.Fatal("invented signing identity")
	}
	if _, err := control.ParseOrchestratorOptions([]string{"run"}, control.EnvironmentLookup(lookup)); err == nil {
		t.Fatal("incomplete production identity admitted")
	}
}

func TestRunConfigurationAcceptsBYOKRenewalReferences(t *testing.T) {
	var settings map[string]string
	if err := json.Unmarshal([]byte(validRunConfig), &settings); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		byokRoleEnvironment:            "arn:aws:iam::123456789012:role/key",
		byokTokenEnvironment:           "/etc/terrascale/byok.token",
		byokKeyIDEnvironment:           "arn:aws:kms:sa-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		byokKeyRegionEnvironment:       "sa-east-1",
		byokKeyEndpointEnvironment:     "https://kms.example.test",
		byokProviderEnvironment:        "aws-kms",
		byokS3RoleEnvironment:          "arn:aws:iam::123456789012:role/backup",
		byokS3TokenEnvironment:         "/etc/terrascale/s3.token",
		byokS3EndpointEnvironment:      "https://s3.example.test",
		byokS3BucketEnvironment:        "backups",
		byokS3RegionEnvironment:        "sa-east-1",
		byokS3RevisionEnvironment:      "placement-1",
		byokS3TenantEnvironment:        "tenant-1",
		byokS3ProjectEnvironment:       "project-1",
		byokS3DatabaseEnvironment:      "database-1",
		byokS3ExternalIDEnvironment:    "external-1",
		byokRenewalEndpointEnvironment: "https://dashboard.example.test/internal/byok/renewal-policy",
		byokRenewalKeyEnvironment:      "renewal-service-key",
	} {
		settings[key] = value
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := parseRunConfiguration(encoded)
	if err != nil {
		t.Fatalf("BYOK renewal configuration rejected: %v", err)
	}
	for key := range settings {
		if _, ok := lookup(key); !ok {
			t.Fatalf("accepted setting %q was not retained", key)
		}
	}
}

func TestRunConfigurationFileAdmission(t *testing.T) {
	for _, mode := range []os.FileMode{0444, 0600, 0644} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "run.json")
			if err := os.WriteFile(path, []byte(validRunConfig), mode); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRunConfiguration(path); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, kind := range []string{"symlink", "fifo", "writable", "hardlink", "empty", "directory", "relative"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "run.json")
			if err := os.WriteFile(path, []byte(validRunConfig), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				other := filepath.Join(dir, "link")
				err = os.Symlink(path, other)
				path = other
			case "fifo":
				path = filepath.Join(dir, "fifo")
				err = syscall.Mkfifo(path, 0600)
			case "writable":
				err = os.Chmod(path, 0666)
			case "hardlink":
				err = os.Link(path, filepath.Join(dir, "other"))
			case "empty":
				err = os.Truncate(path, 0)
			case "directory":
				path = dir
			case "relative":
				path = "run.json"
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loadRunConfiguration(path); err == nil {
				t.Fatal("accepted insecure file")
			}
		})
	}
}

func TestRunConfigurationReplacesEnvironmentForOptionsAndEstate(t *testing.T) {
	restoreHostSeams(t)
	path := filepath.Join(t.TempDir(), "run.json")
	if err := os.WriteFile(path, []byte(validRunConfig), 0444); err != nil {
		t.Fatal(err)
	}
	assertSource := func(lookup control.EnvironmentLookup) {
		t.Helper()
		if value, _ := lookup("TS_ORCH_CELL"); value != "gru" {
			t.Fatalf("cell=%q", value)
		}
		if _, present := lookup("AMBIENT_SECRET"); present {
			t.Fatal("ambient environment consulted")
		}
	}
	parseOptions = func(args []string, lookup control.EnvironmentLookup) (*control.OrchestratorOptions, error) {
		if !reflect.DeepEqual(args, []string{"run"}) {
			t.Fatalf("args=%v", args)
		}
		assertSource(control.EnvironmentLookup(lookup))
		return &control.OrchestratorOptions{Command: control.OrchestratorCommandRun}, nil
	}
	stopped := errors.New("estate sentinel")
	verifyEstate = func(_ context.Context, _ string, lookup envLookup) error {
		assertSource(control.EnvironmentLookup(lookup))
		return stopped
	}
	err := execute(context.Background(), []string{"run", "--config", path}, func(string) (string, bool) { t.Fatal("ambient lookup called"); return "", false }, io.Discard)
	if !errors.Is(err, stopped) {
		t.Fatalf("execute=%v", err)
	}
	for _, args := range [][]string{{"run", "--config"}, {"run", "--config", ""}, {"run", "--config", path, "extra"}, {"check", "--config", path}} {
		if _, err := requestedCommand(args); err == nil {
			t.Fatalf("accepted args %v", args)
		}
	}
}

func TestRunConfigurationVerifiesSignedMaterialBeforeStartup(t *testing.T) {
	dir := t.TempDir()
	broker := filepath.Join(dir, "broker.conf")
	content := []byte("admitted-broker")
	if err := os.WriteFile(broker, content, 0400); err != nil {
		t.Fatal(err)
	}
	inventory, raw, err := runmaterial.Build(map[string][]byte{broker: content}, nil)
	if err != nil {
		t.Fatal(err)
	}
	inventory = filepath.Join(dir, filepath.Base(inventory))
	if err := os.WriteFile(inventory, raw, 0400); err != nil {
		t.Fatal(err)
	}
	var settings map[string]string
	if err := json.Unmarshal([]byte(validRunConfig), &settings); err != nil {
		t.Fatal(err)
	}
	settings[runmaterial.Environment] = inventory
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseRunConfiguration(encoded); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(broker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broker, []byte("replaced-broker"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := parseRunConfiguration(encoded); err == nil {
		t.Fatal("production configuration accepted changed signed broker material")
	}
}
