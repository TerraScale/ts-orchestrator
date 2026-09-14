// This file tests the ts-node flag surface and composition: documented
// defaults, deterministic rejection messages, the fail-closed uid 0 guard,
// and the rootless context validation of the composed agent. Everything is
// table-driven and offline; no NATS server and no podman binary is touched.
package main

import (
	"strings"
	"testing"
	"time"
)

func secureTsNodeArguments(args ...string) []string {
	result := append([]string(nil), args...)
	for index, value := range result {
		if strings.HasPrefix(value, "nats://") {
			result[index] = "tls://" + strings.TrimPrefix(value, "nats://")
		}
	}
	return append(result,
		"--nats-nkey-file", "/run/credentials/terrascale/node.seed",
		"--nats-tls-ca-file", "/run/credentials/terrascale/ca.pem",
		"--nats-tls-cert-file", "/run/credentials/terrascale/node.pem",
		"--nats-tls-key-file", "/run/credentials/terrascale/node-key.pem")
}

func TestParseTsNodeArgumentsAppliesDefaults(t *testing.T) {
	configuration, err := parseTsNodeArguments(secureTsNodeArguments(
		"--node-id", "gru-node-1",
		"--nats-url", "nats://127.0.0.1:4222",
	), 1000, 8)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if configuration.NodeId != "gru-node-1" || configuration.NodeClass != "greenfield" ||
		configuration.NatsUrl != "tls://127.0.0.1:4222" {
		t.Fatalf("identity flags = %#v", configuration)
	}
	if configuration.PodmanBinaryPath != tsNodeDefaultPodmanBinary {
		t.Fatalf("podman binary default = %q", configuration.PodmanBinaryPath)
	}
	if configuration.SystemctlBinaryPath != tsNodeDefaultSystemctlBinary ||
		configuration.SystemdRunBinaryPath != tsNodeDefaultSystemdRunBinary {
		t.Fatalf("systemd binary defaults = %q / %q",
			configuration.SystemctlBinaryPath, configuration.SystemdRunBinaryPath)
	}
	if configuration.XdgRuntimeDir != "/run/user/1000" {
		t.Fatalf("xdg runtime dir default = %q", configuration.XdgRuntimeDir)
	}
	if configuration.SeccompProfilePath != tsNodeDefaultSeccompProfile {
		t.Fatalf("seccomp profile default = %q", configuration.SeccompProfilePath)
	}
	if configuration.RunAsUid != 1000 {
		t.Fatalf("run uid default = %d", configuration.RunAsUid)
	}
	if configuration.HeartbeatInterval != tsNodeDefaultHeartbeatPeriod ||
		configuration.ConnectTimeout != tsNodeDefaultConnectTimeout {
		t.Fatalf("duration defaults = %q / %q", configuration.HeartbeatInterval, configuration.ConnectTimeout)
	}
	if configuration.CpuQuotaPercent != tsNodeDefaultCpuQuotaPercent ||
		configuration.TasksMax != tsNodeDefaultTasksMax ||
		configuration.LogicalCpuCount != 8 {
		t.Fatalf("envelope defaults = %d / %d / %d",
			configuration.CpuQuotaPercent, configuration.TasksMax, configuration.LogicalCpuCount)
	}
}

func TestParseTsNodeArgumentsAcceptsExplicitOverridesInAnyOrder(t *testing.T) {
	configuration, err := parseTsNodeArguments(secureTsNodeArguments(
		"--logical-cpu-count", "4",
		"--heartbeat-interval", "250ms",
		"--tasks-max", "128",
		"--cpu-quota-percent", "400",
		"--podman-binary", "/opt/podman/bin/podman",
		"--systemctl-binary", "/opt/systemd/bin/systemctl",
		"--systemd-run-binary", "/opt/systemd/bin/systemd-run",
		"--xdg-runtime-dir", "/run/user/1001",
		"--seccomp-profile", "/etc/terrascale/seccomp/custom-v1.json",
		"--connect-timeout", "2s",
		"--node-class", "greenfield-tiny",
		"--run-as-uid", "1001",
		"--node-id", "as-node-4",
		"--nats-url", "nats://regional:4222",
	), 1001, 16)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if configuration.NodeId != "as-node-4" || configuration.NodeClass != "greenfield-tiny" ||
		configuration.NatsUrl != "tls://regional:4222" ||
		configuration.PodmanBinaryPath != "/opt/podman/bin/podman" ||
		configuration.SystemctlBinaryPath != "/opt/systemd/bin/systemctl" ||
		configuration.SystemdRunBinaryPath != "/opt/systemd/bin/systemd-run" ||
		configuration.XdgRuntimeDir != "/run/user/1001" ||
		configuration.SeccompProfilePath != "/etc/terrascale/seccomp/custom-v1.json" ||
		configuration.RunAsUid != 1001 ||
		configuration.HeartbeatInterval != 250*time.Millisecond ||
		configuration.ConnectTimeout != 2*time.Second ||
		configuration.CpuQuotaPercent != 400 ||
		configuration.TasksMax != 128 ||
		configuration.LogicalCpuCount != 4 {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestParseTsNodeArgumentsRequiresSecureNatsConfiguration(t *testing.T) {
	base := []string{"--node-id", "gru-node-1", "--nats-url", "tls://127.0.0.1:4222"}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing authentication",
			args: append(append([]string(nil), base...),
				"--nats-tls-ca-file", "/run/credentials/terrascale/ca.pem",
				"--nats-tls-cert-file", "/run/credentials/terrascale/node.pem",
				"--nats-tls-key-file", "/run/credentials/terrascale/node-key.pem"),
			want: "exactly one of --nats-nkey-file or --nats-credentials-file is required",
		},
		{
			name: "both authentication families",
			args: append(append([]string(nil), base...),
				"--nats-nkey-file", "/run/credentials/terrascale/node.seed",
				"--nats-credentials-file", "/run/credentials/terrascale/node.creds",
				"--nats-tls-ca-file", "/run/credentials/terrascale/ca.pem",
				"--nats-tls-cert-file", "/run/credentials/terrascale/node.pem",
				"--nats-tls-key-file", "/run/credentials/terrascale/node-key.pem"),
			want: "exactly one of --nats-nkey-file or --nats-credentials-file is required",
		},
		{
			name: "missing client certificate",
			args: append(append([]string(nil), base...),
				"--nats-nkey-file", "/run/credentials/terrascale/node.seed",
				"--nats-tls-ca-file", "/run/credentials/terrascale/ca.pem",
				"--nats-tls-key-file", "/run/credentials/terrascale/node-key.pem"),
			want: "--nats-tls-cert-file is required",
		},
		{
			name: "plaintext URL",
			args: append([]string{"--node-id", "gru-node-1", "--nats-url", "nats://127.0.0.1:4222"},
				"--nats-nkey-file", "/run/credentials/terrascale/node.seed",
				"--nats-tls-ca-file", "/run/credentials/terrascale/ca.pem",
				"--nats-tls-cert-file", "/run/credentials/terrascale/node.pem",
				"--nats-tls-key-file", "/run/credentials/terrascale/node-key.pem"),
			want: "--nats-url is required and must be an absolute tls:// URL",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseTsNodeArguments(test.args, 1000, 8)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestTsNodeNatsConnectionConfigurationFailsClosedWithoutSecrets(t *testing.T) {
	_, err := tsNodeNatsConnectionConfiguration(tsNodeConfiguration{
		NatsUrl:        "tls://127.0.0.1:4222",
		ConnectTimeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "NATS") {
		t.Fatalf("missing authentication was accepted: %v", err)
	}
}

func TestParseTsNodeArgumentsRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing node id",
			args: []string{"--nats-url", "nats://127.0.0.1:4222"},
			want: "--node-id is required",
		},
		{
			name: "invalid node id token",
			args: []string{"--node-id", "Gru_Node", "--nats-url", "nats://127.0.0.1:4222"},
			want: "--node-id is required and must be a lowercase DNS-style token",
		},
		{
			name: "missing nats url",
			args: []string{"--node-id", "gru-node-1"},
			want: "--nats-url is required",
		},
		{
			name: "flag-like nats url",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "--evil"},
			want: "--nats-url is required and must be an absolute tls:// URL",
		},
		{
			name: "unsupported nats scheme",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "http://nats:4222"},
			want: "must use nats:// for local use or tls:// for production",
		},
		{
			name: "production nats without credentials",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "tls://nats:4222"},
			want: "requires the NKey, CA, certificate, and key files",
		},
		{
			name: "local nats with credentials",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://nats:4222",
				"--nats-nkey-file", "/run/nkey"},
			want: "credential files require a tls:// NATS URL",
		},
		{
			name: "invalid node class token",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--node-class", "Class"},
			want: "--node-class must be a lowercase DNS-style token",
		},
		{
			name: "explicit uid 0",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--run-as-uid", "0"},
			want: "must never run as uid 0",
		},
		{
			name: "run uid mismatch",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--run-as-uid", "1001"},
			want: "must equal the effective account uid 1000",
		},
		{
			name: "non-numeric run uid",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--run-as-uid", "root"},
			want: "--run-as-uid must be a nonzero numeric uid",
		},
		{
			name: "non-positive heartbeat interval",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--heartbeat-interval", "0s"},
			want: "--heartbeat-interval must be a positive duration",
		},
		{
			name: "malformed heartbeat interval",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--heartbeat-interval", "fast"},
			want: "--heartbeat-interval must be a positive duration",
		},
		{
			name: "non-positive connect timeout",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--connect-timeout", "-1s"},
			want: "--connect-timeout must be a positive duration",
		},
		{
			name: "cpu quota above the closed bound",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--cpu-quota-percent", "10001"},
			want: "--cpu-quota-percent must be between 1 and 10000",
		},
		{
			name: "cpu quota below the floor",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--cpu-quota-percent", "0"},
			want: "--cpu-quota-percent must be between 1 and 10000",
		},
		{
			name: "negative task ceiling",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--tasks-max", "-5"},
			want: "--tasks-max must be a non-negative integer",
		},
		{
			name: "zero logical cpu count",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--logical-cpu-count", "0"},
			want: "--logical-cpu-count must be a positive integer",
		},
		{
			name: "relative seccomp profile path",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x",
				"--seccomp-profile", "seccomp.json"},
			want: "--seccomp-profile must be a bounded absolute path",
		},
		{
			name: "unknown flag",
			args: []string{"--node-id", "gru-node-1", "--nats-url", "nats://x", "--root", "yes"},
			want: "the flag --root is not supported",
		},
		{
			name: "duplicate flag",
			args: []string{"--node-id", "gru-node-1", "--node-id", "gru-node-2", "--nats-url", "nats://x"},
			want: "the flag --node-id was given twice",
		},
		{
			name: "flag without value",
			args: []string{"--node-id", "gru-node-1", "--nats-url"},
			want: "the flag --nats-url requires a value",
		},
		{
			name: "bare argument",
			args: []string{"gru-node-1", "--nats-url", "nats://x"},
			want: "every argument must be a --flag value pair",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := secureTsNodeArguments(test.args...)
			if test.name == "flag without value" {
				args = test.args
			}
			_, err := parseTsNodeArguments(args, 1000, 8)
			if err == nil {
				t.Fatalf("invalid args %q were accepted", test.args)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q; want it to contain %q", err.Error(), test.want)
			}
		})
	}
}

func TestParseTsNodeArgumentsFailsClosedUnderUidZero(t *testing.T) {
	_, err := parseTsNodeArguments([]string{
		"--node-id", "gru-node-1",
		"--nats-url", "tls://127.0.0.1:4222",
		"--nats-nkey-file", "/run/credentials/terrascale/node.seed",
		"--nats-tls-ca-file", "/run/credentials/terrascale/ca.pem",
		"--nats-tls-cert-file", "/run/credentials/terrascale/node.pem",
		"--nats-tls-key-file", "/run/credentials/terrascale/node-key.pem",
	}, 0, 8)
	if err == nil || !strings.Contains(err.Error(), "must never run as uid 0") {
		t.Fatalf("uid 0 default was accepted: %v", err)
	}
}

func TestParseTsNodeArgumentsRejectsEffectiveRootAndSetuidMismatch(t *testing.T) {
	args := []string{"--node-id", "gru-node-1", "--nats-url", "nats://127.0.0.1:4222"}
	if _, err := parseTsNodeArguments(args, 1000, 0, 8); err == nil {
		t.Fatal("an effective-root process was accepted")
	}
	if _, err := parseTsNodeArguments(args, 1000, 1001, 8); err == nil ||
		!strings.Contains(err.Error(), "real uid 1000 does not match effective uid 1001") {
		t.Fatalf("a setuid mismatch was accepted: %v", err)
	}
}

func TestComposeTsNodeAgentValidatesRootlessContext(t *testing.T) {
	_, err := composeTsNodeAgent(tsNodeConfiguration{
		NodeId:             "gru-node-1",
		NodeClass:          "greenfield",
		NatsUrl:            "tls://127.0.0.1:4222",
		PodmanBinaryPath:   "podman",
		XdgRuntimeDir:      "/run/user/1000",
		SeccompProfilePath: tsNodeDefaultSeccompProfile,
		RunAsUid:           1000,
		HeartbeatInterval:  time.Second,
		ConnectTimeout:     time.Second,
		CpuQuotaPercent:    100,
		TasksMax:           128,
		LogicalCpuCount:    1,
	})
	if err == nil || !strings.Contains(err.Error(), "rootless podman context is invalid") {
		t.Fatalf("relative podman path was accepted: %v", err)
	}

	_, err = composeTsNodeAgent(tsNodeConfiguration{
		NodeId:             "gru-node-1",
		NodeClass:          "greenfield",
		NatsUrl:            "tls://127.0.0.1:4222",
		PodmanBinaryPath:   "/usr/bin/podman",
		XdgRuntimeDir:      "run/user/1000",
		SeccompProfilePath: tsNodeDefaultSeccompProfile,
		RunAsUid:           1000,
		HeartbeatInterval:  time.Second,
		ConnectTimeout:     time.Second,
		CpuQuotaPercent:    100,
		TasksMax:           128,
		LogicalCpuCount:    1,
	})
	if err == nil || !strings.Contains(err.Error(), "rootless podman context is invalid") {
		t.Fatalf("relative xdg runtime dir was accepted: %v", err)
	}

	_, err = composeTsNodeAgent(tsNodeConfiguration{
		NodeId:             "gru-node-1",
		NodeClass:          "greenfield",
		NatsUrl:            "tls://127.0.0.1:4222",
		PodmanBinaryPath:   "/usr/bin/podman",
		XdgRuntimeDir:      "/run/user/1000",
		SeccompProfilePath: tsNodeDefaultSeccompProfile,
		RunAsUid:           1000,
		HeartbeatInterval:  time.Second,
		ConnectTimeout:     time.Second,
		CpuQuotaPercent:    100,
		TasksMax:           128,
		LogicalCpuCount:    1,
	})
	if err == nil || !strings.Contains(err.Error(), "NATS") {
		t.Fatalf("configuration without NATS identity must fail closed: %v", err)
	}
}

func TestTsNodePendingRelayReportsZeroBeforeBinding(t *testing.T) {
	relay := &tsNodePendingRelay{}
	if relay.PendingAllocations() != 0 {
		t.Fatalf("unbound relay reported %d", relay.PendingAllocations())
	}
}
