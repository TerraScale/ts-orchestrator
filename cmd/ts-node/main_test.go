// This file tests the ts-node flag surface and composition: documented
// defaults, deterministic rejection messages, the fail-closed uid 0 guard,
// and the rootless context validation of the composed agent. Everything is
// table-driven and offline; no NATS server and no host binary is touched.
package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseTsNodeArgumentsAppliesDefaults(t *testing.T) {
	configuration, err := parseTsNodeArguments([]string{
		"--node-id", "gru-node-1",
		"--nats-url", "nats://127.0.0.1:4222",
	}, 1000, 1000, 8)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if configuration.NodeId != "gru-node-1" || configuration.NodeClass != "greenfield" ||
		configuration.NatsUrl != "nats://127.0.0.1:4222" {
		t.Fatalf("identity flags = %#v", configuration)
	}
	if configuration.SystemctlBinaryPath != tsNodeDefaultSystemctlBinary ||
		configuration.SystemdRunBinaryPath != tsNodeDefaultSystemdRunBinary {
		t.Fatalf("systemd binary defaults = %q / %q",
			configuration.SystemctlBinaryPath, configuration.SystemdRunBinaryPath)
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
	configuration, err := parseTsNodeArguments([]string{
		"--logical-cpu-count", "4",
		"--heartbeat-interval", "250ms",
		"--tasks-max", "128",
		"--cpu-quota-percent", "400",
		"--systemctl-binary", "/opt/systemd/bin/systemctl",
		"--systemd-run-binary", "/opt/systemd/bin/systemd-run",
		"--connect-timeout", "2s",
		"--node-class", "greenfield-tiny",
		"--run-as-uid", "1001",
		"--node-id", "as-node-4",
		"--nats-url", "nats://regional:4222",
	}, 1001, 1001, 16)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if configuration.NodeId != "as-node-4" || configuration.NodeClass != "greenfield-tiny" ||
		configuration.NatsUrl != "nats://regional:4222" ||
		configuration.SystemctlBinaryPath != "/opt/systemd/bin/systemctl" ||
		configuration.SystemdRunBinaryPath != "/opt/systemd/bin/systemd-run" ||
		configuration.RunAsUid != 1001 ||
		configuration.HeartbeatInterval != 250*time.Millisecond ||
		configuration.ConnectTimeout != 2*time.Second ||
		configuration.CpuQuotaPercent != 400 ||
		configuration.TasksMax != 128 ||
		configuration.LogicalCpuCount != 4 {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestParseTsNodeArgumentsBindsProductionNatsCredentials(t *testing.T) {
	configuration, err := parseTsNodeArguments([]string{
		"--node-id", "gru-node-1",
		"--nats-url", "tls://regional.internal:4222",
		"--nats-nkey-file", "/run/credentials/ts-node/nkey.seed",
		"--nats-tls-ca-file", "/run/credentials/ts-node/ca.pem",
		"--nats-tls-cert-file", "/run/credentials/ts-node/client.pem",
		"--nats-tls-key-file", "/run/credentials/ts-node/client.key",
	}, 1000, 1000, 8)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if configuration.NatsNKeyFile != "/run/credentials/ts-node/nkey.seed" ||
		configuration.NatsTlsCaFile != "/run/credentials/ts-node/ca.pem" ||
		configuration.NatsTlsCertFile != "/run/credentials/ts-node/client.pem" ||
		configuration.NatsTlsKeyFile != "/run/credentials/ts-node/client.key" {
		t.Fatalf("NATS credential paths = %#v", configuration)
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
			want: "--nats-url is required and must be whitespace-free and flag-safe",
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
			_, err := parseTsNodeArguments(test.args, 1000, 1000, 8)
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
		"--nats-url", "nats://127.0.0.1:4222",
	}, 0, 0, 8)
	if err == nil || !strings.Contains(err.Error(), "real or effective uid of 0") {
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

func TestComposeTsNodeAgentComposesSystemdAgent(t *testing.T) {
	agent, err := composeTsNodeAgent(tsNodeConfiguration{
		NodeId:               "gru-node-1",
		NodeClass:            "greenfield",
		NatsUrl:              "nats://127.0.0.1:4222",
		SystemctlBinaryPath:  tsNodeDefaultSystemctlBinary,
		SystemdRunBinaryPath: tsNodeDefaultSystemdRunBinary,
		RunAsUid:             1000,
		HeartbeatInterval:    time.Second,
		ConnectTimeout:       time.Second,
		CpuQuotaPercent:      100,
		TasksMax:             128,
		LogicalCpuCount:      1,
	})
	if err != nil {
		t.Fatalf("valid configuration failed to compose: %v", err)
	}
	if agent == nil || agent.NodeId().Value != "gru-node-1" {
		t.Fatalf("agent = %#v", agent)
	}
	if agent.Cordoned() {
		t.Fatal("a fresh agent must not be cordoned")
	}
}

func TestTsNodePendingRelayReportsZeroBeforeBinding(t *testing.T) {
	relay := &tsNodePendingRelay{}
	if relay.PendingAllocations() != 0 {
		t.Fatalf("unbound relay reported %d", relay.PendingAllocations())
	}
}
