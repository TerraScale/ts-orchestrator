package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

func TestHostRunResultOnlyTreatsParentCancellationAsShutdown(t *testing.T) {
	if err := hostRunResult(t.Context(), context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("live parent concealed agent cancellation: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := hostRunResult(ctx, context.Canceled); err != nil {
		t.Fatalf("canceled parent was treated as a host failure: %v", err)
	}

	failure := errors.New("host session lost")
	if err := hostRunResult(ctx, failure); !errors.Is(err, failure) {
		t.Fatalf("canceled parent concealed an unrelated host failure: %v", err)
	}
}

func TestHostSessionTraceConfigAccepted(t *testing.T) {
	path := testJSONFile(t, t.TempDir(), "host.json", Config{Host: HostConfig{SessionTrace: true, WorkloadUID: 2000, WorkloadGID: 2000}})
	loaded, err := LoadConfig(path)
	if err != nil || !loaded.Host.SessionTrace || loaded.Host.WorkloadUID != 2000 || loaded.Host.WorkloadGID != 2000 {
		t.Fatalf("load host trace and workload identity config: host=%+v err=%v", loaded.Host, err)
	}
}

func TestHostRejectsZeroWorkloadIdentityBeforeNativeProbe(t *testing.T) {
	root := t.TempDir()
	controllerPublic, _ := testEd25519(t, root, "controller.key")
	_, _ = testEd25519(t, root, "host.key")
	cfg := Config{NATS: natscell.Config{Cell: "gru"}, Host: HostConfig{
		Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		IdentityKeyFile:     filepath.Join(root, "host.key"),
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		InstallRoot:         filepath.Join(root, "install"), StateRoot: filepath.Join(root, "state"),
	}}
	if err := runHost(t.Context(), cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "workload_uid and workload_gid") {
		t.Fatalf("host reached native probe with zero workload identity: %v", err)
	}
}

func TestHostCommandRejectsUnhealthyClockBeforeNativeProbeAndNATS(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("host path fixture requires a non-root process identity")
	}
	root := t.TempDir()
	controllerPublic, _ := testEd25519(t, root, "controller.key")
	_, _ = testEd25519(t, root, "host.key")
	stateRoot := filepath.Join(root, "state")
	config := testJSONFile(t, root, "host.json", Config{NATS: natscell.Config{
		Cell: "gru", URL: "nats://127.0.0.1:1",
	}, Host: HostConfig{
		Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		IdentityKeyFile: filepath.Join(root, "host.key"), ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		InstallRoot: filepath.Join(root, "install"), StateRoot: stateRoot,
		WorkloadUID: uint32(os.Geteuid()), WorkloadGID: uint32(os.Getegid()),
	}})
	prior := hostClockProbe
	clock := &fixedControllerClock{err: errors.New("test NTP unsynchronized")}
	hostClockProbe = func() brokerauth.ClockProbe { return clock }
	t.Cleanup(func() { hostClockProbe = prior })
	var output bytes.Buffer
	err := Run(t.Context(), []string{"host", "--config", config}, &output)
	if err == nil || !strings.Contains(err.Error(), "host NTP clock health") || clock.calls != 1 {
		t.Fatalf("public host command reached native or NATS startup with unhealthy clock: %v, samples=%d", err, clock.calls)
	}
	if output.Len() != 0 {
		t.Fatalf("host reported readiness before clock admission: %q", output.String())
	}
	if _, err := os.Stat(stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host created native state before clock admission: %v", err)
	}
}
