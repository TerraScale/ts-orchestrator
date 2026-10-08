package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
)

func TestNetBirdWorkerSkipsCustomRootThroughActivationAndDelegatedPrepare(t *testing.T) {
	dir := t.TempDir()
	layout := selfupdate.Layout{Root: filepath.Join(dir, "root"), Owner: os.Getuid()}
	baked := filepath.Join(dir, "new-baked")
	supported := []byte("#!/bin/sh\n[ \"$*\" = 'netbird agent run --help' ]\n")
	if err := os.WriteFile(baked, supported, 0755); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "old")
	if err := os.WriteFile(old, []byte("#!/bin/sh\n[ \"$1\" = selfupdate ]\n"), 0755); err != nil {
		t.Fatal(err)
	}
	previous, err := selfupdate.Seed(layout, old)
	if err != nil {
		t.Fatal(err)
	}
	// A confirmed older release delegates root steps successfully while
	// lacking the worker command introduced by this release.
	if err := os.Remove(filepath.Join(layout.ReleaseDir(previous), "baked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/"+previous, filepath.Join(layout.Root, "known-good")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(delegatedEnv, "")
	systemd := t.TempDir()
	if err := os.WriteFile(filepath.Join(systemd, selfupdate.HostSetupUnit), []byte("[Service]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	prepare := []string{"prepare", "--root", layout.Root, "--owner", fmt.Sprint(layout.Owner), "--unit", selfupdate.HostUnit,
		"--baked-binary", baked, "--systemd-dir", systemd}
	now := time.Now()
	restart := func(context.Context, string) error { t.Fatal("scratch prepare requested a live restart"); return nil }
	if err := run(t.Context(), prepare, io.Discard, func() time.Time { return now }, restart); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{selfupdate.NetBirdAgentUnit, selfupdate.HostUnit + ".d/65-netbird-agent.conf"} {
		if _, err := os.Stat(filepath.Join(systemd, path)); !os.IsNotExist(err) {
			t.Fatalf("unsupported current received worker dependency %s: %v", path, err)
		}
	}
	sum := sha256.Sum256(supported)
	target := hex.EncodeToString(sum[:])
	if err := os.Mkdir(layout.ReleaseDir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.BinaryPath(target), supported, 0555); err != nil {
		t.Fatal(err)
	}
	if _, err := selfupdate.Activate(layout, target, selfupdate.HostUnit, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	// The activation's unit restart runs the same ExecStartPre prepare.
	// A capable custom current must not install units that execute the default root.
	if err := run(t.Context(), prepare, io.Discard, func() time.Time { return now }, restart); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{selfupdate.NetBirdAgentUnit, selfupdate.HostUnit + ".d/65-netbird-agent.conf",
		"terrascale-netbird-enroll.service.d/zz-selfupdate.conf"} {
		if _, err := os.Stat(filepath.Join(systemd, path)); !os.IsNotExist(err) {
			t.Fatalf("custom current received default-root unit %s: %v", path, err)
		}
	}
}

func TestNetBirdWorkerCustomRootDoesNotProbeOrStart(t *testing.T) {
	dir := t.TempDir()
	layout := selfupdate.Layout{Root: filepath.Join(dir, "custom-root"), Owner: os.Getuid()}
	binary := filepath.Join(dir, "capable")
	probe := filepath.Join(dir, "probed")
	t.Setenv("NETBIRD_PROBE", probe)
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf called > \"$NETBIRD_PROBE\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := selfupdate.Seed(layout, binary); err != nil {
		t.Fatal(err)
	}
	systemd := t.TempDir()
	c := command{ctx: t.Context(), restart: func(context.Context, string) error {
		t.Fatal("custom root requested default-root worker startup")
		return nil
	}}
	if err := c.installCurrentNetBirdAgent(layout, systemd, selfupdate.HostUnit); err == nil ||
		!strings.Contains(err.Error(), "managed NetBird units require --root "+selfupdate.DefaultRoot) {
		t.Fatalf("custom layout did not explicitly skip managed units: %v", err)
	}
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Fatalf("probed a custom binary for default-root units: %v", err)
	}
}

func TestNetBirdWorkerRequiresCapableBinary(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "unsupported-current")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	systemd := t.TempDir()
	if err := os.WriteFile(filepath.Join(systemd, selfupdate.HostSetupUnit), []byte("[Service]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c := command{ctx: t.Context(), restart: func(context.Context, string) error {
		t.Fatal("unsupported current requested worker startup")
		return nil
	}}
	if err := c.installNetBirdAgent(binary, systemd, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(systemd, selfupdate.NetBirdAgentUnit)); !os.IsNotExist(err) {
		t.Fatalf("unsupported current received a worker unit: %v", err)
	}
}

func TestNetBirdWorkerUnmanagedHostDoesNotReloadEnableOrStart(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent-worker", true: "stale-worker"}[stale], func(t *testing.T) {
			dir := t.TempDir()
			binary := filepath.Join(dir, "current")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n[ \"$*\" = 'netbird agent run --help' ]\n"), 0755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "systemctl.log")
			t.Setenv("SYSTEMCTL_LOG", log)
			if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\n"), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			systemd := t.TempDir()
			if stale {
				if err := os.WriteFile(filepath.Join(systemd, selfupdate.NetBirdAgentUnit), []byte(selfupdate.NetBirdAgentService), 0644); err != nil {
					t.Fatal(err)
				}
			}
			c := command{ctx: t.Context(), restart: func(context.Context, string) error {
				t.Fatal("unmanaged host requested worker startup")
				return nil
			}}
			if err := c.installNetBirdAgent(binary, systemd, true); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(log); !os.IsNotExist(err) {
				t.Fatalf("unmanaged host invoked systemctl: %v", err)
			}
			if _, err := os.Stat(filepath.Join(systemd, selfupdate.HostUnit+".d/65-netbird-agent.conf")); !os.IsNotExist(err) {
				t.Fatalf("unmanaged host received worker dependency: %v", err)
			}
		})
	}
}

func TestNetBirdWorkerProbeFaultsAreReported(t *testing.T) {
	for _, fault := range []string{"missing", "non-executable", "timeout", "signal"} {
		t.Run(fault, func(t *testing.T) {
			dir := t.TempDir()
			binary := filepath.Join(dir, "current")
			ctx := t.Context()
			var expected error
			switch fault {
			case "missing":
				expected = os.ErrNotExist
			case "non-executable":
				if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0644); err != nil {
					t.Fatal(err)
				}
				expected = os.ErrPermission
			case "timeout":
				if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 30\n"), 0755); err != nil {
					t.Fatal(err)
				}
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
				expected = context.DeadlineExceeded
			case "signal":
				if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 'probe crashed' >&2\nkill -TERM $$\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			systemd := t.TempDir()
			if err := os.WriteFile(filepath.Join(systemd, selfupdate.HostSetupUnit), []byte("[Service]\n"), 0644); err != nil {
				t.Fatal(err)
			}
			c := command{ctx: ctx, restart: func(context.Context, string) error {
				t.Fatal("faulted capability probe requested worker startup")
				return nil
			}}
			err := c.installNetBirdAgent(binary, systemd, true)
			if err == nil || !strings.Contains(err.Error(), "probe NetBird worker support") || expected != nil && !errors.Is(err, expected) {
				t.Fatalf("capability probe hid %s: %v", fault, err)
			}
			if fault == "signal" && !strings.Contains(err.Error(), "probe crashed") {
				t.Fatalf("capability probe lost stderr: %v", err)
			}
			if _, err := os.Stat(filepath.Join(systemd, selfupdate.NetBirdAgentUnit)); !os.IsNotExist(err) {
				t.Fatalf("faulted probe installed worker: %v", err)
			}
		})
	}
}

func TestNetBirdWorkerRetriesReloadOfUnchangedInstalledUnits(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed-reload", true: "crash-before-reload"}[interrupted], func(t *testing.T) {
			dir := t.TempDir()
			binary := filepath.Join(dir, "current")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n[ \"$*\" = 'netbird agent run --help' ]\n"), 0755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "systemctl.log")
			t.Setenv("SYSTEMCTL_LOG", log)
			t.Setenv("SYSTEMCTL_FAIL", "daemon-reload")
			if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\n"+
				"if [ \"$*\" = \"$SYSTEMCTL_FAIL\" ]; then echo 'unit reload failed' >&2; exit 1; fi\n"), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			systemd := t.TempDir()
			if err := os.WriteFile(filepath.Join(systemd, selfupdate.HostSetupUnit), []byte("[Service]\n"), 0644); err != nil {
				t.Fatal(err)
			}
			c := command{ctx: t.Context(), restart: SystemctlRestart}
			if interrupted {
				if installed, err := selfupdate.InstallNetBirdAgent(systemd); !installed || err != nil {
					t.Fatalf("interrupted prepare did not write units: installed=%t error=%v", installed, err)
				}
			} else {
				if err := c.installNetBirdAgent(binary, systemd, true); err == nil || !strings.Contains(err.Error(), "unit reload failed") {
					t.Fatalf("first prepare did not report reload failure: %v", err)
				}
				wire, err := os.ReadFile(log)
				if err != nil || string(wire) != "daemon-reload\n" {
					t.Fatalf("failed reload proceeded to enable/start: %q %v", wire, err)
				}
				if err := os.Remove(log); err != nil {
					t.Fatal(err)
				}
			}
			if changed, err := selfupdate.InstallNetBirdAgent(systemd); changed || err != nil {
				t.Fatalf("retry fixture did not retain unchanged units: changed=%t error=%v", changed, err)
			}
			t.Setenv("SYSTEMCTL_FAIL", "")
			if err := c.installNetBirdAgent(binary, systemd, true); err != nil {
				t.Fatal(err)
			}
			wire, err := os.ReadFile(log)
			want := "daemon-reload\nenable " + selfupdate.NetBirdAgentUnit + "\n--no-block restart " + selfupdate.NetBirdAgentUnit + "\n"
			if err != nil || string(wire) != want {
				t.Fatalf("unchanged units did not retry reload before worker start: %q %v", wire, err)
			}
		})
	}
}

func TestNetBirdWorkerStartupCapturesSystemctlFailures(t *testing.T) {
	for _, phase := range []string{"", "daemon-reload", "enable", "restart"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			binary := filepath.Join(dir, "current")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n[ \"$*\" = 'netbird agent run --help' ]\n"), 0755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "systemctl.log")
			t.Setenv("SYSTEMCTL_LOG", log)
			t.Setenv("SYSTEMCTL_FAIL", phase)
			if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\n"+
				"if [ -n \"$SYSTEMCTL_FAIL\" ]; then case \"$*\" in *\"$SYSTEMCTL_FAIL\"*) echo 'unit permission denied' >&2; exit 1;; esac; fi\n"), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			systemd := t.TempDir()
			if err := os.WriteFile(filepath.Join(systemd, selfupdate.HostSetupUnit), []byte("[Service]\n"), 0644); err != nil {
				t.Fatal(err)
			}
			c := command{ctx: t.Context(), restart: SystemctlRestart}
			err := c.installNetBirdAgent(binary, systemd, true)
			if phase != "" {
				if err == nil || !strings.Contains(err.Error(), "unit permission denied") || !strings.Contains(err.Error(), phase) {
					t.Fatalf("systemctl failure lost its diagnostic: %v", err)
				}
			} else {
				wire, readErr := os.ReadFile(log)
				want := "daemon-reload\nenable " + selfupdate.NetBirdAgentUnit + "\n--no-block restart " + selfupdate.NetBirdAgentUnit + "\n"
				if err != nil || readErr != nil || string(wire) != want {
					t.Fatalf("capable current did not start automatically: %q %v %v", wire, err, readErr)
				}
			}
		})
	}
}
