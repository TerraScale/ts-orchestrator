package firecracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func managedRuntimeLab(t *testing.T) *ManagedLab {
	t.Helper()
	root := t.TempDir()
	l := &ManagedLab{Ctx: t.Context(), Root: root, Commands: filepath.Join(root, "commands"), Images: filepath.Join(root, "images"), Mounts: filepath.Join(root, "mounts"), Fixture: filepath.Join(root, "fixture"), VMs: map[string]*ManagedVM{}, Mounted: map[string]bool{}}
	for _, directory := range []string{l.Commands, l.Images, l.Mounts, l.Fixture} {
		if e := os.Mkdir(directory, 0o700); e != nil {
			t.Fatal(e)
		}
	}
	return l
}

func TestManagedCommandOwnershipSurvivesCleanupFailure(t *testing.T) {
	l := managedRuntimeLab(t)
	rootfs := filepath.Join(l.Images, "a-rootfs.ext4")
	if e := os.WriteFile(rootfs, []byte("credential-bearing-rootfs"), 0o600); e != nil {
		t.Fatal(e)
	}
	blocked := true
	l.commandHooks = &processHooks{signal: func(group int, signal syscall.Signal) error {
		if blocked {
			return syscall.EPERM
		}
		return syscall.Kill(-group, signal)
	}}
	_, e := l.RunCommand("mutating-helper", []string{"/bin/sh", "-c", "sleep 300"}, false, 25*time.Millisecond, []int{0}, nil)
	if !errors.Is(e, syscall.EPERM) || !errors.Is(e, context.DeadlineExceeded) || len(l.pendingCommands) != 1 {
		t.Fatalf("lost pending command ownership: %v, %#v", e, l.pendingCommands)
	}
	p := l.pendingCommands[0].process
	t.Cleanup(func() {
		blocked = false
		if !p.Reaped {
			if e := p.Stop(time.Second, true); e != nil {
				t.Error(e)
			}
		}
	})
	l.CreatedLinks = []string{"private-owned-link"}
	l.VMs["never-started"] = &ManagedVM{Lab: l}
	l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
		return CommandResult{Stdout: "[]"}, nil
	}
	l.Cleanup()
	if p.Reaped || p.Output == nil || len(l.pendingCommands) != 1 || !slices.Equal(l.CreatedLinks, []string{"private-owned-link"}) || !l.VMs["never-started"].Stopped {
		t.Fatalf("cleanup released uncertain ownership: %+v", l)
	}
	for _, path := range []string{rootfs, l.Fixture} {
		if _, e := os.Stat(path); e != nil {
			t.Fatalf("resource removed before helper stopped: %s: %v", path, e)
		}
	}
	blocked = false
	l.Cleanup()
	if !p.Reaped || p.Output != nil || len(l.pendingCommands) != 0 || len(l.CreatedLinks) != 0 {
		t.Fatalf("retry did not release stopped command: %+v", l)
	}
	for _, path := range []string{rootfs, l.Fixture} {
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatalf("resource retained after helper stopped: %s: %v", path, e)
		}
	}
}

func TestManagedS3StagingRejectsCredentialMutation(t *testing.T) {
	for _, mutated := range []int{0, 1} {
		t.Run(fmt.Sprint(mutated), func(t *testing.T) {
			l := managedRuntimeLab(t)
			mount := t.TempDir()
			for i, value := range []string{"fixture_access_123", "fixture_secret_456"} {
				l.S3CredentialPaths[i] = filepath.Join(t.TempDir(), "credential")
				if e := os.WriteFile(l.S3CredentialPaths[i], []byte(value), 0o600); e != nil {
					t.Fatal(e)
				}
				l.S3KeyHashes[i] = hashBytes([]byte(value))
			}
			installs := 0
			l.Command = func(ctx context.Context, argv []string, o CommandOptions) (CommandResult, error) {
				argv = argv[2:]
				if argv[0] == "install" {
					source, target := argv[len(argv)-2], argv[len(argv)-1]
					if installs == mutated {
						if e := os.WriteFile(source, []byte("changed_fixture_key"), 0o600); e != nil {
							return CommandResult{}, e
						}
					}
					installs++
					b, e := os.ReadFile(source)
					if e != nil {
						return CommandResult{}, e
					}
					if e = os.MkdirAll(filepath.Dir(target), 0o700); e == nil {
						e = os.WriteFile(target, b, 0o600)
					}
					return CommandResult{}, e
				}
				return Execute(ctx, argv, o)
			}
			requireError(t, l.stageS3Credentials(mount, "a"), "staged S3 credential changed")
			if installs != mutated+1 {
				t.Fatal(installs)
			}
		})
	}
}

func TestManagedCanceledNetworkCreateRetainsOwnedLink(t *testing.T) {
	for _, kind := range []string{"bridge", "tap"} {
		t.Run(kind, func(t *testing.T) {
			l := managedRuntimeLab(t)
			l.Bridge = "tsmtestb"
			l.Taps = map[string]string{"a": "tsmtesta", "b": "tsmtestc"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l.Ctx = ctx
			active := map[string]bool{}
			l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
				if argv[0] == "sudo" {
					argv = argv[2:]
				}
				if slices.Equal(argv, []string{"ip", "-json", "link", "show"}) {
					links := []any{}
					for name := range active {
						links = append(links, Object{"ifname": name})
					}
					return CommandResult{Stdout: marshal(links)}, nil
				}
				if slices.Equal(argv, []string{"ip", "-j", "addr", "show"}) || slices.Equal(argv, []string{"ip", "-j", "route", "show", "table", "all"}) {
					return CommandResult{Stdout: "[]"}, nil
				}
				if slices.Contains(argv, "add") && (slices.Contains(argv, "bridge") || slices.Contains(argv, "tuntap")) {
					name := l.Bridge
					if slices.Contains(argv, "tuntap") {
						name = argv[4]
					}
					active[name] = true
					if (kind == "bridge" && name == l.Bridge) || (kind == "tap" && name == l.Taps["a"]) {
						cancel()
						return CommandResult{}, ctx.Err()
					}
				}
				if slices.Contains(argv, "del") {
					delete(active, argv[len(argv)-1])
				}
				return CommandResult{}, nil
			}
			requireError(t, l.Network(), "context canceled")
			if len(l.CreatedLinks) == 0 || len(active) == 0 {
				t.Fatal("canceled successful kernel mutation lost ownership")
			}
			l.Cleanup()
			if len(l.CleanupErrors) > 0 || len(l.CreatedLinks) > 0 || len(active) > 0 {
				t.Fatalf("owned links not cleaned: %+v, %v", l, active)
			}
		})
	}
}

func TestNativeProvenancePinsExecutableAndModuleInputs(t *testing.T) {
	p, e := CaptureNativeProvenance()
	if e != nil {
		t.Fatal(e)
	}
	h, e := Digest("/proc/self/exe")
	if e != nil || h != p.ExecutableSHA256 || p.GoVersion == "" {
		t.Fatalf("missing executable provenance: %+v, %v", p, e)
	}
	if e := p.VerifyExecutable(); e != nil {
		t.Fatal(e)
	}
	p.ExecutableSHA256 = strings.Repeat("0", 64)
	requireError(t, p.VerifyExecutable(), "executable changed")
	source, e := filepath.Abs("../../..")
	if e != nil {
		t.Fatal(e)
	}
	l, e := NewManagedLab(t.Context(), ManagedManifest{}, filepath.Join(t.TempDir(), "run"), source, [2]string{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		if l.SourcePaths[name] != filepath.Join(source, name) || l.SourceHashes[name] == "" {
			t.Fatalf("module input not pinned: %s", name)
		}
	}
}

func TestNativeCommandWaitIsBoundedForEscapedPipeHolder(t *testing.T) {
	if _, e := exec.LookPath("setsid"); e != nil {
		t.Skip("setsid is required to exercise escaped pipe holders")
	}
	for _, bounded := range []bool{false, true} {
		t.Run(fmt.Sprint(bounded), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "escaped.pid")
			t.Cleanup(func() {
				b, e := os.ReadFile(path)
				if e == nil {
					pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
					if e == nil {
						_ = syscall.Kill(pid, syscall.SIGKILL)
					}
				}
			})
			argv := []string{"/bin/sh", "-c", `setsid sleep 30 & echo $! > "$1"; sleep 0.1`, "sh", path}
			start := time.Now()
			var e error
			if bounded {
				_, e = BoundedCommand(t.Context(), argv, CommandOptions{Timeout: time.Second}, filepath.Join(t.TempDir(), "log"), 1024)
			} else {
				_, e = Execute(t.Context(), argv, CommandOptions{Timeout: time.Second})
			}
			if !errors.Is(e, exec.ErrWaitDelay) || time.Since(start) > 5*time.Second {
				t.Fatalf("escaped pipe holder stalled wait: %v after %s", e, time.Since(start))
			}
		})
	}
}

func TestManagedVMStartFailureReleasesCaptureAndResources(t *testing.T) {
	l := managedRuntimeLab(t)
	l.Logs = t.TempDir()
	l.Manifest.Inputs = map[string]ManagedInput{"firecracker": {Path: filepath.Join(t.TempDir(), "missing-firecracker")}}
	v := &ManagedVM{Lab: l, Member: "a", Socket: filepath.Join(t.TempDir(), "a.sock"), Resources: func() ([]FirecrackerRequest, error) { return nil, nil }}
	if e := v.Start(); e == nil {
		t.Fatal("missing executable started")
	}
	if v.Serial != nil || v.VMM != nil || v.Process != nil {
		t.Fatal("failed start retained captures or process")
	}
	if errs := v.Stop(); len(errs) > 0 || !v.Stopped {
		t.Fatalf("never-started VM blocked cleanup: %v", errs)
	}
}

func TestManagedManifestRequiresCurrentUserExecutableAccess(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can execute files with any executable mode bit")
	}
	for _, rejected := range []string{"firecracker", "go_host_test", "tb_server"} {
		t.Run(rejected, func(t *testing.T) {
			dir := t.TempDir()
			inputs := Object{}
			for _, name := range ManagedCommonInputs {
				path := filepath.Join(dir, name)
				mode := os.FileMode(0o700)
				if name == rejected {
					mode = 0o601
				}
				if e := os.WriteFile(path, []byte(name), mode); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(path, mode); e != nil {
					t.Fatal(e)
				}
				inputs[name] = Object{"path": path, "sha256": hashBytes([]byte(name))}
			}
			path := filepath.Join(dir, "manifest.json")
			if e := writeJSON(path, Object{"profile": ManagedMemberProfile, "source_commits": Object{"orchestrator": strings.Repeat("a", 40), "terrabase": strings.Repeat("b", 40)}, "inputs": inputs, "members": Object{"a": Object{}, "b": Object{}}}); e != nil {
				t.Fatal(e)
			}
			_, e := LoadManagedManifest(path)
			requireError(t, e, rejected+": input must be executable")
		})
	}
}
