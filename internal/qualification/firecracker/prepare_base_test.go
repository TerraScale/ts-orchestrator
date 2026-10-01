package firecracker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPrepareBaseStagesPinnedDisposableImage(t *testing.T) {
	for _, mode := range []string{"valid", "hash", "existing_output", "key_mismatch", "client_key", "enable_failure", "group_mismatch", "cancelled_staging", "pending_mount", "pending_staging"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				"rootfs": "reviewed base", "binary": "reviewed binary", "host-private": "private-key", "host-public": "ssh-ed25519 host-key comment\n", "client-public": "ssh-ed25519 client-key comment\n",
				"deploy/image/terrascale-orchestrator.sysusers":             "u terrascale-orchestrator - -\n",
				"deploy/systemd/terrascale-orchestrator-bootstrap.service":  "bootstrap unit\n",
				"deploy/systemd/terrascale-orchestrator-controller.service": "controller unit\n",
			}
			if mode == "client_key" {
				files["client-public"] = "ssh-rsa client-key\n"
			}
			for name, content := range files {
				path := filepath.Join(root, name)
				if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path, []byte(content), 0o600); e != nil {
					t.Fatal(e)
				}
			}
			output, known := filepath.Join(root, "output.ext4"), filepath.Join(root, "known-hosts")
			args := []string{"--source-root", root, "--output", output, "--known-hosts", known}
			for _, name := range []string{"rootfs", "binary", "client-public", "host-private", "host-public"} {
				args = append(args, "--"+name, filepath.Join(root, name))
			}
			rootSHA := hashBytes([]byte(files["rootfs"]))
			if mode == "hash" {
				rootSHA = strings.Repeat("0", 64)
			}
			args = append(args, "--rootfs-sha256", rootSHA, "--binary-sha256", hashBytes([]byte(files["binary"])))
			if mode == "existing_output" {
				if e := os.WriteFile(output, nil, 0o600); e != nil {
					t.Fatal(e)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			commands := [][]string{}
			mounted, unmounted, staged := false, false, map[string]string{}
			pending := fixtureProcess()
			pending.hooks.quiescent = func(int, time.Duration) error { return errors.New("still has live members") }
			command := func(ctx context.Context, argv []string, o CommandOptions) (CommandResult, error) {
				commands = append(commands, slices.Clone(argv))
				if argv[0] == "cp" {
					requireEqual(t, o.Timeout, 600*time.Second)
				} else {
					requireEqual(t, o.Timeout, 300*time.Second)
				}
				switch argv[0] {
				case "ssh-keygen":
					if mode == "key_mismatch" {
						return CommandResult{Stdout: "ssh-ed25519 other-key"}, nil
					}
					return CommandResult{Stdout: "ssh-ed25519 host-key"}, nil
				case "cp":
					requireEqual(t, argv[1:3], []string{"--reflink=never", "--sparse=always"})
					b, e := os.ReadFile(argv[3])
					if e != nil {
						return CommandResult{}, e
					}
					return CommandResult{}, os.WriteFile(argv[4], b, 0o600)
				case "mount":
					requireEqual(t, argv[1:4], []string{"-o", "loop", output})
					mounted = true
					if mode == "pending_mount" {
						return CommandResult{}, &PendingCommandError{Process: pending, Err: context.DeadlineExceeded}
					}
					return CommandResult{}, nil
				case "systemd-sysusers":
					mount := strings.TrimPrefix(argv[1], "--root=")
					if mode == "pending_staging" {
						return CommandResult{}, &PendingCommandError{Process: pending, Err: context.DeadlineExceeded}
					}
					if mode == "cancelled_staging" {
						cancel()
						return CommandResult{}, context.Canceled
					}
					group := "988"
					if mode == "group_mismatch" {
						group = "999"
					}
					for name, content := range map[string]string{"passwd": "terrascale-orchestrator:x:988:988::/:/sbin/nologin\n", "group": "terrascale-orchestrator:x:" + group + ":\n"} {
						if e := os.WriteFile(filepath.Join(mount, "etc", name), []byte(content), 0o644); e != nil {
							return CommandResult{}, e
						}
					}
					return CommandResult{}, nil
				case "systemctl":
					if argv[2] == "is-enabled" {
						if mode == "enable_failure" {
							return CommandResult{Stdout: "disabled\n"}, nil
						}
						return CommandResult{Stdout: "enabled\n"}, nil
					}
					return CommandResult{}, nil
				case "umount":
					if e := ctx.Err(); e != nil {
						t.Fatal("cleanup inherited cancelled context", e)
					}
					unmounted = true
					if mode == "valid" {
						for path, want := range map[string]struct {
							content string
							mode    os.FileMode
						}{
							"etc/sysusers.d/terrascale-orchestrator.conf":                                 {files["deploy/image/terrascale-orchestrator.sysusers"], 0o644},
							"etc/systemd/system/terrascale-orchestrator-bootstrap.service":                {"bootstrap unit\n", 0o644},
							"etc/systemd/system/terrascale-orchestrator-controller.service":               {"controller unit\n", 0o644},
							"etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf": {"[Service]\nTimeoutStartSec=300s\n", 0o644},
							"usr/local/bin/terrascale-orchestrator":                                       {files["binary"], 0o755},
							"root/.ssh/authorized_keys":                                                   {files["client-public"], 0o600},
							"etc/ssh/ssh_host_ed25519_key":                                                {files["host-private"], 0o600},
							"etc/ssh/ssh_host_ed25519_key.pub":                                            {files["host-public"], 0o644},
						} {
							p := filepath.Join(argv[1], path)
							b, e := os.ReadFile(p)
							if e != nil {
								t.Fatal(e)
							}
							s, e := os.Stat(p)
							if e != nil {
								t.Fatal(e)
							}
							requireEqual(t, string(b), want.content)
							requireEqual(t, s.Mode().Perm(), want.mode)
							staged[path] = string(b)
						}
						sshDir, e := os.Stat(filepath.Join(argv[1], "root/.ssh"))
						if e != nil {
							t.Fatal(e)
						}
						requireEqual(t, sshDir.Mode().Perm(), os.FileMode(0o700))
					}
					entries, e := os.ReadDir(argv[1])
					if e != nil {
						return CommandResult{}, e
					}
					for _, entry := range entries {
						if e := os.RemoveAll(filepath.Join(argv[1], entry.Name())); e != nil {
							return CommandResult{}, e
						}
					}
					return CommandResult{}, nil
				}
				t.Fatalf("unexpected command %q", argv)
				return CommandResult{}, nil
			}
			var out bytes.Buffer
			e := runPrepareBase(ctx, args, &out, io.Discard, command, func() int { return 0 })
			if mode != "valid" {
				parts := map[string]string{"hash": "reviewed SHA-256", "existing_output": "must be new paths", "key_mismatch": "differs from private key", "client_key": "must be Ed25519", "enable_failure": "was not enabled", "group_mismatch": "matching primary group", "cancelled_staging": "context canceled"}
				if strings.HasPrefix(mode, "pending_") {
					requireError(t, e, "not confirmed stopped")
					if unmounted || pending.Reaped {
						t.Fatal("cleanup tore down a live helper")
					}
					entries, e := filepath.Glob(filepath.Join(root, "tspr-base-*"))
					if e != nil {
						t.Fatal(e)
					}
					requireEqual(t, len(entries), 1)
					if _, e := os.Stat(output); e != nil {
						t.Fatal("pending helper lost image", e)
					}
					if _, e := os.Stat(known); !os.IsNotExist(e) {
						t.Fatal("pending helper published known hosts", e)
					}
					return
				}
				requireError(t, e, parts[mode])
				if mounted && !unmounted {
					t.Fatal("failed staging did not unmount")
				}
				if _, e := os.Stat(known); !os.IsNotExist(e) {
					t.Fatal("failed staging published known hosts", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			requireEqual(t, []bool{mounted, unmounted}, []bool{true, true})
			requireEqual(t, len(staged), 8)
			b, e := os.ReadFile(known)
			if e != nil {
				t.Fatal(e)
			}
			requireEqual(t, string(b), "10.44.0.10 ssh-ed25519 host-key\n10.44.0.11 ssh-ed25519 host-key\n10.44.0.12 ssh-ed25519 host-key\n")
			info, e := os.Stat(known)
			if e != nil {
				t.Fatal(e)
			}
			requireEqual(t, info.Mode().Perm(), os.FileMode(0o644))
			base, e := os.Stat(filepath.Join(root, "rootfs"))
			if e != nil {
				t.Fatal(e)
			}
			copyInfo, e := os.Stat(output)
			if e != nil {
				t.Fatal(e)
			}
			if os.SameFile(base, copyInfo) {
				t.Fatal("base modified in place")
			}
			if !strings.Contains(out.String(), "service uid=988 gid=988") || !strings.Contains(out.String(), "base ext4 sha256="+rootSHA) || !strings.Contains(out.String(), "known-hosts sha256=") {
				t.Fatal(out.String())
			}
		})
	}
}

func TestPrepareBaseRejectsNonRoot(t *testing.T) {
	e := runPrepareBase(t.Context(), nil, io.Discard, io.Discard, func(context.Context, []string, CommandOptions) (CommandResult, error) {
		t.Fatal("non-root preparation ran a command")
		return CommandResult{}, nil
	}, func() int { return 1000 })
	requireError(t, e, "requires root")
	if errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
