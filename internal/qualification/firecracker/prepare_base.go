package firecracker

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

func RunPrepareBase(ctx context.Context, args []string, out, errout io.Writer) error {
	return runPrepareBase(ctx, args, out, errout, Execute, os.Geteuid)
}

func runPrepareBase(ctx context.Context, args []string, out, errout io.Writer, command CommandFunc, uid func() int) error {
	pendingCommands := []*Process{}
	execute := command
	command = func(ctx context.Context, argv []string, options CommandOptions) (CommandResult, error) {
		r, e := execute(ctx, argv, options)
		if pending, ok := errors.AsType[*PendingCommandError](e); ok && !slices.Contains(pendingCommands, pending.Process) {
			pendingCommands = append(pendingCommands, pending.Process)
		}
		return r, e
	}
	f := flag.NewFlagSet("qualification firecracker prepare-base", flag.ContinueOnError)
	f.SetOutput(errout)
	paths := map[string]string{}
	for _, name := range []string{"source-root", "rootfs", "binary", "client-public", "host-private", "host-public", "output", "known-hosts"} {
		f.Func(name, "input or new output path", func(value string) error { paths[name] = value; return nil })
	}
	var rootfsSHA, binarySHA string
	f.StringVar(&rootfsSHA, "rootfs-sha256", "", "reviewed rootfs SHA-256")
	f.StringVar(&binarySHA, "binary-sha256", "", "reviewed executable SHA-256")
	if e := f.Parse(args); e != nil {
		return e
	}
	if uid() != 0 {
		return errors.New("offline ext4 preparation requires root")
	}
	for _, name := range []string{"source-root", "rootfs", "binary", "client-public", "host-private", "host-public", "output", "known-hosts"} {
		if paths[name] == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}
	for _, name := range []string{"source-root", "rootfs", "binary", "client-public", "host-private", "host-public"} {
		p, e := filepath.EvalSymlinks(paths[name])
		if e != nil {
			return e
		}
		p, e = filepath.Abs(p)
		if e != nil {
			return e
		}
		s, e := os.Stat(p)
		if e != nil {
			return e
		}
		if name != "source-root" && !s.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", name)
		}
		paths[name] = p
	}
	rootHash, e := Digest(paths["rootfs"])
	if e != nil {
		return e
	}
	binaryHash, e := Digest(paths["binary"])
	if e != nil {
		return e
	}
	if rootHash != rootfsSHA || binaryHash != binarySHA {
		return errors.New("base or production executable differs from its reviewed SHA-256")
	}
	for _, name := range []string{"output", "known-hosts"} {
		p, e := filepath.Abs(paths[name])
		if e != nil {
			return e
		}
		paths[name] = p
		if _, e = os.Lstat(p); e == nil || !os.IsNotExist(e) {
			return errors.New("base output and known-hosts output must be new paths")
		}
		if p == paths["rootfs"] {
			return errors.New("base output and known-hosts output must be new paths")
		}
		if e = os.MkdirAll(filepath.Dir(p), 0o755); e != nil {
			return e
		}
	}
	hostPublic, e := os.ReadFile(paths["host-public"])
	if e != nil {
		return e
	}
	derived, e := command(ctx, []string{"ssh-keygen", "-y", "-f", paths["host-private"]}, CommandOptions{Timeout: 300 * time.Second})
	if e != nil {
		return e
	}
	hostFields, derivedFields := strings.Fields(string(hostPublic)), strings.Fields(derived.Stdout)
	if len(hostFields) < 2 || len(derivedFields) < 2 || hostFields[0] != derivedFields[0] || hostFields[1] != derivedFields[1] {
		return errors.New("host SSH public key differs from private key")
	}
	client, e := os.ReadFile(paths["client-public"])
	if e != nil {
		return e
	}
	clientPublic := strings.TrimSpace(string(client))
	if !strings.HasPrefix(clientPublic, "ssh-ed25519 ") {
		return errors.New("client SSH key must be Ed25519")
	}
	if _, e = command(ctx, []string{"cp", "--reflink=never", "--sparse=always", paths["rootfs"], paths["output"]}, CommandOptions{Timeout: 600 * time.Second}); e != nil {
		return e
	}
	copyHash, e := Digest(paths["output"])
	if e != nil {
		return e
	}
	base, e := os.Stat(paths["rootfs"])
	if e != nil {
		return e
	}
	copyStat, e := os.Stat(paths["output"])
	if e != nil {
		return e
	}
	if copyHash != rootfsSHA || os.SameFile(base, copyStat) {
		return errors.New("disposable ext4 copy differs from pinned base")
	}
	mount, e := os.MkdirTemp(filepath.Dir(paths["output"]), "tspr-base-")
	if e != nil {
		return e
	}
	mounted := false
	stageErr := func() error {
		mounted = true
		if _, e := command(ctx, []string{"mount", "-o", "loop", paths["output"], mount}, CommandOptions{Timeout: 300 * time.Second}); e != nil {
			return e
		}
		install := func(source, destination string, mode os.FileMode) error {
			b, e := os.ReadFile(source)
			if e != nil {
				return e
			}
			p := filepath.Join(mount, strings.TrimPrefix(destination, "/"))
			if e = os.MkdirAll(filepath.Dir(p), 0o755); e != nil {
				return e
			}
			if e = os.WriteFile(p, b, mode); e != nil {
				return e
			}
			return os.Chmod(p, mode)
		}
		text := func(destination, content string, mode os.FileMode) error {
			p := filepath.Join(mount, strings.TrimPrefix(destination, "/"))
			if e := os.MkdirAll(filepath.Dir(p), 0o755); e != nil {
				return e
			}
			if e := os.WriteFile(p, []byte(content), mode); e != nil {
				return e
			}
			return os.Chmod(p, mode)
		}
		if e := install(filepath.Join(paths["source-root"], "deploy/image/terrascale-orchestrator.sysusers"), "/etc/sysusers.d/terrascale-orchestrator.conf", 0o644); e != nil {
			return e
		}
		if _, e := command(ctx, []string{"systemd-sysusers", "--root=" + mount}, CommandOptions{Timeout: 300 * time.Second}); e != nil {
			return e
		}
		for _, unit := range []string{"bootstrap", "controller"} {
			name := "terrascale-orchestrator-" + unit + ".service"
			if e := install(filepath.Join(paths["source-root"], "deploy/systemd", name), "/etc/systemd/system/"+name, 0o644); e != nil {
				return e
			}
		}
		if e := text("/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf", "[Service]\nTimeoutStartSec=300s\n", 0o644); e != nil {
			return e
		}
		if e := install(paths["binary"], "/usr/local/bin/terrascale-orchestrator", 0o755); e != nil {
			return e
		}
		if e := text("/root/.ssh/authorized_keys", clientPublic+"\n", 0o600); e != nil {
			return e
		}
		if e := os.Chmod(filepath.Join(mount, "root/.ssh"), 0o700); e != nil {
			return e
		}
		if e := install(paths["host-private"], "/etc/ssh/ssh_host_ed25519_key", 0o600); e != nil {
			return e
		}
		if e := install(paths["host-public"], "/etc/ssh/ssh_host_ed25519_key.pub", 0o644); e != nil {
			return e
		}
		for _, unit := range ProductionUnits {
			if _, e := command(ctx, []string{"systemctl", "--root=" + mount, "enable", unit}, CommandOptions{Timeout: 300 * time.Second}); e != nil {
				return e
			}
			r, e := command(ctx, []string{"systemctl", "--root=" + mount, "is-enabled", unit}, CommandOptions{Timeout: 300 * time.Second})
			if e != nil {
				return e
			}
			if strings.TrimSpace(r.Stdout) != "enabled" {
				return fmt.Errorf("%s was not enabled: %s", unit, r.Stdout)
			}
		}
		passwd, e := os.ReadFile(filepath.Join(mount, "etc/passwd"))
		if e != nil {
			return e
		}
		group, e := os.ReadFile(filepath.Join(mount, "etc/group"))
		if e != nil {
			return e
		}
		users, groups := [][]string{}, [][]string{}
		for line := range strings.SplitSeq(string(passwd), "\n") {
			if strings.HasPrefix(line, "terrascale-orchestrator:") {
				users = append(users, strings.Split(line, ":"))
			}
		}
		for line := range strings.SplitSeq(string(group), "\n") {
			if strings.HasPrefix(line, "terrascale-orchestrator:") {
				groups = append(groups, strings.Split(line, ":"))
			}
		}
		if len(users) != 1 || len(groups) != 1 || len(users[0]) < 4 || len(groups[0]) < 3 || users[0][3] != groups[0][2] {
			return errors.New("guest service account was not created with a matching primary group")
		}
		fmt.Fprintf(out, "service uid=%s gid=%s\n", users[0][2], users[0][3])
		return nil
	}()
	if pendingErrors := quiescePendingCommands(&pendingCommands); len(pendingErrors) > 0 {
		return errors.Join(stageErr, fmt.Errorf("preserve base image and mount %s: %s", mount, strings.Join(pendingErrors, "; ")))
	}
	var cleanup error
	if mounted {
		_, cleanup = command(context.WithoutCancel(ctx), []string{"umount", mount}, CommandOptions{Timeout: 300 * time.Second})
	}
	if pendingErrors := quiescePendingCommands(&pendingCommands); len(pendingErrors) > 0 {
		return errors.Join(stageErr, cleanup, fmt.Errorf("preserve base image and mount %s: %s", mount, strings.Join(pendingErrors, "; ")))
	}
	if cleanup == nil {
		cleanup = os.Remove(mount)
	}
	if e = errors.Join(stageErr, cleanup); e != nil {
		return e
	}
	key := hostFields[0] + " " + hostFields[1]
	var known strings.Builder
	for _, address := range []string{"10.44.0.10", "10.44.0.11", "10.44.0.12"} {
		fmt.Fprintf(&known, "%s %s\n", address, key)
	}
	if e = os.WriteFile(paths["known-hosts"], []byte(known.String()), 0o644); e != nil {
		return e
	}
	if e = os.Chmod(paths["known-hosts"], 0o644); e != nil {
		return e
	}
	owner, e := os.Stat(filepath.Dir(paths["output"]))
	if e != nil {
		return e
	}
	s, ok := owner.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("output directory ownership unavailable")
	}
	for _, name := range []string{"output", "known-hosts"} {
		if e = os.Chown(paths[name], int(s.Uid), int(s.Gid)); e != nil {
			return e
		}
	}
	outputHash, e := Digest(paths["output"])
	if e != nil {
		return e
	}
	knownHash, e := Digest(paths["known-hosts"])
	if e != nil {
		return e
	}
	fmt.Fprintf(out, "base ext4 sha256=%s\nknown-hosts sha256=%s\n", outputHash, knownHash)
	return nil
}
