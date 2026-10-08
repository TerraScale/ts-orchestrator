package image

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Bootstrap = "/etc/terrascale-orchestrator/bootstrap"
const App = "/etc/terrascale-orchestrator"
const AppLib = "/usr/local/lib/terrascale-orchestrator"
const Native = AppLib + "/managed-material/terrabase-server"
const NetBird = "/usr/local/bin/netbird"
const NetBirdConfig = App + "/netbird.json"
const NetBirdPin = App + "/netbird-pin.json"
const NetBirdFallback = AppLib + "/netbird-client"
const TimeConfig = "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf"
const TimeDropin = "/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf"
const Profile = App + "/runtime-priority.json"
const Helper = AppLib + "/runtime-priority/qualify"
const VolumeState = "/var/lib/terrascale-orchestrator-volume-init"
const OCIDevicePaths = "/etc/udev/rules.d/65-terrascale-oci-device-paths.rules"

var Dropins = []string{"/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf", "/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf", "/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf"}
var NetBirdUnits = []string{"netbird.service", "terrascale-netbird-enroll.service", "terrascale-netbird-agent.service"}

const SSHUnit = "ssh.socket"

var Units = []string{"systemd-timesyncd.service", "systemd-time-wait-sync.service", "terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service", "netbird.service", "terrascale-netbird-enroll.service", "terrascale-netbird-agent.service", SSHUnit}
var HostUnits = []string{"terrascale-orchestrator-host-setup.service", "terrascale-orchestrator-host-setup.timer", "terrascale-orchestrator-host-volume-init.socket"}
var HostUnitFiles = append(append([]string{}, HostUnits...), "terrascale-orchestrator-host-volume-init.service")

// SelfUpdateDropins install binary self-update and NetBird isolation from
// deploy/systemd/selfupdate. The image enables SelfUpdateTimers, the watchdog
// instances of SelfUpdateUnitFiles for each role.
var SelfUpdateDropins = []string{"terrascale-orchestrator-controller.service.d/60-selfupdate.conf", "terrascale-orchestrator-host.service.d/60-selfupdate.conf", "terrascale-orchestrator-host.service.d/65-netbird-agent.conf", "terrascale-orchestrator-host-setup.service.d/60-selfupdate.conf", "terrascale-netbird-enroll.service.d/zz-selfupdate.conf"}
var SelfUpdateUnitFiles = []string{"terrascale-orchestrator-selfupdate-watchdog@.service", "terrascale-orchestrator-selfupdate-watchdog@.timer"}
var SelfUpdateTimers = []string{"terrascale-orchestrator-selfupdate-watchdog@controller.timer", "terrascale-orchestrator-selfupdate-watchdog@host.timer"}
var VolumeTools = []string{"/usr/sbin/mkfs.ext4", "/usr/sbin/blkid", "/usr/sbin/wipefs", "/usr/bin/mount"}

// Exec is an injectable observation boundary for external image tools.
type Exec func(ctx context.Context, dir string, env []string, command ...string) (string, error)

func Execute(ctx context.Context, dir string, env []string, command ...string) (string, error) {
	if len(command) == 0 {
		return "", errors.New("empty command")
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	cmd.WaitDelay = 2 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	var output, stderr bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	if e := cmd.Run(); e != nil {
		action := strings.Join(command[:min(2, len(command))], " ")
		return "", fmt.Errorf("%s failed: %s: %w", action, strings.TrimSpace(stderr.String()+output.String()), e)
	}
	return strings.TrimSpace(output.String()), nil
}

// Guest owns one persistent libguestfs appliance; guest code is never executed.
type Guest struct {
	ctx         context.Context
	PID         int
	Env         []string
	Errors      *os.File
	directories map[string]bool
	exec        Exec
}

func NewGuest(ctx context.Context, image string, readOnly bool, env []string) (*Guest, error) {
	errorsFile, e := os.CreateTemp("", "ts-guestfish-errors-")
	if e != nil {
		return nil, e
	}
	os.Remove(errorsFile.Name())
	g := &Guest{ctx: ctx, Env: env, Errors: errorsFile, directories: map[string]bool{}, exec: Execute}
	if g.Env == nil {
		g.Env = os.Environ()
	}
	args := []string{"--listen"}
	if readOnly {
		args = append(args, "--ro")
	}
	args = append(args, "--format=qcow2", "-a", image, "-i")
	cmd := exec.CommandContext(ctx, "guestfish", args...)
	cmd.Env = g.Env
	cmd.Stderr = errorsFile
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.WaitDelay = 2 * time.Second
	if e = cmd.Run(); e != nil {
		tail := g.ErrorTail()
		g.Errors.Close()
		return nil, fmt.Errorf("guestfish --listen failed: %s %s: %w", tail, strings.TrimSpace(stdout.String()), e)
	}
	match := regexp.MustCompile(`\bGUESTFISH_PID=(\d+)\b`).FindStringSubmatch(stdout.String())
	if match == nil {
		defer errorsFile.Close()
		return nil, fmt.Errorf("guestfish did not return a remote PID: %s; stderr: %s", strings.TrimSpace(stdout.String()), g.ErrorTail())
	}
	g.PID, e = strconv.Atoi(match[1])
	if e != nil {
		errorsFile.Close()
		return nil, e
	}
	g.Env = append(append([]string{}, g.Env...), "GUESTFISH_PID="+match[1])
	return g, nil
}
func (g *Guest) ErrorTail() string {
	s, e := g.Errors.Stat()
	if e != nil {
		return ""
	}
	size := min(s.Size(), int64(16384))
	b := make([]byte, size)
	_, _ = g.Errors.ReadAt(b, max(0, s.Size()-size))
	return strings.TrimSpace(string(b))
}
func (g *Guest) daemonState() string {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", g.PID))
	if e != nil {
		return "exited"
	}
	_, tail, ok := strings.CutLast(string(b), ")")
	if !ok || len(strings.Fields(tail)) == 0 {
		return "exited"
	}
	return strings.Fields(tail)[0]
}
func (g *Guest) Call(command string, args ...string) (string, error) {
	argv := append([]string{"guestfish", "--remote", command}, args...)
	out, e := g.exec(g.ctx, "", g.Env, argv...)
	if e != nil {
		tail := g.ErrorTail()
		if tail == "" {
			tail = "(empty)"
		}
		return "", fmt.Errorf("%w; guestfish listener pid=%d state=%s; listener stderr: %s", e, g.PID, g.daemonState(), tail)
	}
	return out, nil
}
func (g *Guest) Close(ignoreError bool) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(g.ctx), 10*time.Second)
	defer cancel()
	_, e := g.exec(cleanupCtx, "", g.Env, "guestfish", "--remote", "exit")
	closeErr := g.Errors.Close()
	if ignoreError {
		e = nil
	}
	return errors.Join(e, closeErr)
}
func (g *Guest) Kind(path string) (string, error) {
	if g.directories[path] {
		return "dir", nil
	}
	exists, e := g.Call("exists", path)
	if e != nil {
		return "", e
	}
	if exists == "false" {
		link, e := g.Call("is-symlink", path)
		if e != nil {
			return "", e
		}
		switch link {
		case "true":
			return "symlink", nil
		case "false":
			return "", nil
		}
		return "", fmt.Errorf("guestfish returned an invalid is-symlink result for %s: %s", path, link)
	}
	if exists != "true" {
		return "", fmt.Errorf("guestfish returned an invalid exists result for %s: %s", path, exists)
	}
	meta, e := g.Metadata(path)
	if e != nil {
		return "", e
	}
	switch meta["st_mode"] & syscall.S_IFMT {
	case syscall.S_IFLNK:
		return "symlink", nil
	case syscall.S_IFDIR:
		g.directories[path] = true
		return "dir", nil
	case syscall.S_IFREG:
		return "file", nil
	}
	return "other", nil
}
func (g *Guest) Metadata(path string) (map[string]int, error) {
	out, e := g.Call("lstatns", path)
	if e != nil {
		return nil, e
	}
	meta := map[string]int{}
	for line := range strings.SplitSeq(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.HasPrefix(key, "st_") {
			continue
		}
		n, e := strconv.Atoi(strings.TrimSpace(value))
		if e != nil {
			return nil, e
		}
		meta[key] = n
	}
	for _, key := range []string{"st_mode", "st_uid", "st_gid", "st_nlink"} {
		if _, ok := meta[key]; !ok {
			return nil, fmt.Errorf("guestfish omitted %s for %s", key, path)
		}
	}
	return meta, nil
}
func (g *Guest) Read(path, target string) ([]byte, error) {
	if _, e := g.Call("download", path, target); e != nil {
		return nil, e
	}
	return os.ReadFile(target)
}
func (g *Guest) List(path string) ([]string, error) {
	kind, e := g.Kind(path)
	if e != nil {
		return nil, e
	}
	if kind == "" {
		return []string{}, nil
	}
	if kind != "dir" {
		return nil, fmt.Errorf("expected guest directory: %s", path)
	}
	out, e := g.Call("ls", path)
	if e != nil {
		return nil, e
	}
	if out == "" {
		return []string{}, nil
	}
	names := strings.Split(out, "\n")
	for _, name := range names {
		if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
			return nil, fmt.Errorf("unsafe directory entry under %s", path)
		}
	}
	return names, nil
}
func (g *Guest) AssertAbsent(path, label string) error {
	kind, e := g.Kind(path)
	if e != nil {
		return e
	}
	if kind != "" {
		return fmt.Errorf("base image has a conflicting %s: %s", label, path)
	}
	return nil
}
func parents(p string) []string {
	parent := path.Dir(p)
	parts := strings.Split(strings.TrimPrefix(parent, "/"), "/")
	out := []string{"/"}
	current := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		current += "/" + part
		out = append(out, current)
	}
	return out
}
func (g *Guest) AssertDirectParents(p string) error {
	for _, parent := range parents(p) {
		kind, e := g.Kind(parent)
		if e != nil {
			return e
		}
		if kind != "dir" {
			return fmt.Errorf("guest artifact parent is not a direct directory: %s", parent)
		}
	}
	return nil
}
func (g *Guest) Directory(p string, uid, gid, mode int) error {
	for _, parent := range parents(p) {
		kind, e := g.Kind(parent)
		if e != nil {
			return e
		}
		if kind != "" && kind != "dir" {
			return fmt.Errorf("guest directory parent is not a direct directory: %s", parent)
		}
	}
	kind, e := g.Kind(p)
	if e != nil {
		return e
	}
	if kind != "" && kind != "dir" {
		return fmt.Errorf("guest directory is not a direct directory: %s", p)
	}
	if kind == "" {
		if _, e = g.Call("mkdir-p", p); e != nil {
			return e
		}
	}
	if e = g.AssertDirectParents(p); e != nil {
		return e
	}
	if _, e = g.Call("chown", strconv.Itoa(uid), strconv.Itoa(gid), p); e != nil {
		return e
	}
	_, e = g.Call("chmod", fmt.Sprintf("0%o", mode), p)
	return e
}
func (g *Guest) AssertFile(p string, uid, gid, mode int) error {
	kind, e := g.Kind(p)
	if e != nil {
		return e
	}
	if kind != "file" {
		return fmt.Errorf("installed image path is not a regular file: %s", p)
	}
	meta, e := g.Metadata(p)
	if e != nil {
		return e
	}
	if meta["st_uid"] != uid || meta["st_gid"] != gid || meta["st_mode"]&07777 != mode || meta["st_nlink"] != 1 {
		return fmt.Errorf("installed image file has unexpected metadata: %s", p)
	}
	return nil
}
func (g *Guest) AssertBytes(p, source string) error {
	work, e := os.MkdirTemp("", "ts-image-readback-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	readback := filepath.Join(work, "readback")
	if _, e = g.Call("download", p, readback); e != nil {
		return e
	}
	a, e := fileDigest(source)
	if e != nil {
		return e
	}
	b, e := fileDigest(readback)
	if e != nil {
		return e
	}
	if a != b {
		return fmt.Errorf("installed image bytes differ from staged input: %s", p)
	}
	return nil
}
func (g *Guest) Upload(source, p string, mode int) error {
	if e := g.AssertDirectParents(p); e != nil {
		return e
	}
	if e := g.AssertAbsent(p, "image artifact"); e != nil {
		return e
	}
	return g.Replace(source, p, mode)
}
func (g *Guest) Replace(source, p string, mode int) error {
	if _, e := g.Call("upload", source, p); e != nil {
		return e
	}
	if _, e := g.Call("chown", "0", "0", p); e != nil {
		return e
	}
	if _, e := g.Call("chmod", fmt.Sprintf("0%o", mode), p); e != nil {
		return e
	}
	if e := g.AssertFile(p, 0, 0, mode); e != nil {
		return e
	}
	return g.AssertBytes(p, source)
}
func fileDigest(p string) (string, error) { return fileHash(p) }
func copyFile(src, dst string, mode os.FileMode) error {
	source, e := os.Open(src)
	if e != nil {
		return e
	}
	defer source.Close()
	output, e := os.OpenFile(dst, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, mode)
	if e != nil {
		return e
	}
	_, e = io.Copy(output, source)
	return errors.Join(e, output.Close(), os.Chmod(dst, mode))
}
