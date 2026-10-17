//go:build linux && amd64

// This test-only tool stages and owns one offline Source renewal VM.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/qualification/firecracker"
	"github.com/TerraScale/ts-orchestrator/tests/source_renewal_vm/protocol"
)

type input struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type file struct {
	input
	Guest string `json:"guest"`
	Mode  uint32 `json:"mode"`
}

type link struct {
	Guest, Target string
}

type manifest struct {
	Kernel, QEMU, Env, Nice, TestBinary, GuestInit input
	Files                                          []file
	Links                                          []link
	Modules                                        []file
	SudoPluginDirectory, PAMDirectory              string
}

type staged struct {
	ID        string
	Manifest  manifest
	Kernel    input
	Initramfs input
}

func main() {
	var err error
	switch {
	case len(os.Args) == 4 && os.Args[1] == "stage":
		err = stage(os.Args[2], os.Args[3])
	case len(os.Args) == 3 && os.Args[1] == "run":
		err = run(context.Background(), os.Args[2])
	default:
		err = errors.New("usage: source-renewal-vm stage MANIFEST NEW_DIRECTORY | run STAGED_DIRECTORY")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func digest(wire []byte) string {
	h := sha256.Sum256(wire)
	return hex.EncodeToString(h[:])
}

func read(in input) ([]byte, error) {
	if !filepath.IsAbs(in.Path) || in.Path != filepath.Clean(in.Path) || len(in.SHA256) != 64 {
		return nil, errors.New("input requires absolute path and SHA256")
	}
	info, err := os.Stat(in.Path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("input is not a regular file: %s", in.Path)
	}
	wire, err := os.ReadFile(in.Path)
	if err != nil {
		return nil, err
	}
	if digest(wire) != in.SHA256 {
		return nil, fmt.Errorf("input changed: %s", in.Path)
	}
	return wire, nil
}

func writeJSON(name string, value any) error {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return err
	}
	return os.WriteFile(name, append(wire, '\n'), 0o600)
}

func stage(manifestPath, directory string) (result error) {
	wire, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m manifest
	if err := json.Unmarshal(wire, &m, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if filepath.Base(m.Env.Path) != "env" || filepath.Base(m.Nice.Path) != "nice" {
		return errors.New("preserve named env/nice paths for multicall argv0 dispatch")
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return err
	}
	s := staged{ID: digest(wire), Manifest: m}
	for _, in := range []input{m.QEMU, m.Env, m.Nice} {
		if _, err := read(in); err != nil {
			return err
		}
	}
	kernel, err := read(m.Kernel)
	if err != nil {
		return err
	}
	s.Kernel = input{Path: filepath.Join(directory, "bzImage"), SHA256: digest(kernel)}
	if err := os.WriteFile(s.Kernel.Path, kernel, 0o600); err != nil {
		return err
	}
	archive, err := os.OpenFile(filepath.Join(directory, "guest.cpio.gz"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, archive.Close()) }()
	compressed := gzip.NewWriter(archive)
	defer func() {
		if compressed != nil {
			result = errors.Join(result, compressed.Close())
		}
	}()
	c := newc{out: compressed, paths: map[string]bool{}}
	var directoryEntry func(string) error
	directoryEntry = func(name string) error {
		if name == "/" || c.paths[strings.TrimPrefix(name, "/")] {
			return nil
		}
		if err := directoryEntry(path.Dir(name)); err != nil {
			return err
		}
		return c.entry(name, 0o040755, nil, 0, 0)
	}
	add := func(name string, mode uint32, data []byte) error {
		if name != path.Clean(name) || !path.IsAbs(name) {
			return fmt.Errorf("unclean guest path %q", name)
		}
		if err := directoryEntry(path.Dir(name)); err != nil {
			return err
		}
		return c.entry(name, mode, data, 0, 0)
	}
	for _, f := range append(append(slices.Clone(m.Files), m.Modules...), file{input: m.TestBinary, Guest: "/qa/app.test", Mode: 0o755}, file{input: m.GuestInit, Guest: "/init", Mode: 0o755}) {
		if f.Guest != "/qa/app.test" && f.Guest != "/init" {
			canonical, err := filepath.EvalSymlinks(f.Path)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(canonical, "/nix/store/") {
				return errors.New("guest runtime closure must contain only explicit Nix-store files")
			}
		}
		if f.Mode > 0o777 {
			return errors.New("guest file permissions must exclude setuid and special bits")
		}
		data, err := read(f.input)
		if err != nil {
			return err
		}
		if err := add(f.Guest, 0o100000|f.Mode, data); err != nil {
			return err
		}
	}
	for _, l := range m.Links {
		if err := add(l.Guest, 0o120777, []byte(l.Target)); err != nil {
			return err
		}
	}
	for _, name := range []string{"/bin/env", "/bin/nice", "/bin/unshare", "/bin/sudo", "/bin/ip", "/bin/containerd", "/bin/containerd-shim-runc-v2", "/bin/runc", "/bin/losetup", "/bin/blkid", "/usr/sbin/mkfs.ext4", "/sbin/kmod", m.SudoPluginDirectory + "/sudoers.so", m.PAMDirectory + "/pam_rootok.so", m.PAMDirectory + "/pam_permit.so"} {
		if !c.paths[strings.TrimPrefix(name, "/")] {
			return fmt.Errorf("missing explicit guest runtime input %s", name)
		}
	}
	for _, name := range []string{m.SudoPluginDirectory, m.PAMDirectory} {
		if !strings.HasPrefix(name, "/nix/store/") || name != path.Clean(name) || strings.ContainsAny(name, "\r\n\x00") {
			return errors.New("sudo/PAM paths require explicit guest Nix closure")
		}
	}
	config := protocol.Guest{ID: s.ID}
	for _, module := range m.Modules {
		if !strings.HasPrefix(module.Guest, "/modules/") {
			return errors.New("module load order must name explicit /modules files")
		}
		config.Modules = append(config.Modules, module.Guest)
	}
	guest, err := json.Marshal(config)
	if err != nil {
		return err
	}
	configs := map[string]string{
		"/qa/guest.json":     string(guest),
		"/etc/passwd":        "root:x:0:0:root:/root:/bin/false\nmember:x:65532:65532:member:/:/bin/false\n",
		"/etc/group":         "root:x:0:\nmember:x:65532:\n",
		"/etc/nsswitch.conf": "passwd: files\ngroup: files\nhosts: files\n",
		"/etc/hosts":         "127.0.0.1 localhost\n",
		"/etc/sudoers":       "Defaults secure_path=\"/bin:/sbin:/usr/sbin\"\nroot ALL=(ALL:ALL) NOPASSWD: ALL\n",
		"/etc/sudo.conf":     "Plugin sudoers_policy " + m.SudoPluginDirectory + "/sudoers.so\nPlugin sudoers_io " + m.SudoPluginDirectory + "/sudoers.so\n",
		"/etc/pam.d/sudo":    "auth required " + m.PAMDirectory + "/pam_rootok.so\naccount required " + m.PAMDirectory + "/pam_permit.so\nsession required " + m.PAMDirectory + "/pam_permit.so\n",
	}
	for _, name := range slices.Sorted(maps.Keys(configs)) {
		if err := add(name, 0o100644, []byte(configs[name])); err != nil {
			return err
		}
	}
	if err := directoryEntry("/dev"); err != nil {
		return err
	}
	if err := c.entry("/dev/console", 0o020600, nil, 5, 1); err != nil {
		return err
	}
	if err := c.entry("TRAILER!!!", 0, nil, 0, 0); err != nil {
		return err
	}
	if err := compressed.Close(); err != nil {
		return err
	}
	compressed = nil
	if err := archive.Sync(); err != nil {
		return err
	}
	archiveSHA, err := firecracker.Digest(archive.Name())
	if err != nil {
		return err
	}
	s.Initramfs = input{Path: archive.Name(), SHA256: archiveSHA}
	return writeJSON(filepath.Join(directory, "staged.json"), s)
}

type cappedLog struct {
	mu        sync.Mutex
	file      *os.File
	bytes     int64
	exhausted bool
}

func (l *cappedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bytes+int64(len(p)) > 64<<20 {
		l.exhausted = true
		return 0, errors.New("VM serial output exceeds 64 MiB")
	}
	n, err := l.file.Write(p)
	l.bytes += int64(n)
	return n, err
}

func (l *cappedLog) Close() error { return l.file.Close() }

func (l *cappedLog) status() (int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bytes, l.exhausted
}

func qemuArgv(s staged, directory string) []string {
	return []string{s.Manifest.Nice.Path, "-n", "19", s.Manifest.Env.Path, "-i", "HOME=" + directory, "LANG=C.UTF-8", "PATH=/nonexistent", s.Manifest.QEMU.Path,
		"-no-user-config", "-nodefaults", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "8192",
		"-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none", "-no-reboot",
		"-kernel", s.Kernel.Path, "-initrd", s.Initramfs.Path, "-append", "console=ttyS0 panic=1 rdinit=/init cgroup_no_v1=all"}
}

type guestEvidence struct {
	ready, results, successes, testPasses int
}

func (e guestEvidence) complete() bool {
	return e.ready == 1 && e.results == 1 && e.successes == 1 && e.testPasses == 1
}

func scanGuestEvidence(scanner *bufio.Scanner, id string) (guestEvidence, error) {
	var evidence guestEvidence
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == protocol.ReadyPrefix+id {
			evidence.ready++
		}
		if strings.HasPrefix(line, protocol.ResultPrefix+id+":") {
			evidence.results++
		}
		if line == protocol.ResultPrefix+id+":0" {
			evidence.successes++
		}
		if strings.HasPrefix(line, "--- PASS: "+protocol.TestName+" (") {
			evidence.testPasses++
		}
	}
	return evidence, scanner.Err()
}

func run(ctx context.Context, directory string) error {
	wire, err := os.ReadFile(filepath.Join(directory, "staged.json"))
	if err != nil {
		return err
	}
	var s staged
	if err := json.Unmarshal(wire, &s, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	for _, in := range []input{s.Kernel, s.Initramfs, s.Manifest.QEMU, s.Manifest.Env, s.Manifest.Nice} {
		if _, err := read(in); err != nil {
			return err
		}
	}
	log, err := os.OpenFile(filepath.Join(directory, "serial.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	output := &cappedLog{file: log}
	argv := qemuArgv(s, directory)
	process, err := firecracker.Start(argv, directory, output)
	if err != nil {
		return errors.Join(err, output.Close())
	}
	process.Output = output
	started := firecracker.Object{"pid": process.PID(), "argv": argv, "guest_id": s.ID, "timeout_seconds": 240}
	err = writeJSON(filepath.Join(directory, "started.json"), started)
	deadline, cancel := context.WithTimeout(ctx, 240*time.Second)
	defer cancel()
	for err == nil {
		if _, exhausted := output.status(); exhausted {
			err = errors.New("VM serial output exceeds 64 MiB")
			break
		}
		var exited bool
		exited, err = process.Exited()
		if err != nil || exited {
			break
		}
		select {
		case <-deadline.Done():
			err = deadline.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	err = errors.Join(err, process.Stop(5*time.Second, true))
	if !process.Reaped {
		err = errors.Join(err, writeJSON(filepath.Join(directory, "receipt.json"), firecracker.Object{"pass": false, "pid": process.PID(), "reaped": false, "error": fmt.Sprint(err), "guest_id": s.ID, "cleanup": "PENDING; retain owned process and all artifacts"}))
		return &firecracker.PendingCommandError{Process: process, Err: err}
	}
	var evidence guestEvidence
	serial, serialErr := os.Open(filepath.Join(directory, "serial.log"))
	if serialErr == nil {
		evidence, serialErr = scanGuestEvidence(bufio.NewScanner(serial), s.ID)
		serialErr = errors.Join(serialErr, serial.Close())
	}
	post := error(nil)
	for _, in := range []input{s.Kernel, s.Initramfs, s.Manifest.QEMU, s.Manifest.Env, s.Manifest.Nice} {
		_, check := read(in)
		post = errors.Join(post, check)
	}
	bytes, exhausted := output.status()
	pass := err == nil && serialErr == nil && post == nil && !exhausted && process.ExitCode == 0 && evidence.complete()
	receipt := firecracker.Object{"pass": pass, "pid": process.PID(), "reaped": process.Reaped, "qemu_exit": process.ExitCode, "error": fmt.Sprint(errors.Join(err, serialErr, post)), "serial_bytes": bytes, "serial_cap_exhausted": exhausted, "ready_markers": evidence.ready, "result_markers": evidence.results, "success_markers": evidence.successes, "test_pass_markers": evidence.testPasses, "guest_id": s.ID, "host_loops_mounts_network_cgroups": "none"}
	if e := writeJSON(filepath.Join(directory, "receipt.json"), receipt); e != nil {
		return errors.Join(err, e)
	}
	if !pass {
		return fmt.Errorf("VM qualification failed: %v", receipt)
	}
	return nil
}
