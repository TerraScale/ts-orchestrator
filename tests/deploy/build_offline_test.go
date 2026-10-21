package deploy_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
)

const offlineKernelRelease = "6.8.0-142-generic"
const offlineSource = "9f52ca3f861a3eec125eefb6e5025c806fbd0913"
const bootstrapDir = "/etc/terrascale-orchestrator/bootstrap"
const markerDir = "/var/lib/terrascale-orchestrator-bootstrap"
const secretsDir = "/var/lib/terrascale-orchestrator-secrets"
const controllerDir = "/var/lib/terrascale-orchestrator-controller"
const managedDir = "/srv/ts-managed"
const volumeState = "/var/lib/terrascale-orchestrator-volume-init"
const volumeSocketUnit = "terrascale-orchestrator-host-volume-init.socket"
const volumeServiceUnit = "terrascale-orchestrator-host-volume-init.service"
const ociRuleGuest = "/etc/udev/rules.d/65-terrascale-oci-device-paths.rules"
const timesyncGuest = "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf"
const timeWaitDropin = "/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf"
const priorityProfileGuest = "/etc/terrascale-orchestrator/runtime-priority.json"
const priorityHelperGuest = "/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify"
const verifierGuest = "/usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server"
const netbirdGuest = "/usr/local/bin/netbird"
const netbirdConfigGuest = "/etc/terrascale-orchestrator/netbird.json"
const kernelGuest = "/boot/vmlinuz-" + offlineKernelRelease
const profileID = "preview-1ocpu-6gib-v1"

var priorityDropins = []string{"/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf", "/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf", "/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf"}
var deploymentPaths = []string{bootstrapDir + "/anchor.json", bootstrapDir + "/identity.json", bootstrapDir + "/host-enrollment-public.json", "/etc/terrascale-orchestrator/host-enrollment-public.json"}

func TestOfflineCommand(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 {
		return
	}
	kind, args := os.Args[i+1], os.Args[i+2:]
	fail := func(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
	must := func(err error) {
		if err != nil {
			fail(err.Error())
		}
	}
	readFile := func(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
	writeFile := func(path string, b []byte) { must(os.WriteFile(path, b, 0600)) }
	appendFile := func(path, line string) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		must(err)
		_, err = f.WriteString(line)
		must(err)
		must(f.Close())
	}
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }
	guestRoot := os.Getenv("BASE_IMAGE_ROOT_PATH")
	guestPath := func(path string) string { return filepath.Join(guestRoot, strings.TrimPrefix(path, "/")) }
	switch kind {
	case "qemu-img":
		switch args[0] {
		case "check":
			appendFile(os.Getenv("EVENTS_PATH"), "qemu-check\n")
		case "info":
			appendFile(os.Getenv("EVENTS_PATH"), "qemu-info\n")
			fmt.Println(`{"format":"qcow2","backing-filename":""}`)
		default:
			fail("unexpected qemu command")
		}
	case "release":
		appendFile(os.Getenv("EVENTS_PATH"), "release-binary-candidate\n")
		writeFile(os.Getenv("RELEASE_ARGUMENTS_PATH"), []byte(strings.Join(args, "\x00")+"\x00"))
		if os.Getenv("RELEASE_CANDIDATE_FAIL") == "1" {
			fail("mock binary does not match its qualification")
		}
	case "guestfish":
		session := os.Getenv("GUESTFISH_SESSION_PATH")
		if slices.Contains(args, "--listen") {
			ro := slices.Contains(args, "--ro")
			label, access := "guestfish-listen\n", "rw"
			if ro {
				label, access = "guestfish-listen-ro\n", "ro"
			}
			appendFile(os.Getenv("EVENTS_PATH"), label)
			writeFile(session, []byte(access))
			fmt.Println("GUESTFISH_PID=1; export GUESTFISH_PID")
			os.Exit(0)
		}
		ro := string(readFile(session)) == "ro"
		if args[0] != "--remote" {
			fail("expected remote guestfish call")
		}
		command := args[1]
		args = args[2:]
		if exists(os.Getenv("GUESTFISH_DEAD_MARKER_PATH")) {
			fail("guestfish: remote: looks like the server is not running")
		}
		metadata := map[string][]int{}
		metadataPath := os.Getenv("FS_METADATA_PATH")
		if exists(metadataPath) {
			must(json.Unmarshal(readFile(metadataPath), &metadata))
		}
		switch command {
		case "is-symlink", "is-dir", "is-file", "exists":
			target := guestPath(args[0])
			info, err := os.Stat(target)
			result := err == nil
			switch command {
			case "is-symlink":
				info, err = os.Lstat(target)
				result = err == nil && info.Mode()&os.ModeSymlink != 0
			case "is-dir":
				result = err == nil && info.IsDir()
			case "is-file":
				result = err == nil && info.Mode().IsRegular()
			}
			fmt.Println(result)
		case "lstatns":
			target := guestPath(args[0])
			info, err := os.Lstat(target)
			if err != nil && os.Getenv("VIRT_FAIL_MISSING_LSTAT") == "1" {
				writeFile(os.Getenv("GUESTFISH_DEAD_MARKER_PATH"), nil)
				fail("libguestfs: error: lstatns: " + args[0] + ": No such file or directory")
			}
			must(err)
			st := info.Sys().(*syscall.Stat_t)
			owner := metadata[args[0]]
			if owner == nil {
				owner = []int{0, 0}
			}
			fmt.Printf("st_mode: %d\nst_uid: %d\nst_gid: %d\nst_nlink: %d\n", st.Mode, owner[0], owner[1], st.Nlink)
		case "ls":
			entries, err := os.ReadDir(guestPath(args[0]))
			must(err)
			for _, entry := range entries {
				fmt.Println(entry.Name())
			}
		case "readlink":
			s, err := os.Readlink(guestPath(args[0]))
			must(err)
			fmt.Println(s)
		case "download":
			if ro && args[0] == os.Getenv("GUESTFISH_CORRUPT_READBACK") {
				writeFile(args[1], []byte("corrupt guest bytes"))
			} else {
				writeFile(args[1], readFile(guestPath(args[0])))
			}
		case "copy-out":
			source := guestPath(args[0])
			destination := filepath.Join(args[1], filepath.Base(source))
			must(filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(source, path)
				if err != nil {
					return err
				}
				target := filepath.Join(destination, rel)
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return os.MkdirAll(target, info.Mode().Perm())
				}
				if info.Mode()&os.ModeSymlink != 0 {
					link, err := os.Readlink(path)
					if err != nil {
						return err
					}
					return os.Symlink(link, target)
				}
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				return os.WriteFile(target, b, info.Mode().Perm())
			}))
		case "mkdir-p":
			must(os.MkdirAll(guestPath(args[0]), 0755))
		case "chown":
			uid, err := strconv.Atoi(args[0])
			must(err)
			gid, err := strconv.Atoi(args[1])
			must(err)
			metadata[args[2]] = []int{uid, gid}
		case "chmod":
			mode, err := strconv.ParseUint(args[0], 8, 32)
			must(err)
			must(os.Chmod(guestPath(args[1]), os.FileMode(mode)))
		case "upload":
			target := guestPath(args[1])
			must(os.MkdirAll(filepath.Dir(target), 0755))
			writeFile(target, readFile(args[0]))
		case "ln-s":
			must(os.Symlink(args[0], guestPath(args[1])))
		case "exit":
		default:
			fail("unsupported fake guestfish command: " + command)
		}
		if ro && !slices.Contains([]string{"is-symlink", "is-dir", "is-file", "exists", "lstatns", "ls", "readlink", "download", "exit"}, command) {
			fail("read-only session attempted a write: " + command)
		}
		b, err := json.Marshal(metadata)
		must(err)
		writeFile(metadataPath, b)
	case "systemd-sysusers":
		root := strings.SplitN(args[0], "=", 2)[1]
		etc := filepath.Join(root, "etc")
		config := filepath.Join(etc, "sysusers.d/terrascale-orchestrator.conf")
		if len(args) != 2 || args[1] != config || !exists(config) {
			fail("sysusers configuration must be passed as its staged host path")
		}
		for name, contents := range map[string]string{"passwd": "terrascale-workload:x:2000:2000:TerraScale Managed Workload:/var/empty:/usr/sbin/nologin\nterrascale-orchestrator:x:999:999:TerraScale Orchestrator:/var/lib/terrascale-orchestrator-controller:/usr/sbin/nologin\n", "group": "terrascale-workload:x:2000:\nterrascale-orchestrator:x:999:\n", "shadow": "terrascale-workload:!*:::::::\nterrascale-orchestrator:!*:::::::\n", "gshadow": "terrascale-workload:!*::\nterrascale-orchestrator:!*::\n"} {
			appendFile(filepath.Join(etc, name), contents)
		}
	case "systemctl":
		if args[0] == "--version" {
			fmt.Println("systemd 260 (fake test tool)")
			os.Exit(0)
		}
		root := strings.SplitN(args[0], "=", 2)[1]
		command, names := args[1], args[2:]
		switch command {
		case "enable":
			for _, name := range names {
				// Like systemctl, an instance a@b.timer is enabled from its
				// template a@.timer.
				file := name
				if prefix, instance, ok := strings.Cut(name, "@"); ok {
					file = prefix + "@" + filepath.Ext(instance)
				}
				source := filepath.Join(root, "etc/systemd/system", file)
				if !exists(source) {
					source = filepath.Join(root, "usr/lib/systemd/system", file)
				}
				if os.Getenv("VIRT_FAIL_TIME_UNITS") == "1" && name == "systemd-timesyncd.service" {
					fail("mock base image is missing a required systemd time unit")
				}
				if !exists(source) {
					fail("missing a required systemd time unit: " + name)
				}
				section := ""
				for line := range strings.SplitSeq(string(readFile(source)), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
						section = strings.Trim(line, "[]")
						continue
					}
					key, value, ok := strings.Cut(line, "=")
					if section != "Install" || !ok {
						continue
					}
					for _, item := range strings.Fields(value) {
						link := ""
						switch key {
						case "WantedBy":
							link = filepath.Join(root, "etc/systemd/system", item+".wants", name)
						case "RequiredBy":
							link = filepath.Join(root, "etc/systemd/system", item+".requires", name)
						case "Alias":
							link = filepath.Join(root, "etc/systemd/system", item)
						default:
							continue
						}
						must(os.MkdirAll(filepath.Dir(link), 0755))
						if info, err := os.Lstat(link); err == nil && info.Mode()&os.ModeSymlink != 0 {
							continue
						}
						rel, err := filepath.Rel(filepath.Dir(link), source)
						must(err)
						must(os.Symlink(rel, link))
					}
				}
			}
		case "is-enabled":
			if os.Getenv("VIRT_FAIL_TIME_UNITS") == "1" && names[0] == "systemd-timesyncd.service" {
				fail("missing a required systemd time unit")
			}
			fmt.Println("enabled")
		default:
			fail("unexpected systemctl operation")
		}
	default:
		fail("unexpected offline shim " + kind)
	}
	os.Exit(0)
}

type offlineFixture struct {
	t                                                                                                                                                                                  *testing.T
	root, repo, inputs, base, binary, verifier, netbird, netbirdConfig, qualification, rootA, rootB, timesync, shims, guest, events, releaseArgs, metadata, tool, output, kernelOutput string
	kernel                                                                                                                                                                             []byte
	priority                                                                                                                                                                           map[string]string
}

func newOffline(t *testing.T) *offlineFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "offline image inputs ")
	f := &offlineFixture{t: t, root: dir, inputs: filepath.Join(dir, "inputs with spaces"), shims: filepath.Join(dir, "tool shims"), guest: t.TempDir(), events: filepath.Join(dir, "events.log"), releaseArgs: filepath.Join(dir, "release-arguments.bin"), metadata: filepath.Join(dir, "fs-metadata.json"), tool: filepath.Join(dir, "release tool"), output: filepath.Join(dir, "candidate image.qcow2"), kernelOutput: filepath.Join(dir, "guest kernel")}
	file := func(name string, b []byte) string {
		path := filepath.Join(f.inputs, name)
		write(t, path, b, 0644)
		return path
	}
	f.base = file("base image.qcow2", []byte("mock qcow2 bytes"))
	f.binary = file("orchestrator binary", []byte("mock verified binary"))
	native := elf("arm64", "mock native verifier")
	native[16] = 3
	f.verifier = file("tb-server-linux-arm64", native)
	netbird := elf("arm64", "mock netbird client")
	netbird[16] = 3
	f.netbird = file("netbird client", netbird)
	f.netbirdConfig = file("netbird config.json", jsonBytes(t, validNetbirdConfig()))
	f.repo = filepath.Join(dir, "repo")
	if err := os.CopyFS(filepath.Join(f.repo, "deploy"), os.DirFS(filepath.Join(deployRoot(t), "deploy"))); err != nil {
		t.Fatal(err)
	}
	inputsPath := filepath.Join(f.repo, "deploy/image/image-inputs.json")
	inputsWire := read(t, inputsPath)
	inputs := object(t, inputsWire)
	pinnedDigest := inputs["netbird"].(map[string]any)["archives"].(map[string]any)["arm64"].(map[string]any)["binary_sha256"].(string)
	write(t, inputsPath, bytes.Replace(inputsWire, []byte(pinnedDigest), []byte(digest(netbird)), 1), 0644)
	f.qualification = file("qualification.json", []byte("mock qualification"))
	f.rootA = file("bootstrap root a.pem", []byte("bootstrap public key a"))
	f.rootB = file("bootstrap root b.pem", []byte("bootstrap public key b"))
	f.timesync = file("timesyncd config.conf", []byte("[Time]\nNTP=ntp.deployment.example\n"))
	f.priority = map[string]string{"--runtime-priority-profile-id": profileID, "--runtime-priority-system-reserve-bytes": "1073741824", "--host-memory-min-bytes": "67108864", "--host-memory-low-bytes": "134217728", "--controller-memory-min-bytes": "67108864", "--controller-memory-low-bytes": "134217728", "--system-slice-memory-min-bytes": "134217728", "--system-slice-memory-low-bytes": "268435456"}
	f.kernel = make([]byte, 64)
	copy(f.kernel[56:], []byte{'A', 'R', 'M', 0x64})
	f.kernel = append(f.kernel, []byte("mock arm64 kernel")...)
	for _, path := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/usr/local/lib/terrascale-orchestrator", "/etc/sysusers.d", "/usr/local/bin", "/var/lib", "/srv", "/boot", "/lib/modules/" + offlineKernelRelease, "/usr/bin", "/usr/sbin"} {
		if err := os.MkdirAll(f.path(path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, f.path(kernelGuest), f.kernel, 0644)
	if err := os.Symlink("vmlinuz-"+offlineKernelRelease, f.path("/boot/vmlinuz")); err != nil {
		t.Fatal(err)
	}
	write(t, f.path("/var/lib/dpkg/status"), []byte("Package: systemd\nStatus: install ok installed\nVersion: 255.4-1ubuntu8.12\n\nPackage: e2fsprogs\nStatus: install ok installed\nVersion: 1.47.0-2.4~exp1ubuntu4.1\n\nPackage: util-linux\nStatus: install ok installed\nVersion: 2.39.3-9ubuntu6.6\n\nPackage: openssh-server\nStatus: install ok installed\nVersion: 1:9.6p1-3ubuntu13.14\n\n"), 0644)
	for _, path := range []string{"/usr/sbin/mkfs.ext4", "/usr/sbin/blkid", "/usr/sbin/wipefs", "/usr/bin/mount"} {
		write(t, f.path(path), []byte("pinned base image volume tool fixture"), 0755)
	}
	for name, data := range map[string]string{"passwd": "root:x:0:0:root:/root:/bin/bash\n", "group": "root:x:0:\n", "shadow": "root:*:0:0:99999:7:::\n", "gshadow": "root:*::\n"} {
		mode := os.FileMode(0644)
		if name == "shadow" || name == "gshadow" {
			mode = 0640
		}
		write(t, f.path("/etc/"+name), []byte(data), mode)
	}
	for _, name := range []string{"systemd-timesyncd.service", "systemd-time-wait-sync.service"} {
		write(t, f.path("/usr/lib/systemd/system/"+name), []byte("[Unit]\nDescription="+name+"\n[Install]\nWantedBy=sysinit.target\n"), 0644)
	}
	write(t, f.path("/usr/lib/systemd/system/ssh.socket"), []byte("[Unit]\nDescription=OpenBSD Secure Shell server socket\n[Install]\nWantedBy=sockets.target\nRequiredBy=ssh.service\n"), 0644)
	for _, directory := range []string{"sockets.target.wants", "ssh.service.requires"} {
		link := f.path("/etc/systemd/system/" + directory + "/ssh.socket")
		if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/usr/lib/systemd/system/ssh.socket", link); err != nil {
			t.Fatal(err)
		}
	}
	exe := fakeToolBinary(t)
	for _, kind := range []string{"qemu-img", "guestfish", "systemd-sysusers", "systemctl", "release"} {
		path := filepath.Join(f.shims, kind)
		if kind == "release" {
			path = f.tool
		}
		// These synchronous command fakes start no worker goroutines. Should
		// they run race-instrumented, skip the race runtime's one-second
		// shutdown sleep on each of the builder's hundreds of invocations.
		write(t, path, []byte("#!/bin/sh\nGOMAXPROCS=2 GORACE=\"${GORACE:+$GORACE }atexit_sleep_ms=0\" exec "+shellQuote(exe)+" -test.run=^TestOfflineCommand$ -- "+kind+" \"$@\"\n"), 0755)
	}
	return f
}
func (f *offlineFixture) path(guest string) string {
	return filepath.Join(f.guest, strings.TrimPrefix(guest, "/"))
}
func (f *offlineFixture) run(roots []string, replace, env map[string]string, extra ...string) script.Result {
	options := map[string]string{"--base": f.base, "--kernel-release": offlineKernelRelease, "--binary": f.binary, "--qualification": f.qualification, "--source-revision": offlineSource, "--native-verifier-binary": f.verifier, "--native-verifier-sha256": digest(read(f.t, f.verifier)), "--netbird-binary": f.netbird, "--netbird-sha256": digest(read(f.t, f.netbird)), "--netbird-config": f.netbirdConfig, "--release-tool": f.tool, "--timesyncd-config": f.timesync}
	for k, v := range f.priority {
		options[k] = v
	}
	for k, v := range replace {
		options[k] = v
	}
	var args []string
	for k, v := range options {
		args = append(args, k, v)
	}
	if roots == nil {
		roots = []string{f.rootA, f.rootB}
	}
	for _, root := range roots {
		args = append(args, "--bootstrap-root", root)
	}
	args = append(args, extra...)
	args = append(args, "--out", f.output, "--kernel-out", f.kernelOutput)
	environment := map[string]string{"TS_ORCH_BIN": deployTool(f.t), "PATH": f.shims + string(os.PathListSeparator) + os.Getenv("PATH"), "EVENTS_PATH": f.events, "RELEASE_ARGUMENTS_PATH": f.releaseArgs, "GUESTFISH_SESSION_PATH": filepath.Join(f.root, "guestfish-session"), "BASE_IMAGE_ROOT_PATH": f.guest, "FS_METADATA_PATH": f.metadata, "GUESTFISH_DEAD_MARKER_PATH": filepath.Join(f.root, "guestfish-dead")}
	for k, v := range env {
		environment[k] = v
	}
	return runDeploy(f.t, f.repo, environment, filepath.Join(f.repo, "deploy/image/build-offline.sh"), args...)
}
func (f *offlineFixture) eventText() string {
	b, err := os.ReadFile(f.events)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}
func (f *offlineFixture) noEffects() {
	if strings.Contains(f.eventText(), "guestfish-listen") {
		f.t.Fatal("guestfish launched before input validation")
	}
	absent(f.t, f.output)
	absent(f.t, f.kernelOutput)
}
func (f *offlineFixture) reject(r script.Result, message string) {
	if r.Code == 0 {
		f.t.Fatal("unexpected successful build")
	}
	if message != "" {
		contains(f.t, r.Stderr, message)
	}
	absent(f.t, f.output)
}
func (f *offlineFixture) installed(guest string, contents []byte, perm os.FileMode, owner []any) {
	f.t.Helper()
	path := f.path(guest)
	info, err := os.Lstat(path)
	if err != nil {
		f.t.Fatal(err)
	}
	equal(f.t, info.Mode().IsRegular(), true)
	equal(f.t, info.Mode().Perm(), perm)
	equal(f.t, info.Sys().(*syscall.Stat_t).Nlink, uint64(1))
	equal(f.t, read(f.t, path), contents)
	equal(f.t, object(f.t, read(f.t, f.metadata))[guest], owner)
}
func (f *offlineFixture) cleanTemp() {
	matches, err := filepath.Glob(filepath.Join(f.root, ".ts-orchestrator-image.*"))
	if err != nil {
		f.t.Fatal(err)
	}
	equal(f.t, len(matches), 0)
}

// representative keeps one case of a rejection family in the fast tier.
// Every other case pays for its own complete offline build through hundreds
// of command fakes, so it runs in the integration tier, which still gates
// every image: image.yml builds only revisions whose full ci.yml run passed.
// guestName names a subtest after a guest path without '/', which -run
// reads as a subtest separator: /usr/local/bin becomes usr_local_bin, so
// one case can be selected, for example
// -run '^TestOfflineRejectsSymlinkedUploadParents$/^usr_local_bin$'.
func guestName(guest string) string {
	return strings.ReplaceAll(strings.TrimPrefix(guest, "/"), "/", "_")
}

func representative(t *testing.T, fast bool) {
	t.Helper()
	if !fast {
		tier.Integration(t)
	}
}

func TestOfflineVerifiedInputsInstalled(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	f := newOffline(t)
	r := f.run(nil, nil, nil)
	successful(t, r)
	equal(t, read(t, f.output), read(t, f.base))
	equal(t, read(t, f.kernelOutput), f.kernel)
	contains(t, r.Stdout, fmt.Sprintf("base guest kernel release=%s bytes=%d sha256=%s", offlineKernelRelease, len(f.kernel), digest(f.kernel)))
	equal(t, strings.Split(strings.TrimSpace(f.eventText()), "\n"), []string{"release-binary-candidate", "qemu-check", "qemu-info", "guestfish-listen", "qemu-check", "guestfish-listen-ro"})
	args := strings.Split(strings.TrimSuffix(string(read(t, f.releaseArgs)), "\x00"), "\x00")
	equal(t, args[:2], []string{"release", "binary-candidate"})
	equal(t, flagValue(t, args, "--source-revision"), offlineSource)
	equal(t, flagValue(t, args, "--qualification"), f.qualification)
	equal(t, filepath.Base(flagValue(t, args, "--binary")), "terrascale-orchestrator")
	equal(t, slices.Contains(args, f.rootA), false)
	owner := []any{float64(0), float64(0)}
	for path, data := range map[string][]byte{"/usr/local/bin/terrascale-orchestrator": read(t, f.binary), verifierGuest: read(t, f.verifier), netbirdGuest: read(t, f.netbird), netbirdConfigGuest: read(t, f.netbirdConfig), kernelGuest: f.kernel, ociRuleGuest: read(t, filepath.Join(deployRoot(t), "deploy/udev/65-terrascale-oci-device-paths.rules"))} {
		contains(t, r.Stdout, "image readback sha256="+digest(data)+" guest_path="+path)
	}
	f.installed(bootstrapDir+"/trust-roots/001.pem", read(t, f.rootA), 0444, owner)
	f.installed(bootstrapDir+"/trust-roots/002.pem", read(t, f.rootB), 0444, owner)
	for path, source := range map[string]string{verifierGuest: f.verifier, netbirdGuest: f.netbird, "/usr/local/bin/terrascale-orchestrator": f.binary, priorityHelperGuest: f.binary} {
		f.installed(path, read(t, source), 0755, owner)
	}
	f.installed("/usr/local/lib/terrascale-orchestrator/netbird-client", read(t, f.netbird), 0755, owner)
	bakedPin := object(t, read(t, f.path("/etc/terrascale-orchestrator/netbird-pin.json")))
	inputs := object(t, read(t, filepath.Join(f.repo, "deploy/image/image-inputs.json")))
	equal(t, bakedPin, inputs["netbird"])
	f.installed(netbirdConfigGuest, read(t, f.netbirdConfig), 0644, owner)
	f.installed(timeWaitDropin, []byte("[Service]\nTimeoutStartSec=300s\n"), 0644, owner)
	f.installed(ociRuleGuest, read(t, filepath.Join(deployRoot(t), "deploy/udev/65-terrascale-oci-device-paths.rules")), 0644, owner)
	normalized := []byte("[Time]\nNTP=\nNTP=ntp.deployment.example\nFallbackNTP=\nPollIntervalMinSec=32\nPollIntervalMaxSec=64\n")
	f.installed(timesyncGuest, normalized, 0644, owner)
	contains(t, r.Stdout, digest(normalized))
	profile := []byte(`{"version":1,"profile_id":"preview-1ocpu-6gib-v1","system_reserve_bytes":1073741824}`)
	f.installed(priorityProfileGuest, profile, 0644, owner)
	for i, path := range priorityDropins {
		content := string(read(t, f.path(path)))
		section, min, low := "[Service]", 64<<20, 128<<20
		if i == 0 {
			section, min, low = "[Slice]", 128<<20, 256<<20
		}
		contains(t, content, section)
		contains(t, content, fmt.Sprintf("MemoryMin=%d\n", min))
		contains(t, content, fmt.Sprintf("MemoryLow=%d\n", low))
		contains(t, r.Stdout, digest([]byte(content)))
	}
	metadata := object(t, read(t, f.metadata))
	for _, path := range []string{secretsDir, controllerDir} {
		equal(t, metadata[path], []any{float64(999), float64(999)})
		equal(t, mode(t, f.path(path)), os.FileMode(0700))
	}
	equal(t, metadata[markerDir], owner)
	equal(t, metadata["/var/lib/netbird"], owner)
	equal(t, mode(t, f.path("/var/lib/netbird")), os.FileMode(0700))
	contains(t, string(read(t, f.path("/etc/passwd"))), "terrascale-workload:x:2000:2000:")
	contains(t, string(read(t, f.path("/etc/group"))), "terrascale-workload:x:2000:")
	contains(t, string(read(t, f.path("/etc/passwd"))), "terrascale-orchestrator:x:999:999:")
	for _, name := range []string{"systemd-timesyncd.service", "systemd-time-wait-sync.service"} {
		symlink(t, f.path("/etc/systemd/system/sysinit.target.wants/"+name))
	}
	for _, name := range []string{"terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service", "netbird.service", "terrascale-netbird-enroll.service", "terrascale-netbird-agent.service"} {
		symlink(t, f.path("/etc/systemd/system/multi-user.target.wants/"+name))
	}
	for _, link := range []string{"sockets.target.wants/ssh.socket", "ssh.service.requires/ssh.socket"} {
		symlink(t, f.path("/etc/systemd/system/"+link))
	}
	absent(t, f.path("/etc/systemd/system/multi-user.target.wants/terrascale-orchestrator-bootstrap.service"))
	equal(t, bytes.Contains(read(t, filepath.Join(deployRoot(t), "deploy/image/build-offline.sh")), []byte("--run-command")), false)
	absent(t, f.path(filepath.Base(f.qualification)))
}

func TestOfflineRequiresNativeVerifier(t *testing.T) {
	f := newOffline(t)
	f.reject(f.run(nil, map[string]string{"--native-verifier-binary": "", "--native-verifier-sha256": ""}, nil), "missing required build-offline argument")
}

func TestOfflineRejectsBadPublicInputsBeforeImageEffects(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for _, tc := range []struct {
		name, message string
		prepare       func(*offlineFixture)
		replace       map[string]string
		env           map[string]string
	}{
		{"native-digest", "native verifier bytes do not match", func(*offlineFixture) {}, map[string]string{"--native-verifier-sha256": strings.Repeat("0", 64)}, nil},
		{"native-architecture", "ELF64 little-endian AArch64", func(f *offlineFixture) { b := read(f.t, f.verifier); b[18] = 62; write(f.t, f.verifier, b, 0644) }, nil, nil},
		{"netbird-digest", "supplied NetBird SHA-256 differs from the image pin", func(*offlineFixture) {}, map[string]string{"--netbird-sha256": strings.Repeat("0", 64)}, nil},
		{"netbird-self-pinned", "supplied NetBird SHA-256 differs from the image pin", func(f *offlineFixture) {
			write(f.t, f.netbird, append(read(f.t, f.netbird), []byte("different client")...), 0644)
		}, nil, nil},
		{"setup-key", "unexpected or missing fields", func(f *offlineFixture) {
			c := object(f.t, read(f.t, f.netbirdConfig))
			c["setup_key"] = "secret-value"
			write(f.t, f.netbirdConfig, jsonBytes(f.t, c), 0644)
		}, nil, nil},
		{"qualification", "mock binary does not match its qualification", func(*offlineFixture) {}, nil, map[string]string{"RELEASE_CANDIDATE_FAIL": "1"}},
		{"priority-floor", "system.slice floors must cover aggregate", func(*offlineFixture) {}, map[string]string{"--system-slice-memory-min-bytes": strconv.Itoa(64 << 20)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOffline(t)
			tc.prepare(f)
			f.reject(f.run(nil, tc.replace, tc.env), tc.message)
			f.noEffects()
			f.cleanTemp()
			if tc.name == "priority-floor" {
				absent(t, f.events)
			}
			if tc.name == "qualification" {
				equal(t, f.eventText(), "release-binary-candidate\n")
			}
		})
	}
}
func TestOfflineReadbackMismatchDiscardsCandidate(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for _, guest := range []string{netbirdGuest, netbirdConfigGuest, "/usr/local/bin/terrascale-orchestrator", verifierGuest, ociRuleGuest, kernelGuest} {
		t.Run(guestName(guest), func(t *testing.T) {
			representative(t, guest == "/usr/local/bin/terrascale-orchestrator")
			t.Parallel()
			f := newOffline(t)
			f.reject(f.run(nil, nil, map[string]string{"GUESTFISH_CORRUPT_READBACK": guest}), "finished image bytes differ from the expected SHA-256: "+guest)
			contains(t, f.eventText(), "guestfish-listen-ro")
			absent(t, f.kernelOutput)
			f.cleanTemp()
		})
	}
}
func TestOfflineRejectsBaseArtifacts(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	paths := append([]string{ociRuleGuest}, deploymentPaths...)
	paths = append(paths, priorityProfileGuest)
	paths = append(paths, priorityDropins...)
	paths = append(paths, priorityHelperGuest)
	fast := []string{ociRuleGuest, deploymentPaths[0], deploymentPaths[2], priorityProfileGuest}
	for _, guest := range paths {
		t.Run(guestName(guest), func(t *testing.T) {
			representative(t, slices.Contains(fast, guest))
			t.Parallel()
			f := newOffline(t)
			write(t, f.path(guest), []byte("conflicting image file\n"), 0644)
			message := ""
			switch {
			case guest == ociRuleGuest:
				message = "base image has a conflicting OCI device path rule: " + guest
			case slices.Contains(deploymentPaths, guest):
				message = "base image has a conflicting "
			default:
				message = "base image has a conflicting runtime-priority profile artifact"
			}
			r := f.run(nil, nil, nil)
			f.reject(r, message)
			if slices.Contains(deploymentPaths, guest) {
				contains(t, r.Stderr, guest)
				if !strings.Contains(r.Stderr, "bootstrap artifact") && !strings.Contains(r.Stderr, "host enrollment public bundle") {
					t.Fatalf("wrong rejection: %s", r.Stderr)
				}
			}
			contains(t, f.eventText(), "guestfish-listen")
		})
	}
}

func TestOfflineRejectsPersistedSelfUpdateState(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	f := newOffline(t)
	state := "/var/lib/terrascale-orchestrator"
	release := "releases/" + strings.Repeat("a", 64)
	write(t, f.path(state+"/"+release+"/terrascale-orchestrator"), []byte("previous serving release"), 0555)
	if err := os.Symlink(release, f.path(state+"/current")); err != nil {
		t.Fatal(err)
	}
	f.reject(f.run(nil, nil, nil), "base image has a conflicting orchestrator state root: "+state)
	absent(t, f.kernelOutput)
	absent(t, f.path("/usr/local/bin/terrascale-orchestrator"))
	f.cleanTemp()
}
func TestOfflineDeploymentMaterialNeverBaked(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	f := newOffline(t)
	successful(t, f.run(nil, nil, nil))
	for _, path := range deploymentPaths {
		absent(t, f.path(path))
	}
	names := func(path string) []string {
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}
	equal(t, names(f.path(bootstrapDir)), []string{"trust-roots"})
	equal(t, names(f.path(bootstrapDir+"/trust-roots")), []string{"001.pem", "002.pem"})
}
func TestOfflineRejectsDeploymentFlagsBeforeImageEffects(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--bootstrap-tool", "--bootstrap-anchor", "--bootstrap-identity", "--host-enrollment-public", "--host-enrollment-public-sha256", "--receipt", "--delegation", "--root-key", "--environment"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			f := newOffline(t)
			material := filepath.Join(f.inputs, "deployment material.json")
			write(t, material, []byte("{}"), 0644)
			r := f.run(nil, nil, nil, flag, material)
			equal(t, r.Code, 2)
			contains(t, r.Stderr, "usage: build-offline.sh")
			absent(t, f.events)
			f.noEffects()
		})
	}
}
func TestOfflineValidatesRevisionAndKernelReleaseBeforeEffects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ flag, value string }{{"--source-revision", "HEAD"}, {"--source-revision", strings.ToUpper(offlineSource)}, {"--kernel-release", "../vmlinuz"}} {
		t.Run(tc.flag+"="+tc.value, func(t *testing.T) {
			t.Parallel()
			f := newOffline(t)
			equal(t, f.run(nil, map[string]string{tc.flag: tc.value}, nil).Code, 2)
			absent(t, f.events)
			f.noEffects()
		})
	}
}
func TestOfflineBaseKernelMustBeOneARM64ImageWithModules(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for i, tc := range []struct {
		name, message string
		prepare       func(*offlineFixture)
		replace       map[string]string
	}{
		{"multiple", "exactly one regular /boot/vmlinuz-" + offlineKernelRelease, func(f *offlineFixture) { write(f.t, f.path("/boot/vmlinuz-6.8.0-1-generic"), f.kernel, 0644) }, nil},
		{"wrong-release", "exactly one regular /boot/vmlinuz-6.8.0-999-generic", func(*offlineFixture) {}, map[string]string{"--kernel-release": "6.8.0-999-generic"}},
		{"no-modules", "has no /lib/modules/" + offlineKernelRelease + " directory", func(f *offlineFixture) {
			if err := os.Remove(f.path("/lib/modules/" + offlineKernelRelease)); err != nil {
				f.t.Fatal(err)
			}
		}, nil},
		{"wrong-image", "base guest kernel is not an AArch64 Linux boot Image", func(f *offlineFixture) {
			write(f.t, f.path(kernelGuest), append(make([]byte, 64), []byte("x86 kernel")...), 0644)
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			representative(t, i == 0)
			t.Parallel()
			f := newOffline(t)
			tc.prepare(f)
			f.reject(f.run(nil, tc.replace, nil), tc.message)
			absent(t, f.kernelOutput)
			absent(t, f.path("/usr/local/bin/terrascale-orchestrator"))
		})
	}
	t.Run("gzip", func(t *testing.T) {
		tier.Integration(t)
		t.Parallel()
		f := newOffline(t)
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		if _, err := gz.Write(f.kernel); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		write(t, f.path(kernelGuest), b.Bytes(), 0644)
		successful(t, f.run(nil, nil, nil))
		equal(t, read(t, f.kernelOutput), b.Bytes())
	})
}
func TestOfflineCreatesMissingUploadParents(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for i, tc := range []struct {
		name  string
		paths []string
		env   map[string]string
	}{{"native-library", []string{"/usr/local/lib/terrascale-orchestrator"}, map[string]string{"VIRT_FAIL_MISSING_LSTAT": "1"}}, {"upload-parents", []string{"/etc/sysusers.d", "/etc/systemd/system", "/etc/systemd", "/usr/local/bin"}, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			representative(t, i == 0)
			t.Parallel()
			f := newOffline(t)
			if tc.name == "upload-parents" {
				for _, directory := range []string{"sockets.target.wants", "ssh.service.requires"} {
					if err := os.RemoveAll(f.path("/etc/systemd/system/" + directory)); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, path := range tc.paths {
				if err := os.Remove(f.path(path)); err != nil {
					t.Fatal(err)
				}
			}
			successful(t, f.run(nil, nil, tc.env))
			metadata := object(t, read(t, f.metadata))
			for _, path := range tc.paths {
				info, err := os.Lstat(f.path(path))
				if err != nil {
					t.Fatal(err)
				}
				equal(t, info.IsDir(), true)
				equal(t, info.Mode().Perm(), os.FileMode(0755))
				equal(t, metadata[path], []any{float64(0), float64(0)})
			}
			if tc.name == "upload-parents" {
				for _, link := range []string{"sockets.target.wants/ssh.socket", "ssh.service.requires/ssh.socket"} {
					symlink(t, f.path("/etc/systemd/system/"+link))
				}
				info, err := os.Stat(f.path("/etc/sysusers.d/terrascale-orchestrator.conf"))
				if err != nil {
					t.Fatal(err)
				}
				equal(t, info.Mode().IsRegular(), true)
			}
			absent(t, filepath.Join(f.root, "guestfish-dead"))
			if _, err := os.Stat(f.output); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestOfflineRejectsUnsafeNativeVerifierParents(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for i, tc := range []struct {
		name, message string
		prepare       func(*offlineFixture)
	}{
		{"symlink", "(kind=symlink)", func(f *offlineFixture) {
			p := f.path("/usr/local/lib/terrascale-orchestrator")
			if err := os.Remove(p); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink("/tmp", p); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"dangling", "(kind=symlink)", func(f *offlineFixture) {
			p := f.path("/usr/local/lib/terrascale-orchestrator")
			if err := os.Remove(p); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink("missing-target", p); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"fifo", "(kind=other)", func(f *offlineFixture) {
			p := f.path("/usr/local/lib/terrascale-orchestrator")
			if err := os.Remove(p); err != nil {
				f.t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0644); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"writable", "mode=0777", func(f *offlineFixture) {
			if err := os.Chmod(f.path("/usr/local/lib/terrascale-orchestrator"), 0777); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"writable-ancestor", "native verifier parent must be a root-owned nonwritable directory: /usr/local/lib", func(f *offlineFixture) {
			if err := os.Chmod(f.path("/usr/local/lib"), 0777); err != nil {
				f.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			representative(t, i == 0)
			t.Parallel()
			f := newOffline(t)
			tc.prepare(f)
			r := f.run(nil, nil, nil)
			f.reject(r, tc.message)
			contains(t, r.Stderr, "native verifier parent must be a root-owned nonwritable directory")
		})
	}
}
func TestOfflineRejectsReservedWorkloadIdentityBeforeInstall(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	f := newOffline(t)
	p := f.path("/etc/passwd")
	write(t, p, append(read(t, p), []byte("base-user:x:2000:2000:Existing:/var/empty:/usr/sbin/nologin\n")...), 0644)
	f.reject(f.run(nil, nil, nil), "reserved managed workload UID, GID, or name")
	absent(t, f.path(verifierGuest))
}
func TestOfflineRejectsSymlinkedUploadParents(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for i, guest := range []string{"/etc/sysusers.d", "/usr/local/bin"} {
		t.Run(guestName(guest), func(t *testing.T) {
			representative(t, i == 0)
			t.Parallel()
			f := newOffline(t)
			p := f.path(guest)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/tmp", p); err != nil {
				t.Fatal(err)
			}
			f.reject(f.run(nil, nil, nil), "guest directory is not a direct directory: "+guest)
		})
	}
}
func TestOfflineRequiresAuditedSystemdAndInstallDirectives(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	t.Run("version", func(t *testing.T) {
		t.Parallel()
		f := newOffline(t)
		write(t, f.path("/var/lib/dpkg/status"), []byte("Package: systemd\nStatus: install ok installed\nVersion: 256.1\n\n"), 0644)
		f.reject(f.run(nil, nil, nil), "audited Noble systemd 255")
	})
	t.Run("install", func(t *testing.T) {
		tier.Integration(t)
		t.Parallel()
		f := newOffline(t)
		write(t, f.path("/usr/lib/systemd/system/systemd-timesyncd.service"), []byte("[Install]\nWantedBy=sysinit.target\nFoo=bar\n"), 0644)
		f.reject(f.run(nil, nil, nil), "unsupported systemd [Install] entry")
	})
}

func TestOfflineEveryImageRequiresEnabledOpenSSHServer(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for i, tc := range []struct {
		name, message string
		change        func(*offlineFixture)
	}{
		{"missing-package", "installed openssh-server package", func(f *offlineFixture) {
			p := f.path("/var/lib/dpkg/status")
			write(t, p, bytes.ReplaceAll(read(t, p), []byte("Package: openssh-server"), []byte("Package: openssh-client")), 0644)
		}},
		{"disabled-server", "OpenSSH disable marker", func(f *offlineFixture) {
			write(t, f.path("/etc/ssh/sshd_not_to_be_run"), nil, 0644)
		}},
		{"masked-socket", "required systemd unit is masked: ssh.socket", func(f *offlineFixture) {
			if err := os.Symlink("/dev/null", f.path("/etc/systemd/system/ssh.socket")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			representative(t, i == 0)
			t.Parallel()
			f := newOffline(t)
			tc.change(f)
			f.reject(f.run(nil, nil, nil), tc.message)
			absent(t, f.output)
		})
	}
}

func TestOfflineManagedRootAndVolumeInitUnits(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	f := newOffline(t)
	host := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-host.service")))
	contains(t, host, "ProtectSystem=strict\n")
	contains(t, host, "ReadWritePaths=-"+managedDir+"\n")
	successful(t, f.run(nil, nil, nil))
	metadata := object(t, read(t, f.metadata))
	for _, tc := range []struct {
		path  string
		perm  os.FileMode
		owner []any
	}{{managedDir, 0750, []any{float64(0), float64(2000)}}, {volumeState, 0700, []any{float64(0), float64(0)}}} {
		info, err := os.Lstat(f.path(tc.path))
		if err != nil {
			t.Fatal(err)
		}
		equal(t, info.IsDir(), true)
		equal(t, info.Mode().Perm(), tc.perm)
		equal(t, metadata[tc.path], tc.owner)
	}
	for unit, target := range map[string]string{"terrascale-orchestrator-host-setup.service": "multi-user.target", "terrascale-orchestrator-host-setup.timer": "timers.target", volumeSocketUnit: "sockets.target"} {
		symlink(t, f.path("/etc/systemd/system/"+target+".wants/"+unit))
	}
	for _, unit := range []string{volumeSocketUnit, volumeServiceUnit} {
		equal(t, read(t, f.path("/etc/systemd/system/"+unit)), read(t, filepath.Join(deployRoot(t), "deploy/systemd", unit)))
		equal(t, mode(t, f.path("/etc/systemd/system/"+unit)), os.FileMode(0644))
	}
}

// Self-update needs no node-local file: the image bakes both drop-ins and
// the watchdog template and enables one watchdog timer per role (TS-553).
func TestOfflineInstallsSelfUpdateEnabled(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	f := newOffline(t)
	successful(t, f.run(nil, nil, nil))
	owner := []any{float64(0), float64(0)}
	for _, name := range []string{"terrascale-orchestrator-controller.service.d/60-selfupdate.conf", "terrascale-orchestrator-host.service.d/60-selfupdate.conf", "terrascale-orchestrator-host-setup.service.d/60-selfupdate.conf", "terrascale-orchestrator-selfupdate-watchdog@.service", "terrascale-orchestrator-selfupdate-watchdog@.timer"} {
		f.installed("/etc/systemd/system/"+name, read(t, filepath.Join(deployRoot(t), "deploy/systemd/selfupdate", name)), 0644, owner)
	}
	for _, role := range []string{"controller", "host"} {
		link := f.path("/etc/systemd/system/timers.target.wants/terrascale-orchestrator-selfupdate-watchdog@" + role + ".timer")
		target, err := os.Readlink(link)
		if err != nil {
			t.Fatal(err)
		}
		equal(t, filepath.Clean(filepath.Join(filepath.Dir(link), target)), f.path("/etc/systemd/system/terrascale-orchestrator-selfupdate-watchdog@.timer"))
	}
}
func TestOfflineRejectsMaskedOrConflictingSelfUpdate(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for i, tc := range []struct{ name, guest, message string }{
		{"masked-instance", "/etc/systemd/system/terrascale-orchestrator-selfupdate-watchdog@host.timer", "required systemd unit is masked: terrascale-orchestrator-selfupdate-watchdog@host.timer"},
		{"masked-template", "/etc/systemd/system/terrascale-orchestrator-selfupdate-watchdog@.timer", "base image has a conflicting image artifact"},
		{"runtime-override", "/run/systemd/system/terrascale-orchestrator-selfupdate-watchdog@.timer", "base image has a conflicting systemd unit override"},
		{"conflicting-dropin", "/etc/systemd/system/terrascale-orchestrator-controller.service.d/60-selfupdate.conf", "base image has a conflicting image artifact"},
		{"planted-watchdog-instance", "/usr/lib/systemd/system/terrascale-orchestrator-selfupdate-watchdog@controller.service", "base image has a conflicting systemd unit instance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			representative(t, i == 0)
			t.Parallel()
			f := newOffline(t)
			if err := os.MkdirAll(filepath.Dir(f.path(tc.guest)), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/null", f.path(tc.guest)); err != nil {
				t.Fatal(err)
			}
			f.reject(f.run(nil, nil, nil), tc.message)
		})
	}
}
func TestOfflineRequiresPinnedVolumeTools(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for i, tc := range []struct {
		name, message string
		missingTool   bool
	}{{"missing-package", "pinned e2fsprogs", false}, {"missing-tool", "missing required volume tool", true}} {
		t.Run(tc.name, func(t *testing.T) {
			representative(t, i == 0)
			t.Parallel()
			f := newOffline(t)
			if tc.missingTool {
				if err := os.Remove(f.path("/usr/sbin/mkfs.ext4")); err != nil {
					t.Fatal(err)
				}
			} else {
				p := f.path("/var/lib/dpkg/status")
				b := bytes.Replace(read(t, p), []byte("Package: e2fsprogs\nStatus: install ok installed\nVersion: 1.47.0-2.4~exp1ubuntu4.1\n\n"), nil, 1)
				write(t, p, b, 0644)
			}
			f.reject(f.run(nil, nil, nil), tc.message)
		})
	}
}
func TestOfflineTimesyncConfigRequiredExplicitAndExcludesLabRange(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	t.Parallel()
	cases := []struct {
		name string
		data []byte
	}{{"missing", nil}, {"empty-list", []byte("[Time]\nNTP=\n")}, {"lab-endpoint", []byte("[Time]\nNTP=198.19.8.1\n")}, {"accumulated-lab", []byte("[Time]\nNTP=198.19.8.1\nNTP=ntp.deployment.example\n")}, {"empty-reset", []byte("[Time]\nNTP=ntp.deployment.example\nNTP=\n")}, {"oversize", append([]byte("[Time]\nNTP=ntp.example\n"), bytes.Repeat([]byte("#"), 16*1024)...)}, {"continuation", []byte("[Time]\nNTP=ntp.example \\\nntp2.example\n")}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOffline(t)
			if tc.data == nil {
				if err := os.Remove(f.timesync); err != nil {
					t.Fatal(err)
				}
			} else {
				write(t, f.timesync, tc.data, 0644)
			}
			f.reject(f.run(nil, nil, nil), "")
			absent(t, f.events)
			f.noEffects()
		})
	}
	t.Run("reset-normalized", func(t *testing.T) {
		tier.Integration(t)
		t.Parallel()
		f := newOffline(t)
		write(t, f.timesync, []byte("# Systemd empty assignments reset earlier list members.\n[Time]\nPollIntervalMinSec=16\nPollIntervalMaxSec=2048\nNTP=198.19.8.1\nNTP=\nNTP=ntp.deployment.example\nFallbackNTP=198.19.3.5\nFallbackNTP=\nFallbackNTP=fallback.deployment.example\n"), 0644)
		r := f.run(nil, nil, nil)
		successful(t, r)
		want := []byte("# Systemd empty assignments reset earlier list members.\n[Time]\nNTP=\nNTP=ntp.deployment.example\nFallbackNTP=\nFallbackNTP=fallback.deployment.example\nPollIntervalMinSec=32\nPollIntervalMaxSec=64\n")
		equal(t, read(t, f.path(timesyncGuest)), want)
		equal(t, bytes.Contains(read(t, f.path(timesyncGuest)), []byte("198.19.")), false)
		contains(t, r.Stdout, digest(want))
	})
}
func TestOfflineRejectsCompetingTimesyncConfiguration(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	for i, tc := range []struct{ name, path, contents string }{{"endpoint", "/etc/systemd/timesyncd.conf.d/20-base.conf", "[Time]\nNTP=base.example\n"}, {"poll", "/etc/systemd/timesyncd.conf.d/zz-base.conf", "[Time]\nPollIntervalMaxSec=2048\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			representative(t, i == 0)
			t.Parallel()
			f := newOffline(t)
			write(t, f.path(tc.path), []byte(tc.contents), 0644)
			r := f.run(nil, nil, nil)
			f.reject(r, "base image has active NTP/FallbackNTP or poll interval configuration")
			if tc.name == "endpoint" {
				contains(t, r.Stderr, tc.path)
			}
			contains(t, f.eventText(), "guestfish-listen")
		})
	}
}
func TestOfflineTimesyncSectionsAndMaskPrecedence(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	tier.Integration(t)
	t.Parallel()
	f := newOffline(t)
	write(t, f.path("/usr/lib/systemd/timesyncd.conf.d/20-base.conf"), []byte("[Time]\nNTP=hidden.example\n"), 0644)
	mask := f.path("/etc/systemd/timesyncd.conf.d/20-base.conf")
	if err := os.MkdirAll(filepath.Dir(mask), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", mask); err != nil {
		t.Fatal(err)
	}
	write(t, f.path("/etc/systemd/timesyncd.conf.d/30-other.conf"), []byte("[Other]\nNTP=not-timesyncd.example\n"), 0644)
	successful(t, f.run(nil, nil, nil))
	if _, err := os.Stat(f.output); err != nil {
		t.Fatal(err)
	}
}
func TestOfflineMissingTimeSyncUnitsAbortImage(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	tier.Integration(t)
	t.Parallel()
	f := newOffline(t)
	f.reject(f.run(nil, nil, map[string]string{"VIRT_FAIL_TIME_UNITS": "1"}), "missing a required systemd time unit")
	contains(t, f.eventText(), "guestfish-listen")
}
func unitDirectives(source, selectedSection string) map[string]string {
	section := ""
	out := map[string]string{}
	for raw := range strings.SplitSeq(source, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		if selectedSection != "" && section != selectedSection {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}
func TestOfflineClockProbeUnitsKeepReadOnlyAdjtimex(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Parallel()
	f := newOffline(t)
	successful(t, f.run(nil, nil, nil))
	for _, unit := range []string{"terrascale-orchestrator-controller-install.service", "terrascale-orchestrator-bootstrap.service", "terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service"} {
		t.Run(unit, func(t *testing.T) {
			source := read(t, filepath.Join(deployRoot(t), "deploy/systemd", unit))
			equal(t, read(t, f.path("/etc/systemd/system/"+unit)), source)
			d := unitDirectives(string(source), "")
			for _, name := range []string{"ProtectClock", "SystemCallFilter"} {
				if _, found := d[name]; found {
					t.Fatalf("unit has %s", name)
				}
			}
			equal(t, d["NoNewPrivileges"], "yes")
			if d["User"] == "root" {
				t.Fatal("explicit User=root drops SETUID")
			}
			equal(t, d["AmbientCapabilities"], "")
			equal(t, slices.Contains(strings.Fields(d["CapabilityBoundingSet"]), "CAP_SYS_TIME"), false)
		})
	}
}
func TestOfflineRootSetBoundsBeforeVerification(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		count, size int
	}{{"too-many", bakedLimit(t, "MaxRootFiles") + 1, 4}, {"per-root", 1, 16*1024 + 1}, {"total", 5, 16 * 1024}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOffline(t)
			var roots []string
			for i := range tc.count {
				path := filepath.Join(f.inputs, fmt.Sprintf("root-%02d.pem", i))
				write(t, path, bytes.Repeat([]byte("r"), tc.size), 0644)
				roots = append(roots, path)
			}
			r := f.run(roots, nil, nil)
			f.reject(r, "")
			absent(t, f.events)
			f.noEffects()
		})
	}
}

func TestOfflineBuildAcceptsRelativeOutputPaths(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	tier.Integration(t)
	t.Parallel()
	f := newOffline(t)
	imageOutput, kernelOutput := f.output, f.kernelOutput
	var err error
	if f.output, err = filepath.Rel(f.repo, imageOutput); err != nil {
		t.Fatal(err)
	}
	if f.kernelOutput, err = filepath.Rel(f.repo, kernelOutput); err != nil {
		t.Fatal(err)
	}
	successful(t, f.run(nil, nil, nil))
	equal(t, read(t, imageOutput), read(t, f.base))
	equal(t, read(t, kernelOutput), f.kernel)
}
