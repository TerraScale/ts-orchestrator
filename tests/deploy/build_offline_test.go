package deploy_test

import (
	"bytes"
	"encoding/binary"
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
)

const offlineKernelRelease = "6.8.0-142-generic"
const offlineSource = "9f52ca3f861a3eec125eefb6e5025c806fbd0913"
const bootstrapDir = "/etc/terrascale-orchestrator/bootstrap"
const markerDir = "/var/lib/terrascale-orchestrator-bootstrap"
const secretsDir = "/var/lib/terrascale-orchestrator-secrets"
const controllerDir = "/var/lib/terrascale-orchestrator-controller"

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
		case "realpath":
			resolved, err := filepath.EvalSymlinks(guestPath(args[0]))
			must(err)
			relative, err := filepath.Rel(guestRoot, resolved)
			if err != nil || !filepath.IsLocal(relative) {
				fail("fake guestfish realpath escaped the guest root: " + args[0])
			}
			fmt.Println("/" + filepath.ToSlash(relative))
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
	f.binary = file("orchestrator binary", elf("arm64", "mock verified binary"))
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
	f.kernel = make([]byte, 0x206) // a gzip kernel's header is read as 0x206 bytes
	copy(f.kernel[56:], []byte{'A', 'R', 'M', 0x64})
	f.kernel = append(f.kernel, []byte("mock arm64 kernel")...)
	for _, path := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/usr/local/lib/terrascale-orchestrator", "/etc/sysusers.d", "/usr/local/bin", "/var/lib", "/srv", "/boot", "/lib/modules/" + offlineKernelRelease, "/usr/bin", "/usr/sbin"} {
		if err := os.MkdirAll(f.path(path), 0755); err != nil {
			t.Fatal(err)
		}
		// The builder checks guest modes; do not inherit the caller's umask.
		if err := os.Chmod(f.path(path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, f.path(kernelGuest), f.kernel, 0644)
	if err := os.Symlink("vmlinuz-"+offlineKernelRelease, f.path("/boot/vmlinuz")); err != nil {
		t.Fatal(err)
	}
	write(t, f.path("/var/lib/dpkg/status"), []byte("Package: systemd\nStatus: install ok installed\nVersion: 255.4-1ubuntu8.12\n\nPackage: e2fsprogs\nStatus: install ok installed\nVersion: 1.47.0-2.4~exp1ubuntu4.1\n\nPackage: util-linux\nStatus: install ok installed\nVersion: 2.39.3-9ubuntu6.6\n\nPackage: openssh-server\nStatus: install ok installed\nVersion: 1:9.6p1-3ubuntu13.14\n\nPackage: nftables\nStatus: install ok installed\nVersion: 1.0.9-1ubuntu0.1\n\nPackage: libnftables1\nStatus: install ok installed\nVersion: 1.0.9-1ubuntu0.1\n\n"), 0644)
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
	// The pinned nft metadata fence and its loader chain, read but never run.
	libraries := "/usr/lib/aarch64-linux-gnu/"
	write(t, f.path("/usr/sbin/nft"), metadataELF(libraries+"ld-linux-aarch64.so.1", "libnftables.so.1"), 0755)
	write(t, f.path(libraries+"libnftables.so.1"), metadataELF("", "libc.so.6"), 0644)
	write(t, f.path(libraries+"libc.so.6"), metadataELF(""), 0644)
	write(t, f.path(libraries+"ld-linux-aarch64.so.1"), metadataELF(""), 0755)
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

// metadataELF is a minimal ARM64 ELF with an optional PT_INTERP and a
// DT_NEEDED entry per library, mirroring internal/image's runtime fixture.
func metadataELF(interpreter string, libraries ...string) []byte {
	file := make([]byte, 1024)
	copy(file, "\x7fELF\x02\x01\x01")
	put16, put32, put64 := binary.LittleEndian.PutUint16, binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	put16(file[16:], 3)
	put16(file[18:], 183)
	put32(file[20:], 1)
	put16(file[52:], 64)
	put64(file[40:], 128)
	put16(file[58:], 64)
	put16(file[60:], 3)
	if interpreter != "" {
		put64(file[32:], 64)
		put16(file[54:], 56)
		put16(file[56:], 1)
		put32(file[64:], 3)
		put64(file[72:], 384)
		put64(file[96:], uint64(len(interpreter)+1))
		copy(file[384:], interpreter)
	}
	put32(file[196:], 6)
	put64(file[216:], 512)
	put64(file[224:], uint64((len(libraries)+1)*16))
	put32(file[232:], 2)
	put64(file[248:], 16)
	put32(file[260:], 3)
	put64(file[280:], 768)
	size := 1
	for i, library := range libraries {
		put64(file[512+i*16:], 1)
		put64(file[520+i*16:], uint64(size))
		copy(file[768+size:], library)
		size += len(library) + 1
	}
	put64(file[288:], uint64(size))
	return file
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

func TestOfflineVerifiedInputsInstalled(t *testing.T) {
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

func TestOfflineRejectsBadPublicInputsBeforeImageEffects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, message string
		prepare       func(*offlineFixture)
		replace       map[string]string
		env           map[string]string
	}{
		{"native-digest", "native verifier bytes do not match", func(*offlineFixture) {}, map[string]string{"--native-verifier-sha256": strings.Repeat("0", 64)}, nil},
		{"native-architecture", "native verifier and orchestrator architectures differ", func(f *offlineFixture) { b := read(f.t, f.verifier); b[18] = 62; write(f.t, f.verifier, b, 0644) }, nil, nil},
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
