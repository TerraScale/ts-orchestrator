//go:build linux

package memberstatus

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/qualification/firecracker"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

const goPass = "=== RUN   " + GoTestName + "\n--- PASS: " + GoTestName + " (0.00s)\nPASS\n"
const rustPass = "running 1 test\ntest " + RustTestName + " ...\n" + MemberStatusSuccess + "\n" + SenderSuccess + "\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
const volumeEvidence = "managed-volume-v1 device=/dev/oracleoci/oraclevdb uuid=" + ManagedVolumeUUID + " mount=" + MountPath + " mount_id=23 replication_shard=absent"
const volumePass = "=== RUN   " + ManagedVolumeGoTestName + "\n    test.go:1: " + volumeEvidence + "\n--- PASS: " + ManagedVolumeGoTestName + " (0.00s)\nPASS\n"

func reject(t *testing.T, err error, fragment string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), fragment) {
		t.Fatalf("expected rejection containing %q, got %v", fragment, err)
	}
}
func TestQualificationParsers(t *testing.T) {
	serial := goPass + rustPass + RunnerSuccess + "\n"
	for _, prefixed := range []bool{false, true} {
		t.Run(fmt.Sprint(prefixed), func(t *testing.T) {
			text := serial
			if prefixed {
				var ls []string
				for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
					ls = append(ls, "[   33.785579] ts-member-status-qualification[770]: "+line)
				}
				text = strings.Join(ls, "\n")
			}
			r, e := ParseQualificationResult(goPass, 0, rustPass, 0, text, RustTestName)
			if e != nil || obj(r["go_host_test"])["status"] != "PASS" || obj(r["rust_test"])["sender_marker"] != SenderSuccess {
				t.Fatal(r, e)
			}
		})
	}
	for _, tc := range []struct {
		name, text string
		code       int
	}{{"skip", strings.ReplaceAll(goPass, "--- PASS:", "--- SKIP:"), 0}, {"missing", "PASS\n", 0}, {"multiple", goPass + goPass, 0}, {"zero", "testing: warning: no tests to run\nPASS\n", 0}, {"wrong_name", strings.ReplaceAll(goPass, GoTestName, "TestElse"), 0}, {"failed_exit", goPass, 1}, {"after_pass", goPass + "later output\n", 0}} {
		t.Run("go/"+tc.name, func(t *testing.T) { _, e := ParseGoTestOutput(tc.text, tc.code, GoTestName); reject(t, e, "") })
	}
	for _, tc := range []struct {
		name, text string
		code       int
	}{{"ignored", strings.ReplaceAll(rustPass, "1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored"), 0}, {"zero", strings.ReplaceAll(rustPass, "running 1 test", "running 0 tests"), 0}, {"multiple", rustPass + rustPass, 0}, {"missing_marker", strings.ReplaceAll(rustPass, MemberStatusSuccess, ""), 0}, {"missing_sender", strings.ReplaceAll(rustPass, SenderSuccess, ""), 0}, {"failed_exit", rustPass, 1}} {
		t.Run("rust/"+tc.name, func(t *testing.T) { _, e := ParseRustTestOutput(tc.text, tc.code, RustTestName); reject(t, e, "") })
	}
	for _, text := range []string{"", RunnerSuccess + "\n" + RunnerSuccess, RunnerPrefix + "FAILED stage=unknown status=1", RunnerPrefix + "FAILED stage=go-host-test status=0"} {
		_, e := ParseRunnerResult(text, false)
		reject(t, e, "")
	}
	failure, e := ParseRunnerResult(RunnerPrefix+"FAILED stage=rust-test status=17", false)
	if e != nil || failure["exit_status"] != 17 {
		t.Fatal(failure, e)
	}
	_, e = ParseQualificationResult(goPass, 0, rustPass, 0, RunnerSuccess+"\n"+rustPass, RustTestName)
	reject(t, e, "before")
}
func TestManagedVolumeParser(t *testing.T) {
	r, e := ParseManagedVolumeResult(volumePass, 0, volumePass+VolumeRunnerSuccess+"\n")
	if e != nil || obj(r["managed_volume"])["mount_id"] != uint64(23) {
		t.Fatal(r, e)
	}
	for _, serial := range []string{volumePass, volumePass + VolumeRunnerSuccess + VolumeRunnerSuccess, VolumeRunnerSuccess + "\n" + volumePass, strings.ReplaceAll(volumePass, "mount_id=23", "mount_id=0") + VolumeRunnerSuccess, volumePass + volumeEvidence + "\n" + VolumeRunnerSuccess} {
		_, e := ParseManagedVolumeResult(volumePass, 0, serial)
		reject(t, e, "")
	}
}
func manifestFixture(t *testing.T, managed bool) (string, Object) {
	t.Helper()
	dir := t.TempDir()
	names := InputNames
	if managed {
		names = ManagedVolumeInputNames
	}
	inputs := Object{}
	for _, name := range names {
		path := filepath.Join(dir, name)
		body := []byte("immutable " + name)
		script.Write(t, path, body, 0755)
		inputs[name] = Object{"path": path, "sha256": shaBytes(body)}
	}
	m := Object{"source_commits": Object{"orchestrator": strings.Repeat("a", 40), "terrabase": strings.Repeat("b", 40)}, "inputs": inputs}
	if managed {
		m["profile"] = ManagedVolumeProfile
		m["go_test_name"] = ManagedVolumeGoTestName
		m["managed_volume"] = Object{"filesystem_uuid": ManagedVolumeUUID}
	} else {
		m["rust_test_name"] = RustTestName
	}
	path := filepath.Join(dir, "manifest.json")
	writeJSON(t, path, m)
	return path, m
}
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	script.Write(t, path, b, 0600)
}
func TestManifests(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprint(managed), func(t *testing.T) {
			path, m := manifestFixture(t, managed)
			loaded, raw, inputs, e := LoadManifest(path)
			if e != nil || len(raw) == 0 || len(inputs) != len(obj(m["inputs"])) {
				t.Fatal(loaded, inputs, e)
			}
			if !managed {
				if loaded["profile"] != nil || loaded["rust_test_name"] != RustTestName {
					t.Fatal(loaded)
				}
			}
			for _, name := range []string{"wrong_test", "extra_input", "relative_path", "bad_digest", "changed_input", "bad_commit", "wrong_uuid", "profile_null"} {
				t.Run(name, func(t *testing.T) {
					wire, _ := json.Marshal(m)
					var changed Object
					json.Unmarshal(wire, &changed)
					switch name {
					case "wrong_test":
						if managed {
							changed["go_test_name"] = "TestElse"
						} else {
							changed["rust_test_name"] = "test-else"
						}
					case "extra_input":
						obj(changed["inputs"])["extra"] = obj(changed["inputs"])["kernel"]
					case "relative_path":
						obj(obj(changed["inputs"])["kernel"])["path"] = "relative"
					case "bad_digest":
						obj(obj(changed["inputs"])["kernel"])["sha256"] = strings.Repeat("A", 64)
					case "changed_input":
						obj(obj(changed["inputs"])["kernel"])["sha256"] = strings.Repeat("0", 64)
					case "bad_commit":
						obj(changed["source_commits"])["orchestrator"] = "short"
					case "wrong_uuid":
						if !managed {
							return
						}
						obj(changed["managed_volume"])["filesystem_uuid"] = "foreign"
					case "profile_null":
						changed["profile"] = nil
					}
					writeJSON(t, path, changed)
					_, _, _, e := LoadManifest(path)
					reject(t, e, "")
				})
			}
		})
	}
}
func TestGuestReadsRefuseSymlinksAndBoundEvidence(t *testing.T) {
	dir := t.TempDir()
	guest := filepath.Join(dir, "guest")
	outside := filepath.Join(dir, "outside")
	script.Write(t, filepath.Join(outside, "evidence.log"), []byte("forged"), 0600)
	os.MkdirAll(guest, 0755)
	os.Symlink(outside, filepath.Join(guest, "var"))
	_, _, e := ReadGuestRegularFile(guest, "/var/evidence.log", 1024)
	reject(t, e, "symlink")
	os.Remove(filepath.Join(guest, "var"))
	script.Write(t, filepath.Join(guest, "var/log/evidence.log"), []byte("regular evidence"), 0600)
	s, oversized, e := ReadGuestRegularFile(guest, "/var/log/evidence.log", 4)
	if e != nil || !oversized || s != "regu" {
		t.Fatal(s, oversized, e)
	}
	for _, path := range []string{"relative", "/var/../outside"} {
		_, e = GuestPath(guest, path)
		reject(t, e, "unsafe")
	}
}
func TestPrivateSocketDirectory(t *testing.T) {
	dir, e := privateSocketDirectory()
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(dir)
	info, e := os.Stat(dir)
	if e != nil || info.Mode().Perm() != 0700 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Getuid() || len([]byte(filepath.Join(dir, "api.sock"))) >= 100 {
		t.Fatal(info, e)
	}
}
func TestBoundedOutputAndCommandEvidence(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "commands"), 0700)
	os.Mkdir(filepath.Join(dir, "logs"), 0700)
	events := &EventLog{Path: filepath.Join(dir, "logs/events.json")}
	runner := &CommandRunner{Root: dir, Events: events, Maximum: 4}
	_, path, e := runner.Run(t.Context(), "truncated", []string{"/bin/sh", "-c", "printf 'more than four bytes'"}, 2*time.Second, nil)
	reject(t, e, "log was truncated")
	b, e := os.ReadFile(path)
	if e != nil || string(b) != "more" || runner.Pending() {
		t.Fatal(string(b), e, runner.Pending())
	}
	serial, e := NewBoundedOutput(filepath.Join(dir, "serial.log"), 4)
	if e != nil {
		t.Fatal(e)
	}
	serial.Write([]byte("oversized serial"))
	vm := &VM{Serial: serial, Events: events}
	reject(t, vm.FinishOutput(), "truncated: serial")
}
func TestManagedDriveAttachmentOrder(t *testing.T) {
	vm := &VM{Kernel: "kernel", Image: "rootfs", ManagedVolume: "managed-volume.ext4"}
	requests := vm.Requests()
	rootIndex, driveIndex, startIndex := -1, -1, -1
	for i, r := range requests {
		switch r.Path {
		case "/drives/rootfs":
			rootIndex = i
		case "/drives/" + ManagedVolumeDriveID:
			driveIndex = i
			if !equal(r.Payload, Object{"drive_id": ManagedVolumeDriveID, "path_on_host": "managed-volume.ext4", "is_root_device": false, "is_read_only": false}) {
				t.Fatal(r)
			}
		case "/actions":
			startIndex = i
		}
	}
	if rootIndex < 0 || driveIndex <= rootIndex || startIndex <= driveIndex {
		t.Fatal(requests)
	}
}
func nativeQualification(t *testing.T, managed bool) *Qualification {
	t.Helper()
	root := filepath.Join(t.TempDir(), "run")
	q, e := New(t.Context(), Object{"profile": nil, "source_commits": Object{}, "rust_test_name": RustTestName}, []byte("{}"), map[string]string{}, root, "")
	if e != nil {
		t.Fatal(e)
	}
	q.Managed = managed
	if e = q.PrepareDirs(); e != nil {
		t.Fatal(e)
	}
	q.IsMounted = func(string) bool { return false }
	return q
}
func TestManagedRootfsRequiresPinnedBlkidAndInstalledSystemd(t *testing.T) {
	for _, name := range []string{"valid", "alternate_blkid", "old_systemd", "symlink_status"} {
		t.Run(name, func(t *testing.T) {
			q := nativeQualification(t, true)
			required := []string{"usr/lib/systemd/systemd", "usr/bin/systemctl", "usr/bin/findmnt", "usr/bin/mountpoint", "usr/bin/readlink", "usr/sbin/blkid"}
			if name == "alternate_blkid" {
				required[len(required)-1] = "usr/bin/blkid"
			}
			for _, path := range required {
				script.Write(t, filepath.Join(q.MountPath, path), nil, 0755)
			}
			version := "255.4-1ubuntu8"
			if name == "old_systemd" {
				version = "254.1"
			}
			status := filepath.Join(q.MountPath, "var/lib/dpkg/status")
			if name == "symlink_status" {
				outside := filepath.Join(q.Root, "outside")
				script.Write(t, outside, []byte("Package: systemd\nStatus: install ok installed\nVersion: "+version+"\n"), 0644)
				os.MkdirAll(filepath.Dir(status), 0755)
				os.Symlink(outside, status)
			} else {
				script.Write(t, status, []byte("Package: systemd\nStatus: install ok installed\nVersion: "+version+"\n"), 0644)
			}
			q.ValidateGuestRootfs()
			if name == "valid" {
				if q.Err() != nil {
					t.Fatal(q.Err())
				}
			} else {
				reject(t, q.Err(), "")
			}
		})
	}
}
func TestManagedLockdownUsesCapturedPathsAfterRestrictingTraversal(t *testing.T) {
	q := nativeQualification(t, true)
	q.SudoPath = "sudo"
	dirs := ManagedDirectories()
	var materials []Material
	var statLines, statTargets []string
	for i, d := range dirs {
		dirs[i].Target = filepath.Join(q.MountPath, strings.TrimPrefix(d.Guest, "/"))
		statTargets = append(statTargets, dirs[i].Target)
		statLines = append(statLines, fmt.Sprintf("0:65534:%x", uint32(0040000|d.Mode)))
	}
	for _, name := range []string{"authority.tbca", "server.key"} {
		path := MaterialPath + "/" + name
		target := filepath.Join(q.MountPath, strings.TrimPrefix(path, "/"))
		materials = append(materials, Material{path, target})
		statTargets = append(statTargets, target)
		statLines = append(statLines, "0:65534:8120")
	}
	log := filepath.Join(q.Root, "stat.log")
	script.Write(t, log, []byte(strings.Join(statLines, "\n")+"\n"), 0600)
	var labels []string
	q.Command = func(ctx context.Context, label string, args []string, timeout time.Duration, allowed []int) (int, string, error) {
		labels = append(labels, label)
		if label == "verify-managed-volume-layout" {
			if !slices.Equal(args[2:6], []string{"stat", "-c", "%u:%g:%f", "--"}) || !slices.Equal(args[6:], statTargets) {
				t.Fatal(args)
			}
		}
		return 0, log, nil
	}
	q.LockdownManagedVolumeLayout(dirs, materials)
	want := []string{"install-dir-volume", "install-dir-control", "install-dir-material", "install-dir-6efe9447512debbf02bcd921c78d666c", "install-dir-ts-managed", "verify-managed-volume-layout"}
	if q.Err() != nil || !slices.Equal(labels, want) {
		t.Fatal(labels, q.Err())
	}
	statLines[0] = "1000:65534:41e8"
	script.Write(t, log, []byte(strings.Join(statLines, "\n")+"\n"), 0600)
	q.LockdownManagedVolumeLayout(dirs, materials)
	reject(t, q.Err(), "unsafe final")
}
func TestCleanupRetainsFailedOrLiveGuestEvidence(t *testing.T) {
	for _, name := range []string{"success", "failed", "live", "mounted", "command_live", "foreign_socket"} {
		t.Run(name, func(t *testing.T) {
			q := nativeQualification(t, true)
			script.Write(t, q.Image, []byte("guest evidence"), 0600)
			script.Write(t, q.ManagedVolumeImage, []byte("volume evidence"), 0600)
			q.SocketDir = filepath.Join(q.Root, "socket")
			os.Mkdir(q.SocketDir, 0700)
			switch name {
			case "failed":
				q.Failure = "qualification failed"
			case "live":
				q.VM = &VM{Process: &firecracker.Process{}, SocketDir: q.SocketDir}
			case "mounted":
				q.IsMounted = func(string) bool { return true }
			case "command_live":
				q.CommandRunner.pending = []pendingCommand{{}}
			case "foreign_socket":
				q.VM = &VM{SocketDir: q.SocketDir}
				script.Write(t, q.VM.SocketPath(), nil, 0600)
			}
			q.CleanupSocketDirectory()
			q.CleanupImage()
			if name == "success" {
				if lexists(q.Image) || lexists(q.ManagedVolumeImage) || lexists(q.SocketDir) {
					t.Fatal("successful stopped resources retained")
				}
			} else if !lexists(q.Image) || !lexists(q.ManagedVolumeImage) {
				t.Fatal("failed or uncertain evidence removed")
			}
			if name == "live" && (!lexists(q.SocketDir) || len(q.CleanupErrors) == 0) {
				t.Fatal("live socket removed")
			}
		})
	}
}
func TestSourceInventoryMutationPreventsPass(t *testing.T) {
	q := nativeQualification(t, false)
	path := filepath.Join(q.Root, "source.go")
	script.Write(t, path, []byte("before"), 0600)
	q.SourcePaths["driver"] = path
	q.SourceHashes["driver"] = shaBytes([]byte("before"))
	script.Write(t, path, []byte("after"), 0600)
	q.checkSourceStability()
	if q.SourceStable || q.Failure == "" || q.Summary()["outcome"] != "FAILED" {
		t.Fatal(q.Summary())
	}
}
func TestUnmountRefusesUnownedMount(t *testing.T) {
	q := nativeQualification(t, false)
	q.IsMounted = func(string) bool { return true }
	q.Command = func(context.Context, string, []string, time.Duration, []int) (int, string, error) {
		t.Fatal("unmounted foreign resource")
		return 0, "", nil
	}
	reject(t, q.Unmount(), "unowned mount")
}
func TestManagedProtectedStagingUsesPrivilegedHashReadback(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged staging driver")
	}
	groups, e := os.Getgroups()
	if e != nil {
		t.Fatal(e)
	}
	if slices.Contains(groups, 65534) {
		t.Skip("driver belongs to protected guest material group")
	}
	sudo, e := Sudo()
	if e != nil {
		t.Skip(e)
	}
	if e = exec.Command(sudo, "-n", "true").Run(); e != nil {
		t.Skip("noninteractive sudo is unavailable")
	}
	q := nativeQualification(t, true)
	q.SudoPath = sudo
	t.Cleanup(func() {
		if err := exec.Command(sudo, "-n", "rm", "-rf", "--", q.MountPath).Run(); err != nil {
			t.Errorf("remove owned privileged staging fixture: %v", err)
		}
	})
	dir := MaterialPath
	source := filepath.Join(q.Stage, "server.key")
	script.Write(t, source, []byte("private fixture material"), 0600)
	q.InstallDirectory(dir, "0755", "65534")
	dest := dir + "/server.key"
	q.Install(source, dest, "0440", "65534")
	actual := q.HashStagedGuestFile("protected-hash", dest)
	if q.Err() != nil || actual != shaBytes([]byte("private fixture material")) {
		t.Fatal(actual, q.Err())
	}
	target, _ := GuestPath(q.MountPath, dest)
	if _, e = os.ReadFile(target); !os.IsPermission(e) {
		t.Fatal("unprivileged driver could read protected material", e)
	}
	q.CommandRunner.Run(t.Context(), "restore-test-permissions", []string{sudo, "-n", "chmod", "-R", "u+rwX", q.MountPath}, time.Minute, nil)
}

var _ io.Writer = (*BoundedOutput)(nil)

func TestGuestRunnerFailureIsRetainedWithoutMissingTestLogs(t *testing.T) {
	q := nativeQualification(t, false)
	script.Write(t, filepath.Join(q.Logs, "guest-serial.log"), []byte("[   33.785579] ts-member-status-qualification[770]: "+RunnerPrefix+"FAILED stage=rust-test status=101\n"), 0600)
	q.CheckResults()
	reject(t, q.Err(), "stage=rust-test status=101")
	runner := obj(q.TestResults["runner"])
	if runner["stage"] != "rust-test" || runner["exit_status"] != 101 {
		t.Fatal(q.TestResults)
	}
}
func TestProfileLogInventory(t *testing.T) {
	for _, managed := range []bool{false, true} {
		q := nativeQualification(t, managed)
		logs := obj(q.Summary()["logs"])
		if managed {
			if len(logs) != 4 || logs["managed_volume_test"] != filepath.Join(q.Logs, "guest-managed-volume-test.log") {
				t.Fatal(logs)
			}
		} else if len(logs) != 5 || logs["go_host_test"] != filepath.Join(q.Logs, "guest-go-host-test.log") || logs["rust_test"] != filepath.Join(q.Logs, "guest-rust-test.log") {
			t.Fatal(logs)
		}
	}
}
func TestVMStartupRoutesAPICallsAndSeparatesBoundedLogs(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	os.Mkdir(logs, 0700)
	socket := filepath.Join(dir, "socket")
	os.Mkdir(socket, 0700)
	script.Write(t, filepath.Join(socket, "api.sock"), nil, 0600)
	binary := filepath.Join(dir, "vmm")
	script.Write(t, binary, []byte("#!/bin/sh\nprintf 'serial output\\n'\nprintf 'vmm output\\n' >&2\nsleep 20\n"), 0700)
	vm := &VM{Firecracker: binary, Kernel: "kernel", Image: "rootfs", ManagedVolume: "managed-volume.ext4", SocketDir: socket, Logs: logs, Events: &EventLog{Path: filepath.Join(logs, "events.json")}}
	var calls []APIRequest
	vm.API = func(ctx context.Context, method, path string, payload Object) error {
		calls = append(calls, APIRequest{method, path, payload})
		return nil
	}
	if e := vm.Start(t.Context()); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if !vm.Process.Reaped {
			vm.Process.Stop(time.Second, true)
		}
	})
	if len(calls) != len(vm.Requests())+1 || calls[0].Method != "GET" || calls[0].Path != "/version" {
		t.Fatal(calls)
	}
	for i, want := range vm.Requests() {
		if calls[i+1].Path != want.Path || !equal(calls[i+1].Payload, want.Payload) {
			t.Fatal(calls)
		}
	}
	if e := vm.Process.Stop(time.Second, true); e != nil {
		t.Fatal(e)
	}
	vm.ProcessGroupStopped = true
	if e := vm.FinishOutput(); e != nil {
		t.Fatal(e)
	}
	serial := string(script.Read(t, filepath.Join(logs, "guest-serial.log")))
	vmm := string(script.Read(t, filepath.Join(logs, "firecracker-vmm.log")))
	if serial != "serial output\n" || vmm != "vmm output\n" {
		t.Fatal(serial, vmm)
	}
}
