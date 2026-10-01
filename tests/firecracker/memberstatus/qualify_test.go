//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

const (
	msGoName         = "TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery"
	msRustName       = "member_control_managed::managed_member_status_cross_language_process_boundary"
	msVolumeName     = "TestManagedRuntimeFirecrackerMountedVolume"
	msUUID           = "76f1b43d-7d79-4f41-9a6e-cc1f4aaab102"
	msMember         = "/srv/ts-managed/6efe9447512debbf02bcd921c78d666c"
	msSender         = "memberstatus: authenticated Go client accepted real sender-enabled process"
	msSuccess        = "MEMBER_STATUS_QUALIFICATION_RESULT=PASS"
	msVolumeSuccess  = "TS_MANAGED_VOLUME_QUALIFICATION_RESULT=PASS"
	msGoPass         = "=== RUN   " + msGoName + "\n--- PASS: " + msGoName + " (0.00s)\nPASS\n"
	msRustPass       = "running 1 test\ntest " + msRustName + " ...\nMEMBER_STATUS_GO_OK\n" + msSender + "\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
	msVolumeEvidence = "managed-volume-v1 device=/dev/oracleoci/oraclevdb uuid=" + msUUID + " mount=" + msMember + "/volume mount_id=23 replication_shard=absent"
	msVolumePass     = "=== RUN   " + msVolumeName + "\n    managed_runtime_firecracker_test.go:1: " + msVolumeEvidence + "\n--- PASS: " + msVolumeName + " (0.00s)\nPASS\n"
)

const msPrelude = `from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import os, subprocess, sys
def attempt(fn):
    try:
        return {"value": fn(), "error": "", "error_type": ""}
    except Exception as exc:
        return {"error": str(exc), "error_type": type(exc).__name__}
def normalize(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    return value
`

func msObserve(t *testing.T, input any, body string) map[string]any {
	t.Helper()
	wire := script.Python(t, filepath.Join(script.Root(t), "tests/firecracker/memberstatus/qualify.py"), input, msPrelude+body+"\nresult = normalize(result)")
	var value map[string]any
	if err := json.Unmarshal(wire, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func msEqual(t *testing.T, got, want any) {
	t.Helper()
	gotWire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantWire, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(gotWire, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wantWire, &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("got %s, want %s", gotWire, wantWire)
	}
}

func msContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("%q does not contain %q", got, want)
	}
}

func msExcludes(t *testing.T, got, bad string) {
	t.Helper()
	if strings.Contains(got, bad) {
		t.Fatalf("%q contains %q", got, bad)
	}
}

func msReject(t *testing.T, got map[string]any, typ, message string) {
	t.Helper()
	msEqual(t, got["error_type"], typ)
	msContains(t, fmt.Sprint(got["error"]), message)
}

func msObject(value any) map[string]any { return value.(map[string]any) }

func TestMemberStatusQualificationParsers(t *testing.T) {
	serial := msGoPass + msRustPass + msSuccess + "\n"
	for _, prefixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("valid/prefixed_%t", prefixed), func(t *testing.T) {
			text := serial
			if prefixed {
				var lines []string
				for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
					lines = append(lines, "[   33.785579] ts-member-status-qualification[770]: "+line)
				}
				text = strings.Join(lines, "\n")
			}
			got := msObserve(t, map[string]any{"go": msGoPass, "rust": msRustPass, "serial": text}, `result=m.parse_qualification_result(a["go"],0,a["rust"],0,a["serial"],`+fmt.Sprintf("%q", msRustName)+`)`)
			msEqual(t, msObject(got["go_host_test"])["status"], "PASS")
			msEqual(t, msObject(got["rust_test"])["status"], "PASS")
			msEqual(t, msObject(got["rust_test"])["sender_marker"], msSender)
		})
	}
	for _, tc := range []struct {
		name, output string
		code         int
	}{
		{"skip", strings.ReplaceAll(msGoPass, "--- PASS:", "--- SKIP:"), 0},
		{"missing", "PASS\n", 0}, {"multiple", msGoPass + msGoPass, 0},
		{"zero", "testing: warning: no tests to run\nPASS\n", 0},
		{"wrong_name", strings.ReplaceAll(msGoPass, msGoName, "TestSomethingElse"), 0}, {"failed_exit", msGoPass, 1},
	} {
		t.Run("go/"+tc.name, func(t *testing.T) {
			got := msObserve(t, map[string]any{"text": tc.output, "code": tc.code}, `result=m.parse_go_test_output(a["text"],a["code"])`)
			msReject(t, got, "QualificationError", "")
		})
	}
	for _, tc := range []struct {
		name, output string
		code         int
	}{
		{"zero", strings.ReplaceAll(strings.ReplaceAll(msRustPass, "running 1 test", "running 0 tests"), "1 passed", "0 passed"), 0},
		{"ignored", strings.ReplaceAll(msRustPass, "1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored"), 0},
		{"measured", strings.ReplaceAll(msRustPass, "0 measured", "1 measured"), 0},
		{"wrong_name", strings.ReplaceAll(msRustPass, msRustName, "some_other_test"), 0},
		{"multiple", strings.ReplaceAll(strings.ReplaceAll(msRustPass, "running 1 test", "running 2 tests"), "1 passed;", "2 passed;"), 0},
		{"failed_exit", msRustPass, 1},
		{"missing_go_marker", strings.ReplaceAll(msRustPass, "MEMBER_STATUS_GO_OK\n", ""), 0},
		{"missing_sender", strings.ReplaceAll(msRustPass, msSender+"\n", ""), 0},
		{"duplicate_sender", strings.ReplaceAll(msRustPass, msSender, msSender+"\n"+msSender), 0},
	} {
		t.Run("rust/"+tc.name, func(t *testing.T) {
			got := msObserve(t, map[string]any{"text": tc.output, "code": tc.code, "name": msRustName}, `result=m.parse_rust_test_output(a["text"],a["code"],a["name"])`)
			msReject(t, got, "QualificationError", "")
		})
	}
	for _, tc := range []struct{ name, text, message string }{
		{"missing", msGoPass + msRustPass, "terminal runner result"}, {"before", msSuccess + "\n" + msGoPass + msRustPass, "before"},
	} {
		t.Run("qualification/"+tc.name, func(t *testing.T) {
			got := msObserve(t, map[string]string{"serial": tc.text, "go": msGoPass, "rust": msRustPass, "name": msRustName}, `result=m.parse_qualification_result(a["go"],0,a["rust"],0,a["serial"],a["name"])`)
			msReject(t, got, "QualificationError", tc.message)
		})
	}
	got := msObserve(t, "[   33.785579] ts-member-status-qualification[770]: MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=rust-test status=101\n", `result=m.parse_runner_result(a)`)
	msEqual(t, got["status"], "FAILED")
	msEqual(t, got["stage"], "rust-test")
	msEqual(t, got["exit_status"], 101)
	for _, text := range []string{"guest shut down unexpectedly\n", msSuccess + "\n" + msSuccess + "\n", "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=unknown status=101\n"} {
		got := msObserve(t, text, `result=m.parse_runner_result(a)`)
		msReject(t, got, "QualificationError", "")
	}
}

func TestMemberStatusManagedVolumeParser(t *testing.T) {
	serial := msVolumePass + msVolumeSuccess + "\n"
	got := msObserve(t, map[string]string{"go": msVolumePass, "serial": serial}, `result=m.parse_managed_volume_result(a["go"],0,a["serial"])`)
	msEqual(t, msObject(got["go_host_test"])["name"], msVolumeName)
	msEqual(t, msObject(got["managed_volume"])["mount_id"], 23)
	msEqual(t, msObject(got["managed_volume"])["replication_shard"], "absent")
	for _, tc := range []struct{ name, goOutput, serial string }{
		{"skip", strings.ReplaceAll(msVolumePass, "--- PASS:", "--- SKIP:"), serial},
		{"zero_mount", msVolumePass, strings.ReplaceAll(serial, "mount_id=23", "mount_id=0")},
		{"shard_present", msVolumePass, strings.ReplaceAll(serial, "replication_shard=absent", "replication_shard=present")},
		{"duplicate_terminal", msVolumePass, strings.ReplaceAll(serial, msVolumeSuccess, msVolumeSuccess+"\n"+msVolumeSuccess)},
		{"early_terminal", msVolumePass, msVolumeSuccess + "\n" + msVolumePass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := msObserve(t, map[string]string{"go": tc.goOutput, "serial": tc.serial}, `result=m.parse_managed_volume_result(a["go"],0,a["serial"])`)
			msReject(t, got, "QualificationError", "")
		})
	}
}

var msManagedInputs = []string{"kernel", "rootfs", "firecracker", "go_host_test", "volume_ext4", "authority_tbca", "trusted_public_key", "server_crt", "server_key", "client_ca_pem", "client_managed_manifest", "client_config", "client_chain", "client_private_key", "client_api_keys"}
var msLegacyInputs = []string{"kernel", "rootfs", "firecracker", "go_host_test", "memberstatus_probe", "rust_server", "rust_test"}

func msWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	script.Write(t, path, wire, 0o600)
}
func msSHA(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }

func TestMemberStatusManifests(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed_%t", managed), func(t *testing.T) {
			dir := t.TempDir()
			names := msLegacyInputs
			if managed {
				names = msManagedInputs
			}
			inputs := map[string]any{}
			for _, name := range names {
				path := filepath.Join(dir, name)
				mode := os.FileMode(0o644)
				if slices.Contains([]string{"firecracker", "go_host_test", "memberstatus_probe", "rust_server", "rust_test"}, name) {
					mode = 0o755
				}
				script.Write(t, path, []byte(name), mode)
				inputs[name] = map[string]any{"path": path, "sha256": msSHA([]byte(name))}
			}
			manifest := map[string]any{"source_commits": map[string]string{"orchestrator": strings.Repeat("a", 40), "terrabase": strings.Repeat("b", 40)}, "inputs": inputs}
			if managed {
				manifest["profile"] = "managed-volume-v1"
				manifest["go_test_name"] = msVolumeName
				manifest["managed_volume"] = map[string]string{"filesystem_uuid": msUUID}
			} else {
				manifest["rust_test_name"] = msRustName
			}
			path := filepath.Join(dir, "manifest.json")
			msWriteJSON(t, path, manifest)
			got := msObserve(t, path, `loaded,raw,resolved=m.load_manifest(Path(a));result={"loaded":loaded,"inputs":list(resolved)}`)
			actual := got["inputs"].([]any)
			var sorted []string
			for _, name := range actual {
				sorted = append(sorted, name.(string))
			}
			msEqual(t, slices.Sorted(slices.Values(sorted)), slices.Sorted(slices.Values(names)))
			loaded := msObject(got["loaded"])
			if managed {
				msEqual(t, loaded["profile"], "managed-volume-v1")
			} else {
				msEqual(t, loaded["profile"], nil)
				msEqual(t, loaded["rust_test_name"], msRustName)
				return
			}
			for _, name := range []string{"rust_name", "go_name", "uuid", "extra_input"} {
				t.Run(name, func(t *testing.T) {
					wire, _ := json.Marshal(manifest)
					var changed map[string]any
					json.Unmarshal(wire, &changed)
					switch name {
					case "rust_name":
						changed["rust_test_name"] = msRustName
					case "go_name":
						changed["go_test_name"] = "TestSomethingElse"
					case "uuid":
						changed["managed_volume"] = map[string]string{"filesystem_uuid": "not-pinned"}
					case "extra_input":
						msObject(changed["inputs"])["rust_test"] = inputs["go_host_test"]
					}
					msWriteJSON(t, path, changed)
					got := msObserve(t, path, `result=m.load_manifest(Path(a))`)
					msReject(t, got, "QualificationError", "")
				})
			}
		})
	}
}

func TestMemberStatusGuestReads(t *testing.T) {
	dir := t.TempDir()
	guest := filepath.Join(dir, "guest")
	outside := filepath.Join(dir, "outside")
	script.Write(t, filepath.Join(outside, "evidence.log"), []byte("forged evidence"), 0o600)
	if err := os.MkdirAll(guest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(guest, "var")); err != nil {
		t.Fatal(err)
	}
	got := msObserve(t, guest, `result=m._read_guest_regular_file(Path(a),Path("/var/evidence.log"),1024)`)
	msReject(t, got, "QualificationError", "symlink")
	if err := os.Remove(filepath.Join(guest, "var")); err != nil {
		t.Fatal(err)
	}
	script.Write(t, filepath.Join(guest, "var/log/evidence.log"), []byte("regular evidence"), 0o600)
	got = msObserve(t, guest, `text,oversized=m._read_guest_regular_file(Path(a),Path("/var/log/evidence.log"),1024);result={"text":text,"oversized":oversized}`)
	msEqual(t, got, map[string]any{"text": "regular evidence", "oversized": false})
}

func TestMemberStatusPrivateSocketAndSudo(t *testing.T) {
	got := msObserve(t, nil, `path=m.make_private_socket_dir()
try:
    metadata=path.stat()
    result={"uid":metadata.st_uid,"mode":metadata.st_mode & 0o777,"socket_length":len(os.fsencode(path/"api.sock"))}
finally:
    path.rmdir()`)
	msEqual(t, got["uid"], os.Getuid())
	msEqual(t, got["mode"], 0o700)
	if got["socket_length"].(float64) >= 100 {
		t.Fatal("private socket exceeds Unix path limit")
	}
	got = msObserve(t, nil, `q=object.__new__(m.Qualification)
with patch.object(Path,"is_file",return_value=False),patch.object(m.shutil,"which",return_value="/usr/bin/sudo") as which:
    result={"sudo":q._sudo(),"calls":[list(c.args) for c in which.call_args_list]}`)
	msEqual(t, got, map[string]any{"sudo": "/usr/bin/sudo", "calls": [][]string{{"sudo"}}})
}

func TestMemberStatusBoundedOutput(t *testing.T) {
	for _, serial := range []bool{false, true} {
		t.Run(fmt.Sprintf("serial_%t", serial), func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"commands", "logs"} {
				if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			input := map[string]any{"root": dir, "serial": serial}
			input["command"] = []string{"python3", "-c", "print('more than four bytes')"}
			body := `root=Path(a["root"])
events=m.EventLog(root/"logs/events.json")
runner=m.CommandRunner(root,events)
with patch.object(m,"MAX_COMMAND_LOG_BYTES",4):
    result=attempt(lambda:runner.run("truncate",a["command"],timeout=2))`
			if serial {
				body = `root=Path(a["root"])
events=m.EventLog(root/"events.json")
read_fd,write_fd=os.pipe()
capture=m.BoundedOutput(os.fdopen(read_fd,"rb"),root/"serial.log",4)
os.write(write_fd,b"serial output exceeds limit")
os.close(write_fd)
vm=object.__new__(m.FirecrackerVM)
vm.serial_capture=capture
vm.vmm_capture=None
vm.output_capture={}
vm.events=events
result=attempt(vm._finish_output)`
			}
			got := msObserve(t, input, body)
			if serial {
				msReject(t, got, "QualificationError", "truncated: serial")
			} else {
				msReject(t, got, "CommandFailure", "log was truncated")
			}
		})
	}
}

func TestMemberStatusManagedDriveAttachment(t *testing.T) {
	dir := t.TempDir()
	socketDir := filepath.Join(dir, "socket")
	logs := filepath.Join(dir, "logs")
	script.Write(t, filepath.Join(socketDir, "api.sock"), nil, 0o600)
	if err := os.Mkdir(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	got := msObserve(t, dir, `root=Path(a)
vm=m.FirecrackerVM(root/"firecracker",root/"kernel",root/"rootfs",root/"socket",root/"logs",m.EventLog(root/"logs/events.json"),root/"managed-volume.ext4")
class Capture:
    def __init__(self,stream,path,maximum): self.path=path
process=SimpleNamespace(pid=123,stdout=object(),stderr=object(),returncode=None)
with patch.object(m.subprocess,"Popen",return_value=process),patch.object(m,"BoundedOutput",Capture),patch.object(m,"_child_exited_without_reaping",return_value=False),patch.object(vm,"_api",return_value={}) as api:
    vm.start()
result={"calls":[list(c.args) for c in api.call_args_list],"drive_id":m.MANAGED_VOLUME_DRIVE_ID}`)
	id := got["drive_id"].(string)
	pattern := regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	if !pattern.MatchString(id) || pattern.MatchString("-"+id) {
		t.Fatal("invalid Firecracker drive resource id")
	}
	rootIndex, driveIndex, startIndex := -1, -1, -1
	var request map[string]any
	for i, call := range got["calls"].([]any) {
		parts := call.([]any)
		path := parts[1].(string)
		if path == "/drives/rootfs" {
			rootIndex = i
		}
		if path == "/drives/"+id {
			driveIndex = i
			request = msObject(parts[2])
		}
		if path == "/actions" && msObject(parts[2])["action_type"] == "InstanceStart" {
			startIndex = i
		}
	}
	if rootIndex < 0 || driveIndex <= rootIndex || startIndex <= driveIndex {
		t.Fatalf("drive attach order: root=%d volume=%d start=%d", rootIndex, driveIndex, startIndex)
	}
	msEqual(t, request, map[string]any{"drive_id": id, "path_on_host": filepath.Join(dir, "managed-volume.ext4"), "is_root_device": false, "is_read_only": false})
}

func TestMemberStatusManagedRootfsPreflight(t *testing.T) {
	for _, blkid := range []string{"usr/sbin/blkid", "usr/bin/blkid"} {
		t.Run(blkid, func(t *testing.T) {
			dir := t.TempDir()
			guest := filepath.Join(dir, "guest")
			for _, relative := range []string{"usr/lib/systemd/systemd", "usr/bin/systemctl", "usr/bin/findmnt", "usr/bin/mountpoint", "usr/bin/readlink", blkid, "var/lib/dpkg/status"} {
				data := []byte{}
				mode := os.FileMode(0o755)
				if relative == "var/lib/dpkg/status" {
					data = []byte("Package: systemd\nStatus: install ok installed\nVersion: 255.4-1ubuntu8\n")
					mode = 0o644
				}
				script.Write(t, filepath.Join(guest, relative), data, mode)
			}
			got := msObserve(t, dir, `root=Path(a)
q=object.__new__(m.Qualification)
q.managed_volume_profile=True
q.mount_path=root/"guest"
q.events=m.EventLog(root/"events.json")
with patch.object(q,"_mount"),patch.object(q,"_unmount"),patch.object(q,"_stage_managed_volume_guest") as stage:
    result=attempt(q._stage_guest)
    result["stage_calls"]=stage.call_count
result["setup"]=m._managed_volume_setup_script()`)
			if blkid == "usr/sbin/blkid" {
				msEqual(t, got["error"], "")
				msEqual(t, got["stage_calls"], 1)
				if _, err := os.Stat(filepath.Join(guest, "usr/sbin/blkid")); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(guest, "usr/bin/blkid")); !os.IsNotExist(err) {
					t.Fatal("unexpected alternate blkid path")
				}
				msContains(t, got["setup"].(string), "BLKID=/usr/sbin/blkid")
				msContains(t, got["setup"].(string), `observed_uuid=$("$BLKID" -s UUID -o value "$DEVICE")`)
			} else {
				msReject(t, got, "QualificationError", "missing required probe executable: /usr/sbin/blkid")
				msEqual(t, got["stage_calls"], 0)
			}
		})
	}
}

func msDirectoryModes() []struct {
	path string
	mode os.FileMode
} {
	return []struct {
		path string
		mode os.FileMode
	}{{"/srv/ts-managed", 0o750}, {msMember, 0o750}, {msMember + "/material", 0o750}, {msMember + "/control", 0o730}, {msMember + "/volume", 0o750}}
}

var msMaterialFiles = []string{"authority.tbca", "trusted-public-key", "server.crt", "server.key", "client-ca.pem", "client-managed-manifest.json", "client-config.json", "client-chain.pem", "client-private-key.pem", "client-api-keys.json", "server-ca.pem"}

func TestMemberStatusManagedLockdown(t *testing.T) {
	dir := t.TempDir()
	mount := filepath.Join(dir, "guest-root")
	var directories, materials []any
	var statTargets, statLines []string
	for _, entry := range msDirectoryModes() {
		target := filepath.Join(mount, entry.path)
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		directories = append(directories, []any{entry.path, target, int(entry.mode)})
		statTargets = append(statTargets, target)
		statLines = append(statLines, fmt.Sprintf("0:65534:%x", uint32(0o040000|entry.mode)))
	}
	for _, name := range msMaterialFiles {
		guestPath := msMember + "/material/" + name
		target := filepath.Join(mount, guestPath)
		script.Write(t, target, []byte("pinned"), 0o440)
		materials = append(materials, []string{guestPath, target})
		statTargets = append(statTargets, target)
		statLines = append(statLines, "0:65534:8120")
	}
	statLog := filepath.Join(dir, "stat.log")
	script.Write(t, statLog, []byte(strings.Join(statLines, "\n")+"\n"), 0o600)
	got := msObserve(t, map[string]any{"mount": mount, "directories": directories, "materials": materials, "stat_log": statLog}, `q=object.__new__(m.Qualification)
q.mount_path=Path(a["mount"])
q.events=m.EventLog(q.mount_path.parent/"events.json")
directories=[(Path(guest),Path(target),mode) for guest,target,mode in a["directories"]]
materials=[(Path(guest),Path(target)) for guest,target in a["materials"]]
commands=[]
def sudo_run(label,*args,**kwargs):
    commands.append([label,[str(arg) for arg in args]])
    return 0,Path(a["stat_log"])
q._sudo_run=sudo_run
with patch.object(m,"_guest_path_without_symlinks",side_effect=PermissionError("unprivileged walk after lockdown")) as walk:
    result=attempt(lambda:q._lockdown_managed_volume_layout(directories,materials))
    result.update(commands=commands,walk_count=walk.call_count)`)
	msEqual(t, got["error"], "")
	msEqual(t, got["walk_count"], 0)
	var labels []string
	commands := got["commands"].([]any)
	for _, command := range commands {
		labels = append(labels, command.([]any)[0].(string))
	}
	msEqual(t, labels, []string{"install-dir-volume", "install-dir-control", "install-dir-material", "install-dir-6efe9447512debbf02bcd921c78d666c", "install-dir-ts-managed", "verify-managed-volume-layout"})
	last := commands[len(commands)-1].([]any)[1].([]any)
	msEqual(t, last[:4], []string{"stat", "-c", "%u:%g:%f", "--"})
	msEqual(t, last[4:], statTargets)
}

func msSudo(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("requires a nonroot host user outside the guest material group")
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(groups, 65534) {
		t.Skip("requires a host user outside the guest material group")
	}
	got := msObserve(t, nil, `q=object.__new__(m.Qualification);result={"sudo":q._sudo()}`)
	if got["error"] != nil {
		t.Skip("passwordless sudo is unavailable")
	}
	sudo, ok := got["sudo"].(string)
	if !ok {
		t.Skip("passwordless sudo is unavailable")
	}
	check := script.Run(t, script.Root(t), nil, sudo, "-n", "true")
	if check.Code != 0 {
		t.Skip("passwordless sudo is unavailable")
	}
	return sudo
}

func TestMemberStatusRealProtectedStaging(t *testing.T) {
	sudo := msSudo(t)
	base := t.TempDir()
	mount := filepath.Join(base, "guest-root")
	protected := filepath.Join(mount, "srv/ts-managed")
	if err := os.MkdirAll(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	result := script.Run(t, base, nil, sudo, "-n", "install", "-d", "-o", "root", "-g", "65534", "-m", "0750", protected)
	msEqual(t, result.Code, 0)
	t.Cleanup(func() {
		// Go cancels t.Context before running cleanup callbacks. Keep this
		// bounded sudo cleanup alive so root-owned fixture files are removed.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()
		cleanup := exec.CommandContext(ctx, sudo, "-n", "rm", "-rf", "--", mount)
		if output, err := cleanup.CombinedOutput(); err != nil {
			t.Errorf("remove protected fixture: %v; %s", err, output)
		}
	})
	child := filepath.Join(mount, msMember)
	if _, err := os.Lstat(child); !os.IsPermission(err) {
		t.Fatalf("protected parent traversal = %v, want permission denial", err)
	}
	inputs := map[string]string{}
	hashes := map[string]any{}
	for _, name := range append(slices.Clone(msManagedInputs[5:]), "go_host_test") {
		path := filepath.Join(base, "input-"+name)
		data := []byte("pinned-" + name)
		script.Write(t, path, data, 0o644)
		inputs[name] = path
		hashes[name] = map[string]string{"sha256": msSHA(data)}
	}
	for _, name := range []string{"logs/commands", "stage"} {
		if err := os.MkdirAll(filepath.Join(base, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got := msObserve(t, map[string]any{"base": base, "mount": mount, "inputs": inputs, "hashes": hashes}, `root=Path(a["base"])
q=object.__new__(m.Qualification)
q.mount_path=Path(a["mount"])
q.stage=root/"stage"
q.inputs={name:Path(path) for name,path in a["inputs"].items()}
q.manifest={"inputs":a["hashes"],"managed_volume":{"filesystem_uuid":m.MANAGED_VOLUME_UUID}}
q.events=m.EventLog(root/"logs/events.json")
q.command_runner=m.CommandRunner(root/"logs",q.events)
result=attempt(q._stage_managed_volume_guest)
result["mounted"]=os.path.ismount(q.mount_path)`)
	msEqual(t, got["error"], "")
	msEqual(t, got["mounted"], false)
	var targets, want []string
	for _, entry := range msDirectoryModes() {
		targets = append(targets, filepath.Join(mount, entry.path))
		want = append(want, fmt.Sprintf("0:65534:%x", uint32(0o040000|entry.mode)))
	}
	for _, name := range msMaterialFiles {
		targets = append(targets, filepath.Join(mount, msMember, "material", name))
		want = append(want, "0:65534:8120")
	}
	args := append([]string{"-n", "stat", "-c", "%u:%g:%f", "--"}, targets...)
	result = script.Run(t, base, nil, sudo, args...)
	msEqual(t, result.Code, 0)
	msEqual(t, strings.Split(strings.TrimSpace(result.Stdout), "\n"), want)
	if _, err := os.Lstat(child); !os.IsPermission(err) {
		t.Fatalf("locked parent traversal = %v, want permission denial", err)
	}
}

func msFakeReboot(t *testing.T, base string) (string, string) {
	t.Helper()
	bin := filepath.Join(base, "bin")
	record := filepath.Join(base, "reboot-events")
	script.Write(t, filepath.Join(bin, "sync"), []byte("#!/bin/sh\nprintf '%s\\n' sync >>'"+record+"'\n"), 0o755)
	script.Write(t, filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"systemctl $*\" >>'"+record+"'\n"), 0o755)
	return bin, record
}

func msRunGuestShell(t *testing.T, base, bin, path string) script.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", path)
	cmd.Dir = base
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("guest shell runner exceeded five seconds: %v; %s", ctx.Err(), output)
	}
	code := 0
	if err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return script.Result{Stdout: string(output), Code: code}
}

func TestMemberStatusGuestShellRunner(t *testing.T) {
	for _, kind := range []string{"legacy_pass", "legacy_fail", "managed_volume"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			guest := filepath.Join(base, "guest")
			bin, record := msFakeReboot(t, base)
			var body string
			if kind == "managed_volume" {
				script.Write(t, filepath.Join(guest, "opt/ts-managed-volume-qualification/host.test"), []byte("#!/bin/sh\ncat <<'RESULT'\n"+msVolumePass+"RESULT\n"), 0o755)
				body = `result={"script":m._managed_volume_shell_runner(guest_root=Path(a))}`
			} else {
				goScript := "#!/bin/sh\nprintf 'Go tests passed\\n'\n"
				if kind == "legacy_fail" {
					goScript = "#!/bin/sh\nprintf 'focused Go failure\\n'\nexit 37\n"
				}
				script.Write(t, filepath.Join(guest, "opt/ts-member-status/go-host-test"), []byte(goScript), 0o755)
				script.Write(t, filepath.Join(guest, "opt/ts-member-status/rust-test"), []byte("#!/bin/sh\nprintf 'Rust test passed\\n'\n"), 0o755)
				body = `result={"script":m._shell_runner(Path("unused-go"),Path("unused-probe"),Path("unused-server"),Path("unused-rust"),m.RUST_TEST_NAME,guest_root=Path(a))}`
			}
			got := msObserve(t, guest, body)
			path := filepath.Join(base, "runner.sh")
			script.Write(t, path, []byte(got["script"].(string)), 0o600)
			run := msRunGuestShell(t, base, bin, path)
			console := run.Stdout + run.Stderr
			msEqual(t, strings.Split(strings.TrimSpace(string(script.Read(t, record))), "\n"), []string{"sync", "systemctl --no-wall reboot"})
			switch kind {
			case "legacy_pass":
				msEqual(t, run.Code, 0)
				msEqual(t, strings.Count(console, msSuccess), 1)
				msExcludes(t, console, "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED")
			case "legacy_fail":
				msEqual(t, run.Code, 37)
				msEqual(t, strings.Count(console, "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=go-host-test status=37"), 1)
				msExcludes(t, console, msSuccess)
				log := script.Read(t, filepath.Join(guest, "var/log/ts-member-status-qualification/go-host-test.log"))
				msContains(t, string(log), "stage=go-host-test status=37")
				parsed := msObserve(t, console, `result=m.parse_runner_result(a)`)
				msEqual(t, parsed["stage"], "go-host-test")
				msEqual(t, parsed["exit_status"], 37)
			case "managed_volume":
				msEqual(t, run.Code, 0)
				log := script.Read(t, filepath.Join(guest, "var/log/ts-managed-volume-qualification/go-host-test.log"))
				parsed := msObserve(t, map[string]string{"log": string(log), "serial": console}, `result=m.parse_managed_volume_result(a["log"],0,a["serial"])`)
				msEqual(t, msObject(parsed["managed_volume"])["mount_id"], 23)
			}
		})
	}
}

func TestMemberStatusServicePrivilegeSeparation(t *testing.T) {
	got := msObserve(t, nil, `result={"setup_script":m._managed_volume_setup_script(),"setup_unit":m._managed_volume_setup_unit(m.MANAGED_VOLUME_UUID),"managed_service":m._service_unit(m.MANAGED_VOLUME_UUID),"legacy_service":m._service_unit(),"timeout":m.GUEST_SERVICE_TIMEOUT_SECONDS,"deadline":m.GUEST_DEADLINE_SECONDS}`)
	if got["timeout"].(float64) >= got["deadline"].(float64) {
		t.Fatal("guest service timeout must leave host shutdown fallback")
	}
	msContains(t, got["legacy_service"].(string), "TimeoutStartSec=270s")
	setup := got["setup_script"].(string)
	for _, text := range []string{`ln -s ../vdb "$ALIAS"`, `mount -t ext4 -o rw "$ALIAS" "$MOUNT"`, "BLKID=/usr/sbin/blkid", `chmod 0700 "$MOUNT/data" "$MOUNT/replication"`} {
		msContains(t, setup, text)
	}
	msExcludes(t, setup, "replication/shard")
	unit := got["setup_unit"].(string)
	msContains(t, unit, "Environment=TS_FC_VOLUME_UUID=")
	msContains(t, unit, "Before=ts-member-status-qualification.service")
	managed := got["managed_service"].(string)
	for _, text := range []string{"Requires=ts-member-status-managed-volume-setup.service", "NoNewPrivileges=yes", "CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_READ_SEARCH", "CAP_DAC_READ_SEARCH"} {
		msContains(t, managed, text)
	}
	msExcludes(t, managed, "CAP_DAC_OVERRIDE")
	legacy := got["legacy_service"].(string)
	msContains(t, legacy, "CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP")
	msExcludes(t, legacy, "CAP_DAC_READ_SEARCH")
	msExcludes(t, legacy, "CAP_DAC_OVERRIDE")
	path := filepath.Join(t.TempDir(), "setup.sh")
	script.Write(t, path, []byte(setup), 0o600)
	checked := script.Run(t, script.Root(t), nil, "/bin/sh", "-n", path)
	msEqual(t, checked.Code, 0)
}

func msQualificationDirectories(t *testing.T, root string) {
	t.Helper()
	for _, name := range []string{"logs", "commands", "images", "mount", "stage"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMemberStatusQualificationCleanup(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"legacy", "managed-volume"} {
		msQualificationDirectories(t, filepath.Join(base, name))
	}
	got := msObserve(t, base, `root=Path(a)
legacy=m.Qualification({"source_commits":{},"rust_test_name":m.RUST_TEST_NAME},b"{}",{},root/"legacy")
managed=m.Qualification({"profile":m.MANAGED_VOLUME_PROFILE,"source_commits":{},"go_test_name":m.MANAGED_VOLUME_GO_TEST_NAME},b"{}",{},root/"managed-volume")
result={"legacy":legacy.logs_out,"managed":managed.logs_out}`)
	legacy := msObject(got["legacy"])
	managed := msObject(got["managed"])
	msEqual(t, len(legacy), 5)
	msEqual(t, len(managed), 4)
	for _, key := range []string{"events", "serial", "vmm", "go_host_test", "rust_test"} {
		if _, ok := legacy[key]; !ok {
			t.Fatalf("missing legacy log %s", key)
		}
	}
	for _, key := range []string{"events", "serial", "vmm", "managed_volume_test"} {
		if _, ok := managed[key]; !ok {
			t.Fatalf("missing managed log %s", key)
		}
	}
	msEqual(t, legacy["go_host_test"], filepath.Join(base, "legacy/logs/guest-go-host-test.log"))
	msEqual(t, managed["managed_volume_test"], filepath.Join(base, "managed-volume/logs/guest-managed-volume-test.log"))
	if _, ok := managed["go_host_test"]; ok {
		t.Fatal("legacy Go log in managed profile")
	}
	if _, ok := managed["rust_test"]; ok {
		t.Fatal("Rust log in managed profile")
	}
	root := filepath.Join(base, "failure")
	msQualificationDirectories(t, root)
	script.Write(t, filepath.Join(root, "logs/guest-serial.log"), []byte("[   33.785579] ts-member-status-qualification[770]: MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=rust-test status=101\n"), 0o600)
	got = msObserve(t, root, `q=m.Qualification({"source_commits":{},"rust_test_name":m.RUST_TEST_NAME},b"{}",{},Path(a));result=attempt(q._check_results);result["test_results"]=q.test_results`)
	msReject(t, got, "QualificationError", "stage=rust-test status=101")
	runner := msObject(msObject(got["test_results"])["runner"])
	msEqual(t, runner["stage"], "rust-test")
	msEqual(t, runner["exit_status"], 101)
	script.Write(t, filepath.Join(root, "images/member-status.ext4"), []byte("guest evidence"), 0o600)
	got = msObserve(t, root, `q=m.Qualification({"source_commits":{},"rust_test_name":m.RUST_TEST_NAME},b"{}",{},Path(a));q.failure="QualificationError: focused test failed";q._cleanup_image();result={"image":q.image}`)
	if _, err := os.Stat(got["image"].(string)); err != nil {
		t.Fatal("private image not retained:", err)
	}
}
