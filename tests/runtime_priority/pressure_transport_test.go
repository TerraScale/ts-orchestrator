package runtimepriority

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rp "git.terrascale.tech/TerraScale/ts-orchestrator/internal/runtimepriority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func TestAlphaTransportPinsAndRemoteCompile(t *testing.T) {
	manifest := fullyPinnedAllocationManifest(t)
	adapter := field(manifest, "adapter")
	request := object{"transport": manifest["transport"], "adapter_source_path": adapter["executable_path"], "adapter_source_sha256": adapter["executable_sha256"]}
	if err := rp.VerifyTransport(request); err != nil {
		t.Fatal(err)
	}
	field(field(request, "transport"), "https")["ca_bundle_path"] = filepath.Join(t.TempDir(), "missing-ca.pem")
	assertPressureError(t, errorObservation(rp.VerifyTransport(request)), "TLS CA bundle pinned source file is unavailable")
}
func TestHTTPSLeafPinPrecedesSecretsAndBody(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	script.Write(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	request := object{"transport": object{"https": object{"source_base_url": server.URL, "ca_bundle_path": ca, "source_credential_file": filepath.Join(t.TempDir(), "unreadable-secret")}}, "deadline_seconds": 10, "managed_member": object{"source": object{"authority": object{"tls_leaf_sha256": strings.Repeat("0", 64)}}}}
	_, err := rp.HTTPSRequest(t.Context(), request, "source", "POST", "/transactions", []byte("sensitive transaction body"))
	assertPressureError(t, errorObservation(err), "peer certificate differs")
	assertEqual(t, requests.Load(), int64(0))
}
func rawStat(pid, start int) string {
	return fmt.Sprintf("%d (d15 worker) S %s%d", pid, strings.Repeat("0 ", 18), start)
}
func remoteAction(t *testing.T, request object, action string, race bool, replacements object) object {
	t.Helper()
	payload := field(request, "remote_payload")
	targetKey := "oom_target"
	if action == "failure_inject" {
		targetKey = "target_process"
	}
	target := field(request, targetKey)
	killCalls, raced := 0, false
	remote := rp.Remote{CgroupRoot: fmt.Sprint(payload["fake_cgroup_root"]), Witness: func(pid int64) (rp.Object, error) {
		if payload["missing_process"] == true {
			return nil, os.ErrNotExist
		}
		return field(payload, "witness"), nil
	}, Signal: func(int64) error { killCalls++; return nil }}
	if payload["fake_cgroup_root"] == nil {
		remote.CgroupRoot = rp.CgroupRoot
	}
	if race {
		remote.BeforeOpenFile = func(name string, writing bool) {
			if name == "memory.max" && writing && !raced {
				database := payload["fake_database_path"].(string)
				if err := os.Rename(database, database+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(database, 0700); err != nil {
					t.Fatal(err)
				}
				for name, raw := range replacements {
					script.Write(t, filepath.Join(database, name), []byte(raw.(string)), 0600)
				}
				raced = true
			}
		}
	}
	_ = target
	reply, err := remote.Dispatch(t.Context(), request, action)
	got := object{"code": 0, "stderr": "", "kill_calls": killCalls, "raced": raced}
	if err != nil {
		got["code"] = 2
		got["stderr"] = rp.ErrorType(err) + ": " + err.Error()
	} else {
		got["output"] = reply
	}
	return got
}
func TestRemoteSigkillRejectsChangedRoleBeforeKill(t *testing.T) {
	native := "/sys/fs/cgroup/system.slice/terrascale-host.service/supervisor/runner"
	changed := native + "/another-role"
	target := object{"kind": "terrabase", "pid": 77, "process_start": "9001", "process_nonce": strings.Repeat("b", 32), "cgroup": changed, "host_boot_id": sampleBoot}
	request := object{"transport": object{"runtime": object{}}, "target_process": target, "native_runner_cgroup_path": native, "protected_database_cgroup_path": native + "/terrabase", "remote_payload": object{"witness": object{"stat_raw": rawStat(77, 9001), "cgroup_raw": "0::" + changed + "\n", "host_boot_id": sampleBoot}}}
	got := remoteAction(t, request, "failure_inject", false, object{})
	assertEqual(t, got["code"], 2)
	assertContains(t, fmt.Sprint(got["stderr"]), "HarnessError")
	assertEqual(t, got["kill_calls"], 0)
}
func cgroupInode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}
func remoteCgroupFixture(t *testing.T) (object, string) {
	t.Helper()
	temp := t.TempDir()
	root := filepath.Join(temp, "cgroup-root")
	relative := "system.slice/terrascale-host.service/supervisor/runner"
	database := filepath.Join(root, relative, "terrabase")
	native := "/sys/fs/cgroup/" + relative
	report := "/" + relative + "/terrabase"
	script.Write(t, filepath.Join(database, "memory.max"), []byte("1000\n"), 0600)
	script.Write(t, filepath.Join(database, "memory.current"), []byte("800\n"), 0600)
	script.Write(t, filepath.Join(database, "cgroup.procs"), []byte("77\n"), 0600)
	target := object{"kind": "terrabase", "pid": 77, "process_start": "9001", "process_nonce": strings.Repeat("b", 32), "cgroup": report, "host_boot_id": sampleBoot}
	intent := object{"target": target, "native_runner_cgroup_path": native, "database_cgroup_path": native + "/terrabase", "cgroup_inode": cgroupInode(t, database), "prior_memory_max_bytes": 1000, "temporary_memory_max_bytes": 500}
	request := object{"transport": object{"runtime": object{}}, "run_id": "cleanup-test", "pressure": object{"workload_cgroup": object{"parent_path": "/sys/fs/cgroup/terrascale-workload.slice"}, "io_directory": filepath.Join(temp, "io"), "oom_fault": object{"target_memory_max_bytes": 500, "deadline_seconds": 1}}, "qualification": object{"database_memory_max_bytes": 1000}, "oom_target": target, "oom_restore_intent": intent, "native_runner_cgroup_path": native, "protected_database_cgroup_path": native + "/terrabase", "journal_watermark": object{"cursor": "before"}, "remote_payload": object{"fake_cgroup_root": root, "fake_database_path": database, "pressure_path": filepath.Join(temp, "pressure.scope"), "witness": object{"stat_raw": rawStat(77, 9001), "cgroup_raw": "0::" + report + "\n", "host_boot_id": sampleBoot}}}
	return request, database
}
func validateRemoteCleanup(t *testing.T, request, cleanup object) object {
	t.Helper()
	manifest := exampleManifest(t)
	field(manifest, "qualification")["database_memory_max_bytes"] = 1000
	runner := rp.NewRunner(manifest, strings.Repeat("a", 64), t.TempDir())
	runner.State["oom_restore_intent"] = request["oom_restore_intent"]
	err := runner.ValidateRole("cleanup_verify", "cleanup", object{}, object{"observed_at_utc": sampleTimestamp(time.Now()), "evidence": object{"cleanup": cleanup}})
	result := errorObservation(err)
	result["verified"], result["unresolved"] = runner.State["oom_restore_cleanup_verified"], runner.State["oom_restore_unresolved_reason"]
	return normalize(t, result)
}
func TestRemoteCleanupRestoresOnlyExactKnownCgroup(t *testing.T) {
	for _, tc := range []struct {
		name, cap, reason string
		replacement, race bool
	}{{"unknown", "700\n", "unknown cap", false, false}, {"temporary", "500\n", "", false, false}, {"replaced", "500\n", "cgroup identity changed", true, false}, {"replacement_race", "500\n", "exact TerraBase role memory.max restore could not be verified", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			request, database := remoteCgroupFixture(t)
			field(request, "remote_payload")["missing_process"] = true
			script.Write(t, filepath.Join(database, "memory.max"), []byte(tc.cap), 0600)
			if tc.replacement {
				if err := os.Rename(database, database+"-original"); err != nil {
					t.Fatal(err)
				}
				script.Write(t, filepath.Join(database, "memory.max"), []byte(tc.cap), 0600)
				if cgroupInode(t, database) == field(request, "oom_restore_intent")["cgroup_inode"] {
					t.Fatal("cgroup inode unchanged")
				}
			}
			got := remoteAction(t, request, "cleanup_verify", tc.race, object{"memory.max": "500"})
			assertEqual(t, got["code"], 0)
			cleanup := field(field(got, "output"), "cleanup")
			if tc.reason == "" {
				assertEqual(t, cleanup["oom_restore_verified"], true)
				assertEqual(t, strings.TrimSpace(string(script.Read(t, filepath.Join(database, "memory.max")))), "1000")
			} else {
				assertEqual(t, cleanup["oom_restore_verified"], false)
				assertContains(t, fmt.Sprint(cleanup["oom_restore_unresolved_reason"]), tc.reason)
				assertEqual(t, strings.TrimSpace(string(script.Read(t, filepath.Join(database, "memory.max")))), strings.TrimSpace(tc.cap))
			}
			runner := validateRemoteCleanup(t, request, cleanup)
			if tc.reason == "" {
				assertEqual(t, runner["verified"], true)
			} else {
				assertPressureError(t, runner, "restore obligation unresolved")
				assertEqual(t, runner["verified"], false)
				if runner["unresolved"] == nil {
					t.Fatal(runner)
				}
			}
			if tc.race {
				assertEqual(t, got["raced"], true)
				assertEqual(t, strings.TrimSpace(string(script.Read(t, filepath.Join(database+"-original", "memory.max")))), "1000")
			}
		})
	}
}
func TestRemoteOOMCannotLowerReplacementCgroup(t *testing.T) {
	request, database := remoteCgroupFixture(t)
	got := remoteAction(t, request, "oom_fault", true, object{"memory.max": "700\n", "memory.current": "800\n", "cgroup.procs": "77\n"})
	assertEqual(t, got["code"], 2)
	assertContains(t, fmt.Sprint(got["stderr"]), "HarnessError")
	assertEqual(t, got["raced"], true)
	assertEqual(t, string(script.Read(t, filepath.Join(database, "memory.max"))), "700\n")
	assertEqual(t, string(script.Read(t, filepath.Join(database+"-original", "memory.max"))), "1000\n")
}
