package ociregion_test

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func attemptFixture(t *testing.T, legacy bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	trust := map[string]any{}
	for _, k := range []string{"root_public", "root_private", "release_leaf_public", "release_leaf_private"} {
		trust[k] = filepath.Join(dir, k)
	}
	config := map[string]any{"workdir": work, "deployment_id": "deployment-a", "prefix": "bootstrap/a", "validity_days": 1, "trust": trust, "tools": map[string]any{"fj_dir": "/fj", "guestfs_tools_dir": "/guestfs", "libguestfs_dir": "/libguestfs", "libguestfs_appliance": "/appliance"}, "orchestrator": map[string]any{"repository": "/repository", "source_revision": strings.Repeat("a", 40), "ci_run_number": 1}, "image": map[string]any{"base_qcow2": "/base.qcow2", "kernel_release": "kernel", "native_verifier": "/native", "native_verifier_sha256": strings.Repeat("b", 64), "timesyncd_config": "/timesyncd", "priority": map[string]any{"profile_id": "profile", "system_reserve_bytes": 1, "host_memory_min_bytes": 1, "host_memory_low_bytes": 1, "controller_memory_min_bytes": 1, "controller_memory_low_bytes": 1, "system_slice_memory_min_bytes": 1, "system_slice_memory_low_bytes": 1}}}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "attempt.json")
	script.Write(t, path, b, 0600)
	target := "terrascale-orchestrator"
	if legacy {
		target = "ts-bootstrap"
	}
	script.Write(t, filepath.Join(work, "source", "cmd", target, "main.go"), []byte("pinned entry point\n"), 0600)
	return path, work
}

func attemptObserve(t *testing.T, config string, body string) map[string]any {
	t.Helper()
	var out map[string]any
	data := script.Python(t, "deploy/oci-region/attempt.py", map[string]any{"config": config}, "from pathlib import Path\nfrom unittest import mock\nr = m.Attempt(Path(a['config']))\n"+body)
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAttemptBuildToolsAndReuse(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			config, work := attemptFixture(t, legacy)
			// Go owns the executable fixture; the compile observer copies it to the requested output.
			fixture := filepath.Join(work, "fixture")
			script.Write(t, fixture, []byte("#!/bin/sh\nexit 0\n"), 0700)
			out := attemptObserve(t, config, `import shutil
calls = []
def compile(command, **kwargs):
    calls.append(command)
    shutil.copyfile(r.path('fixture'), command[command.index('-o') + 1])
with mock.patch.object(m.subprocess, 'run', side_effect=compile):
    r.build_tools()
with mock.patch.object(r, 'run') as run, mock.patch.object(m.subprocess, 'run') as build:
    r.build_tools()
    result = {'calls': calls, 'bootstrap': str(r.bootstrap_tool), 'release': str(r.release_tool), 'rerun': run.call_count, 'rebuild': build.call_count}
`)
			want := []string{"./cmd/terrascale-orchestrator"}
			if legacy {
				want = []string{"./cmd/ts-bootstrap", "./cmd/ts-release"}
			}
			calls := out["calls"].([]any)
			if len(calls) != len(want) {
				t.Fatalf("builds: %v", calls)
			}
			for i, call := range calls {
				args := call.([]any)
				if args[len(args)-1] != want[i] {
					t.Fatalf("build target %v", args)
				}
			}
			if out["rerun"] != float64(0) || out["rebuild"] != float64(0) {
				t.Fatalf("cached build reran: %v", out)
			}
			if legacy {
				if filepath.Base(out["bootstrap"].(string)) != "ts-bootstrap" || filepath.Base(out["release"].(string)) != "ts-release" {
					t.Fatal(out)
				}
			} else if out["bootstrap"] != out["release"] {
				t.Fatal(out)
			}
		})
	}
}

func TestAttemptReleaseUsesSourceCommandConvention(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			config, work := attemptFixture(t, legacy)
			for _, name := range []string{"qualification.json", "terrascale-orchestrator-linux-arm64", "terrascale-orchestrator-linux-amd64"} {
				script.Write(t, filepath.Join(work, "release", name), []byte("qualified fixture"), 0600)
			}
			out := attemptObserve(t, config, `calls = []
def run(*args, **kwargs):
    if args[0] == 'fj':
        return '{"head_sha":"`+strings.Repeat("a", 40)+`","status":"success","run_id":2}'
    calls.append([str(v) for v in args])
    return ''
with mock.patch.object(r, 'run', side_effect=run):
    r.run_bootstrap('verify-anchor')
    r.phase_release()
result = {'calls': calls}
`)
			calls := out["calls"].([]any)
			want := []string{"verify-anchor", "sign-delegation", "binary-candidate", "sign-binary", "verify-binary"}
			if len(calls) != len(want) {
				t.Fatal(calls)
			}
			for i, v := range calls {
				cmd := v.([]any)
				index := 1
				if !legacy {
					index = 2
					namespace := "release"
					if i == 0 {
						namespace = "bootstrap"
					}
					if cmd[1] != namespace {
						t.Fatal(cmd)
					}
				}
				if cmd[index] != want[i] {
					t.Fatal(cmd)
				}
			}
		})
	}
}

func TestAttemptLaunchPassesLegacyFlags(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			config, work := attemptFixture(t, legacy)
			script.Write(t, filepath.Join(work, "image", "import.json"), []byte(`{"image_id":"ocid1.image.fixture"}`), 0600)
			out := attemptObserve(t, config, `with mock.patch.object(r, 'fresh_admission', return_value=('inventory', 'admission')), mock.patch.object(r, 'run', side_effect=RuntimeError('preflight captured')) as run:
    try:
        r.phase_launch()
    except RuntimeError as e:
        error = str(e)
result = {'error': error, 'command': [str(v) for v in run.call_args.args], 'bootstrap': str(r.bootstrap_tool), 'release': str(r.release_tool)}
`)
			if out["error"] != "preflight captured" {
				t.Fatal(out)
			}
			command := out["command"].([]any)
			for _, flag := range []string{"--legacy-bootstrap-tool", "--legacy-release-tool"} {
				found := false
				for _, v := range command {
					found = found || v == flag
				}
				if found != legacy {
					t.Fatalf("%s legacy=%v: %v", flag, legacy, command)
				}
			}
			for _, pair := range [][2]string{{"--bootstrap-tool", "bootstrap"}, {"--release-tool", "release"}} {
				found := false
				for i, v := range command {
					if v == pair[0] {
						found = true
						if command[i+1] != out[pair[1]] {
							t.Fatal(command)
						}
					}
				}
				if !found {
					t.Fatal(command)
				}
			}
		})
	}
}

func TestAttemptLegacyImageBuilderReleaseTool(t *testing.T) {
	config, work := attemptFixture(t, true)
	out := attemptObserve(t, config, `with mock.patch.object(m.subprocess, 'run', side_effect=RuntimeError('builder captured')) as run:
    try:
        r.phase_image()
    except RuntimeError as e:
        error = str(e)
result = {'error': error, 'command': run.call_args.args[0]}
`)
	args := out["command"].([]any)
	if out["error"] != "builder captured" || args[1] != filepath.Join(work, "source", "deploy/image/build-offline.sh") {
		t.Fatal(out)
	}
	found := false
	for i, v := range args {
		if v == "--release-tool" {
			found = reflect.DeepEqual(args[i+1], filepath.Join(work, "tools", "ts-release"))
		}
	}
	if !found {
		t.Fatal(args)
	}
}

func TestAttemptCheckoutPinnedSource(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			config, work := attemptFixture(t, legacy)
			if err := os.Rename(filepath.Join(work, "source"), filepath.Join(work, "pinned-source")); err != nil {
				t.Fatal(err)
			}
			script.Write(t, filepath.Join(work, "fixture"), []byte("#!/bin/sh\nexit 0\n"), 0700)
			out := attemptObserve(t, config, `import shutil
def checkout(*args, **kwargs):
    shutil.copytree(r.path('pinned-source'), r.path('source'))
def compile(command, **kwargs):
    shutil.copyfile(r.path('fixture'), command[command.index('-o') + 1])
with mock.patch.object(r, 'run', side_effect=checkout) as run, mock.patch.object(m.subprocess, 'run', side_effect=compile):
    r.build_tools()
result = {'count': run.call_count, 'command': [str(v) for v in run.call_args.args]}
`)
			want := []any{"git", "-C", "/repository", "worktree", "add", "--detach", filepath.Join(work, "source"), strings.Repeat("a", 40)}
			if out["count"] != float64(1) || !reflect.DeepEqual(out["command"], want) {
				t.Fatal(out)
			}
		})
	}
}
