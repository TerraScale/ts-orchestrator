package ociregion_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/attempt"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func attemptFixture(t *testing.T, legacy bool) (*attempt.Attempt, string) {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	trust := map[string]any{}
	for _, k := range []string{"root_public", "root_private", "release_leaf_public", "release_leaf_private"} {
		trust[k] = filepath.Join(dir, k)
	}
	config := map[string]any{"workdir": work, "deployment_id": "deployment-a", "prefix": "bootstrap/a", "validity_days": 1, "trust": trust, "tools": map[string]any{"fj_dir": "/fj", "guestfs_tools_dir": "/guestfs", "libguestfs_dir": "/libguestfs", "libguestfs_appliance": "/appliance"}, "orchestrator": map[string]any{"repository": "/repository", "source_revision": strings.Repeat("a", 40), "ci_run_number": 1}, "image": map[string]any{"base_qcow2": "/base.qcow2", "kernel_release": "kernel", "native_verifier": "/native", "native_verifier_sha256": strings.Repeat("b", 64), "timesyncd_config": "/timesyncd", "priority": map[string]any{"profile_id": "profile", "system_reserve_bytes": 1, "host_memory_min_bytes": 1, "host_memory_low_bytes": 1, "controller_memory_min_bytes": 1, "controller_memory_low_bytes": 1, "system_slice_memory_min_bytes": 1, "system_slice_memory_low_bytes": 1}}}
	b, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "attempt.json")
	script.Write(t, path, b, 0600)
	target := "terrascale-orchestrator"
	if legacy {
		target = "ts-bootstrap"
	}
	script.Write(t, filepath.Join(work, "source", "cmd", target, "main.go"), []byte("pinned entry point\n"), 0600)
	a, e := attempt.New(t.Context(), path, io.Discard, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	a.Executable = "/qualified/orchestrator"
	return a, work
}
func commandValue(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 == len(args) {
		return ""
	}
	return args[i+1]
}
func TestAttemptBuildToolsAndReuse(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			a, _ := attemptFixture(t, legacy)
			var calls []attempt.Command
			a.Runner = func(ctx context.Context, c attempt.Command) (string, error) {
				calls = append(calls, c)
				script.Write(t, commandValue(c.Args, "-o"), []byte("compiled fixture"), 0700)
				return "", nil
			}
			a.BuildTools()
			want := []string{"./cmd/terrascale-orchestrator"}
			if legacy {
				want = []string{"./cmd/ts-bootstrap", "./cmd/ts-release"}
			}
			if a.Err() != nil || len(calls) != len(want) {
				t.Fatal(calls, a.Err())
			}
			for i, c := range calls {
				if c.Args[len(c.Args)-1] != want[i] || c.Dir != a.Path("source") || !slices.Contains(c.Args, "-buildvcs=true") {
					t.Fatal(c)
				}
			}
			a.Runner = func(context.Context, attempt.Command) (string, error) { t.Fatal("cached build reran"); return "", nil }
			a.BuildTools()
			if legacy {
				if filepath.Base(a.BootstrapTool()) != "ts-bootstrap" || filepath.Base(a.ReleaseTool()) != "ts-release" {
					t.Fatal(a.BootstrapTool(), a.ReleaseTool())
				}
			} else if a.BootstrapTool() != a.ReleaseTool() {
				t.Fatal(a.BootstrapTool(), a.ReleaseTool())
			}
		})
	}
}
func TestAttemptReleaseUsesSourceCommandConvention(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			a, work := attemptFixture(t, legacy)
			for _, name := range []string{"qualification.json", "terrascale-orchestrator-linux-arm64", "terrascale-orchestrator-linux-amd64"} {
				script.Write(t, filepath.Join(work, "release", name), []byte("qualified fixture"), 0600)
			}
			var calls [][]string
			a.Runner = func(ctx context.Context, c attempt.Command) (string, error) {
				if c.Args[0] == "fj" {
					return `{"head_sha":"` + strings.Repeat("a", 40) + `","status":"success","run_id":2}`, nil
				}
				calls = append(calls, c.Args)
				return "", nil
			}
			a.RunBootstrap("verify-anchor")
			a.PhaseRelease()
			want := []string{"verify-anchor", "sign-delegation", "binary-candidate", "sign-binary", "verify-binary"}
			if a.Err() != nil || len(calls) != len(want) {
				t.Fatal(calls, a.Err())
			}
			for i, c := range calls {
				index := 1
				if !legacy {
					index = 2
					namespace := "release"
					if i == 0 {
						namespace = "bootstrap"
					}
					if c[1] != namespace {
						t.Fatal(c)
					}
				}
				if c[index] != want[i] {
					t.Fatal(c)
				}
			}
		})
	}
}
func TestAttemptLaunchPassesLegacyFlags(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			a, work := attemptFixture(t, legacy)
			script.Write(t, filepath.Join(work, "image", "import.json"), []byte(`{"image_id":"ocid1.image.fixture"}`), 0600)
			var command []string
			sentinel := errors.New("preflight captured")
			a.Runner = func(ctx context.Context, c attempt.Command) (string, error) {
				if slices.Contains(c.Args, "inventory") || slices.Contains(c.Args, "admit") {
					return "", nil
				}
				command = c.Args
				return "", sentinel
			}
			a.PhaseLaunch()
			if !errors.Is(a.Err(), sentinel) {
				t.Fatal(a.Err())
			}
			if !slices.Equal(command[:4], []string{a.Executable, "oci-region", "preview", "seed-preflight"}) {
				t.Fatal(command)
			}
			for _, flag := range []string{"--legacy-bootstrap-tool", "--legacy-release-tool"} {
				if slices.Contains(command, flag) != legacy {
					t.Fatal(flag, legacy, command)
				}
			}
			for _, pair := range [][2]string{{"--bootstrap-tool", a.BootstrapTool()}, {"--release-tool", a.ReleaseTool()}} {
				if commandValue(command, pair[0]) != pair[1] {
					t.Fatal(command)
				}
			}
		})
	}
}
func TestAttemptLegacyImageBuilderReleaseTool(t *testing.T) {
	a, work := attemptFixture(t, true)
	var command attempt.Command
	sentinel := errors.New("builder captured")
	a.Runner = func(ctx context.Context, c attempt.Command) (string, error) { command = c; return "", sentinel }
	a.PhaseImage()
	if !errors.Is(a.Err(), sentinel) || command.Args[1] != filepath.Join(work, "source", "deploy/image/build-offline.sh") || command.Dir != filepath.Join(work, "source") || commandValue(command.Args, "--release-tool") != filepath.Join(work, "tools", "ts-release") {
		t.Fatal(command, a.Err())
	}
}
func TestAttemptCheckoutPinnedSource(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			a, work := attemptFixture(t, legacy)
			if e := os.Rename(filepath.Join(work, "source"), filepath.Join(work, "pinned-source")); e != nil {
				t.Fatal(e)
			}
			var checkout []string
			a.Runner = func(ctx context.Context, c attempt.Command) (string, error) {
				if c.Args[0] == "git" {
					checkout = c.Args
					return "", os.Rename(filepath.Join(work, "pinned-source"), filepath.Join(work, "source"))
				}
				script.Write(t, commandValue(c.Args, "-o"), []byte("compiled fixture"), 0700)
				return "", nil
			}
			a.BuildTools()
			want := []string{"git", "-C", "/repository", "worktree", "add", "--detach", filepath.Join(work, "source"), strings.Repeat("a", 40)}
			if a.Err() != nil || !slices.Equal(checkout, want) {
				t.Fatal(checkout, a.Err())
			}
		})
	}
}
func TestAttemptAdmissionRetriesRemainInUnifiedBinary(t *testing.T) {
	a, _ := attemptFixture(t, false)
	inventoryCalls, admissionCalls := 0, 0
	a.Runner = func(ctx context.Context, c attempt.Command) (string, error) {
		if !slices.Equal(c.Args[:3], []string{a.Executable, "oci-region", "preview"}) {
			t.Fatal(c.Args)
		}
		switch c.Args[3] {
		case "inventory":
			inventoryCalls++
			if inventoryCalls < 3 {
				return "", errors.New("transient inventory")
			}
		case "admit":
			admissionCalls++
		default:
			t.Fatal(c.Args)
		}
		return "", nil
	}
	inventory, admission := a.FreshAdmission("launch/launch")
	if a.Err() != nil || inventoryCalls != 3 || admissionCalls != 1 || inventory != a.Path("launch", "launch-inventory.json") || admission != a.Path("launch", "launch-admission.json") {
		t.Fatal(inventory, admission, inventoryCalls, admissionCalls, a.Err())
	}
}
func TestAttemptReservationCannotLaunchAgain(t *testing.T) {
	a, _ := attemptFixture(t, false)
	script.Write(t, a.Path("launch", "seed-reservation.json"), []byte("reserved"), 0600)
	a.Runner = func(context.Context, attempt.Command) (string, error) {
		t.Fatal("invoked external tool after unresolved reservation")
		return "", nil
	}
	a.PhaseLaunch()
	if a.Err() == nil || !strings.Contains(a.Err().Error(), "reconcile") {
		t.Fatal(a.Err())
	}
}
func TestAttemptFreshAdmissionAndEmptyPrefixPrecedeReservation(t *testing.T) {
	for _, name := range []string{"stale_admission", "existing_slot", "valid"} {
		t.Run(name, func(t *testing.T) {
			a, _ := attemptFixture(t, false)
			now := time.Now().UTC()
			a.Now = func() time.Time { return now }
			script.Write(t, a.Path("image", "import.json"), []byte(`{"image_id":"ocid1.image.fixture"}`), 0600)
			script.Write(t, a.Plan(), []byte(`{"foundation_buckets":{"head":"head","ledger":"ledger"}}`), 0600)
			var calls []string
			a.Runner = func(ctx context.Context, c attempt.Command) (string, error) {
				calls = append(calls, strings.Join(c.Args, " "))
				if c.Args[0] == "oci" {
					if slices.Contains(c.Args, "launch") {
						return `{"data":{"id":"ocid1.instance.a"}}`, nil
					}
					if name == "existing_slot" {
						return `{"data":[{"name":"bootstrap/a/slot/record"}]}`, nil
					}
					return `{"data":[{"name":"bootstrap/a/founder-selection/1"}]}`, nil
				}
				if slices.Contains(c.Args, "admit") {
					expires := now.Add(10 * time.Minute)
					if name == "stale_admission" {
						expires = now.Add(179 * time.Second)
					}
					script.Write(t, commandValue(c.Args, "--out"), []byte(`{"expires_at":"`+expires.Format(time.RFC3339)+`"}`), 0600)
				}
				if slices.Contains(c.Args, "seed-preflight") {
					script.Write(t, commandValue(c.Args, "--out"), []byte(`{"create_identity":"seed-a"}`), 0600)
				}
				if slices.Contains(c.Args, "sign-external-seed-reservation") {
					script.Write(t, commandValue(c.Args, "--out"), []byte("reserved"), 0600)
				}
				return "", nil
			}
			a.PhaseLaunch()
			reserved := existsTest(a.Path("launch", "seed-reservation.json"))
			if name == "valid" {
				if a.Err() != nil || !reserved || !existsTest(a.Path("launch", "controller-a.ocid")) {
					t.Fatal(calls, a.Err())
				}
				n := len(calls)
				a.PhaseLaunch()
				if len(calls) != n {
					t.Fatal("successful launch was repeated")
				}
			} else if a.Err() == nil || reserved {
				t.Fatal(name, calls, a.Err())
			}
		})
	}
}
func existsTest(path string) bool { _, e := os.Stat(path); return e == nil }
