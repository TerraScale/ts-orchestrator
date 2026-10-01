package ci

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func digest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

type admissionCacheFixture struct {
	root, prepare, binary, cache string
	env                          map[string]string
}

func newAdmissionCache(t *testing.T) admissionCacheFixture {
	t.Helper()
	root := t.TempDir()
	repo := script.Root(t)
	scripts := filepath.Join(root, "repo/scripts/ci")
	script.Write(t, filepath.Join(scripts, "fj-run-detail.patch"), script.Read(t, filepath.Join(repo, "scripts/ci/fj-run-detail.patch")), 0o644)
	lock := filepath.Join(root, "Cargo.lock")
	script.Write(t, lock, []byte("pinned fixture lock\n"), 0o644)
	binary := filepath.Join(root, "fixture-fj")
	script.Write(t, binary, script.Read(t, filepath.Join(repo, "scripts/ci/testdata/admission-cache/fixture-fj")), 0o755)
	source := string(script.Read(t, filepath.Join(repo, "scripts/ci/prepare-fj-admission.sh")))
	for old, newValue := range map[string]string{
		"2f6f4c0392ec8ad8a46ca1b96b856abf9b8a5583f044044e9776989eec51c4e4": digest(script.Read(t, binary)),
		"4de42ee153468f31e6f0f0062777fa684cc519a122e5e7139020428a9da72651": digest(script.Read(t, lock)),
	} {
		if !strings.Contains(source, old) {
			t.Fatalf("missing production pin %s", old)
		}
		source = strings.ReplaceAll(source, old, newValue)
	}
	prepare := filepath.Join(scripts, "prepare-fj-admission.sh")
	script.Write(t, prepare, []byte(source), 0o644)
	for _, name := range []string{"fj", "git", "nix", "jq", "rustup"} {
		script.Write(t, filepath.Join(root, "mock-bin", name), script.Read(t, filepath.Join(repo, "scripts/ci/testdata/admission-cache", name)), 0o755)
	}
	script.Write(t, filepath.Join(root, "mock-bin/go"), []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$MOCK_PROBE_LOG\"\n"), 0o755)
	runnerTemp := filepath.Join(root, "runner-temp")
	if err := os.Mkdir(runnerTemp, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "cache")
	return admissionCacheFixture{root, prepare, binary, cache, map[string]string{
		"PATH": filepath.Join(root, "mock-bin") + string(os.PathListSeparator) + os.Getenv("PATH"), "GO": "go",
		"RUNNER_TEMP": runnerTemp, "TS_FJ_ADMISSION_CACHE_DIR": cache, "MOCK_LOCK": lock, "MOCK_BINARY": binary,
		"MOCK_BUILD_LOG": filepath.Join(root, "build.log"), "MOCK_EXEC_LOG": filepath.Join(root, "exec.log"), "MOCK_PROBE_LOG": filepath.Join(root, "probe.log"),
	}}
}

func (f admissionCacheFixture) run(t *testing.T, label string) script.Result {
	t.Helper()
	output := filepath.Join(f.root, label)
	r := script.Run(t, f.root, f.env, "bash", f.prepare, output)
	if r.Code != 0 {
		t.Fatalf("prepare exit %d: %s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	if digest(script.Read(t, filepath.Join(output, "fj"))) != digest(script.Read(t, f.binary)) {
		t.Fatal("output binary differs from pin")
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("output permissions: %o", info.Mode().Perm())
	}
	return r
}

func TestAdmissionCacheMissHitTamper(t *testing.T) {
	f := newAdmissionCache(t)
	miss := f.run(t, "miss-output")
	if !strings.Contains(miss.Stdout, "cache=build") {
		t.Fatal(miss.Stdout)
	}
	if got := strings.Count(string(script.Read(t, f.env["MOCK_BUILD_LOG"])), "compile\n"); got != 1 {
		t.Fatalf("compiles %d", got)
	}
	entries, err := filepath.Glob(filepath.Join(f.cache, "*/fj"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("cache entries: %v", entries)
	}
	if digest(script.Read(t, entries[0])) != digest(script.Read(t, f.binary)) {
		t.Fatal("cached digest differs")
	}
	hit := f.run(t, "hit-output")
	if !strings.Contains(hit.Stdout, "cache=hit") {
		t.Fatal(hit.Stdout)
	}
	if got := strings.Count(string(script.Read(t, f.env["MOCK_BUILD_LOG"])), "compile\n"); got != 1 {
		t.Fatalf("compiles after hit %d", got)
	}
	if got := strings.Count(string(script.Read(t, f.env["MOCK_PROBE_LOG"])), "\n"); got != 2 {
		t.Fatalf("probe runs %d", got)
	}
	if got := strings.Count(string(script.Read(t, f.env["MOCK_EXEC_LOG"])), "\n"); got != 6 {
		t.Fatalf("help checks %d", got)
	}
	marker := filepath.Join(f.root, "tamper-executed")
	script.Write(t, entries[0], []byte("#!/usr/bin/env bash\nprintf 'tampered\\n' >> '"+marker+"'\n"), 0o755)
	tamper := f.run(t, "tamper-output")
	if !strings.Contains(tamper.Stderr, "cache entry failed verification") || !strings.Contains(tamper.Stdout, "cache=build") {
		t.Fatalf("tamper: %s %s", tamper.Stdout, tamper.Stderr)
	}
	if got := strings.Count(string(script.Read(t, f.env["MOCK_BUILD_LOG"])), "compile\n"); got != 2 {
		t.Fatalf("compiles after tamper %d", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unverified cached binary executed")
	}
	if digest(script.Read(t, entries[0])) != digest(script.Read(t, f.binary)) {
		t.Fatal("cache was not repaired")
	}
	if got := strings.Count(string(script.Read(t, f.env["MOCK_PROBE_LOG"])), "\n"); got != 3 {
		t.Fatalf("probe runs %d", got)
	}
}

func TestAdmissionCacheToolchainIdentity(t *testing.T) {
	f := newAdmissionCache(t)
	f.run(t, "first-output")
	before, err := os.ReadDir(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatal("expected one cache key")
	}
	script.Write(t, f.prepare, []byte(strings.ReplaceAll(string(script.Read(t, f.prepare)), "rust_toolchain=1.98.1", "rust_toolchain=1.98.2")), 0o644)
	r := f.run(t, "changed-output")
	if !strings.Contains(r.Stdout, "cache=build") {
		t.Fatal(r.Stdout)
	}
	after, err := os.ReadDir(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Fatalf("cache keys %d", len(after))
	}
	if got := strings.Count(string(script.Read(t, f.env["MOCK_BUILD_LOG"])), "compile\n"); got != 2 {
		t.Fatalf("compiles %d", got)
	}
	if _, err := os.Stat(filepath.Join(f.cache, before[0].Name())); err != nil {
		t.Fatal("prior key lost", err)
	}
}
