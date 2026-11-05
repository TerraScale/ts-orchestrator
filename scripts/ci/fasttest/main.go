// fasttest runs the unchanged Go short tier, splitting slow packages into
// isolated test processes. It never retries failures or changes lab gates.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const jobs = 24
const packageShards = 6
const cacheLimitBytes = 32 << 30

type event struct {
	Action  string
	Package string
	Test    string  `json:",omitempty"`
	Output  string  `json:",omitempty"`
	Elapsed float64 `json:",omitempty"`
}

type shard struct {
	Package string
	Tests   []string
	Cost    float64
	ID      int
}

type result struct {
	Shard    shard
	Cases    []event
	Problems []string
	Log      string
	Elapsed  float64
}

type estimate struct {
	Package, Pattern string
	Cost             float64
}

// Estimates affect only ordering and packing. Unknown packages and cases
// always remain in the plan. Keep the race scheduler and its semantics separate.
func estimates(data string) []estimate {
	var out []estimate
	for line := range strings.SplitSeq(data, "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "./") {
			continue
		}
		var seconds float64
		parts := strings.Split(fields[2], "/")
		if _, err := fmt.Sscan(parts[len(parts)-1], &seconds); err == nil {
			out = append(out, estimate{strings.TrimPrefix(fields[0], "."), fields[1], seconds})
		}
	}
	return out
}

func plan(packages map[string][]string, hints []estimate) []shard {
	// Plain -short observations, including packages the race planner does not
	// split. All other estimated slow packages also receive six shards.
	heavy := map[string]float64{
		"/internal/app": 70, "/internal/natscell/mesh": 35,
		"/internal/ociregion/publicapi": 35, "/internal/bootstrapstart": 35,
		"/internal/swarmruntime": 20, "/internal/oci": 20,
		"/internal/bootstrapmaterial": 20, "/internal/bootstrapstart/materialsource": 20,
		"/internal/natscell": 20, "/internal/region": 15,
		"/internal/observability": 15, "/internal/edge": 15,
		"/internal/host": 15, "/internal/authority": 12,
	}
	var queue []shard
	for pkg, tests := range packages {
		cost, split := 1.0, false
		for suffix, seconds := range heavy {
			if strings.HasSuffix(pkg, suffix) {
				cost, split = seconds, true
			}
		}
		for _, hint := range hints {
			if strings.HasSuffix(pkg, hint.Package) && hint.Pattern == "-" {
				cost = hint.Cost
				split = split || cost >= 20
			}
		}
		weights := make(map[string]float64)
		for _, test := range tests {
			weights[test] = max(1, cost/float64(max(1, len(tests))))
			for _, hint := range hints {
				if strings.HasSuffix(pkg, hint.Package) && hint.Pattern != "-" {
					if matches, _ := path.Match(hint.Pattern, test); matches {
						weights[test] = max(1, hint.Cost)
						break
					}
				}
			}
		}
		ordered := slices.Clone(tests)
		slices.SortFunc(ordered, func(a, b string) int {
			if weights[a] > weights[b] {
				return -1
			}
			if weights[a] < weights[b] {
				return 1
			}
			return strings.Compare(a, b)
		})
		count := 1
		if split {
			// Keep short packages together: each extra Go invocation repeats
			// package loading, vet and TestMain setup. Split roughly thirty
			// seconds of estimated work per process, up to the existing limit.
			count = min(packageShards, max(1, (int(cost)+29)/30), max(1, len(tests)))
		}
		bins := make([]shard, count)
		for i := range bins {
			bins[i].Package = pkg
		}
		// Internal and external test packages may export the same top-level
		// name. Go lists and executes both; keep their multiplicity and place
		// every occurrence in one shard because -run selects them together.
		assigned := make(map[string]int)
		for _, test := range ordered {
			least := 0
			if previous, ok := assigned[test]; ok {
				least = previous
			} else {
				for i := range bins {
					if bins[i].Cost < bins[least].Cost {
						least = i
					}
				}
				assigned[test] = least
			}
			bins[least].Tests = append(bins[least].Tests, test)
			bins[least].Cost += weights[test]
		}
		for i := range bins {
			slices.Sort(bins[i].Tests)
			bins[i].Cost = max(1, bins[i].Cost)
		}
		queue = append(queue, bins...)
	}
	slices.SortFunc(queue, func(a, b shard) int {
		if a.Cost > b.Cost {
			return -1
		}
		if a.Cost < b.Cost {
			return 1
		}
		if a.Package != b.Package {
			return strings.Compare(a.Package, b.Package)
		}
		return strings.Compare(strings.Join(a.Tests, "|"), strings.Join(b.Tests, "|"))
	})
	for i := range queue {
		queue[i].ID = i
	}
	return queue
}

func command(ctx context.Context, goCommand []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, goCommand[0], append(slices.Clone(goCommand[1:]), args...)...)
	// -cpu bounds the test binary, but not the Go tool or re-executed helpers.
	// Carry the same budget through the whole shard process tree.
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	// Cancellation stops the Go tool and its test binary/helper descendants.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	return cmd
}

func wait(ctx context.Context, cmd *exec.Cmd) error {
	// The reader is closed on cancellation before this call. Kill the still
	// owned process group before reaping its leader, including helpers which
	// ignored the first termination signal.
	if ctx.Err() != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return cmd.Wait()
}

func validatePlan(packages map[string][]string, queue []shard) error {
	seen := make(map[string]map[string]int)
	for _, s := range queue {
		tests, known := packages[s.Package]
		if !known {
			return fmt.Errorf("plan contains unknown package %s", s.Package)
		}
		if seen[s.Package] == nil {
			seen[s.Package] = make(map[string]int)
		}
		for _, name := range s.Tests {
			if !slices.Contains(tests, name) {
				return fmt.Errorf("plan contains unlisted case %s/%s", s.Package, name)
			}
			seen[s.Package][name]++
		}
	}
	for pkg, tests := range packages {
		if seen[pkg] == nil {
			return fmt.Errorf("plan omitted package %s", pkg)
		}
		want := make(map[string]int)
		for _, name := range tests {
			want[name]++
		}
		for name, count := range want {
			if seen[pkg][name] != count {
				return fmt.Errorf("plan case %s/%s occurs %d times, want %d", pkg, name, seen[pkg][name], count)
			}
		}
	}
	// A repeated name cannot span shards: either shard would run every
	// occurrence and violate the actual execution receipt.
	owners := make(map[string]int)
	for i, s := range queue {
		for _, name := range s.Tests {
			key := s.Package + "/" + name
			if owner, ok := owners[key]; ok && owner != i {
				return fmt.Errorf("plan splits repeated case %s across shards", key)
			}
			owners[key] = i
		}
	}
	return nil
}

type testBinary struct{ Path, Dir, SearchPath string }

const binaryMarker = "_TS_FAST_BINARY\t"

func retainWrapper(directory string) (string, error) {
	// Go still builds and vets every package before listing it. Retain the exact
	// executable from that invocation so shards need not reload/vet the graph.
	wrapper := filepath.Join(directory, "retain-test")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nset -eu\nbinary=$(mktemp "+shellQuote(filepath.Join(directory, "test.XXXXXX"))+")\nrm -f \"$binary\"\nln \"$1\" \"$binary\" 2>/dev/null || cp \"$1\" \"$binary\"\nprintf '_TS_FAST_BINARY\\t%s\\t%s\\t%s\\n' \"$binary\" \"$PWD\" \"$PATH\"\nexec \"$@\"\n"), 0700); err != nil {
		return "", err
	}
	return wrapper, nil
}

func discover(ctx context.Context, goCommand []string, directory string, binaries map[string]testBinary) (map[string][]string, error) {
	started := time.Now()
	wrapper, err := retainWrapper(directory)
	if err != nil {
		return nil, err
	}
	cmd := command(ctx, goCommand, "list", "./...")
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("package graph: %w", err)
	}
	packages := make(map[string][]string)
	for _, pkg := range strings.Fields(string(data)) {
		if _, duplicate := packages[pkg]; duplicate {
			return nil, fmt.Errorf("duplicate package %s", pkg)
		}
		packages[pkg] = nil
	}
	if len(packages) == 0 {
		return nil, errors.New("empty package graph")
	}
	fmt.Fprintf(os.Stderr, "fast phase=graph elapsed=%.2fs\n", time.Since(started).Seconds())
	// Listing uses the same package concurrency as execution; GOMAXPROCS
	// bounds each process without reducing the pool to two packages.
	cmd = command(ctx, goCommand, "test", "-short", "-json", "-count=1", fmt.Sprintf("-p=%d", jobs), "-exec", wrapper, "-list", ".", "./...")
	cmd.Stderr = os.Stderr
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	stopRead := context.AfterFunc(ctx, func() { _ = output.Close() })
	defer stopRead()
	// test2json emits long output lines as several events without test names;
	// a retained-binary marker longer than one event must be reassembled.
	pendingLines := make(map[string]*strings.Builder)
	terminal := make(map[string]int)
	var invalid error
	decoder := json.NewDecoder(output)
	for {
		var e event
		err := decoder.Decode(&e)
		if err == io.EOF {
			break
		}
		if err != nil {
			invalid = fmt.Errorf("invalid listing JSON: %w", err)
			_, _ = io.Copy(io.Discard, output)
			break
		}
		if _, exists := packages[e.Package]; !exists {
			invalid = fmt.Errorf("listing unknown package %q", e.Package)
			continue
		}
		if e.Action == "fail" {
			invalid = fmt.Errorf("listing failed for %s", e.Package)
		}
		if e.Action == "pass" || e.Action == "skip" {
			terminal[e.Package]++
		}
		if e.Action != "output" {
			continue
		}
		// test2json splits lines longer than its buffer across several output
		// events; only a trailing newline completes one. Retained-binary
		// markers exceed that buffer whenever PATH is long.
		if pending, ok := pendingLines[e.Package]; ok {
			pending.WriteString(e.Output)
			if !strings.HasSuffix(pending.String(), "\n") {
				continue
			}
			delete(pendingLines, e.Package)
			e.Output = pending.String()
		} else if !strings.HasSuffix(e.Output, "\n") {
			pendingLines[e.Package] = new(strings.Builder)
			pendingLines[e.Package].WriteString(e.Output)
			continue
		}
		name := strings.TrimSpace(e.Output)
		if marker, ok := strings.CutPrefix(name, binaryMarker); ok {
			fields := strings.SplitN(marker, "\t", 3)
			if len(fields) != 3 || !filepath.IsAbs(fields[0]) || !filepath.IsAbs(fields[1]) || filepath.Dir(fields[0]) != directory || binaries[e.Package].Path != "" {
				invalid = fmt.Errorf("invalid retained binary for %s", e.Package)
			} else {
				binaries[e.Package] = testBinary{fields[0], fields[1], fields[2]}
			}
			continue
		}
		if strings.HasPrefix(name, "Benchmark") {
			continue
		}
		if !strings.HasPrefix(name, "Test") && !strings.HasPrefix(name, "Example") && !strings.HasPrefix(name, "Fuzz") {
			continue
		}
		if strings.ContainsAny(name, " \t\r\n/") {
			invalid = fmt.Errorf("invalid listed case %q", name)
			continue
		}
		packages[e.Package] = append(packages[e.Package], name)
	}
	if err := wait(ctx, cmd); err != nil {
		return nil, fmt.Errorf("test listing: %w", err)
	}
	if invalid != nil {
		return nil, invalid
	}
	for pkg := range packages {
		if terminal[pkg] != 1 {
			return nil, fmt.Errorf("listing package %s has %d results, want 1", pkg, terminal[pkg])
		}
	}
	fmt.Fprintf(os.Stderr, "fast phase=list elapsed=%.2fs\n", time.Since(started).Seconds())
	return packages, nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

const cacheFormat = 1

// cacheRoot holds discovery generations under the user cache directory, never
// inside a checkout. FASTTEST_CACHE redirects it in contract tests.
func cacheRoot() string {
	if root := os.Getenv("FASTTEST_CACHE"); root != "" {
		return root
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "ts-orchestrator-fasttest")
	}
	return filepath.Join(base, "ts-orchestrator-fasttest")
}

type pkgInventory struct {
	ImportPath   string
	Dir          string
	GoFiles      []string
	CgoFiles     []string
	TestGoFiles  []string
	XTestGoFiles []string
	EmbedFiles   []string
	HFiles       []string
	SFiles       []string
}

// generationKey fingerprints every input a rebuilt test binary reads: the
// module's whole source inventory, its module pins, the toolchain executable
// and the build-relevant environment. Retained binaries are transitive
// compilation outputs, so their validity is a module-wide property; a
// per-package key would reuse a stale binary after a dependency edit.
func generationKey(ctx context.Context, goCommand []string) string {
	cmd := command(ctx, goCommand, "list", "-json", "./...")
	cmd.Stderr = nil
	data, err := cmd.Output()
	if err != nil {
		return ""
	}
	digest := sha256.New()
	fmt.Fprintln(digest, cacheFormat)
	for _, name := range []string{"GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOTOOLCHAIN"} {
		fmt.Fprintf(digest, "%s=%s\n", name, os.Getenv(name))
	}
	if info, err := os.Stat(goCommand[0]); err == nil {
		fmt.Fprintf(digest, "tool=%s:%d:%d\n", goCommand[0], info.Size(), info.ModTime().UnixNano())
	}
	var packages []pkgInventory
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var pkg pkgInventory
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return ""
		}
		packages = append(packages, pkg)
	}
	slices.SortFunc(packages, func(a, b pkgInventory) int { return strings.Compare(a.ImportPath, b.ImportPath) })
	for _, pkg := range packages {
		fmt.Fprintf(digest, "pkg %s\n", pkg.ImportPath)
		for _, group := range [][]string{pkg.GoFiles, pkg.CgoFiles, pkg.TestGoFiles, pkg.XTestGoFiles, pkg.EmbedFiles, pkg.HFiles, pkg.SFiles} {
			names := slices.Clone(group)
			slices.Sort(names)
			for _, name := range names {
				info, err := os.Stat(filepath.Join(pkg.Dir, name))
				if err != nil {
					return ""
				}
				fmt.Fprintf(digest, "file %s:%d:%d\n", name, info.Size(), info.ModTime().UnixNano())
			}
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for _, name := range []string{"go.mod", "go.sum", "go.work"} {
		info, err := os.Stat(filepath.Join(cwd, name))
		if err != nil {
			continue
		}
		fmt.Fprintf(digest, "module %s:%d:%d\n", name, info.Size(), info.ModTime().UnixNano())
	}
	return hex.EncodeToString(digest.Sum(nil))[:32]
}

type cacheEntry struct {
	Format   int
	Working  string
	Search   string
	Tests    map[string][]string
	Binaries map[string]string
}

// loadCache returns the stored generation only when it is complete: same
// package set, same working directory and every retained binary present.
func loadCache(root, key string, packages map[string][]string) (map[string]testBinary, bool) {
	if key == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(root, key, "entry.json"))
	if err != nil {
		return nil, false
	}
	var entry cacheEntry
	if json.Unmarshal(data, &entry) != nil || entry.Format != cacheFormat {
		return nil, false
	}
	cwd, err := os.Getwd()
	if err != nil || entry.Working != cwd || len(entry.Tests) != len(packages) {
		return nil, false
	}
	binaries := make(map[string]testBinary)
	for pkg, names := range entry.Tests {
		if _, known := packages[pkg]; !known || !slices.Equal(names, packages[pkg]) {
			return nil, false
		}
		relative := entry.Binaries[pkg]
		if relative == "" {
			continue
		}
		path := filepath.Join(root, key, relative)
		if info, err := os.Stat(path); err != nil || info.IsDir() || info.Mode()&0111 == 0 {
			return nil, false
		}
		binaries[pkg] = testBinary{path, entry.Working, entry.Search}
	}
	return binaries, true
}

// storeCache writes one generation atomically and keeps only the newest few,
// bounding the cache far below the dev hosts' spare disk.
func storeCache(root, key string, packages map[string][]string, binaries map[string]testBinary) {
	if key == "" {
		return
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return
	}
	staging, err := os.MkdirTemp(root, ".staging-")
	if err != nil {
		return
	}
	entry := cacheEntry{Format: cacheFormat, Tests: packages, Binaries: map[string]string{}}
	cwd, _ := os.Getwd()
	entry.Working = cwd
	entry.Search = os.Getenv("PATH")
	kept := 0
	for pkg, tests := range packages {
		if len(tests) == 0 && binaries[pkg].Path == "" {
			continue
		}
		binary := binaries[pkg]
		if binary.Path == "" {
			continue
		}
		relative := fmt.Sprintf("test-%04d", kept)
		if err := os.Link(binary.Path, filepath.Join(staging, relative)); err != nil {
			_ = os.RemoveAll(staging)
			return
		}
		entry.Binaries[pkg] = relative
		kept++
	}
	data, err := json.Marshal(entry)
	if err != nil {
		_ = os.RemoveAll(staging)
		return
	}
	if os.WriteFile(filepath.Join(staging, "entry.json"), data, 0o600) != nil {
		_ = os.RemoveAll(staging)
		return
	}
	if os.Rename(staging, filepath.Join(root, key)) != nil {
		_ = os.RemoveAll(staging)
		return
	}
	pruneCache(root, key)
}

func pruneCache(root, keep string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	var generations []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".staging-") {
			_ = os.RemoveAll(filepath.Join(root, entry.Name()))
		} else if entry.IsDir() && len(entry.Name()) == 32 && entry.Name() != keep {
			generations = append(generations, entry)
		}
	}
	slices.SortFunc(generations, func(a, b os.DirEntry) int {
		left, leftErr := a.Info()
		right, rightErr := b.Info()
		if leftErr != rightErr {
			return -1
		}
		return left.ModTime().Compare(right.ModTime())
	})
	for _, stale := range generations[:max(0, len(generations)-2)] {
		_ = os.RemoveAll(filepath.Join(root, stale.Name()))
	}
}

func execute(ctx context.Context, goCommand []string, s shard, directory string) result {
	return executeBinary(ctx, goCommand, s, directory, testBinary{})
}

func executeBinary(ctx context.Context, goCommand []string, s shard, directory string, binary testBinary) result {
	started := time.Now()
	r := result{Shard: s, Log: filepath.Join(directory, fmt.Sprintf("%04d.jsonl", s.ID))}
	log, err := os.Create(r.Log)
	if err != nil {
		r.Problems = append(r.Problems, err.Error())
		return r
	}
	defer log.Close()
	var names []string
	for _, name := range s.Tests {
		names = append(names, regexp.QuoteMeta(name))
	}
	expression := "^$"
	if len(names) != 0 {
		expression = "^(" + strings.Join(names, "|") + ")$"
	}
	cmd := command(ctx, goCommand, "test", "-short", "-json", "-count=1", "-p=1", "-parallel=2", "-cpu=2", "-run", expression, s.Package)
	var source *exec.Cmd
	var input, writer *os.File
	if binary.Path != "" {
		input, writer, err = os.Pipe()
		if err != nil {
			r.Problems = append(r.Problems, err.Error())
			return r
		}
		defer input.Close()
		defer writer.Close()
		// test2json's child-launch mode ignores SIGINT before spawning the
		// executable. Launch it ourselves so tests and helpers retain Go test's
		// signal disposition, and convert only the resulting output stream.
		source = command(ctx, []string{binary.Path},
			"-test.paniconexit0", "-test.v=test2json", "-test.timeout=10m", "-test.short", "-test.count=1", "-test.parallel=2", "-test.cpu=2", "-test.run", expression)
		source.Dir = binary.Dir
		// Replace PATH instead of appending it: a duplicate would shadow the
		// original on the last-wins platforms and drop every later entry.
		source.Env = append(slices.DeleteFunc(source.Env, func(entry string) bool {
			return strings.HasPrefix(entry, "PATH=")
		}), "PATH="+binary.SearchPath)
		source.Stdout, source.Stderr = writer, writer
		cmd = command(ctx, goCommand, "tool", "test2json", "-p", s.Package, "-t")
		cmd.Stdin = input
	}
	cmd.Stderr = log
	output, err := cmd.StdoutPipe()
	if err != nil {
		r.Problems = append(r.Problems, err.Error())
		return r
	}
	if err := cmd.Start(); err != nil {
		r.Problems = append(r.Problems, err.Error())
		return r
	}
	if source != nil {
		err := source.Start()
		_ = input.Close()
		_ = writer.Close()
		if err != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
			r.Problems = append(r.Problems, err.Error())
			return r
		}
	}
	stopRead := context.AfterFunc(ctx, func() { _ = output.Close() })
	defer stopRead()
	runs, ends := make(map[string]int), make(map[string]int)
	expected := make(map[string]int)
	for _, name := range s.Tests {
		expected[name]++
	}
	packageEnd := 0
	// Copy raw JSON while decoding so failures, seed cases and subtests retain
	// their complete evidence, including output from TestMain helpers.
	decoder := json.NewDecoder(io.TeeReader(output, log))
	for {
		var e event
		err := decoder.Decode(&e)
		if err == io.EOF {
			break
		}
		if err != nil {
			r.Problems = append(r.Problems, "invalid execution JSON: "+err.Error())
			_, _ = io.Copy(log, output)
			break
		}
		if e.Package != s.Package {
			r.Problems = append(r.Problems, "unexpected event package: "+e.Package)
			continue
		}
		if e.Test == "" {
			if e.Action == "pass" || e.Action == "skip" || e.Action == "fail" {
				packageEnd++
			}
			if e.Action == "fail" {
				r.Problems = append(r.Problems, "package failed")
			}
			continue
		}
		if e.Action == "pass" || e.Action == "skip" || e.Action == "fail" {
			r.Cases = append(r.Cases, e)
		}
		if e.Action == "fail" {
			r.Problems = append(r.Problems, "case failed: "+e.Test)
		}
		if strings.Contains(e.Test, "/") {
			continue
		}
		if expected[e.Test] == 0 {
			r.Problems = append(r.Problems, "unexpected case: "+e.Test)
		}
		if e.Action == "run" {
			runs[e.Test]++
		}
		if e.Action == "pass" || e.Action == "skip" || e.Action == "fail" {
			ends[e.Test]++
		}
	}
	if source != nil {
		if err := wait(ctx, source); err != nil {
			r.Problems = append(r.Problems, err.Error())
		}
	}
	if err := wait(ctx, cmd); err != nil {
		r.Problems = append(r.Problems, err.Error())
	}
	if packageEnd != 1 {
		r.Problems = append(r.Problems, fmt.Sprintf("package terminal count %d, want 1", packageEnd))
	}
	for name, count := range expected {
		if runs[name] != count || ends[name] != count {
			r.Problems = append(r.Problems, fmt.Sprintf("%s run=%d terminal=%d, want %d each", name, runs[name], ends[name], count))
		}
	}
	r.Elapsed = time.Since(started).Seconds()
	return r
}

func run(ctx context.Context, goCommand []string, hints []estimate, directory string, out io.Writer) error {
	binaries := make(map[string]testBinary)
	defer func() {
		for _, binary := range binaries {
			_ = os.Remove(binary.Path)
		}
		_ = os.Remove(filepath.Join(directory, "retain-test"))
	}()
	root := cacheRoot()
	key := generationKey(ctx, goCommand)
	packages, cached := map[string][]string(nil), false
	if key != "" {
		if data, err := os.ReadFile(filepath.Join(root, key, "entry.json")); err == nil {
			var entry cacheEntry
			if json.Unmarshal(data, &entry) == nil && entry.Format == cacheFormat {
				candidates := entry.Tests
				if binaries, cached = loadCache(root, key, candidates); cached {
					for pkg, tests := range candidates {
						if binaries[pkg].Path == "" && len(tests) > 0 {
							cached = false
							break
						}
					}
					if cached {
						packages = candidates
					}
				}
			}
		}
	}
	fmt.Fprintf(os.Stderr, "fast phase=cache hit=%v key=%s\n", cached, key)
	if !cached {
		discovered, err := discover(ctx, goCommand, directory, binaries)
		if err != nil {
			return err
		}
		packages = discovered
		storeCache(root, key, packages, binaries)
	}
	queue := plan(packages, hints)
	if err := validatePlan(packages, queue); err != nil {
		return err
	}
	cases := 0
	for _, names := range packages {
		cases += len(names)
	}
	fmt.Fprintf(out, "fast plan packages=%d cases=%d shards=%d jobs=%d receipts=%s\n", len(packages), cases, len(queue), jobs, filepath.Join(directory, "receipts.json"))
	work := make(chan shard)
	results := make(chan result, len(queue))
	var workers sync.WaitGroup
	for range min(jobs, len(queue)) {
		workers.Go(func() {
			for s := range work {
				results <- executeBinary(ctx, goCommand, s, directory, binaries[s.Package])
			}
		})
	}
	go func() {
		defer close(work)
		for _, s := range queue {
			select {
			case work <- s:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	var receipts []result
	failed := false
	for r := range results {
		receipts = append(receipts, r)
		status := "ok"
		if len(r.Problems) != 0 {
			status = "FAIL"
			failed = true
		}
		fmt.Fprintf(out, "fast %04d %s cases=%d elapsed=%.2fs %s\n", r.Shard.ID, r.Shard.Package, len(r.Shard.Tests), r.Elapsed, status)
		if len(r.Problems) != 0 {
			fmt.Fprintf(out, "fast errors: %s; log=%s\n", strings.Join(r.Problems, "; "), r.Log)
			if f, err := os.Open(r.Log); err == nil {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					var e event
					if json.Unmarshal(scanner.Bytes(), &e) != nil {
						fmt.Fprintln(out, scanner.Text())
					} else if e.Output != "" {
						fmt.Fprint(out, e.Output)
					}
				}
				_ = f.Close()
			}
		}
	}
	slices.SortFunc(receipts, func(a, b result) int { return a.Shard.ID - b.Shard.ID })
	f, err := os.Create(filepath.Join(directory, "receipts.json"))
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(receipts)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(receipts) != len(queue) {
		return errors.New("incomplete shard receipts")
	}
	if failed {
		return errors.New("Fast failed; no cases were retried")
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Leave time to terminate all shard groups and write failed receipts
	// before ts-ship's independent 299-second execution deadline.
	ctx, cancel := context.WithTimeout(ctx, 270*time.Second)
	defer cancel()
	goCommand := os.Args[1:]
	if len(goCommand) > 0 && goCommand[0] == "--" {
		goCommand = goCommand[1:]
	}
	if len(goCommand) == 0 {
		goCommand = []string{"go"}
	}
	data, err := os.ReadFile("scripts/ci/fasttest/durations.txt")
	if err == nil {
		var directory string
		directory, err = os.MkdirTemp("", "fast-test.")
		if err == nil {
			err = run(ctx, goCommand, estimates(string(data)), directory, os.Stdout)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
