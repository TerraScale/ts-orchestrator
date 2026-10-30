// fasttest runs the unchanged Go short tier, splitting slow packages into
// isolated test processes. It never retries failures or changes lab gates.
package main

import (
	"bufio"
	"context"
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

const jobs = 12
const packageShards = 6

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
		"/internal/app": 170, "/internal/natscell": 85,
		"/internal/natscell/mesh": 170, "/internal/region": 180,
		"/internal/bootstrapstart": 90, "/internal/swarmruntime": 90,
		"/internal/observability": 75, "/internal/ociregion/publicapi": 85,
		"/internal/edge": 75, "/internal/host": 70,
		"/internal/foundationbinding": 40, "/internal/delivery": 30,
		"/internal/kvsnapshot": 25, "/internal/netbird/client": 25,
		"/internal/ociresource/lb": 30, "/internal/ociresource/nlb": 25,
		"/tests/deploy": 180,
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
			count = min(packageShards, max(1, len(tests)))
		}
		bins := make([]shard, count)
		for i := range bins {
			bins[i].Package = pkg
		}
		for _, test := range ordered {
			least := 0
			for i := range bins {
				if bins[i].Cost < bins[least].Cost {
					least = i
				}
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
	// Cancellation stops the Go tool and its test binary/helper descendants.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	return cmd
}

func discover(ctx context.Context, goCommand []string) (map[string][]string, error) {
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
	cmd = command(ctx, goCommand, "test", "-short", "-json", "-list", ".", "./...")
	cmd.Stderr = os.Stderr
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	terminal := make(map[string]int)
	seen := make(map[string]bool)
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
		name := strings.TrimSpace(e.Output)
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
		key := e.Package + "/" + name
		if seen[key] {
			invalid = fmt.Errorf("duplicate listed case %s", key)
			continue
		}
		seen[key] = true
		packages[e.Package] = append(packages[e.Package], name)
	}
	if err := cmd.Wait(); err != nil {
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
	return packages, nil
}

func execute(ctx context.Context, goCommand []string, s shard, directory string) result {
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
	runs, ends := make(map[string]int), make(map[string]int)
	expected := make(map[string]bool)
	for _, name := range s.Tests {
		expected[name] = true
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
		if !expected[e.Test] {
			r.Problems = append(r.Problems, "unexpected case: "+e.Test)
		}
		if e.Action == "run" {
			runs[e.Test]++
		}
		if e.Action == "pass" || e.Action == "skip" || e.Action == "fail" {
			ends[e.Test]++
		}
	}
	if err := cmd.Wait(); err != nil {
		r.Problems = append(r.Problems, err.Error())
	}
	if packageEnd != 1 {
		r.Problems = append(r.Problems, fmt.Sprintf("package terminal count %d, want 1", packageEnd))
	}
	for _, name := range s.Tests {
		if runs[name] != 1 || ends[name] != 1 {
			r.Problems = append(r.Problems, fmt.Sprintf("%s run=%d terminal=%d, want exactly one each", name, runs[name], ends[name]))
		}
	}
	r.Elapsed = time.Since(started).Seconds()
	return r
}

func run(ctx context.Context, goCommand []string, hints []estimate, directory string, out io.Writer) error {
	packages, err := discover(ctx, goCommand)
	if err != nil {
		return err
	}
	queue := plan(packages, hints)
	fmt.Fprintf(out, "fast plan packages=%d shards=%d jobs=%d receipts=%s\n", len(packages), len(queue), jobs, filepath.Join(directory, "receipts.json"))
	work := make(chan shard)
	results := make(chan result, len(queue))
	var workers sync.WaitGroup
	for range min(jobs, len(queue)) {
		workers.Go(func() {
			for s := range work {
				results <- execute(ctx, goCommand, s, directory)
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
	goCommand := os.Args[1:]
	if len(goCommand) > 0 && goCommand[0] == "--" {
		goCommand = goCommand[1:]
	}
	if len(goCommand) == 0 {
		goCommand = []string{"go"}
	}
	data, err := os.ReadFile("scripts/ci/racetest/race-durations.txt")
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
