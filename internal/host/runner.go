package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

type Workload struct {
	Role                 string
	Digest               string
	Fingerprint          string
	Executable           string
	Args                 []string
	Env                  map[string]string
	CgroupMemoryMaxBytes uint64 // Zero leaves the role cgroup's default limit unchanged.
	SystemReserveBytes   uint64 // Signed managed reserve; zero for non-managed workloads.
	// DrainTimeout, when nonzero, makes Stop send SIGTERM and wait this long
	// for the workload to exit before its cgroup is killed.
	DrainTimeout time.Duration
}

// WorkloadIdentity is the dedicated, unprivileged identity for every native
// workload on this host. Zero is never a valid production identity.
type WorkloadIdentity struct {
	UID uint32
	GID uint32
}

type Observation struct {
	Role                 string
	Digest               string
	Fingerprint          string
	Running              bool
	PID                  int
	CgroupMemoryMaxBytes uint64
}

// Runner owns native workload processes. Recover must finish before any Apply.
type Runner interface {
	Recover(context.Context) error
	Apply(context.Context, Workload) error
	Stop(context.Context, string) error
	Observe(context.Context, string) (Observation, error)
	Close(context.Context) error
}

type processRecord struct {
	Role        string `json:"role"`
	Digest      string `json:"digest"`
	Fingerprint string `json:"fingerprint"`
	PID         int    `json:"pid"`
	StartTime   string `json:"start_time"`
	DrainMillis int64  `json:"-"` // Recover kills every cgroup; older agents decode the inventory strictly.
}

type processRunner struct {
	root      string
	cgroups   string
	cell      string
	node      string
	identity  WorkloadIdentity
	mu        sync.Mutex
	closeOnce sync.Once
	closing   chan struct{}
	lock      *os.File
	records   map[string]processRecord
	commands  map[string]*exec.Cmd
}

func NewProcessRunner(stateRoot string, identity WorkloadIdentity, cell, node string) Runner {
	return &processRunner{root: stateRoot, cell: cell, node: node, identity: identity, closing: make(chan struct{}), records: make(map[string]processRecord), commands: make(map[string]*exec.Cmd)}
}

func nativeCgroupName(stateRoot string) string {
	hash := sha256.Sum256([]byte(stateRoot))
	return "terrascale-host-" + hex.EncodeToString(hash[:8])
}

func (p *processRunner) Recover(ctx context.Context) error {
	if p.root == "" || !filepath.IsAbs(p.root) {
		return errors.New("native runner requires absolute state root")
	}
	if err := validateWorkloadIdentity(p.identity); err != nil {
		return err
	}
	root, err := nativeCgroupRoot(p.root)
	if err != nil {
		return err
	}
	p.cgroups = root
	if err := os.MkdirAll(p.root, 0700); err != nil {
		return err
	}
	if err := validatePrivateStateRoot(p.root); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(p.root, "owner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return fmt.Errorf("host is already owned: %w", err)
	}
	p.mu.Lock()
	if p.lock != nil {
		p.mu.Unlock()
		lock.Close()
		return errors.New("runner already recovered")
	}
	p.lock = lock
	p.mu.Unlock()
	if err := prepareNativeCgroupRoot(p.cgroups); err != nil {
		return err
	}
	if err := configureTenantCgroupDirectory(p.cgroups, p.identity); err != nil {
		return fmt.Errorf("configure native runner cgroup traversal: %w", err)
	}
	if err := validateTenantCgroupTraversal(p.cgroups, p.identity); err != nil {
		return err
	}
	for _, name := range []string{"cgroup.procs", "cgroup.subtree_control"} {
		if err := validateTenantCgroupControl(filepath.Join(p.cgroups, name), p.identity); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(p.cgroups)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if err := validateToken(entry.Name(), "cgroup role"); err != nil {
			return err
		}
		if err := terminateCgroup(ctx, filepath.Join(p.cgroups, entry.Name())); err != nil {
			return fmt.Errorf("recover native cgroup %s: %w", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(p.cgroups, entry.Name(), "cgroup.freeze"), []byte("0"), 0600); err != nil {
			return fmt.Errorf("unfreeze recovered native cgroup %s: %w", entry.Name(), err)
		}
	}
	data, err := os.ReadFile(filepath.Join(p.root, "inventory.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var records []processRecord
	if err := decodeStrict(data, &records); err != nil {
		return fmt.Errorf("invalid native inventory: %w", err)
	}
	if len(records) > 32 {
		return errors.New("native inventory exceeds role limit")
	}
	for _, record := range records {
		if err := validateToken(record.Role, "inventory role"); err != nil {
			return err
		}
		if err := validateDigest(record.Digest); err != nil {
			return err
		}
		if record.PID < 2 || record.StartTime == "" {
			return errors.New("invalid native inventory process")
		}
		// The cgroup scan above kills descendants even if the recorded leader exited.
	}
	return p.persist()
}

func (p *processRunner) Apply(ctx context.Context, w Workload) error {
	if err := validateToken(w.Role, "role"); err != nil {
		return err
	}
	if err := validateDigest(w.Digest); err != nil {
		return err
	}
	if err := validateDigest(w.Fingerprint); err != nil {
		return fmt.Errorf("invalid workload fingerprint: %w", err)
	}
	if err := validateCgroupMemoryMax(w.CgroupMemoryMaxBytes); err != nil {
		return err
	}
	if !filepath.IsAbs(w.Executable) {
		return errors.New("workload executable must be absolute")
	}
	if err := validateTenantExecutable(w.Executable, p.identity); err != nil {
		return err
	}
	if err := p.Stop(ctx, w.Role); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lock == nil {
		return errors.New("runner is not recovered")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if runnerClosing(p.closing) {
		return errors.New("runner is closing")
	}
	if w.SystemReserveBytes != 0 {
		if err := validateNativeSupervisorReservation(filepath.Dir(p.cgroups), p.cgroups, w.SystemReserveBytes); err != nil {
			return fmt.Errorf("validate managed supervisor reservation: %w", err)
		}
	}
	cgroupPath := filepath.Join(p.cgroups, w.Role)
	// Linux 6.1.155 can compare the host's kill sequence to the target's
	// incremented sequence after cgroup.kill, killing a clone3 child before exec.
	if err := removeEmptyCgroupTree(cgroupPath); err != nil {
		return fmt.Errorf("reset workload cgroup: %w", err)
	}
	if w.CgroupMemoryMaxBytes != 0 {
		if err := enableCgroupMemoryController(p.cgroups); err != nil {
			return fmt.Errorf("enable workload memory controller: %w", err)
		}
	}
	if err := os.MkdirAll(cgroupPath, 0700); err != nil {
		return fmt.Errorf("create workload cgroup: %w", err)
	}
	if w.CgroupMemoryMaxBytes != 0 {
		if err := setCgroupMemoryMax(cgroupPath, w.CgroupMemoryMaxBytes); err != nil {
			return fmt.Errorf("configure workload memory cap: %w", err)
		}
	}
	quota, err := deriveNativeWorkloadCPUQuota(filepath.Dir(p.cgroups))
	if err != nil {
		return fmt.Errorf("derive workload CPU cap: %w", err)
	}
	if err := setNativeCPUMax(filepath.Join(p.cgroups, "cpu.max"), quota); err != nil {
		return fmt.Errorf("configure aggregate workload CPU cap: %w", err)
	}
	if err := configureNativeRoleResources(cgroupPath, quota); err != nil {
		return fmt.Errorf("configure workload resource isolation: %w", err)
	}
	if err := configureTenantCgroupDirectory(cgroupPath, p.identity); err != nil {
		return fmt.Errorf("configure workload cgroup traversal: %w", err)
	}
	if err := validateTenantCgroupControl(filepath.Join(cgroupPath, "cgroup.procs"), p.identity); err != nil {
		return err
	}
	if w.CgroupMemoryMaxBytes != 0 {
		if err := validateTenantCgroupAccounting(cgroupPath, p.identity); err != nil {
			return err
		}
	} else if err := validateTenantCgroupTraversal(cgroupPath, p.identity); err != nil {
		return err
	}
	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return err
	}
	defer cgroup.Close()
	if err := terminateCgroup(ctx, cgroupPath); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if runnerClosing(p.closing) {
		return errors.New("runner is closing")
	}
	target := exec.Command(w.Executable, w.Args...)
	target.Stdout = os.Stdout
	target.Stderr = os.Stderr
	environment := map[string]string{"HOME": "/", "LANG": "C", "PATH": "/usr/bin:/bin"}
	for key, value := range w.Env {
		environment[key] = value
	}
	// Set last, so the workload reports the identity the agent gave it.
	environment["TS_SERVICE"] = w.Role
	environment["TS_REGION"] = p.cell
	environment["TS_NODE"] = p.node
	for key, value := range environment {
		target.Env = append(target.Env, key+"="+value)
	}
	sort.Strings(target.Env)
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
		case <-p.closing:
		case <-watchDone:
			if runnerApplyInterrupted(ctx, p.closing) == nil {
				return
			}
		}
		killCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sealCgroup(killCtx, cgroupPath)
	}()
	cmd, release, waited, err := launchNativeWorkload(ctx, target, cgroup, cgroupPath, p.identity)
	if err != nil {
		return fmt.Errorf("start workload in cgroup v2: %w", err)
	}
	defer release()
	if err := runnerApplyInterrupted(ctx, p.closing); err != nil {
		if stopErr := terminateCgroup(context.Background(), cgroupPath); stopErr != nil {
			_ = cmd.Process.Kill()
		}
		release()
		<-waited
		return err
	}
	start := currentStartTime(cmd.Process.Pid)
	if start == "" {
		if err := terminateCgroup(context.Background(), cgroupPath); err != nil {
			_ = cmd.Process.Kill()
		}
		release()
		<-waited
		return errors.New("cannot identify native process")
	}
	record := processRecord{Role: w.Role, Digest: w.Digest, Fingerprint: w.Fingerprint, PID: cmd.Process.Pid, StartTime: start,
		DrainMillis: w.DrainTimeout.Milliseconds()}
	p.records[w.Role] = record
	p.commands[w.Role] = cmd
	if err := p.persistLocked(); err != nil {
		if stopErr := terminateCgroup(context.Background(), cgroupPath); stopErr != nil {
			_ = cmd.Process.Kill()
		}
		release()
		<-waited
		delete(p.records, w.Role)
		delete(p.commands, w.Role)
		return err
	}
	if err := runnerApplyInterrupted(ctx, p.closing); err != nil {
		if stopErr := terminateCgroup(context.Background(), cgroupPath); stopErr != nil {
			_ = cmd.Process.Kill()
		}
		release()
		<-waited
		delete(p.records, w.Role)
		delete(p.commands, w.Role)
		return errors.Join(err, p.persistLocked())
	}
	release()
	go func() {
		level, result := slog.LevelInfo, "exit status 0"
		if err := <-waited; err != nil {
			level, result = slog.LevelWarn, err.Error()
		}
		slog.Log(ctx, level, "native workload exited", observability.ComponentKey, "host",
			"role", w.Role, "pid", record.PID, "digest", w.Digest[:12], "result", result)
	}()
	return nil
}

func validateCgroupMemoryMax(limit uint64) error {
	if limit == 0 {
		return nil
	}
	page := uint64(os.Getpagesize())
	if limit < page || limit > math.MaxInt64 || limit%page != 0 {
		return errors.New("workload cgroup memory cap must be finite, page-aligned and fit signed 64-bit")
	}
	return nil
}

func enableCgroupMemoryController(parent string) error {
	return enableCgroupController(parent, "memory")
}

func enableCgroupCPUController(parent string) error {
	return enableCgroupController(parent, "cpu")
}

func enableCgroupIOController(parent string) error {
	return enableCgroupController(parent, "io")
}

func enableCgroupController(parent, controller string) error {
	path := filepath.Join(parent, "cgroup.subtree_control")
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := file.WriteString("+" + controller); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	readback, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !slices.Contains(strings.Fields(string(readback)), controller) {
		return fmt.Errorf("kernel cgroup.subtree_control does not include %s: %q", controller, strings.TrimSpace(string(readback)))
	}
	return nil
}

func setCgroupMemoryMax(cgroupPath string, limit uint64) error {
	want := strconv.FormatUint(limit, 10)
	path := filepath.Join(cgroupPath, "memory.max")
	if err := os.WriteFile(path, []byte(want), 0600); err != nil {
		return err
	}
	readback, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(readback)) != want {
		return fmt.Errorf("kernel memory.max readback %q differs from requested %q", strings.TrimSpace(string(readback)), want)
	}
	return nil
}

func readCgroupMemoryMax(cgroupPath string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(cgroupPath, "memory.max"))
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return 0, nil
	}
	limit, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("invalid role memory.max readback")
	}
	return limit, nil
}

// Linux delivers Pdeathsig when the thread that created the child exits.
// Keep that thread alive until Wait so an idle Go thread cannot kill a live workload.
func startWorkloadOnLockedThread(cmd *exec.Cmd) (func(), <-chan error, error) {
	return startWorkloadOnLockedThreadWithCheck(cmd, nil)
}

func startWorkloadOnLockedThreadWithCheck(cmd *exec.Cmd, check func() error) (func(), <-chan error, error) {
	started := make(chan error, 1)
	release := make(chan struct{})
	waited := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if check != nil {
			if err := check(); err != nil {
				started <- err
				return
			}
		}
		err := cmd.Start()
		started <- err
		if err != nil {
			return
		}
		<-release
		waited <- cmd.Wait()
	}()
	if err := <-started; err != nil {
		return nil, nil, err
	}
	return sync.OnceFunc(func() { close(release) }), waited, nil
}

func (p *processRunner) Stop(ctx context.Context, role string) error {
	if err := validateToken(role, "role"); err != nil {
		return err
	}
	p.mu.Lock()
	record, exists := p.records[role]
	p.mu.Unlock()
	if exists && record.DrainMillis > 0 {
		p.drain(ctx, record)
	}
	if err := terminateCgroup(ctx, filepath.Join(p.cgroups, role)); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.records[role] == record {
		delete(p.records, role)
		delete(p.commands, role)
		return p.persistLocked()
	}
	return nil
}

func (p *processRunner) Observe(ctx context.Context, role string) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	p.mu.Lock()
	record, exists := p.records[role]
	p.mu.Unlock()
	if !exists {
		return Observation{Role: role}, nil
	}
	populated, err := cgroupPopulated(filepath.Join(p.cgroups, role))
	if err != nil {
		return Observation{}, err
	}
	running := populated && nativeProcessAliveWithStart(record.PID, record.StartTime)
	observation := Observation{Role: role, Digest: record.Digest, Fingerprint: record.Fingerprint, PID: record.PID, Running: running}
	if running {
		observation.CgroupMemoryMaxBytes, err = readCgroupMemoryMax(filepath.Join(p.cgroups, role))
		if err != nil {
			return Observation{}, err
		}
	}
	return observation, nil
}

func (p *processRunner) Close(ctx context.Context) error {
	p.closeOnce.Do(func() { close(p.closing) })
	var failures []error
	entries, err := os.ReadDir(p.cgroups)
	if err != nil {
		failures = append(failures, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			path := filepath.Join(p.cgroups, entry.Name())
			if err := sealCgroup(ctx, path); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if err := lockRunnerUntil(ctx, &p.mu); err != nil {
		return errors.Join(append(failures, err)...)
	}
	defer p.mu.Unlock()
	removed := false
	for role := range p.records {
		if err := sealCgroup(ctx, filepath.Join(p.cgroups, role)); err != nil {
			failures = append(failures, err)
			continue
		}
		delete(p.records, role)
		delete(p.commands, role)
		removed = true
	}
	if removed && p.lock != nil {
		if err := p.persistLocked(); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) == 0 && p.lock != nil {
		_ = syscall.Flock(int(p.lock.Fd()), syscall.LOCK_UN)
		_ = p.lock.Close()
		p.lock = nil
	}
	return errors.Join(failures...)
}

// Seal the cgroup before waiting for Apply's mutex. A frozen child cannot run
// user code; removing the empty cgroup also makes a late clone3 through an
// already-open cgroup FD fail instead of blocking in a frozen child.
func sealCgroup(ctx context.Context, path string) error {
	freezeErr := os.WriteFile(filepath.Join(path, "cgroup.freeze"), []byte("1"), 0600)
	if errors.Is(freezeErr, os.ErrNotExist) {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := terminateCgroup(ctx, path); err != nil {
			return errors.Join(freezeErr, err)
		}
		err := removeEmptyCgroupTree(path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if !errors.Is(err, syscall.EBUSY) && !errors.Is(err, syscall.ENOTEMPTY) {
			return errors.Join(freezeErr, fmt.Errorf("remove workload cgroup: %w", err))
		}
		select {
		case <-ctx.Done():
			return errors.Join(freezeErr, fmt.Errorf("remove workload cgroup: %w", err), ctx.Err())
		case <-ticker.C:
		}
	}
}

func removeEmptyCgroupTree(path string) error {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			if err := removeEmptyCgroupTree(filepath.Join(path, entry.Name())); err != nil {
				return err
			}
		}
	}
	return os.Remove(path)
}

func runnerClosing(closing <-chan struct{}) bool {
	select {
	case <-closing:
		return true
	default:
		return false
	}
}

func runnerApplyInterrupted(ctx context.Context, closing <-chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runnerClosing(closing) {
		return errors.New("runner is closing")
	}
	return nil
}

func lockRunnerUntil(ctx context.Context, mu *sync.Mutex) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *processRunner) persist() error { p.mu.Lock(); defer p.mu.Unlock(); return p.persistLocked() }

func (p *processRunner) persistLocked() error {
	if p.lock == nil {
		return errors.New("runner is not recovered")
	}
	records := make([]processRecord, 0, len(p.records))
	for _, record := range p.records {
		records = append(records, record)
	}
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(p.root, "inventory-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(p.root, "inventory.json")); err != nil {
		return err
	}
	dir, err := os.Open(p.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func currentStartTime(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 {
		return ""
	}
	fields := strings.Fields(string(data[closing+1:]))
	if len(fields) <= 19 {
		return ""
	}
	return fields[19]
}

func nativeProcessAliveWithStart(pid int, start string) bool {
	if start == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 {
		return false
	}
	fields := strings.Fields(string(data[closing+1:]))
	return len(fields) > 19 && fields[19] == start && fields[0] != "Z" && fields[0] != "X" && fields[0] != "x"
}

func cgroupPopulated(path string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "populated 0" {
			return false, nil
		}
		if line == "populated 1" {
			return true, nil
		}
	}
	return false, errors.New("cgroup.events lacks populated status")
}

func terminateCgroup(ctx context.Context, path string) error {
	populated, err := cgroupPopulated(path)
	if err != nil || !populated {
		return err
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0600); err != nil {
		return fmt.Errorf("kill workload cgroup: %w", err)
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		populated, err := cgroupPopulated(path)
		if err != nil || !populated {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
