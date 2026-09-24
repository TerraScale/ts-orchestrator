package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Workload struct {
	Role        string
	Digest      string
	Fingerprint string
	Executable  string
	Args        []string
	Env         map[string]string
}

type Observation struct {
	Role        string
	Digest      string
	Fingerprint string
	Running     bool
	PID         int
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
}

type processRunner struct {
	root     string
	cgroups  string
	mu       sync.Mutex
	lock     *os.File
	records  map[string]processRecord
	commands map[string]*exec.Cmd
}

func NewProcessRunner(stateRoot string) Runner {
	hash := sha256.Sum256([]byte(stateRoot))
	return &processRunner{root: stateRoot, cgroups: filepath.Join("/sys/fs/cgroup", "terrascale-host-"+hex.EncodeToString(hash[:8])), records: make(map[string]processRecord), commands: make(map[string]*exec.Cmd)}
}

func (p *processRunner) Recover(ctx context.Context) error {
	if p.root == "" || !filepath.IsAbs(p.root) {
		return errors.New("native runner requires absolute state root")
	}
	if err := os.MkdirAll(p.root, 0700); err != nil {
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
	if err := os.MkdirAll(p.cgroups, 0700); err != nil {
		return fmt.Errorf("writable cgroup v2 is required: %w", err)
	}
	if _, err := os.Stat(filepath.Join(p.cgroups, "cgroup.controllers")); err != nil {
		return fmt.Errorf("cgroup v2 is required: %w", err)
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
	if !filepath.IsAbs(w.Executable) {
		return errors.New("workload executable must be absolute")
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
	cgroupPath := filepath.Join(p.cgroups, w.Role)
	if err := os.MkdirAll(cgroupPath, 0700); err != nil {
		return fmt.Errorf("create workload cgroup: %w", err)
	}
	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return err
	}
	defer cgroup.Close()
	if err := terminateCgroup(ctx, cgroupPath); err != nil {
		return err
	}
	cmd := exec.Command(w.Executable, w.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	for key, value := range w.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start workload in cgroup v2: %w", err)
	}
	start := currentStartTime(cmd.Process.Pid)
	if start == "" {
		_ = terminateCgroup(context.Background(), cgroupPath)
		_ = cmd.Wait()
		return errors.New("cannot identify native process")
	}
	record := processRecord{Role: w.Role, Digest: w.Digest, Fingerprint: w.Fingerprint, PID: cmd.Process.Pid, StartTime: start}
	p.records[w.Role] = record
	p.commands[w.Role] = cmd
	if err := p.persistLocked(); err != nil {
		_ = terminateCgroup(context.Background(), cgroupPath)
		_ = cmd.Wait()
		delete(p.records, w.Role)
		delete(p.commands, w.Role)
		return err
	}
	go func() {
		result := "exit status 0"
		if err := cmd.Wait(); err != nil {
			result = err.Error()
		}
		fmt.Fprintf(os.Stderr, "native workload exited role=%s pid=%d digest=%s result=%q\n", w.Role, record.PID, w.Digest[:12], result)
	}()
	return nil
}

func (p *processRunner) Stop(ctx context.Context, role string) error {
	if err := validateToken(role, "role"); err != nil {
		return err
	}
	p.mu.Lock()
	record, exists := p.records[role]
	p.mu.Unlock()
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
	return Observation{Role: role, Digest: record.Digest, Fingerprint: record.Fingerprint, PID: record.PID, Running: populated}, nil
}

func (p *processRunner) Close(ctx context.Context) error {
	p.mu.Lock()
	roles := make([]string, 0, len(p.records))
	for role := range p.records {
		roles = append(roles, role)
	}
	p.mu.Unlock()
	var failures []error
	entries, err := os.ReadDir(p.cgroups)
	if err != nil {
		failures = append(failures, err)
	}
	for _, entry := range entries {
		if entry.IsDir() && !slices.Contains(roles, entry.Name()) {
			roles = append(roles, entry.Name())
		}
	}
	for _, role := range roles {
		if err := p.Stop(ctx, role); err != nil {
			failures = append(failures, err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(failures) == 0 && p.lock != nil {
		_ = syscall.Flock(int(p.lock.Fd()), syscall.LOCK_UN)
		_ = p.lock.Close()
		p.lock = nil
	}
	return errors.Join(failures...)
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
