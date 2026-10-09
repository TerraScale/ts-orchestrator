package hostload

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// SamplerConfig names what a host samples.
type SamplerConfig struct {
	// CgroupRoot is the cgroup v2 directory holding one child group per
	// native role (the host runner's role parent). Empty skips role usage.
	CgroupRoot string
	Roles      []string
	// CgroupMount bounds ancestor limit reads; defaults to /sys/fs/cgroup.
	CgroupMount string
	// Filesystems are statfs'd; the fullest one is the host's disk_util.
	Filesystems []observability.FilesystemRole
	// ReadSystem and Now are test seams; they default to /proc and the
	// wall clock.
	ReadSystem func([]observability.FilesystemRole) (observability.SystemView, error)
	Now        func() time.Time
}

type cpuPoint struct {
	usage float64 // CPU seconds (host: busy seconds)
	total float64 // host only: busy+idle seconds
	at    time.Time
	group os.FileInfo // role only: the cgroup directory the counter came from
}

// Sampler turns cumulative counters into per-interval usage. It keeps the
// previous counter per role, so the first sample of a role reports no CPU.
type Sampler struct {
	config SamplerConfig

	mu       sync.Mutex
	host     cpuPoint
	hostSeen bool
	roles    map[string]cpuPoint
}

func NewSampler(config SamplerConfig) *Sampler {
	if config.CgroupMount == "" {
		config.CgroupMount = "/sys/fs/cgroup"
	}
	if config.ReadSystem == nil {
		config.ReadSystem = observability.ReadSystem
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Sampler{config: config, roles: make(map[string]cpuPoint)}
}

// Sample reads the host once. terrabase carries the latest verified load
// block per TerraBase role; roles without one report none. Unreadable
// sources leave their fields nil instead of failing the report.
func (s *Sampler) Sample(terrabase map[string]memberstatus.Load) Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.config.Now()
	report := Report{SchemaVersion: SchemaVersion}
	memTotal := uint64(0)
	if view, err := s.config.ReadSystem(s.config.Filesystems); err == nil {
		memTotal = view.MemTotalBytes
		report.Host.CPUCores = view.CPUCount
		report.Host.MemoryBytes = view.MemTotalBytes
		busy := view.CPUSeconds.Busy()
		total := busy + view.CPUSeconds.Idle + view.CPUSeconds.IOWait
		if s.hostSeen && total > s.host.total && busy >= s.host.usage {
			report.Host.CPU = ratio(busy-s.host.usage, total-s.host.total)
		}
		s.host, s.hostSeen = cpuPoint{usage: busy, total: total, at: now}, true
		if view.MemTotalBytes > 0 && view.MemAvailBytes <= view.MemTotalBytes {
			report.Host.Memory = ratio(float64(view.MemTotalBytes-view.MemAvailBytes), float64(view.MemTotalBytes))
		}
		for _, filesystem := range view.Filesystems {
			if filesystem.SizeBytes == 0 || filesystem.AvailBytes > filesystem.SizeBytes {
				continue
			}
			used := ratio(float64(filesystem.SizeBytes-filesystem.AvailBytes), float64(filesystem.SizeBytes))
			if report.Host.Disk == nil || *used > *report.Host.Disk {
				report.Host.Disk = used
			}
		}
	}
	present := make(map[string]struct{}, len(s.config.Roles))
	for _, role := range s.config.Roles {
		if len(report.Roles) == MaxRoles {
			break
		}
		usage := RoleUsage{Role: role}
		if s.config.CgroupRoot != "" {
			group := filepath.Join(s.config.CgroupRoot, role)
			usage.CPULimit, usage.MemoryLimit, usage.LimitsRead = readLimits(group, s.config.CgroupMount)
			if usage.MemoryLimit != nil && memTotal > 0 {
				limit := min(*usage.MemoryLimit, memTotal)
				usage.MemoryLimit = &limit
			}
			if seconds, identity, ok := readGroupCPUSeconds(group); ok {
				present[role] = struct{}{}
				previous, seen := s.roles[role]
				// A group recreated between samples (a restart or rollout)
				// has a new identity: its counter restarts the baseline even
				// when it already exceeds the old group's counter.
				sameGroup := seen && os.SameFile(previous.group, identity)
				if elapsed := now.Sub(previous.at).Seconds(); sameGroup && elapsed > 0 && seconds >= previous.usage {
					cores := (seconds - previous.usage) / elapsed
					if finiteWithin(cores, MaxCPUCores) {
						usage.CPUCores = &cores
					}
				}
				s.roles[role] = cpuPoint{usage: seconds, at: now, group: identity}
			}
			if memory, ok := readWorkingSet(group); ok && memory <= MaxMemoryBytes && (memTotal == 0 || memory <= memTotal) {
				usage.MemoryBytes = &memory
			}
		}
		if load, ok := terrabase[role]; ok && load.Validate() == nil {
			usage.TerraBase = &load
		}
		if usage.CPUCores != nil || usage.MemoryBytes != nil || usage.TerraBase != nil {
			report.Roles = append(report.Roles, usage)
		}
	}
	// A role whose group vanished (stopped workload) restarts its CPU
	// baseline when it comes back, so a restart never reads as a burst.
	for role := range s.roles {
		if _, ok := present[role]; !ok {
			delete(s.roles, role)
		}
	}
	return report
}

// A nil memory limit with LimitsRead means every ancestor reports "max".
func readLimits(group, mount string) (*float64, *uint64, bool) {
	cpu, err := os.ReadFile(filepath.Join(group, "cpu.max"))
	if err != nil {
		return nil, nil, false
	}
	fields := strings.Fields(string(cpu))
	if len(fields) != 2 {
		return nil, nil, false
	}
	period, err := strconv.ParseFloat(fields[1], 64)
	if err != nil || period <= 0 {
		return nil, nil, false
	}
	var cores *float64
	if fields[0] != "max" {
		quota, err := strconv.ParseFloat(fields[0], 64)
		if err != nil || quota <= 0 || !finiteWithin(quota/period, MaxCPUCores) {
			return nil, nil, false
		}
		value := quota / period
		cores = &value
	}
	group, mount = filepath.Clean(group), filepath.Clean(mount)
	relative, err := filepath.Rel(mount, group)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, nil, false
	}
	controllers, err := os.ReadFile(filepath.Join(mount, "cgroup.controllers"))
	if err != nil || !slices.Contains(strings.Fields(string(controllers)), "memory") {
		return nil, nil, false
	}
	var cap *uint64
	for path := group; ; path = filepath.Dir(path) {
		memory, err := os.ReadFile(filepath.Join(path, "memory.max"))
		// The cgroup v2 filesystem root has no memory.max.
		if err != nil && (path != mount || !errors.Is(err, os.ErrNotExist)) {
			return nil, nil, false
		}
		if err == nil {
			if value := strings.TrimSpace(string(memory)); value != "max" {
				limit, err := strconv.ParseUint(value, 10, 64)
				if err != nil {
					return nil, nil, false
				}
				if cap == nil || limit < *cap {
					cap = &limit
				}
			}
		}
		if path == mount {
			break
		}
	}
	if cap != nil && *cap > MaxMemoryBytes {
		return nil, nil, false
	}
	return cores, cap, true
}

func ratio(numerator, denominator float64) *float64 {
	value := numerator / denominator
	if !fraction(value) {
		value = min(max(value, 0), 1)
	}
	return &value
}

// readGroupCPUSeconds reads a group's counter together with the group's
// identity. The directory is stat'ed before and after the read, so a group
// recreated in between never pairs the new counter with the old identity.
func readGroupCPUSeconds(group string) (float64, os.FileInfo, bool) {
	before, err := os.Stat(group)
	if err != nil {
		return 0, nil, false
	}
	seconds, ok := readCPUSeconds(group)
	if !ok {
		return 0, nil, false
	}
	after, err := os.Stat(group)
	if err != nil || !os.SameFile(before, after) {
		return 0, nil, false
	}
	return seconds, after, true
}

// readCPUSeconds reads usage_usec from a cgroup v2 cpu.stat.
func readCPUSeconds(group string) (float64, bool) {
	value, ok := statField(filepath.Join(group, "cpu.stat"), "usage_usec")
	return float64(value) / 1e6, ok
}

// readWorkingSet is memory.current minus inactive file pages, the memory the
// role cannot give back under pressure.
func readWorkingSet(group string) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(group, "memory.current"))
	if err != nil {
		return 0, false
	}
	current, err := strconv.ParseUint(string(bytes.TrimSpace(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	if inactive, ok := statField(filepath.Join(group, "memory.stat"), "inactive_file"); ok && inactive <= current {
		current -= inactive
	}
	return current, true
}

// statField reads one "key value" line of a cgroup v2 flat-keyed file.
func statField(path, key string) (uint64, bool) {
	file, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, value, found := bytes.Cut(scanner.Bytes(), []byte{' '})
		if !found || string(name) != key {
			continue
		}
		parsed, err := strconv.ParseUint(string(bytes.TrimSpace(value)), 10, 64)
		return parsed, err == nil
	}
	return 0, false
}
