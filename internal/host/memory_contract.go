//go:build linux

package host

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func validateManagedHostMemory(r Registration) error {
	return validateManagedHostMemoryAt(r, "/proc/meminfo", "/proc/self/cgroup", "/sys/fs/cgroup")
}

func validateManagedHostMemoryAt(r Registration, meminfoPath, membershipPath, cgroupRoot string) error {
	meminfo, err := os.ReadFile(meminfoPath)
	if err != nil {
		return fmt.Errorf("read physical memory: %w", err)
	}
	membership, err := os.ReadFile(membershipPath)
	if err != nil {
		return fmt.Errorf("read memory cgroup membership: %w", err)
	}
	physical, err := physicalMemoryBytes(string(meminfo))
	if err != nil {
		return err
	}
	limit, err := ancestorMemoryLimit(cgroupRoot, string(membership))
	if err != nil {
		return err
	}
	available := min(physical, limit)
	reserve := uint64(r.SystemReserveBytes)
	if r.SystemReserveBytes <= 0 || r.Capacity.MemoryBytes <= 0 || reserve > available ||
		uint64(r.Capacity.MemoryBytes) > available-reserve {
		return errors.New("managed allocatable memory plus system reserve exceeds host limit")
	}
	return nil
}

func physicalMemoryBytes(data string) (uint64, error) {
	for line := range strings.SplitSeq(data, "\n") {
		value, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) != 2 || fields[1] != "kB" {
			return 0, errors.New("invalid physical MemTotal")
		}
		kib, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || kib == 0 || kib > math.MaxUint64/1024 {
			return 0, errors.New("invalid physical MemTotal")
		}
		return kib * 1024, nil
	}
	return 0, errors.New("physical MemTotal is absent")
}

func ancestorMemoryLimit(root, membership string) (uint64, error) {
	var relative string
	for line := range strings.SplitSeq(strings.TrimSpace(membership), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		if relative != "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return 0, errors.New("invalid unified memory cgroup membership")
		}
		relative = path
	}
	if relative == "" {
		return 0, errors.New("unified memory cgroup membership is absent")
	}
	root = filepath.Clean(root)
	path := filepath.Join(root, strings.TrimPrefix(relative, "/"))
	limit := uint64(math.MaxUint64)
	for {
		data, err := os.ReadFile(filepath.Join(path, "memory.max"))
		if err != nil {
			return 0, fmt.Errorf("read ancestor memory.max: %w", err)
		}
		value := strings.TrimSpace(string(data))
		if value != "max" {
			bytes, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return 0, errors.New("invalid ancestor memory.max")
			}
			limit = min(limit, bytes)
		}
		if path == root {
			return limit, nil
		}
		parent := filepath.Dir(path)
		if parent == path || len(parent) < len(root) {
			return 0, errors.New("memory cgroup escaped root")
		}
		path = parent
	}
}
