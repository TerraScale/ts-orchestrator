//go:build linux

package execution

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime"
	"slices"
	"strings"
)

// HostCPUProfile identifies only features available on every actual logical CPU.
// A missing per-CPU feature record withholds stateful admission.
func HostCPUProfile() (CPUProfile, error) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return CPUProfile{}, err
	}
	defer file.Close()
	return readCPUProfile(file, runtime.GOARCH)
}

func readCPUProfile(reader io.Reader, architecture string) (CPUProfile, error) {
	if architecture != "amd64" && architecture != "arm64" {
		return CPUProfile{}, ErrUnsafe
	}
	var common map[string]struct{}
	var flags map[string]struct{}
	processor, records, bytes := false, 0, 0
	finish := func() error {
		if !processor && flags == nil {
			return nil
		}
		if !processor || len(flags) == 0 || records >= 65536 {
			return fmt.Errorf("%w: CPU feature record missing or excessive", ErrUnsafe)
		}
		if records == 0 {
			common = flags
		} else {
			for feature := range common {
				if _, ok := flags[feature]; !ok {
					delete(common, feature)
				}
			}
		}
		records++
		processor, flags = false, nil
		return nil
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		bytes += len(line) + 1
		if bytes > 16<<20 {
			return CPUProfile{}, fmt.Errorf("%w: CPU inventory too large", ErrUnsafe)
		}
		if strings.TrimSpace(line) == "" {
			if err := finish(); err != nil {
				return CPUProfile{}, err
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return CPUProfile{}, fmt.Errorf("%w: malformed CPU inventory", ErrUnsafe)
		}
		switch strings.TrimSpace(key) {
		case "processor":
			if processor || strings.TrimSpace(value) == "" {
				return CPUProfile{}, ErrUnsafe
			}
			processor = true
		case "flags", "Features":
			if flags != nil {
				return CPUProfile{}, ErrUnsafe
			}
			flags = make(map[string]struct{})
			for feature := range strings.FieldsSeq(value) {
				for _, character := range feature {
					if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
						return CPUProfile{}, ErrUnsafe
					}
				}
				flags[feature] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return CPUProfile{}, err
	}
	if err := finish(); err != nil {
		return CPUProfile{}, err
	}
	if records == 0 || len(common) == 0 {
		return CPUProfile{}, fmt.Errorf("%w: no common CPU features", ErrUnsafe)
	}
	features := slices.Sorted(maps.Keys(common))
	wire := "terrascale.host-cpu.v1\n" + architecture + "\n" + strings.Join(features, "\n") + "\n"
	return CPUProfile{Architecture: architecture, FeaturesSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(wire)))}, nil
}
