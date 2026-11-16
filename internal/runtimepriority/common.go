// Package runtimepriority contains the native, bounded D15 qualification tools.
package runtimepriority

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type Object = map[string]any

const Schema = "terrascale.runtime-priority-pressure/v5"
const AdapterInputSchema = "terrascale.d15.adapter-input/v3"
const AdapterResultSchema = "terrascale.d15.adapter-result/v1"
const ProbeAsset = "terrascale-d15-qualify"
const ProducerJob = "verify/go + artifact/linux-amd64-arm64"
const MaxProbeBytes = 512 << 20
const MemorySampleSchema = "terrascale.d15.memory-usage-sample/v2"
const CgroupRoot = "/sys/fs/cgroup"
const HostUnit = "terrascale-orchestrator-host.service"
const ControllerUnit = "terrascale-orchestrator-controller.service"

// DomainError distinguishes a rejected qualification from an implementation failure.
type DomainError struct{ Domain, Message string }

func (e *DomainError) Error() string { return e.Message }
func fail(format string, a ...any)   { panic(&DomainError{"HarnessError", fmt.Sprintf(format, a...)}) }
func qfail(format string, a ...any) {
	panic(&DomainError{"QualificationError", fmt.Sprintf(format, a...)})
}
func recoverError(err *error) {
	if p := recover(); p != nil {
		if e, ok := p.(error); ok {
			if _, domain := errors.AsType[*DomainError](e); domain {
				*err = errors.Join(*err, e)
				return
			}
		}
		panic(p)
	}
}

func Hash(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }

func str(o Object, k string) string { s, _ := o[k].(string); return s }
func num(v any, label string, minimum int64) int64 {
	var n int64
	switch x := v.(type) {
	case int:
		n = int64(x)
	case int64:
		n = x
	case uint64:
		if x > 1<<63-1 {
			fail("%s is outside integer range", label)
		}
		n = int64(x)
	case float64:
		n = int64(x)
		if float64(n) != x {
			fail("%s must be an integer", label)
		}
	case float32:
		n = int64(x)
	default:
		fail("%s must be an integer", label)
	}
	if n < minimum {
		fail("%s must be an integer >= %d", label, minimum)
	}
	return n
}
func n(o Object, k string) int64 { return num(o[k], k, 0) }

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func inside(path, root string) bool {
	rel, e := filepath.Rel(root, path)
	return e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../")
}
