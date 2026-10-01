// Package runtimepriority contains the native, bounded D15 qualification tools.
package runtimepriority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/unix"
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
func ErrorType(err error) string {
	if e, ok := errors.AsType[*DomainError](err); ok {
		return e.Domain
	}
	return "error"
}
func Hash(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }
func Canonical(value any) []byte {
	b, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		fail("cannot encode canonical JSON: %v", err)
	}
	first := bytes.IndexFunc(b, func(r rune) bool { return r > 127 })
	if first == -1 {
		return b
	}
	// Preserve the existing evidence schema's Python ensure_ascii hash contract.
	ascii := append(make([]byte, 0, len(b)), b[:first]...)
	for _, r := range string(b[first:]) {
		switch {
		case r <= 127:
			ascii = append(ascii, byte(r))
		case r <= 0xffff:
			ascii = appendCanonicalEscape(ascii, r)
		default:
			high, low := utf16.EncodeRune(r)
			ascii = appendCanonicalEscape(ascii, high)
			ascii = appendCanonicalEscape(ascii, low)
		}
	}
	return ascii
}

func appendCanonicalEscape(dst []byte, r rune) []byte {
	const hex = "0123456789abcdef"
	return append(dst, '\\', 'u', hex[(r>>12)&15], hex[(r>>8)&15], hex[(r>>4)&15], hex[r&15])
}
func obj(v any, label string) Object {
	o, ok := v.(map[string]any)
	if !ok {
		fail("%s must be an object", label)
	}
	return o
}
func sub(o Object, key string) Object { return obj(o[key], key) }
func text(v any, label string) string {
	s, ok := v.(string)
	if !ok || s == "" {
		fail("%s must be nonempty text", label)
	}
	return s
}
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
func same(a, b any) bool         { return string(Canonical(a)) == string(Canonical(b)) }
func exact(o Object, keys ...string) bool {
	if len(o) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := o[k]; !ok {
			return false
		}
	}
	return true
}
func utcNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }
func timestamp(v any, label string) time.Time {
	s := text(v, label)
	if !strings.HasSuffix(s, "Z") {
		fail("%s must be an RFC3339 UTC timestamp ending in Z", label)
	}
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil {
		fail("%s is not a valid RFC3339 UTC timestamp", label)
	}
	return t
}

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var gitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var decimalRE = regexp.MustCompile(`^[0-9]+$`)

func inside(path, root string) bool {
	rel, e := filepath.Rel(root, path)
	return e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../")
}
func safePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.Contains(path, "/../")
}
func readNoFollow(path string, maximum int64) ([]byte, os.FileInfo, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return nil, nil, e
	}
	if !before.Mode().IsRegular() || before.Size() > maximum {
		return nil, nil, fmt.Errorf("%s must be a regular file no larger than %d bytes", path, maximum)
	}
	wire, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil {
		return nil, nil, e
	}
	after, e := f.Stat()
	if e != nil {
		return nil, nil, e
	}
	named, e := os.Lstat(path)
	if e != nil {
		return nil, nil, e
	}
	if int64(len(wire)) > maximum || !os.SameFile(before, after) || !os.SameFile(before, named) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, nil, fmt.Errorf("%s changed during readback", path)
	}
	return wire, before, nil
}
func LoadJSON(path string, maximum int64) (Object, []byte, error) {
	wire, _, e := readNoFollow(path, maximum)
	if e != nil {
		return nil, nil, e
	}
	var o Object
	e = json.Unmarshal(wire, &o)
	if e != nil {
		return nil, nil, fmt.Errorf("%s invalid JSON: %w", path, e)
	}
	if o == nil {
		return nil, nil, fmt.Errorf("%s must be a JSON object", path)
	}
	return o, wire, nil
}
func load(path string, maximum int64) (Object, []byte) {
	o, b, e := LoadJSON(path, maximum)
	if e != nil {
		fail("%v", e)
	}
	return o, b
}
func VerifyPinnedFile(path, hash, label string, executable bool) (err error) {
	defer recoverError(&err)
	verifyPin(path, hash, label, executable)
	return
}
func verifyPin(path, hash, label string, executable bool) {
	if !filepath.IsAbs(path) || !hashRE.MatchString(hash) {
		fail("%s requires an absolute path and exact SHA-256", label)
	}
	maximum := int64(16 << 20)
	if executable {
		maximum = MaxProbeBytes
	}
	b, m, e := readNoFollow(path, maximum)
	if e != nil {
		fail("%s pinned source file is unavailable: %v", label, e)
	}
	if Hash(b) != hash {
		fail("%s pinned source file SHA-256 differs", label)
	}
	if executable && (m.Mode().Perm()&0111 == 0 || m.Mode().Perm()&0022 != 0) {
		fail("%s must be an executable without group/world write", label)
	}
}
func privateFile(path, label string) {
	b, m, e := readNoFollow(path, 16<<20)
	if e != nil || len(b) == 0 {
		fail("%s private file unavailable: %v", label, e)
	}
	st := m.Sys().(*syscall.Stat_t)
	if m.Mode().Perm()&0077 != 0 || m.Mode().Perm()&0400 == 0 || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) {
		fail("%s must be a current-user-owned private regular file with one link", label)
	}
}
func pinReason(o Object, p, h, label string, executable bool, reasons *[]string) {
	if e := VerifyPinnedFile(str(o, p), str(o, h), label, executable); e != nil {
		*reasons = append(*reasons, e.Error())
	}
}
func writeJSON(path string, v any, exclusive bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if exclusive {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	fd, e := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	b, e := json.Marshal(v, json.Deterministic(true))
	if e != nil {
		return e
	}
	if _, e = f.Write(append(b, '\n')); e != nil {
		return e
	}
	return f.Sync()
}
func parseProperties(raw, label string) Object {
	o := Object{}
	for line := range strings.SplitSeq(strings.TrimSpace(raw), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			fail("%s malformed systemd property", label)
		}
		if _, exists := o[k]; exists {
			fail("%s repeats systemd property %s", label, k)
		}
		o[k] = v
	}
	return o
}
func readText(path string, maximum int64) string {
	b, _, e := readNoFollow(path, maximum)
	if e != nil {
		fail("cannot read %s: %v", path, e)
	}
	return string(b)
}
func integerText(raw, label string) int64 {
	s := strings.TrimSpace(raw)
	if !decimalRE.MatchString(s) {
		fail("%s is not decimal bytes", label)
	}
	v, e := strconv.ParseInt(s, 10, 64)
	if e != nil {
		fail("%s outside signed range", label)
	}
	return v
}
func clone(o Object) Object { return maps.Clone(o) }
