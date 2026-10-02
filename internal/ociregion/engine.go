// Package ociregion implements the manual OCI region admission and inspection tools.
package ociregion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"maps"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

type Object = map[string]any

// Dependency permits tests to supply cloud and verification responses without starting processes.
type Dependency func(name string, args []any, kwargs Object) (any, error)
type Engine struct {
	Context    context.Context
	PlanPath   string
	Clock      func() time.Time
	Dependency Dependency
	Overrides  map[string]bool
	Stdout     io.Writer
	Argv       []string
}
type Failure struct {
	Message string
	Kind    string
}

func (f Failure) Error() string { return f.Message }
func fail(s string)             { panic(Failure{s, "ValueError"}) }
func must[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}
func (e *Engine) now() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}
func (e *Engine) ctx() context.Context {
	if e.Context != nil {
		return e.Context
	}
	return context.Background()
}
func obj(v any) Object {
	if v == nil {
		return Object{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	fail("expected an object")
	return nil
}
func arr(v any) []any {
	if v == nil {
		return []any{}
	}
	if a, ok := v.([]any); ok {
		return a
	}
	if a, ok := v.([]string); ok {
		r := make([]any, len(a))
		for i, x := range a {
			r[i] = x
		}
		return r
	}
	fail("expected a list")
	return nil
}
func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case Path:
		return string(x)
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case jsonFloat:
		return strconv.FormatFloat(float64(x), 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Rat:
		return ratText(x)
	}
	return fmt.Sprint(v)
}
func text(v any) string {
	if p, ok := v.(Path); ok {
		return string(p)
	}
	s, _ := v.(string)
	return s
}
func truth(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case Path:
		return string(x) != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case float64:
		return x != 0
	case int:
		return x != 0
	}
	return true
}
func integer(v any) bool {
	switch x := v.(type) {
	case int, int64:
		return true
	case float64:
		return !math.IsNaN(x) && !math.IsInf(x, 0) && math.Trunc(x) == x
	}
	return false
}
func number(v any) float64 {
	if _, ok := v.(bool); ok {
		fail("boolean is not a number")
	}
	f, err := strconv.ParseFloat(str(v), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		fail("invalid numeric amount")
	}
	return f
}
func rat(v any) *big.Rat {
	if _, ok := v.(bool); ok {
		fail("boolean is not a number")
	}
	if r, ok := v.(*big.Rat); ok {
		return new(big.Rat).Set(r)
	}
	r, ok := new(big.Rat).SetString(str(v))
	if !ok {
		fail("invalid numeric amount")
	}
	return r
}
func add(v ...any) *big.Rat {
	r := new(big.Rat)
	for _, x := range v {
		r.Add(r, rat(x))
	}
	return r
}
func sub(a, b any) *big.Rat { return new(big.Rat).Sub(rat(a), rat(b)) }
func mul(v ...any) *big.Rat {
	r := big.NewRat(1, 1)
	for _, x := range v {
		r.Mul(r, rat(x))
	}
	return r
}
func div(a, b any) *big.Rat { return new(big.Rat).Quo(rat(a), rat(b)) }
func greater(a, b any) bool { return rat(a).Cmp(rat(b)) > 0 }
func nonnegative(a any) *big.Rat {
	if rat(a).Sign() < 0 {
		return new(big.Rat)
	}
	return rat(a)
}
func maximum(a, b any) *big.Rat {
	if greater(a, b) {
		return rat(a)
	}
	return rat(b)
}
func ratText(r *big.Rat) string {
	for n := 0; n < 30; n++ {
		s := r.FloatString(n)
		x, _ := new(big.Rat).SetString(s)
		if x.Cmp(r) == 0 {
			return s
		}
	}
	return r.FloatString(28)
}
func fixed(v any, n int) string {
	r := rat(v)
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	num := new(big.Int).Mul(r.Num(), scale)
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(num, r.Denom(), rem)
	twice := new(big.Int).Mul(new(big.Int).Abs(rem), big.NewInt(2))
	cmp := twice.Cmp(r.Denom())
	if cmp > 0 || (cmp == 0 && q.Bit(0) == 1) {
		if r.Sign() < 0 {
			q.Sub(q, big.NewInt(1))
		} else {
			q.Add(q, big.NewInt(1))
		}
	}
	negative := q.Sign() < 0
	s := new(big.Int).Abs(q).String()
	for len(s) <= n {
		s = "0" + s
	}
	if n > 0 {
		s = s[:len(s)-n] + "." + s[len(s)-n:]
	}
	if negative {
		s = "-" + s
	}
	return s
}
func eq(a, b any) bool { return reflect.DeepEqual(normalize(a), normalize(b)) }
func normalize(v any) any {
	switch x := v.(type) {
	case jsonFloat:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case []string:
		return arr(x)
	case Object:
		m := Object{}
		for k, v := range x {
			m[k] = normalize(v)
		}
		return m
	case []any:
		a := make([]any, len(x))
		for i, v := range x {
			a[i] = normalize(v)
		}
		return a
	}
	return v
}
func keys(m Object) []string { return slices.Sorted(maps.Keys(m)) }
func exact(v any, fields ...string) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(fields) {
		return false
	}
	for _, k := range fields {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func contains(v any, x any) bool {
	for _, y := range arr(v) {
		if eq(x, y) {
			return true
		}
	}
	return false
}
func safeMatch(pattern string, v any) bool {
	s, ok := v.(string)
	return ok && regexp.MustCompile("^(?:"+pattern+")$").MatchString(s)
}
func canonical(v any) string { return string(must(json.Marshal(v, json.Deterministic(true)))) }
func orderedRows(v any) []string {
	r := []string{}
	for _, x := range arr(v) {
		r = append(r, canonical(x))
	}
	slices.Sort(r)
	return r
}
func parseTime(v any) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, text(v))
	return t, err == nil
}
func timestamp(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if t.Nanosecond() != 0 {
		s += "." + fmt.Sprintf("%06d", t.Nanosecond()/1000)
	}
	return s + t.Format("Z07:00") /* Python uses +00:00 */
}
func pythonTime(t time.Time) string {
	s := timestamp(t)
	if strings.HasSuffix(s, "Z") {
		return strings.TrimSuffix(s, "Z") + "+00:00"
	}
	return s
}
func rfc3339(t time.Time) string {
	_, offset := t.Zone()
	if offset != 0 {
		fail("budget admission timestamps must be UTC RFC3339 values")
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func fileSHA(path string) string {
	wire := must(os.ReadFile(path))
	h := sha256.Sum256(wire)
	return hex.EncodeToString(h[:])
}
func wireSHA(wire []byte) string { h := sha256.Sum256(wire); return hex.EncodeToString(h[:]) }
func readBytes(path string, limit int, label string) []byte {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		fail(label + " is unreadable or invalid JSON")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		fail(label + " is unreadable or invalid JSON")
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > int64(limit) {
		fail(label + " has invalid size or is not a regular file")
	}
	wire := must(io.ReadAll(io.LimitReader(f, int64(limit+1))))
	if len(wire) == 0 || len(wire) > limit {
		fail(label + " has invalid size")
	}
	return wire
}
func readJSON(path string, limit int, label string) Object {
	wire := readBytes(path, limit, label)
	v, err := decodeJSON(wire)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			fail("JSON document has duplicate fields")
		}
		fail(label + " is unreadable or invalid JSON")
	}
	m, ok := v.(map[string]any)
	if !ok {
		fail(label + " must be an object")
	}
	return m
}
func sourcePath(e *Engine, plan Object) string {
	if p := text(plan["_source_path"]); p != "" {
		return p
	}
	return e.PlanPath
}
func pathValue(v any) string {
	if m, ok := v.(Object); ok {
		if s, ok := m["$path"].(string); ok {
			return s
		}
	}
	return text(v)
}
func (e *Engine) call(name string, args []any, kwargs Object) any {
	if e.Dependency != nil && (name == "oci" || name == "checked_tool" || name == "subprocess.run" || e.Overrides[name]) {
		v, err := e.Dependency(name, args, kwargs)
		if err != nil {
			panic(err)
		}
		return v
	}
	return e.invoke(name, args, kwargs)
}
func (e *Engine) oci(region string, args ...string) any {
	a := make([]any, len(args))
	for i, x := range args {
		a[i] = x
	}
	kw := Object{}
	if region != "" {
		kw["region"] = region
	}
	return e.call("oci", a, kw)
}
func (e *Engine) process(command []string) Object {
	args := []any{arr(command)}
	kw := Object{"capture_output": true, "text": true, "timeout": 180, "check": false}
	if e.Dependency != nil {
		return obj(e.call("subprocess.run", args, kw))
	}
	ctx, cancel := context.WithTimeout(e.ctx(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		panic(ctx.Err())
	}
	code := 0
	if err != nil {
		if cmd.ProcessState == nil {
			panic(err)
		}
		code = cmd.ProcessState.ExitCode()
		if code < 0 {
			panic(err)
		}
	}
	return Object{"args": arr(command), "returncode": code, "stdout": stdout.String(), "stderr": stderr.String()}
}
func (e *Engine) realOCI(args []any, kwargs Object) any {
	if v, ok := e.sdkOCI(args, kwargs); ok {
		return v
	}
	cmd := []string{"oci"}
	for _, x := range args {
		cmd = append(cmd, str(x))
	}
	if truth(kwargs["region"]) {
		cmd = append(cmd, "--region", str(kwargs["region"]))
	}
	cmd = append(cmd, "--output", "json")
	p := e.process(cmd)
	operation := []string{}
	for _, x := range args[:min(3, len(args))] {
		operation = append(operation, str(x))
	}
	if number(p["returncode"]) != 0 {
		fail(fmt.Sprintf("OCI read failed: %s (exit %s)", strings.Join(operation, " "), str(p["returncode"])))
	}
	isObject := len(args) >= 3 && args[0] == "os" && args[1] == "object" && (args[2] == "list" || args[2] == "list-object-versions")
	output := text(p["stdout"])
	if strings.TrimSpace(output) == "" && contains(args, "--all") && !isObject {
		return []any{}
	}
	v, err := decodeJSON([]byte(output))
	if err != nil {
		fail("invalid OCI response for " + strings.Join(operation, " "))
	}
	if isObject && contains(args, "--all") && eq(v, Object{"prefixes": []any{}}) {
		return []any{}
	}
	m, ok := v.(map[string]any)
	if !ok {
		fail("invalid OCI response for " + strings.Join(operation, " "))
	}
	d, ok := m["data"]
	if !ok {
		fail("invalid OCI response for " + strings.Join(operation, " "))
	}
	return d
}

// sdkOCI serves a read in-binary through the OCI Go SDK. It reports false
// only when the CLI backend is selected, or when the auto backend meets a
// command the SDK reader does not serve yet.
func (e *Engine) sdkOCI(args []any, kwargs Object) (any, bool) {
	backend := must(sdkcli.SelectedBackend())
	if backend == sdkcli.BackendCLI {
		return nil, false
	}
	words := make([]string, len(args))
	operation := []string{}
	for i, x := range args {
		words[i] = str(x)
		if i < 3 {
			operation = append(operation, words[i])
		}
	}
	client := must(sdkcli.ForRegion(text(kwargs["region"])))
	data, handled, err := client.Call(e.ctx(), words)
	if !handled {
		if backend == sdkcli.BackendAuto && errors.Is(err, sdkcli.ErrUnsupported) {
			return nil, false
		}
		fail(fmt.Sprintf("OCI read is not served in-binary: %s", strings.Join(operation, " ")))
	}
	if err != nil {
		if ctxErr := e.ctx().Err(); ctxErr != nil {
			panic(ctxErr)
		}
		fail(fmt.Sprintf("OCI read failed: %s", strings.Join(operation, " ")))
	}
	v, err := decodeJSON(data)
	if err != nil {
		fail("invalid OCI response for " + strings.Join(operation, " "))
	}
	return v, true
}

func capture[T any](fn func() T) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("%v", r)
			}
		}
	}()
	return fn(), nil
}
func ReadJSON(path string, limit int, label string) (Object, error) {
	return capture(func() Object { return readJSON(path, limit, label) })
}
func SHA256(path string) (string, error) { return capture(func() string { return fileSHA(path) }) }
func RequireOCID(value any, kind, region string) error {
	_, err := capture(func() bool { requireOCID(value, kind, region); return true })
	return err
}
func RunOCI(ctx context.Context, region string, args ...string) (any, error) {
	e := &Engine{Context: ctx}
	return capture(func() any { return e.oci(region, args...) })
}
func WriteJSON(path string, value any) error {
	_, err := capture(func() bool { writeJSON(path, value); return true })
	return err
}
func writeJSON(path string, value any) {
	must(true, os.MkdirAll(filepath.Dir(path), 0755))
	wire := must(json.Marshal(value, json.Deterministic(true), jsontext.Multiline(true), json.FormatNilMapAsNull(true)))
	wire = append(wire, '\n')
	must(true, os.WriteFile(path+".tmp", wire, 0644))
	must(true, os.Chmod(path+".tmp", 0644))
	must(true, os.Rename(path+".tmp", path))
}
func writeBytes(path string, wire []byte, mode os.FileMode) {
	must(true, os.MkdirAll(filepath.Dir(path), 0755))
	f := must(os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"."))
	defer os.Remove(f.Name())
	must(true, f.Chmod(mode))
	must(f.Write(wire))
	must(true, f.Sync())
	must(true, f.Close())
	must(true, os.Rename(f.Name(), path))
}
