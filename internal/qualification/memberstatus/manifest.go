// Package memberstatus qualifies signed native member status in an isolated
// Firecracker guest, retaining bounded evidence and owned-resource cleanup.
package memberstatus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/qualification/firecracker"
)

type Object = map[string]any

const ManagedVolumeProfile = "managed-volume-v1"
const GoTestName = "TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery"
const RustTestName = "member_control_managed::managed_member_status_cross_language_process_boundary"
const ManagedVolumeGoTestName = "TestManagedRuntimeFirecrackerMountedVolume"
const ManagedVolumeUUID = "76f1b43d-7d79-4f41-9a6e-cc1f4aaab102"
const ManagedVolumeImageSizeBytes = 256 << 20
const ManagedVolumeDriveID = "managed_volume"
const MemberDir = "/srv/ts-managed/6efe9447512debbf02bcd921c78d666c"
const MountPath = MemberDir + "/volume"
const MaterialPath = MemberDir + "/material"
const ControlPath = MemberDir + "/control"
const ManagedVolumeSetupService = "ts-member-status-managed-volume-setup.service"
const ManagedVolumeSetupScriptPath = "/usr/local/sbin/ts-member-status-managed-volume-setup"
const ManagedVolumeBlkidPath = "/usr/sbin/blkid"
const MemberStatusSuccess = "MEMBER_STATUS_GO_OK"
const SenderSuccess = "memberstatus: authenticated Go client accepted real sender-enabled process"
const RunnerPrefix = "MEMBER_STATUS_QUALIFICATION_RESULT="
const RunnerSuccess = RunnerPrefix + "PASS"
const VolumeRunnerPrefix = "TS_MANAGED_VOLUME_QUALIFICATION_RESULT="
const VolumeRunnerSuccess = VolumeRunnerPrefix + "PASS"
const ServiceName = "ts-member-status-qualification.service"
const BootArgs = "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw systemd.unit=multi-user.target"
const GuestRAMMiB = 6144
const GuestVCPUs = 2
const GuestDeadlineSeconds = 300
const GuestServiceTimeoutSeconds = 270
const GoTestTimeout = "120s"
const MaxCommandLogBytes = 8 << 20
const MaxSerialLogBytes = 32 << 20
const MaxGuestLogBytes = 8 << 20
const ImageMinBytes = 8 << 30
const CapabilityBoundingSet = "CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP"
const ManagedVolumeCapabilityBoundingSet = CapabilityBoundingSet + " CAP_DAC_READ_SEARCH"

var InputNames = []string{"kernel", "rootfs", "firecracker", "go_host_test", "memberstatus_probe", "rust_server", "rust_test"}
var ManagedVolumeInputNames = []string{"kernel", "rootfs", "firecracker", "go_host_test", "volume_ext4", "authority_tbca", "trusted_public_key", "server_crt", "server_key", "client_ca_pem", "client_managed_manifest", "client_config", "client_chain", "client_private_key", "client_api_keys"}

func obj(v any) Object              { m, _ := v.(map[string]any); return m }
func str(m Object, k string) string { s, _ := m[k].(string); return s }
func shaBytes(b []byte) string      { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validHex(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func LoadManifest(path string) (Object, []byte, map[string]string, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, nil, e
	}
	var m Object
	if e = json.Unmarshal(raw, &m); e != nil {
		return nil, nil, nil, e
	}
	if m == nil {
		return nil, nil, nil, fmt.Errorf("manifest root must be an object")
	}
	commits := obj(m["source_commits"])
	if !validHex(str(commits, "orchestrator"), 40, 64) || !validHex(str(commits, "terrabase"), 40, 64) {
		return nil, nil, nil, fmt.Errorf("source_commits must contain full orchestrator and terrabase commit IDs")
	}
	names := InputNames
	profile, hasProfile := m["profile"]
	if !hasProfile {
		if str(m, "rust_test_name") != RustTestName {
			return nil, nil, nil, fmt.Errorf("rust_test_name must select the reviewed test %s", RustTestName)
		}
		if _, ok := m["go_test_name"]; ok {
			return nil, nil, nil, fmt.Errorf("legacy manifest cannot include managed-volume profile fields")
		}
		if _, ok := m["managed_volume"]; ok {
			return nil, nil, nil, fmt.Errorf("legacy manifest cannot include managed-volume profile fields")
		}
	} else if profile == ManagedVolumeProfile {
		names = ManagedVolumeInputNames
		if _, ok := m["rust_test_name"]; ok {
			return nil, nil, nil, fmt.Errorf("managed-volume manifest must not include rust_test_name")
		}
		if m["go_test_name"] != ManagedVolumeGoTestName {
			return nil, nil, nil, fmt.Errorf("go_test_name must select the reviewed test %s", ManagedVolumeGoTestName)
		}
		volume := obj(m["managed_volume"])
		if len(volume) != 1 || volume["filesystem_uuid"] != ManagedVolumeUUID {
			return nil, nil, nil, fmt.Errorf("managed_volume must pin filesystem_uuid %s", ManagedVolumeUUID)
		}
	} else {
		return nil, nil, nil, fmt.Errorf("unsupported qualification profile: %v", profile)
	}
	inputs := obj(m["inputs"])
	if len(inputs) != len(names) {
		return nil, nil, nil, fmt.Errorf("manifest inputs must contain exactly %v", names)
	}
	resolved := map[string]string{}
	identity := Object{}
	for _, name := range names {
		r := obj(inputs[name])
		expected := str(r, "sha256")
		supplied := str(r, "path")
		if !validHex(expected, 64, 64) {
			return nil, nil, nil, fmt.Errorf("input %s has an invalid sha256", name)
		}
		if !filepath.IsAbs(supplied) {
			return nil, nil, nil, fmt.Errorf("input %s path must be absolute", name)
		}
		actual, e := filepath.EvalSymlinks(supplied)
		if e != nil {
			return nil, nil, nil, e
		}
		info, e := os.Stat(actual)
		if e != nil {
			return nil, nil, nil, e
		}
		if !info.Mode().IsRegular() {
			return nil, nil, nil, fmt.Errorf("input %s is not a regular file", name)
		}
		digest, e := firecracker.Digest(actual)
		if e != nil {
			return nil, nil, nil, e
		}
		if digest != expected {
			return nil, nil, nil, fmt.Errorf("input %s SHA-256 mismatch", name)
		}
		if slices.Contains([]string{"firecracker", "go_host_test", "memberstatus_probe", "rust_server", "rust_test"}, name) && info.Mode().Perm()&0111 == 0 {
			return nil, nil, nil, fmt.Errorf("input %s is not executable", name)
		}
		resolved[name] = actual
		identity[name] = Object{"supplied_path": supplied, "resolved_path": actual, "sha256": digest, "size_bytes": info.Size()}
	}
	m = maps.Clone(m)
	m["inputs"] = identity
	m["profile"] = profile
	if !hasProfile {
		m["go_test_name"] = GoTestName
	}
	return m, raw, resolved, nil
}
func lines(s string) []string {
	var result []string
	for line := range strings.SplitSeq(strings.TrimSuffix(s, "\n"), "\n") {
		result = append(result, strings.TrimSpace(line))
	}
	return result
}
func ParseGoTestOutput(output string, code int, name string) (Object, error) {
	var runs, passed []string
	skipped, failed, terminal := 0, 0, 0
	ls := lines(output)
	for _, line := range ls {
		if v, ok := strings.CutPrefix(line, "=== RUN   "); ok {
			runs = append(runs, v)
		}
		if v, ok := strings.CutPrefix(line, "--- PASS: "); ok {
			v, _, _ = strings.Cut(v, " (")
			passed = append(passed, v)
		}
		if strings.HasPrefix(line, "--- SKIP:") {
			skipped++
		}
		if strings.HasPrefix(line, "--- FAIL:") {
			failed++
		}
		if line == "PASS" {
			terminal++
		}
	}
	if code != 0 {
		return nil, fmt.Errorf("focused Go test exited %d", code)
	}
	if !slices.Equal(runs, []string{name}) {
		return nil, fmt.Errorf("focused Go test must run exactly %s; observed %v", name, runs)
	}
	if !slices.Equal(passed, []string{name}) || skipped != 0 || failed != 0 {
		return nil, fmt.Errorf("focused Go test result was not one explicit PASS")
	}
	if terminal != 1 || len(ls) == 0 || ls[len(ls)-1] != "PASS" {
		return nil, fmt.Errorf("focused Go test omitted its single terminal PASS result")
	}
	return Object{"name": name, "status": "PASS", "runs": 1, "skips": 0}, nil
}

var rustSummary = regexp.MustCompile(`^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in .+$`)
var rustRunning = regexp.MustCompile(`^running ([0-9]+) tests?$`)
var rustLine = regexp.MustCompile(`^test (.+?) \.\.\.`)

func ParseRustTestOutput(output string, code int, name string) (Object, error) {
	var running, testLines []string
	var summaries [][]string
	for _, line := range lines(output) {
		if m := rustRunning.FindStringSubmatch(line); m != nil {
			running = append(running, m[1])
		}
		if m := rustLine.FindStringSubmatch(line); m != nil {
			testLines = append(testLines, m[1])
		}
		if m := rustSummary.FindStringSubmatch(line); m != nil {
			summaries = append(summaries, m)
		}
	}
	if code != 0 {
		return nil, fmt.Errorf("Rust member-status test exited %d", code)
	}
	if !slices.Equal(running, []string{"1"}) || !slices.Equal(testLines, []string{name}) {
		return nil, fmt.Errorf("Rust test must run exactly %s", name)
	}
	if len(summaries) != 1 {
		return nil, fmt.Errorf("Rust test must report one result summary")
	}
	s := summaries[0]
	if s[1] != "ok" || s[2] != "1" || s[3] != "0" || s[4] != "0" || s[5] != "0" {
		return nil, fmt.Errorf("Rust test did not report one non-ignored pass")
	}
	if strings.Count(output, MemberStatusSuccess) != 1 {
		return nil, fmt.Errorf("Rust test must include exactly one nested %s marker", MemberStatusSuccess)
	}
	if strings.Count(output, SenderSuccess) != 1 {
		return nil, fmt.Errorf("Rust test output must include the current sender-enabled Go probe success marker exactly once")
	}
	r := Object{"name": name, "status": "PASS", "runs": 1, "skips": 0, "nested_go_marker": MemberStatusSuccess, "sender_marker": SenderSuccess}
	for i, k := range []string{"passed", "failed", "ignored", "measured", "filtered"} {
		n, e := strconv.Atoi(s[i+2])
		if e != nil {
			return nil, e
		}
		r[k] = n
	}
	return r, nil
}

var serialService = regexp.MustCompile(`^\[\s*[0-9]+(?:\.[0-9]+)?\]\s+ts-member-status-qualification\[[0-9]+\]: (.*)$`)

func serialPayload(s string) []string {
	ls := lines(s)
	for i, line := range ls {
		if m := serialService.FindStringSubmatch(line); m != nil {
			ls[i] = m[1]
		}
	}
	return ls
}
func ParseRunnerResult(serial string, managed bool) (Object, error) {
	prefix, success := RunnerPrefix, RunnerSuccess
	stages := []string{"go-host-test", "rust-test", "runner"}
	if managed {
		prefix, success = VolumeRunnerPrefix, VolumeRunnerSuccess
		stages = []string{"go-host-test", "runner"}
	}
	var results []string
	for _, line := range serialPayload(serial) {
		if strings.HasPrefix(line, prefix) {
			results = append(results, line)
		}
	}
	if len(results) != 1 {
		return nil, fmt.Errorf("guest serial must contain exactly one terminal runner result; found %d", len(results))
	}
	r := results[0]
	if r == success {
		return Object{"status": "PASS"}, nil
	}
	m := regexp.MustCompile("^" + regexp.QuoteMeta(prefix) + `FAILED stage=([a-z0-9-]+) status=([1-9][0-9]{0,2})$`).FindStringSubmatch(r)
	if m == nil || !slices.Contains(stages, m[1]) {
		return nil, fmt.Errorf("guest serial contains a malformed runner result")
	}
	status, _ := strconv.Atoi(m[2])
	return Object{"status": "FAILED", "stage": m[1], "exit_status": status, "sentinel": r}, nil
}
func ParseQualificationResult(goOutput string, goCode int, rustOutput string, rustCode int, serial, name string) (Object, error) {
	g, e := ParseGoTestOutput(goOutput, goCode, GoTestName)
	if e != nil {
		return nil, e
	}
	r, e := ParseRustTestOutput(rustOutput, rustCode, name)
	if e != nil {
		return nil, e
	}
	runner, e := ParseRunnerResult(serial, false)
	if e != nil {
		return nil, e
	}
	if runner["status"] != "PASS" {
		return nil, fmt.Errorf("guest command failed stage=%v status=%v", runner["stage"], runner["exit_status"])
	}
	serial = strings.Join(serialPayload(serial), "\n")
	position := strings.Index(serial, RunnerSuccess)
	sender := strings.Index(serial, SenderSuccess)
	summary := strings.LastIndex(serial, "test result: ok.")
	if sender < 0 || position < sender {
		return nil, fmt.Errorf("guest runner PASS sentinel appeared before the Go sender probe succeeded")
	}
	if summary < 0 || position < summary {
		return nil, fmt.Errorf("guest runner PASS sentinel appeared before the Rust test result")
	}
	return Object{"go_host_test": g, "rust_test": r}, nil
}
func ParseManagedVolumeResult(goOutput string, code int, serial string) (Object, error) {
	g, e := ParseGoTestOutput(goOutput, code, ManagedVolumeGoTestName)
	if e != nil {
		return nil, e
	}
	runner, e := ParseRunnerResult(serial, true)
	if e != nil {
		return nil, e
	}
	if runner["status"] != "PASS" {
		return nil, fmt.Errorf("guest command failed stage=%v status=%v", runner["stage"], runner["exit_status"])
	}
	serial = strings.Join(serialPayload(serial), "\n")
	pattern := regexp.MustCompile(`managed-volume-v1 device=/dev/oracleoci/oraclevdb uuid=` + regexp.QuoteMeta(ManagedVolumeUUID) + ` mount=` + regexp.QuoteMeta(MountPath) + ` mount_id=([1-9][0-9]*) replication_shard=absent`)
	matches := pattern.FindAllStringSubmatchIndex(serial, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf("guest serial must contain exactly one managed-volume verification record")
	}
	m := matches[0]
	if m[0] >= strings.Index(serial, VolumeRunnerSuccess) {
		return nil, fmt.Errorf("guest runner PASS sentinel appeared before managed-volume verification")
	}
	id, e := strconv.ParseUint(serial[m[2]:m[3]], 10, 64)
	if e != nil {
		return nil, e
	}
	return Object{"go_host_test": g, "managed_volume": Object{"status": "PASS", "device": "/dev/oracleoci/oraclevdb", "filesystem_uuid": ManagedVolumeUUID, "mount_path": MountPath, "mount_id": id, "replication_shard": "absent"}}, nil
}
func GuestPath(root, path string) (string, error) {
	if !filepath.IsAbs(path) || slices.Contains(strings.Split(path, "/"), "..") {
		return "", fmt.Errorf("unsafe guest path: %s", path)
	}
	current := root
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return "", e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("guest path contains a symlink that could escape the image")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", fmt.Errorf("guest path parent is not a directory")
		}
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/")), nil
}
func ReadTextBounded(path string, maximum int64) (string, bool, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", false, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil {
		return "", false, e
	}
	info, e := f.Stat()
	if e != nil {
		return "", false, e
	}
	return strings.ToValidUTF8(string(b[:min(int64(len(b)), maximum)]), "\uFFFD"), int64(len(b)) > maximum || info.Size() > maximum, nil
}
func ReadGuestRegularFile(root, path string, maximum int64) (string, bool, error) {
	host, e := GuestPath(root, path)
	if e != nil {
		return "", false, e
	}
	info, e := os.Lstat(host)
	if e != nil {
		return "", false, e
	}
	if !info.Mode().IsRegular() {
		return "", false, fmt.Errorf("guest evidence path is not a regular file")
	}
	return ReadTextBounded(host, maximum)
}
func canonical(v any) ([]byte, error) { return json.Marshal(v, json.Deterministic(true)) }
func equal(a, b any) bool {
	x, e := canonical(a)
	if e != nil {
		return false
	}
	y, e := canonical(b)
	return e == nil && bytes.Equal(x, y)
}
