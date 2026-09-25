package bootstrapstart

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	materialCapabilityFixtureUID = 1000
	materialCapabilityFixtureGID = 1000
	materialCapabilityMask       = uint64(0xe3) // CHOWN, DAC_OVERRIDE, KILL, SETGID, SETUID.
)

func TestMaterialInstallUnderRestrictedCapabilities(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("restricted material installation requires the privileged test invocation")
	}
	if !materialCapabilitiesMatch(t, materialCapabilityMask) {
		t.Skip("run under the exact five-capability bootstrap unit set")
	}

	root := t.TempDir()
	if err := os.Chmod(filepath.Dir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "service-secrets")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, materialCapabilityFixtureUID, materialCapabilityFixtureGID); err != nil {
		t.Fatal(err)
	}
	dirFD, err := openMaterialDirectory(directory, materialCapabilityFixtureUID, materialCapabilityFixtureGID, 0o700, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirFD)

	content := []byte("restricted-capability service credential")
	want := digest(content)
	store := MaterialStore{serviceUID: materialCapabilityFixtureUID, serviceGID: materialCapabilityFixtureGID}
	if err := store.installMaterial(dirFD, "controller.jwt", content, want, 256); err != nil {
		t.Fatalf("install with exact capability set: %v", err)
	}
	info, err := os.Lstat(filepath.Join(directory, "controller.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("installed credential did not expose Unix ownership: %T", info.Sys())
	}
	if stat.Uid != materialCapabilityFixtureUID || stat.Gid != materialCapabilityFixtureGID || info.Mode().Perm() != 0o600 {
		t.Fatalf("installed credential identity/mode = uid %d gid %d mode %04o", stat.Uid, stat.Gid, info.Mode().Perm())
	}
	installed, err := readMaterial(dirFD, "controller.jwt", materialCapabilityFixtureUID, materialCapabilityFixtureGID, want, 256)
	if err != nil || string(installed) != string(content) {
		t.Fatalf("read installed credential = %q, %v", installed, err)
	}
	clear(installed)
}

func TestMaterialInstallWithoutDACOverride(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("restricted material denial requires the privileged test invocation")
	}
	if !materialCapabilitiesMatch(t, materialCapabilityMask&^(uint64(1)<<1)) {
		t.Skip("run under the four-capability no-DAC denial set")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "service-secrets")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, materialCapabilityFixtureUID, materialCapabilityFixtureGID); err != nil {
		t.Fatal(err)
	}
	store := MaterialStore{serviceUID: materialCapabilityFixtureUID, serviceGID: materialCapabilityFixtureGID}
	dirFD, err := openMaterialDirectory(directory, materialCapabilityFixtureUID, materialCapabilityFixtureGID, 0o700, true)
	if err == nil {
		defer unix.Close(dirFD)
		if installErr := store.installMaterial(dirFD, "blocked.jwt", []byte("must not install"), digest([]byte("must not install")), 256); installErr == nil {
			t.Fatal("material installation succeeded without CAP_DAC_OVERRIDE")
		}
	} else if !errors.Is(err, unix.EACCES) {
		t.Fatalf("service-owned 0700 directory without CAP_DAC_OVERRIDE = %v, want EACCES", err)
	}
	if err := os.Chown(directory, 0, 0); err != nil {
		t.Fatalf("restore root ownership to inspect denied install: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "blocked.jwt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-DAC attempt left a partial credential: %v", err)
	}
}

func TestBootstrapUnitPinsMaterialInstallCapabilities(t *testing.T) {
	unit, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "terrascale-orchestrator-bootstrap.service"))
	if err != nil {
		t.Fatal(err)
	}
	directives := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(unit)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := strings.Cut(line, "=")
		if ok {
			directives[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	want := "CAP_CHOWN CAP_SETGID CAP_SETUID CAP_DAC_OVERRIDE CAP_KILL"
	if directives["CapabilityBoundingSet"] != want {
		t.Fatalf("bootstrap CapabilityBoundingSet = %q, want %q", directives["CapabilityBoundingSet"], want)
	}
	if directives["NoNewPrivileges"] != "yes" {
		t.Fatalf("bootstrap NoNewPrivileges = %q, want yes", directives["NoNewPrivileges"])
	}
}

func materialCapabilitiesMatch(t *testing.T, want uint64) bool {
	t.Helper()
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return false
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapBnd"} {
		got, err := strconv.ParseUint(values[key], 16, 64)
		if err != nil || got != want {
			return false
		}
	}
	return values["NoNewPrivs"] == "1"
}
