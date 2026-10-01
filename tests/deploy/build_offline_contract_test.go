package deploy_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func capture(t *testing.T, source, pattern string) []string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(source)
	if m == nil {
		t.Fatalf("could not find contract %s", pattern)
	}
	return m
}
func bakedLimit(t *testing.T, name string) int {
	t.Helper()
	source := string(read(t, filepath.Join(deployRoot(t), "internal/bootstrapstart/baked.go")))
	m := capture(t, source, `\b`+name+`\s*=\s*(\d+)(?:\s*<<\s*(\d+))?`)
	value, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if m[2] != "" {
		shift, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatal(err)
		}
		value <<= shift
	}
	return value
}
func TestOfflineBuilderLimitsMatchBakedLoader(t *testing.T) {
	root := deployRoot(t)
	builder := string(read(t, filepath.Join(root, "deploy/image/build-offline.sh")))
	helper := string(read(t, filepath.Join(root, "deploy/image/offline-guestfs.py")))
	loader := string(read(t, filepath.Join(root, "internal/bootstrapstart/baked.go")))
	equal(t, capture(t, helper, `(?m)^BOOTSTRAP = "([^"]+)"$`)[1], capture(t, loader, `BakedDirectory\s*=\s*"([^"]+)"`)[1])
	for bash, goName := range map[string]string{"bootstrap_root_limit": "MaxRootFiles", "bootstrap_root_max_bytes": "MaxRootBytes", "bootstrap_roots_max_total_bytes": "MaxRootsTotal"} {
		value, err := strconv.Atoi(capture(t, builder, `(?m)^`+bash+`=(\d+)$`)[1])
		if err != nil {
			t.Fatal(err)
		}
		equal(t, value, bakedLimit(t, goName))
	}
	pattern := capture(t, loader, "rootFilenameRE\\s*=\\s*regexp\\.MustCompile\\(`([^`]+)`\\)")[1]
	reserved := capture(t, loader, `!rootFilenameRE\.MatchString\(name\)\s*\|\|\s*name\s*==\s*"([^"]+)"`)[1]
	names := []string{"001.pem", "002.pem"}
	if len(names) > bakedLimit(t, "MaxRootFiles") {
		t.Fatal("builder roots exceed loader bounds")
	}
	for _, name := range names {
		if !regexp.MustCompile(pattern).MatchString(name) || name == reserved {
			t.Fatalf("loader rejects installed root %s", name)
		}
	}
}

const profileAdapter = `
from pathlib import Path
from types import SimpleNamespace
m.RUNTIME_PRIORITY_PROFILE=Path(a["profile"])
original_lstat=Path.lstat
Path.lstat=lambda self: SimpleNamespace(**a["metadata"])
try:
    result=m.Probe(SimpleNamespace(**a["probe"])).verify_baked_profile()
finally:
    Path.lstat=original_lstat
`

func TestOfflineProbeVerifiesCanonicalBakedReserve(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("mismatch=%t", mismatch), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runtime-priority.json")
			wire := []byte(`{"version":1,"profile_id":"preview-1ocpu-6gib-v1","system_reserve_bytes":1073741824}`)
			write(t, path, wire, 0644)
			reserve := 1 << 30
			if mismatch {
				reserve += 4096
			}
			r := object(t, script.Python(t, "tests/runtime_priority/qualify.py", map[string]any{"profile": path, "metadata": map[string]any{"st_mode": 0100644, "st_uid": 0, "st_gid": 0, "st_nlink": 1}, "probe": map[string]any{"profile_id": profileID, "system_reserve_bytes": reserve}}, profileAdapter))
			if mismatch {
				equal(t, r["error_type"], "QualificationError")
				contains(t, r["error"].(string), "profile ID/reserve differs")
			} else {
				equal(t, r["sha256"], digest(wire))
				equal(t, r["profile_id"], profileID)
				equal(t, r["system_reserve_bytes"], float64(1<<30))
			}
		})
	}
}
func TestOfflinePackagedProbeWithoutGitCheckout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py")
	write(t, path, []byte("# packaged helper\n"), 0644)
	r := object(t, script.Python(t, "tests/runtime_priority/qualify.py", map[string]any{"packaged": path}, `from types import SimpleNamespace
m.__file__=a["packaged"]
revision,unit_directory=m.Probe(SimpleNamespace()).source_identity()
result={"revision":revision,"unit_directory":str(unit_directory)}`))
	equal(t, r["revision"], nil)
	equal(t, r["unit_directory"], "/etc/systemd/system")
}
func TestOfflineVolumeInitRootOnlyInHostNamespace(t *testing.T) {
	socketSource := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd", volumeSocketUnit)))
	serviceSource := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd", volumeServiceUnit)))
	socket := unitDirectives(socketSource, "Socket")
	for key, value := range map[string]string{"ListenStream": "/run/terrascale-orchestrator-volume-init.sock", "SocketMode": "0600", "SocketUser": "root", "SocketGroup": "root", "Accept": "no", "Service": volumeServiceUnit} {
		equal(t, socket[key], value)
	}
	contains(t, socketSource, "WantedBy=sockets.target")
	service := unitDirectives(serviceSource, "Service")
	for _, key := range []string{"User", "Group"} {
		if _, found := service[key]; found {
			t.Fatalf("unexpected explicit %s", key)
		}
	}
	equal(t, service["ExecStart"], "/usr/local/bin/terrascale-orchestrator host-volume-init --config /etc/terrascale-orchestrator/host.json")
	caps := strings.Fields(service["CapabilityBoundingSet"])
	slices.Sort(caps)
	equal(t, caps, []string{"CAP_CHOWN", "CAP_SYS_ADMIN"})
	for _, key := range []string{"NoNewPrivileges", "RestrictNamespaces"} {
		equal(t, service[key], "yes")
	}
	for _, key := range []string{"BindPaths", "BindReadOnlyPaths", "CacheDirectory", "ConfigurationDirectory", "InaccessiblePaths", "LogsDirectory", "MountAPIVFS", "PrivateDevices", "PrivateMounts", "PrivateTmp", "PrivateUsers", "ProtectClock", "ProtectControlGroups", "ProtectHome", "ProtectHostname", "ProtectKernelLogs", "ProtectKernelModules", "ProtectKernelTunables", "ProtectProc", "ProtectSystem", "ProcSubset", "ReadOnlyPaths", "ReadWritePaths", "RootDirectory", "RootImage", "RuntimeDirectory", "StateDirectory", "TemporaryFileSystem"} {
		if _, found := service[key]; found {
			t.Fatalf("volume init creates filesystem namespace via %s", key)
		}
	}
}
func TestOfflineControllerWaitsForBoundedClockSync(t *testing.T) {
	bootstrap := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-bootstrap.service")))
	controller := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-controller.service")))
	for _, want := range []string{"Requires=systemd-timesyncd.service systemd-time-wait-sync.service", "After=systemd-timesyncd.service systemd-time-wait-sync.service", "TimeoutStartSec=300s", "Type=oneshot", "Restart=on-failure", "RestartSec=10s", "OnSuccess=terrascale-orchestrator-controller.service", "CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID CAP_DAC_OVERRIDE CAP_KILL", "ReadWritePaths=" + markerDir + " " + secretsDir + " " + controllerDir + " /run/terrascale-orchestrator-bootstrap"} {
		contains(t, bootstrap, want)
	}
	contains(t, controller, "Requires=terrascale-orchestrator-bootstrap.service")
	contains(t, controller, "After=terrascale-orchestrator-bootstrap.service")
}
func TestOfflineSysusersMatchesControllerUserAndGroup(t *testing.T) {
	source := string(read(t, filepath.Join(deployRoot(t), "deploy/image/terrascale-orchestrator.sysusers")))
	var lines []string
	users := map[string]string{}
	count := 0
	for line := range strings.SplitSeq(source, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, "u ") {
			parts := strings.Fields(line)
			users[parts[1]] = parts[2]
			count++
		}
	}
	equal(t, count, 2)
	equal(t, users["terrascale-workload"], "2000:2000")
	equal(t, slices.Contains(lines, "g terrascale-workload 2000"), true)
	equal(t, users["terrascale-orchestrator"], "-")
	d := unitDirectives(string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-controller.service"))), "")
	equal(t, d["User"], "terrascale-orchestrator")
	equal(t, d["Group"], "terrascale-orchestrator")
	if _, found := users[d["User"]]; !found {
		t.Fatal("controller user is not provisioned")
	}
}
func TestOfflineHostSandboxWritableManagedPathOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires nonroot user, systemd and passwordless sudo")
	}
	for _, command := range []string{"sudo", "systemctl", "systemd-run", "install", "touch", "sh"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skip("requires nonroot user, systemd and passwordless sudo")
		}
	}
	if script.Run(t, deployRoot(t), nil, "sudo", "-n", "true").Code != 0 {
		t.Skip("passwordless sudo unavailable")
	}
	if script.Run(t, deployRoot(t), nil, "systemctl", "show", "--property=Version", "--value").Code != 0 {
		t.Skip("systemd manager unavailable")
	}
	d := unitDirectives(string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-host.service"))), "")
	equal(t, d["ProtectSystem"], "strict")
	equal(t, d["ReadWritePaths"], "-"+managedDir)
	base := t.TempDir()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	allowed, denied := filepath.Join(base, "allowed"), filepath.Join(base, "denied")
	defer func() {
		successful(t, script.Run(t, deployRoot(t), nil, "sudo", "-n", "rm", "-rf", "--", allowed, denied))
	}()
	for _, path := range []string{allowed, denied} {
		successful(t, script.Run(t, deployRoot(t), nil, "sudo", "-n", "install", "-d", "-o", "root", "-g", "root", "-m", "0755", path))
	}
	args := []string{"-n", "systemd-run", "--wait", "--collect", "--unit=ts-managed-sandbox-" + filepath.Base(base)}
	for _, key := range []string{"ProtectSystem", "NoNewPrivileges", "CapabilityBoundingSet", "AmbientCapabilities"} {
		args = append(args, "--property="+key+"="+d[key])
	}
	sh, _ := exec.LookPath("sh")
	touch, _ := exec.LookPath("touch")
	args = append(args, "--property=ReadWritePaths=-"+allowed, sh, "-c", `"$3" "$1/created" || exit 21; if "$3" "$2/created"; then exit 22; fi; exit 0`, "probe", allowed, denied, touch)
	successful(t, script.Run(t, deployRoot(t), nil, "sudo", args...))
	if _, err := os.Stat(filepath.Join(allowed, "created")); err != nil {
		t.Fatal(err)
	}
	absent(t, filepath.Join(denied, "created"))
}
