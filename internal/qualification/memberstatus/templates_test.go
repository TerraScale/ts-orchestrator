package memberstatus

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func templateContains(t *testing.T, s, part string) {
	t.Helper()
	if !strings.Contains(s, part) {
		t.Fatalf("missing %q in %s", part, s)
	}
}
func templateExcludes(t *testing.T, s, part string) {
	t.Helper()
	if strings.Contains(s, part) {
		t.Fatalf("unexpected %q in %s", part, s)
	}
}
func templateEqual(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func templateFakeReboot(t *testing.T, base string) (string, string) {
	t.Helper()
	bin := filepath.Join(base, "bin")
	record := filepath.Join(base, "reboot-events")
	script.Write(t, filepath.Join(bin, "sync"), []byte("#!/bin/sh\nprintf '%s\\n' sync >>"+templateQuote(record)+"\n"), 0755)
	script.Write(t, filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"systemctl $*\" >>"+templateQuote(record)+"\n"), 0755)
	return bin, record
}

func templateRunShell(t *testing.T, base, bin, path string) script.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", path)
	cmd.Dir = base
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("guest shell exceeded five seconds: %v; %s", ctx.Err(), output)
	}
	code := 0
	if err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return script.Result{Stdout: string(output), Code: code}
}

func TestMemberStatusGuestShellRunner(t *testing.T) {
	for _, kind := range []string{"legacy_pass", "legacy_fail", "managed_volume"} {
		t.Run(kind, func(t *testing.T) {
			// Spaces and quotes in the test root exercise shell argument quoting.
			base := filepath.Join(t.TempDir(), "root with 'quotes'")
			if e := os.Mkdir(base, 0700); e != nil {
				t.Fatal(e)
			}
			guest := filepath.Join(base, "guest")
			bin, record := templateFakeReboot(t, base)
			var body string
			if kind == "managed_volume" {
				evidence := "managed-volume-v1 device=/dev/oracleoci/oraclevdb uuid=" + ManagedVolumeUUID + " mount=" + MountPath + " mount_id=23 replication_shard=absent"
				pass := "=== RUN   " + ManagedVolumeGoTestName + "\n    managed_runtime_firecracker_test.go:1: " + evidence + "\n--- PASS: " + ManagedVolumeGoTestName + " (0.00s)\nPASS\n"
				script.Write(t, filepath.Join(guest, "opt/ts-managed-volume-qualification/host.test"), []byte("#!/bin/sh\ncat <<'RESULT'\n"+pass+"RESULT\n"), 0755)
				body = ManagedVolumeShellRunner(guest)
			} else {
				goScript := "#!/bin/sh\nprintf 'Go tests passed\\n'\n"
				if kind == "legacy_fail" {
					goScript = "#!/bin/sh\nprintf 'focused Go failure\\n'\nexit 37\n"
				}
				script.Write(t, filepath.Join(guest, "opt/ts-member-status/go-host-test"), []byte(goScript), 0755)
				script.Write(t, filepath.Join(guest, "opt/ts-member-status/rust-test"), []byte("#!/bin/sh\nprintf 'Rust test passed\\n'\n"), 0755)
				body = ShellRunner(guest, RustTestName)
			}
			path := filepath.Join(base, "runner.sh")
			script.Write(t, path, []byte(body), 0600)
			run := templateRunShell(t, base, bin, path)
			console := run.Stdout + run.Stderr
			templateEqual(t, strings.Split(strings.TrimSpace(string(script.Read(t, record))), "\n"), []string{"sync", "systemctl --no-wall reboot"})
			switch kind {
			case "legacy_pass":
				templateEqual(t, run.Code, 0)
				templateEqual(t, strings.Count(console, RunnerSuccess), 1)
				templateExcludes(t, console, "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED")
			case "legacy_fail":
				templateEqual(t, run.Code, 37)
				templateEqual(t, strings.Count(console, "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=go-host-test status=37"), 1)
				templateExcludes(t, console, RunnerSuccess)
				log := script.Read(t, filepath.Join(guest, "var/log/ts-member-status-qualification/go-host-test.log"))
				templateContains(t, string(log), "stage=go-host-test status=37")
				parsed, e := ParseRunnerResult(console, false)
				if e != nil {
					t.Fatal(e)
				}
				templateEqual(t, parsed["stage"], "go-host-test")
				templateEqual(t, parsed["exit_status"], 37)
			case "managed_volume":
				templateEqual(t, run.Code, 0)
				templateEqual(t, strings.Count(console, VolumeRunnerSuccess), 1)
				log := string(script.Read(t, filepath.Join(guest, "var/log/ts-managed-volume-qualification/go-host-test.log")))
				parsed, e := ParseManagedVolumeResult(log, 0, console)
				if e != nil {
					t.Fatal(e)
				}
				templateEqual(t, parsed["managed_volume"].(Object)["mount_id"], uint64(23))
			}
		})
	}
}

func TestMemberStatusServicePrivilegeSeparation(t *testing.T) {
	if GuestServiceTimeoutSeconds >= GuestDeadlineSeconds {
		t.Fatal("guest service timeout must leave host shutdown fallback")
	}
	legacy := ServiceUnit("")
	templateContains(t, legacy, "TimeoutStartSec=270s")
	setup := ManagedVolumeSetupScript()
	for _, part := range []string{`ln -s ../vdb "$ALIAS"`, `mount -t ext4 -o rw "$ALIAS" "$MOUNT"`, "BLKID=/usr/sbin/blkid", `chmod 0700 "$MOUNT/data" "$MOUNT/replication"`} {
		templateContains(t, setup, part)
	}
	templateExcludes(t, setup, "replication/shard")
	unit := ManagedVolumeSetupUnit(ManagedVolumeUUID)
	templateContains(t, unit, "Environment=TS_FC_VOLUME_UUID=")
	templateContains(t, unit, "Before=ts-member-status-qualification.service")
	managed := ServiceUnit(ManagedVolumeUUID)
	for _, part := range []string{"Requires=ts-member-status-managed-volume-setup.service", "NoNewPrivileges=yes", "CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_READ_SEARCH", "CAP_DAC_READ_SEARCH"} {
		templateContains(t, managed, part)
	}
	templateExcludes(t, managed, "CAP_DAC_OVERRIDE")
	templateContains(t, legacy, "CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP")
	templateExcludes(t, legacy, "CAP_DAC_READ_SEARCH")
	templateExcludes(t, legacy, "CAP_DAC_OVERRIDE")
	path := filepath.Join(t.TempDir(), "setup.sh")
	script.Write(t, path, []byte(setup), 0600)
	checked := script.Run(t, script.Root(t), nil, "/bin/sh", "-n", path)
	templateEqual(t, checked.Code, 0)
}
