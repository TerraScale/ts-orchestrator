package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

// execLines returns the values of key in a unit file, skipping comments.
func execLines(t *testing.T, path, key string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var values []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if name, value, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") && name == key {
			values = append(values, value)
		}
	}
	return values
}

// The image's drop-ins must execute the release the layout flips with the
// unit's own arguments, run prepare for the same unit and root before every
// start, and need no node-local file. The watchdog must read the same role
// config the unit runs with.
func TestSelfUpdateUnitsMatchLayout(t *testing.T) {
	deploy := filepath.Join("..", "..", "..", "deploy", "systemd")
	dir := filepath.Join(deploy, "selfupdate")
	for relative, expected := range map[string]string{
		selfupdate.ManagedRuntimeUnit:                                                                   selfupdate.ManagedRuntimeService,
		"selfupdate/" + selfupdate.HostUnit + ".d/90-managed-runtime.conf":                              selfupdate.ManagedRuntimeHostDropin,
		"selfupdate/" + selfupdate.ControllerUnit + ".d/90-managed-runtime.conf":                        selfupdate.ManagedRuntimeControllerDropin,
		"selfupdate/terrascale-orchestrator-selfupdate-watchdog@host.service.d/90-managed-runtime.conf": selfupdate.ManagedRuntimeWatchdogDropin,
	} {
		if actual, err := os.ReadFile(filepath.Join(deploy, relative)); err != nil || string(actual) != expected {
			t.Fatalf("managed runtime image contract differs: %s: %v", relative, err)
		}
	}
	for role, unit := range map[string]string{"controller": selfupdate.ControllerUnit, "host": selfupdate.HostUnit} {
		dropin := filepath.Join(dir, unit+".d", "60-selfupdate.conf")
		base := execLines(t, filepath.Join(deploy, unit), "ExecStart")
		if len(base) != 1 || !strings.HasPrefix(base[0], selfupdate.DefaultBakedBinary+" ") {
			t.Fatalf("%s ExecStart = %q", unit, base)
		}
		args := strings.TrimPrefix(base[0], selfupdate.DefaultBakedBinary)
		if config := "/etc/terrascale-orchestrator/" + role + ".json"; !strings.HasSuffix(args, " --config "+config) {
			t.Fatalf("%s does not run with %s: %q", unit, config, args)
		}
		want := selfupdate.NewLayout(selfupdate.DefaultRoot).CurrentExecutable() + args
		if got := execLines(t, dropin, "ExecStart"); len(got) != 2 || got[0] != "" || got[1] != want {
			t.Fatalf("%s ExecStart = %q, want reset then %q", unit, got, want)
		}
		pre := "+" + selfupdate.DefaultBakedBinary + " selfupdate prepare --root " + selfupdate.DefaultRoot + " --unit " + unit
		if got := execLines(t, dropin, "ExecStartPre"); len(got) != 1 || got[0] != pre {
			t.Fatalf("%s ExecStartPre = %q, want %q", unit, got, pre)
		}
		if got := execLines(t, dropin, "EnvironmentFile"); len(got) != 0 {
			t.Fatalf("%s needs a node-local environment file: %q", unit, got)
		}
		// The default proof file is in the unit's own writable state.
		state := execLines(t, filepath.Join(deploy, unit), "StateDirectory")
		if proof := selfupdate.DefaultProofFile(selfupdate.DefaultRoot, unit); len(state) != 1 || filepath.Dir(proof) != "/var/lib/"+state[0] {
			t.Fatalf("%s default proof %s is outside its StateDirectory %q", unit, proof, state)
		}
	}
	watchdog := filepath.Join(dir, "terrascale-orchestrator-selfupdate-watchdog@.service")
	want := selfupdate.DefaultBakedBinary + " selfupdate watchdog --root " + selfupdate.DefaultRoot +
		" --unit terrascale-orchestrator-%i.service --config /etc/terrascale-orchestrator/%i.json"
	if got := execLines(t, watchdog, "ExecStart"); len(got) != 1 || got[0] != want {
		t.Fatalf("watchdog ExecStart = %q, want %q", got, want)
	}
	if got := execLines(t, watchdog, "EnvironmentFile"); len(got) != 0 {
		t.Fatalf("watchdog needs a node-local environment file: %q", got)
	}
	if got := execLines(t, watchdog, "TimeoutStartSec"); len(got) != 1 {
		t.Fatalf("watchdog can hang its timer: TimeoutStartSec = %q", got)
	}
	if got := execLines(t, filepath.Join(dir, "terrascale-orchestrator-selfupdate-watchdog@.timer"), "WantedBy"); len(got) != 1 || got[0] != "timers.target" {
		t.Fatalf("watchdog timer WantedBy = %q", got)
	}
}

// The unit files are fixed when the image is built, while their root steps
// run the newest known-good release: every release must keep accepting
// exactly these arguments.
func TestImageUnitArgumentsStillRun(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "deploy", "systemd", "selfupdate")
	temp := t.TempDir()
	root := filepath.Join(temp, "root")
	baked := filepath.Join(temp, "baked")
	if err := os.WriteFile(baked, []byte("baked build"), 0o755); err != nil {
		t.Fatal(err)
	}
	watchdog := execLines(t, filepath.Join(dir, "terrascale-orchestrator-selfupdate-watchdog@.service"), "ExecStart")[0]
	for role, unit := range map[string]string{"controller": selfupdate.ControllerUnit, "host": selfupdate.HostUnit} {
		prepare := strings.TrimPrefix(execLines(t, filepath.Join(dir, unit+".d", "60-selfupdate.conf"), "ExecStartPre")[0], "+")
		for _, line := range []string{prepare, strings.ReplaceAll(watchdog, "%i", role)} {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != selfupdate.DefaultBakedBinary || fields[1] != "selfupdate" {
				t.Fatalf("unexpected root step %q", line)
			}
			args := fields[2:]
			for i := range args {
				if args[i] == selfupdate.DefaultRoot {
					args[i] = root
				}
			}
			args = append(args, "--owner", fmt.Sprint(os.Getuid()))
			if args[0] == "prepare" {
				args = append(args, "--baked-binary", baked)
			}
			var output strings.Builder
			if err := run(t.Context(), args, &output, time.Now, func(context.Context, string) error { return nil }); err != nil {
				t.Fatalf("%s: %v", line, err)
			}
			// The watchdog prints nothing while idle; prepare always reports its outcome.
			if want := "selfupdate " + args[0] + " unit=" + unit + " outcome="; args[0] == "prepare" && !strings.HasPrefix(output.String(), want) {
				t.Fatalf("%s printed %q, want %q", line, output.String(), want)
			}
		}
	}
}

// host-setup runs the current release with the image unit's own arguments,
// and the image-baked binary while there is none; prepare installs the same
// drop-in on hosts whose image predates it, once (TS-632).
func TestHostSetupDropinRunsTheCurrentRelease(t *testing.T) {
	deploy := filepath.Join("..", "..", "..", "deploy", "systemd")
	dropin := filepath.Join(deploy, "selfupdate", selfupdate.HostSetupUnit+".d", "60-selfupdate.conf")
	if data, err := os.ReadFile(dropin); err != nil || string(data) != selfupdate.HostSetupDropin {
		t.Fatalf("%s differs from selfupdate.HostSetupDropin: %v", dropin, err)
	}
	checkCurrentReleaseDropin(t, selfupdate.HostSetupUnit, "host-setup", selfupdate.HostSetupDropin,
		selfupdate.InstallHostSetupDropin)
}

// Bootstrap admission runs the current release too, so a controller.json a
// material generation installed is admitted at boot (TS-668: the image's
// binary refused its server_name and ts-sjc-3 did not come back).
func TestBootstrapDropinRunsTheCurrentRelease(t *testing.T) {
	checkCurrentReleaseDropin(t, selfupdate.BootstrapUnit, "bootstrap-controller", selfupdate.BootstrapDropin,
		selfupdate.InstallBootstrapDropin)
}

// Config installation runs the current release too, so an identity or config a
// newer release installed survives a reboot (TS-803).
func TestControllerInstallDropinRunsTheCurrentRelease(t *testing.T) {
	checkCurrentReleaseDropin(t, selfupdate.ControllerInstallUnit, "install-controller-config", selfupdate.ControllerInstallDropin,
		selfupdate.InstallControllerInstallDropin)
}

// checkCurrentReleaseDropin checks that dropin runs the image unit's own
// command with the current release, or the baked binary while there is none,
// and that install writes it once, only beside the unit.
func checkCurrentReleaseDropin(t *testing.T, unit, command, dropin string, install func(string) (bool, error)) {
	t.Helper()
	deploy := filepath.Join("..", "..", "..", "deploy", "systemd")
	base := execLines(t, filepath.Join(deploy, unit), "ExecStart")
	if len(base) != 1 || !strings.HasPrefix(base[0], selfupdate.DefaultBakedBinary+" "+command) {
		t.Fatalf("%s ExecStart = %q", unit, base)
	}
	args := strings.TrimPrefix(base[0], selfupdate.DefaultBakedBinary)
	path := filepath.Join(t.TempDir(), "60-selfupdate.conf")
	if err := os.WriteFile(path, []byte(dropin), 0o644); err != nil {
		t.Fatal(err)
	}
	got := execLines(t, path, "ExecStart")
	if len(got) != 2 || got[0] != "" || !strings.HasPrefix(got[1], "/bin/sh -c '") || !strings.HasSuffix(got[1], args+"'") {
		t.Fatalf("drop-in ExecStart = %q, want reset then a shell running %q", got, args)
	}
	// Run the shell line as systemd would ($$ is a literal $), with the
	// release and baked paths moved into a scratch root.
	temp := t.TempDir()
	current := filepath.Join(temp, "current", selfupdate.BinaryName)
	baked := filepath.Join(temp, "baked")
	script := strings.TrimSuffix(strings.TrimPrefix(got[1], "/bin/sh -c '"), "'")
	script = strings.NewReplacer("$$", "$", selfupdate.NewLayout(selfupdate.DefaultRoot).CurrentExecutable(), current,
		selfupdate.DefaultBakedBinary, baked).Replace(script)
	for _, path := range []string{current, baked} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+filepath.Base(filepath.Dir(path))+" \"$@\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range []string{"current", filepath.Base(temp)} {
		if i == 1 {
			if err := os.Remove(current); err != nil {
				t.Fatal(err)
			}
		}
		out, err := exec.Command("/bin/sh", "-c", script).Output()
		if err != nil || !strings.HasPrefix(string(out), want+args) {
			t.Fatalf("drop-in ran %q, %v; want %s%s", out, err, want, args)
		}
	}
	// prepare's installer: nothing without the unit, then the drop-in once.
	systemd := t.TempDir()
	if installed, err := install(systemd); err != nil || installed {
		t.Fatalf("installed without %s: %v, %v", unit, installed, err)
	}
	if err := os.WriteFile(filepath.Join(systemd, unit), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, want := range []bool{true, false} {
		if installed, err := install(systemd); err != nil || installed != want {
			t.Fatalf("install %s = %v, %v, want %v", unit, installed, err, want)
		}
	}
	if data, err := os.ReadFile(filepath.Join(systemd, unit+".d", "60-selfupdate.conf")); err != nil || string(data) != dropin {
		t.Fatalf("installed drop-in: %v", err)
	}
}

// prepare reloads systemd after it installs a drop-in, so the other unit
// reads it at its next start, and never fails the start for it (a failed
// prepare would make the baked binary run its own; TS-745).
func TestPrepareReloadsSystemdForNewDropins(t *testing.T) {
	reloads := 0
	previous := daemonReload
	daemonReload = func(context.Context) error { reloads++; return nil }
	defer func() { daemonReload = previous }()
	temp := t.TempDir()
	baked := filepath.Join(temp, "baked")
	if err := os.WriteFile(baked, []byte("baked build"), 0o755); err != nil {
		t.Fatal(err)
	}
	systemd := filepath.Join(temp, "systemd")
	if err := os.Mkdir(systemd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(systemd, selfupdate.HostSetupUnit), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"prepare", "--root", filepath.Join(temp, "root"), "--unit", selfupdate.HostUnit,
		"--owner", fmt.Sprint(os.Getuid()), "--baked-binary", baked, "--systemd-dir", systemd}
	for i := range 2 {
		if err := run(t.Context(), args, &strings.Builder{}, time.Now, func(context.Context, string) error { return nil }); err != nil || reloads != 1 {
			t.Fatalf("prepare %d: %v after %d reloads", i, err, reloads)
		}
	}
	if data, err := os.ReadFile(filepath.Join(systemd, selfupdate.HostSetupUnit+".d", "60-selfupdate.conf")); err != nil ||
		string(data) != selfupdate.HostSetupDropin {
		t.Fatalf("host-setup drop-in: %v", err)
	}
	uninstalled := filepath.Join(temp, "uninstalled-root")
	if err := run(t.Context(), []string{"prepare-managed-runtime", "--unit", selfupdate.HostUnit, "--root", uninstalled,
		"--owner", fmt.Sprint(os.Getuid()), "--systemd-dir", systemd}, &strings.Builder{}, time.Now, func(context.Context, string) error { t.Fatal("uninstalled runtime restarted"); return nil }); err == nil {
		t.Fatal("specialized prepare accepted a native installation")
	}
	if _, err := os.Stat(uninstalled); !os.IsNotExist(err) {
		t.Fatal("refused prepare created its release root")
	}
	managed := managedRuntimeSystemd(t)
	if installed, err := selfupdate.ManagedRuntimeInstalled(managed, os.Getuid()); err != nil || !installed {
		t.Fatalf("image alias contract = %v, %v", installed, err)
	}
	if err := os.WriteFile(filepath.Join(managed, selfupdate.HostSetupUnit), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := selfupdate.InstallNetBirdAgent(managed); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{selfupdate.NetBirdAgentUnit, "terrascale-netbird-enroll.service.d/zz-selfupdate.conf"} {
		if _, err := os.Stat(filepath.Join(managed, relative)); err != nil {
			t.Fatalf("real NetBird installer omitted %s: %v", relative, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(managed, selfupdate.HostUnit+".d/65-netbird-agent.conf")); !os.IsNotExist(err) {
		t.Fatalf("NetBird installer restored controller-dependent ordering: %v", err)
	}
	// The old native ExecStart remains below the fixed 90 file.
	for relative, contents := range map[string]string{
		selfupdate.HostUnit + ".d/60-selfupdate.conf": "[Service]\nExecStart=\nExecStart=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator host --config /etc/terrascale-orchestrator/host.json\n",
	} {
		if err := os.WriteFile(filepath.Join(managed, relative), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	managedArgs := slices.Clone(args)
	for index, value := range managedArgs {
		if value == systemd {
			managedArgs[index] = managed
		}
	}
	if err := run(t.Context(), managedArgs, &strings.Builder{}, time.Now, func(context.Context, string) error { t.Fatal("prepare restarted service"); return nil }); err != nil {
		t.Fatal(err)
	}
	if installed, err := selfupdate.ManagedRuntimeInstalled(managed, os.Getuid()); err != nil || !installed {
		t.Fatalf("legacy prepare replaced managed runtime: %v, %v", installed, err)
	}
	wrongOwner := slices.Clone(managedArgs)
	wrongOwner[0] = "prepare-managed-runtime"
	for index, value := range wrongOwner {
		if value == selfupdate.HostUnit {
			wrongOwner[index] = selfupdate.ControllerUnit
		}
	}
	if err := run(t.Context(), wrongOwner, &strings.Builder{}, time.Now, func(context.Context, string) error { t.Fatal("wrong owner restarted"); return nil }); err == nil {
		t.Fatal("managed worker accepted controller prepare owner")
	}
	for _, damage := range []string{"alias", "primary", "dropin", "directory", "native-ordering"} {
		t.Run(damage, func(t *testing.T) {
			installed := managedRuntimeSystemd(t)
			switch damage {
			case "alias":
				file := filepath.Join(installed, selfupdate.ManagedRuntimeUnit)
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("another.service", file); err != nil {
					t.Fatal(err)
				}
			case "primary":
				if err := os.Chmod(filepath.Join(installed, selfupdate.HostUnit), 0o666); err != nil {
					t.Fatal(err)
				}
			case "dropin":
				if err := os.WriteFile(filepath.Join(installed, selfupdate.HostUnit+".d/90-managed-runtime.conf"), []byte("[Service]\nExecStart=host\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Chmod(installed, 0o777); err != nil {
					t.Fatal(err)
				}
			case "native-ordering":
				if err := os.WriteFile(filepath.Join(installed, selfupdate.HostUnit+".d/65-netbird-agent.conf"), []byte(selfupdate.NetBirdAgentHostDropin), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if recognized, err := selfupdate.ManagedRuntimeInstalled(installed, os.Getuid()); err == nil || recognized {
				t.Fatalf("unsafe image contract accepted: %v, %v", recognized, err)
			}
		})
	}
}

// Bootstrap's restore step fails the unit on any restore failure; only a
// release whose CLI lacks the command (a rollback) skips it (TS-745).
func TestBootstrapRestoreStepSkipsOnlyAnOlderRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "60-selfupdate.conf")
	if err := os.WriteFile(path, []byte(selfupdate.BootstrapDropin), 0o644); err != nil {
		t.Fatal(err)
	}
	pre := execLines(t, path, "ExecStartPre")
	if len(pre) != 2 || pre[0] != "" || !strings.HasPrefix(pre[1], "+/bin/sh -c '") {
		t.Fatalf("bootstrap ExecStartPre = %q, want reset then one strict root step", pre)
	}
	script := strings.TrimSuffix(strings.TrimPrefix(pre[1], "+/bin/sh -c '"), "'")
	temp := t.TempDir()
	current := filepath.Join(temp, "current", selfupdate.BinaryName)
	script = strings.NewReplacer("$$", "$", selfupdate.NewLayout(selfupdate.DefaultRoot).CurrentExecutable(), current).Replace(script)
	if err := os.MkdirAll(filepath.Dir(current), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, help string
		exit       int
		want       int
	}{{"older release", "Runtime:\n  run", 3, 0}, {"restore succeeds", "  restore-controller-material  Rebuild", 0, 0},
		{"restore fails", "  restore-controller-material  Rebuild", 7, 7}} {
		fake := "#!/bin/sh\nif [ \"$1\" = --help ]; then printf '%s\\n' '" + tc.help + "'; exit 0; fi\nexit " + fmt.Sprint(tc.exit) + "\n"
		if err := os.WriteFile(current, []byte(fake), 0o755); err != nil {
			t.Fatal(err)
		}
		err := exec.Command("/bin/sh", "-c", script).Run()
		code := 0
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if code != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, code, tc.want)
		}
	}
}

// managedRuntimeSystemd installs the same fixed filesystem contract as the image.
func managedRuntimeSystemd(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	for relative, contents := range map[string]string{
		selfupdate.HostUnit: selfupdate.ManagedRuntimeService,
		selfupdate.HostUnit + ".d/90-managed-runtime.conf":                                   selfupdate.ManagedRuntimeHostDropin,
		selfupdate.ControllerUnit + ".d/90-managed-runtime.conf":                             selfupdate.ManagedRuntimeControllerDropin,
		"terrascale-orchestrator-selfupdate-watchdog@host.service.d/90-managed-runtime.conf": selfupdate.ManagedRuntimeWatchdogDropin,
	} {
		file := filepath.Join(directory, relative)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(selfupdate.HostUnit, filepath.Join(directory, selfupdate.ManagedRuntimeUnit)); err != nil {
		t.Fatal(err)
	}
	return directory
}
