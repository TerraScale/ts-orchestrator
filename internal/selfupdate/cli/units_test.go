package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
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
		" --unit terrascale-orchestrator-%i.service --config /etc/terrascale-orchestrator/%i.json --restart"
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
			if want := "selfupdate " + args[0] + " unit=" + unit + " outcome="; !strings.HasPrefix(output.String(), want) {
				t.Fatalf("%s printed %q, want %q", line, output.String(), want)
			}
		}
	}
}
