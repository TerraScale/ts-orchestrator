package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
)

// The opt-in drop-ins must execute the release the layout flips and run
// prepare for the same unit and root before every start.
func TestSelfUpdateDropInsMatchLayout(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "deploy", "systemd", "selfupdate")
	for unit, command := range map[string]string{
		"terrascale-orchestrator-controller": "run --config /etc/terrascale-orchestrator/controller.json",
		"terrascale-orchestrator-host":       "host --config /etc/terrascale-orchestrator/host.json",
	} {
		data, err := os.ReadFile(filepath.Join(dir, unit+".service.d", "60-selfupdate.conf"))
		if err != nil {
			t.Fatal(err)
		}
		var execStart, execStartPre []string
		environment := ""
		for line := range strings.SplitSeq(string(data), "\n") {
			key, value, ok := strings.Cut(line, "=")
			switch {
			case !ok || strings.HasPrefix(line, "#"):
			case key == "ExecStart":
				execStart = append(execStart, value)
			case key == "ExecStartPre":
				execStartPre = append(execStartPre, value)
			case key == "EnvironmentFile":
				environment = value
			}
		}
		want := selfupdate.NewLayout(selfupdate.DefaultRoot).CurrentExecutable() + " " + command
		if len(execStart) != 2 || execStart[0] != "" || execStart[1] != want {
			t.Fatalf("%s ExecStart = %q, want reset then %q", unit, execStart, want)
		}
		if len(execStartPre) != 1 || !strings.HasPrefix(execStartPre[0], "+"+selfupdate.DefaultBakedBinary+" selfupdate prepare ") ||
			!strings.Contains(execStartPre[0], "--root "+selfupdate.DefaultRoot+" ") ||
			!strings.Contains(execStartPre[0], "--unit "+unit+".service ") {
			t.Fatalf("%s ExecStartPre = %q", unit, execStartPre)
		}
		if environment != "/etc/terrascale-orchestrator/selfupdate-"+unit+".env" {
			t.Fatalf("%s EnvironmentFile = %q", unit, environment)
		}
	}
	watchdog, err := os.ReadFile(filepath.Join(dir, "terrascale-orchestrator-selfupdate-watchdog@.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"EnvironmentFile=/etc/terrascale-orchestrator/selfupdate-%i.env",
		selfupdate.DefaultBakedBinary + " selfupdate watchdog --root " + selfupdate.DefaultRoot + " --unit %i.service", "--restart"} {
		if !strings.Contains(string(watchdog), want) {
			t.Fatalf("watchdog unit lacks %q", want)
		}
	}
}
