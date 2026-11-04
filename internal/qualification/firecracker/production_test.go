package firecracker

import (
	"context"

	"os"

	"strings"

	"testing"
	"time"
)

func TestProductionHealthFailureNamesStageAndDiagnostics(t *testing.T) {
	if !strings.Contains(productionHealthScript, "|| fail ntp-synchronized") || !strings.Contains(productionHealthDiagnosticScript, "SYSLOG_IDENTIFIER=systemd") {
		t.Fatal("missing stage or curated journal")
	}
	if strings.Contains(productionHealthDiagnosticScript, "journalctl -u terrascale-orchestrator") {
		t.Fatal("uncurated application journal")
	}
	q := nativeProduction(t)
	current := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	q.now = func() time.Time { return current }
	q.sleep = func(time.Duration) error { current = current.Add(301 * time.Second); return nil }
	commands := []string{}
	q.Command = func(_ context.Context, argv []string, options CommandOptions) (CommandResult, error) {
		commands = append(commands, argv[len(argv)-1])
		if len(commands) == 1 {
			requireEqual(t, options.Timeout, 15*time.Second)
			return CommandResult{Code: 1, Stderr: "failed-stage=ntp-synchronized\n"}, nil
		}
		requireEqual(t, options.Timeout, 20*time.Second)
		return CommandResult{Stdout: "[clock]\nno\n"}, nil
	}
	vm := &ProductionVM{Q: q, Slot: "controller-a"}
	_, failure := vm.Health(988, 988)
	requireError(t, failure, "failed-stage=ntp-synchronized")
	requireError(t, failure, "guest diagnostics:\n[clock]\nno")
	requireEqual(t, len(commands), 2)
	requireEqual(t, commands, []string{quote(productionHealthScript), quote(productionHealthDiagnosticScript)})
	_, e := ProductionHealthEvidence("Uid: 988 988 988 988\nGid: 988 988 988 988\ninvocation\nboot\n", 988, 988)
	if e != nil {
		t.Fatal(e)
	}
	_, e = ProductionHealthEvidence("Uid: 0 0 0 0\nGid: 988 988 988 988\ninvocation\nboot\n", 988, 988)
	requireError(t, e, "failed-stage=service-identity")
}

func nativeProduction(t *testing.T) *ProductionQualification {
	t.Helper()
	q, e := NewProductionQualification(t.Context(), ProductionOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(q.Root) })
	return q
}
