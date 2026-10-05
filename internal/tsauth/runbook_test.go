package tsauth

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTSAuthRunbookPreparesEnvBeforeRestartAndStopsOnFailure(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "ts-auth-deployment.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, step, ok := strings.Cut(string(doc), "3. On each controller,")
	if !ok {
		t.Fatal("missing controller preparation step")
	}
	_, step, ok = strings.Cut(step, "```sh\n")
	if !ok {
		t.Fatal("missing controller preparation commands")
	}
	step, _, ok = strings.Cut(step, "```")
	if !ok {
		t.Fatal("unclosed runbook commands")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"", "test -x /usr/sbin/nft", "systemctl enable", "systemctl restart"} {
		t.Run(failure, func(t *testing.T) {
			work := t.TempDir()
			stub := "#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> \"$TS_AUTH_RUNBOOK_LOG\"\n" +
				"if [ -n \"$TS_AUTH_RUNBOOK_FAIL\" ]; then case \"$*\" in *\"$TS_AUTH_RUNBOOK_FAIL\"*) exit 1;; esac; fi\nprintf '{}\\n'\n"
			for _, name := range []string{"ssh", "jq", "shred", "terrascale-orchestrator"} {
				if err := os.WriteFile(filepath.Join(work, name), []byte(stub), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			logPath := filepath.Join(work, "calls")
			command := exec.CommandContext(t.Context(), "bash", "-c", step)
			command.Env = append(os.Environ(), "PATH="+work+string(os.PathListSeparator)+os.Getenv("PATH"),
				"REPO="+repo, "WORK="+work, "VAULT=fixture-vault", "TS_AUTH_RUNBOOK_LOG="+logPath, "TS_AUTH_RUNBOOK_FAIL="+failure)
			output, err := command.CombinedOutput()
			if (err != nil) != (failure != "") {
				t.Fatalf("failure %q: err=%v, output=%s", failure, err, output)
			}
			calls, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			log := string(calls)
			if failure != "" {
				if strings.Contains(log, "gru-1-ctl-2") || strings.Contains(log, "/shred ") {
					t.Fatalf("continued after failure:\n%s", log)
				}
				return
			}
			for _, line := range strings.Split(log, "\n") {
				if strings.Contains(line, "systemctl restart terrascale-ts-auth-metadata.service") {
					t.Fatal("restarted the required metadata unit independently")
				}
			}
			env, restart := strings.Index(log, "ts-auth env-file"), strings.Index(log, "systemctl restart terrascale-orchestrator-host.service")
			if env < 0 || restart <= env || !strings.Contains(log, "gru-1-ctl-3") {
				t.Fatalf("env file was not ready before restart, or skipped a controller:\n%s", log)
			}
		})
	}
}
