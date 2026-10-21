package logscan

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
)

func logscanProcess(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Env = append(cmd.Env, env...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return out, err
}

func logscanFiles(t *testing.T) (Fetchers, string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"gru-1-ctl-1":  journal,
		"gru-1-ctl-2":  "",
		"ts-dashboard": fly,
		"journalctl": `#!/bin/sh
printf '%s\n' "$@" > "$LOGSCAN_FIXTURES/journal-args"
exec cat "$LOGSCAN_FIXTURES/$LOGSCAN_NODE"
`,
		"fly": `#!/bin/sh
[ "$#" -eq 4 ] && [ "$1" = logs ] && [ "$2" = -a ] && [ "$4" = --no-tail ] || exit 2
exec cat "$LOGSCAN_FIXTURES/$3"
`,
	} {
		mode := os.FileMode(0o600)
		if name == "journalctl" || name == "fly" {
			mode = 0o700
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LOGSCAN_FIXTURES", dir)
	return Fetchers{
		Node: func(ctx context.Context, node, command string) ([]byte, error) {
			return logscanProcess(ctx, []string{"LOGSCAN_NODE=" + node}, "bash", "-c", command)
		},
		Fly: func(ctx context.Context, app string) ([]byte, error) {
			return logscanProcess(ctx, nil, "fly", "logs", "-a", app, "--no-tail")
		},
	}, dir
}

// journal is RemoteCommand output in the shapes gru-1 logs on 2026-10-07.
const journal = `{"__CURSOR":"s=1","_COMM":"terrabase","_PID":"7137","MESSAGE":"warn: TerraBase.Features.Replication.ReplicationSender[1858781747]"}
{"__CURSOR":"s=2","_COMM":"ts-auth","_PID":"1342","MESSAGE":"info: Microsoft.AspNetCore.Routing.EndpointMiddleware[0]"}
{"__CURSOR":"s=3","_COMM":"terrabase","_PID":"7137","MESSAGE":"      Replication of 2 databases to peer #1 failed; retrying within 500 ms"}
--
{"__CURSOR":"s=4","_COMM":"terrabase","_PID":"7137","MESSAGE":"warn: TerraBase.Features.Replication.ReplicationSender[1858781747]"}
{"__CURSOR":"s=5","_COMM":"terrabase","_PID":"7137","MESSAGE":"      Replication of 1 databases to peer #0 failed; retrying within 250 ms"}
{"__CURSOR":"s=6","_COMM":"ts-auth","_PID":"1342","MESSAGE":"fail: TerraScale.Auth.Hosting.ErrorEnvelopeMiddleware[0]"}
{"__CURSOR":"s=7","_COMM":"ts-auth","_PID":"1342","MESSAGE":"      Request failed with temporarily_unavailable"}
{"__CURSOR":"s=8","_COMM":"terrascale-orch","_PID":"976","MESSAGE":"{\"time\":\"2026-10-07T12:59:12.09Z\",\"level\":\"WARN\",\"msg\":\"rollout step relay\",\"cell\":\"gru\",\"component\":\"rollout\",\"unit\":\"controller-a\",\"error\":\"nats: key not found\"}"}
{"__CURSOR":"s=9","_COMM":"terrascale-orch","_PID":"976","MESSAGE":"{\"time\":\"2026-10-07T12:59:14.09Z\",\"level\":\"INFO\",\"msg\":\"host regional session\"}"}
{"__CURSOR":"s=10","_COMM":"terrascale-orch","_PID":"976","MESSAGE":"[976] [ERR] Error trying to connect to route (attempt 2): dial tcp 10.251.0.11:6222: connect: connection refused"}
{"__CURSOR":"s=11","_COMM":"terrascale-orch","_PID":"976","MESSAGE":"[976] [INF] 10.251.0.11:6222 - rid:338 - Route connection created"}
{"__CURSOR":"s=12","_COMM":"terrascale-orch","_PID":"973","MESSAGE":[104,105]}
`

func TestParseJournalClassifiesEveryFormat(t *testing.T) {
	fetch, _ := logscanFiles(t)
	out, err := fetch.Node(t.Context(), "gru-1-ctl-1", RemoteCommand(20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got := ParseJournal(out)
	want := []Record{
		{"terrabase", "WARN", "TerraBase.Features.Replication.ReplicationSender: Replication of N databases to peer #N failed; retrying within N ms"},
		{"terrabase", "WARN", "TerraBase.Features.Replication.ReplicationSender: Replication of N databases to peer #N failed; retrying within N ms"},
		{"ts-auth", "ERROR", "TerraScale.Auth.Hosting.ErrorEnvelopeMiddleware: Request failed with temporarily_unavailable"},
		{"ts-orchestrator", "WARN", "rollout: rollout step relay: nats: key not found"},
		{"ts-orchestrator", "ERROR", "nats: Error trying to connect to route (attempt N): dial tcp N: connect: connection refused"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseJournal =\n%q\nwant\n%q", got, want)
	}
}

func TestLevelPatternSelectsWarningsAndErrorsOnly(t *testing.T) {
	fetch, dir := logscanFiles(t)
	out, err := logscanProcess(t.Context(), nil, "grep", "-a", "-E", levelPattern, filepath.Join(dir, "gru-1-ctl-1"))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for line := range strings.Lines(string(out)) {
		kept = append(kept, strings.Split(line, `"`)[3])
	}
	if want := []string{"s=1", "s=4", "s=6", "s=8", "s=10"}; !slices.Equal(kept, want) {
		t.Fatalf("pattern kept %q, want %q", kept, want)
	}
	if _, err := fetch.Node(t.Context(), "gru-1-ctl-1", RemoteCommand(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(filepath.Join(dir, "journal-args"))
	if want := "--since\n-1200s\n--no-pager\n-o\njson\n--output-fields=_COMM,_PID,MESSAGE\n-u\nterrascale-orchestrator*\n"; err != nil || string(args) != want {
		t.Fatalf("journalctl arguments = %q, error %v; want %q", args, err, want)
	}
}

// fly is "fly logs --no-tail" output for ts-dashboard, colors included.
const fly = "\x1b[2m2026-10-07T14:00:00Z\x1b[0m app[d8d96000b74e78] \x1b[32mgru\x1b[0m [\x1b[34minfo\x1b[0m]time=2026-10-07T14:00:00.1Z level=WARN msg=\"too old\" error=x\n" +
	"2026-10-07T14:50:00Z app[d8d96000b74e78] gru [info]time=2026-10-07T14:50:00.1Z level=WARN msg=\"read system database\" error=\"system collection list failed: terrabase: 404 not_found\" ref=1\n" +
	"2026-10-07T14:51:00Z app[d8d96000b74e78] gru [info]time=2026-10-07T14:51:00.1Z level=INFO msg=\"New SSH session\"\n" +
	"2026-10-07T14:52:00Z app[d8d96000b74e78] gru [info]time=2026-10-07T14:52:00.1Z level=ERROR msg=resolve error=\"store unavailable\"\n" +
	"2026-10-07T14:53:00Z proxy[d8d96000b74e78] gru [error][PC01] instance refused connection. is your app listening on 0.0.0.0:8080?\n"

func TestParseFlyKeepsRecentWarningsAndErrors(t *testing.T) {
	fetch, _ := logscanFiles(t)
	out, err := fetch.Fly(t.Context(), "ts-dashboard")
	if err != nil {
		t.Fatal(err)
	}
	got := ParseFly("ts-dashboard", out, time.Date(2026, 10, 7, 14, 40, 0, 0, time.UTC))
	want := []Record{
		{"ts-dashboard", "WARN", "read system database: system collection list failed: terrabase: N not_found"},
		{"ts-dashboard", "ERROR", "resolve: store unavailable"},
		{"ts-dashboard", "ERROR", "proxy: [PCN] instance refused connection. is your app listening on N?"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseFly =\n%q\nwant\n%q", got, want)
	}
}

func TestScanCountsPerServiceAndNodeAndFailsOnAnUnreadableNode(t *testing.T) {
	fetch, _ := logscanFiles(t)
	var out bytes.Buffer
	now := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	err := Scan(t.Context(), &out, []string{"gru-1-ctl-1", "gru-1-ctl-2", "ts-sjc-1"}, []string{"ts-dashboard"}, 20*time.Minute, 2, now, fetch)
	if err == nil || !strings.Contains(err.Error(), "node ts-sjc-1: exit status 1") || !strings.Contains(err.Error(), "No such file or directory") {
		t.Fatalf("error %v", err)
	}
	report := regexp.MustCompile(` +`).ReplaceAllString(out.String(), " ")
	for _, want := range []string{
		"terrabase gru-1-ctl-1 2 0\n",
		"ts-auth gru-1-ctl-1 0 1\n",
		"ts-orchestrator gru-1-ctl-1 1 1\n",
		"ts-orchestrator gru-1-ctl-2 0 0\n",
		"ts-dashboard fly 1 2\n",
		"unreadable ts-sjc-1 - -\n",
		"TOTAL 4 4\n",
		" 2 WARN terrabase TerraBase.Features.Replication.ReplicationSender: Replication of N databases to peer #N failed; retrying within N ms [gru-1-ctl-1]\n",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Count(report, "\n") != 13 { // window, header, 6 rows, total, blank, title, 2 classes
		t.Errorf("report has %d lines, --top 2 should list 2 classes:\n%s", strings.Count(report, "\n"), out.String())
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	if os.Getenv("LOGSCAN_ARGS_CHILD") == "1" {
		args := os.Args[slices.Index(os.Args, "--")+1:]
		if err := Run(t.Context(), args, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childEnv := []string{"LOGSCAN_ARGS_CHILD=1", "GORACE=atexit_sleep_ms=0", "PATH=" + t.TempDir()}
	for _, args := range [][]string{
		{"--since", "0s", "--node", "gru-1-ctl-1"},
		{"--node", "gru-1-ctl-1", "extra"},
		{"--help"},
	} {
		out, err := logscanProcess(t.Context(), childEnv, executable,
			append([]string{"-test.run=^TestRunRejectsBadArguments$", "--"}, args...)...)
		if args[0] == "--help" {
			if err != nil || !strings.Contains(string(out), "--fly-app") {
				t.Fatalf("help: %v %q", err, out)
			}
		} else if exit, ok := errors.AsType[*exec.ExitError](err); !ok || exit.ExitCode() != 2 ||
			!strings.Contains(string(out), "log-scan needs a --since of at least 1s and no positional arguments") {
			t.Errorf("Run(%q) error %v, output %q", args, err, out)
		}
	}
}

func TestServersAreThePeersNamedLikeCellServers(t *testing.T) {
	fetch, dir := logscanFiles(t)
	var details []map[string]string
	for _, name := range []string{"ts-gru-1", "ts-sjc-3", "gru-1-ctl-2", "gru-1-db-1", "gru-1-pool-app-3",
		"gru-1", "ts-ops", "delta", "mariogk-dev-ops", "ts-xyz-1"} {
		details = append(details, map[string]string{"fqdn": name + ".nb.ts.internal", "netbirdIp": "10.200.0.1"})
	}
	status, err := json.Marshal(map[string]any{"peers": map[string]any{"details": details}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "netbird.json"), status, 0o600); err != nil {
		t.Fatal(err)
	}
	netbird := filepath.Join(dir, "netbird")
	if err := os.WriteFile(netbird, []byte(`#!/bin/sh
[ "$#" -eq 2 ] && [ "$1" = status ] && [ "$2" = --json ] || exit 2
exec cat "$LOGSCAN_FIXTURES/netbird.json"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	peers, err := sshlogin.Peers(ctx, netbird)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gru-1-ctl-2", "gru-1-db-1", "gru-1-pool-app-3", "ts-gru-1", "ts-sjc-3"}
	got := Servers(peers)
	if !slices.Equal(got, want) {
		t.Fatalf("Servers = %q, want %q", got, want)
	}
	for _, node := range want {
		if err := os.WriteFile(filepath.Join(dir, node), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := Scan(t.Context(), &out, got, nil, 20*time.Minute, 2, time.Now(), fetch); err != nil {
		t.Fatal(err)
	}
	report := regexp.MustCompile(` +`).ReplaceAllString(out.String(), " ")
	for _, node := range want {
		if !strings.Contains(report, "ts-orchestrator "+node+" 0 0\n") {
			t.Errorf("report omitted selected server %s:\n%s", node, out.String())
		}
	}
}
