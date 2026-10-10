package logscan

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

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
	got := ParseJournal([]byte(journal))
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
	pattern := regexp.MustCompile(levelPattern) // the ERE is also valid RE2
	var kept []string
	for line := range strings.Lines(journal) {
		if pattern.MatchString(line) {
			kept = append(kept, strings.Split(line, `"`)[3])
		}
	}
	if want := []string{"s=1", "s=4", "s=6", "s=8", "s=10"}; !slices.Equal(kept, want) {
		t.Fatalf("pattern kept %q, want %q", kept, want)
	}
	if command := RemoteCommand(20 * time.Minute); !strings.Contains(command, "--since -1200s ") || !strings.Contains(command, "'"+levelPattern+"'") {
		t.Fatalf("remote command %q", command)
	}
}

// fly is "fly logs --no-tail" output for ts-dashboard, colors included.
const fly = "\x1b[2m2026-10-07T14:00:00Z\x1b[0m app[d8d96000b74e78] \x1b[32mgru\x1b[0m [\x1b[34minfo\x1b[0m]time=2026-10-07T14:00:00.1Z level=WARN msg=\"too old\" error=x\n" +
	"2026-10-07T14:50:00Z app[d8d96000b74e78] gru [info]time=2026-10-07T14:50:00.1Z level=WARN msg=\"read system database\" error=\"system collection list failed: terrabase: 404 not_found\" ref=1\n" +
	"2026-10-07T14:51:00Z app[d8d96000b74e78] gru [info]time=2026-10-07T14:51:00.1Z level=INFO msg=\"New SSH session\"\n" +
	"2026-10-07T14:52:00Z app[d8d96000b74e78] gru [info]time=2026-10-07T14:52:00.1Z level=ERROR msg=resolve error=\"store unavailable\"\n" +
	"2026-10-07T14:53:00Z proxy[d8d96000b74e78] gru [error][PC01] instance refused connection. is your app listening on 0.0.0.0:8080?\n"

func TestParseFlyKeepsRecentWarningsAndErrors(t *testing.T) {
	got := ParseFly("ts-dashboard", []byte(fly), time.Date(2026, 10, 7, 14, 40, 0, 0, time.UTC))
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
	fetch := Fetchers{
		Node: func(_ context.Context, node, command string) ([]byte, error) {
			switch node {
			case "gru-1-ctl-1":
				return []byte(journal), nil
			case "gru-1-ctl-2":
				return nil, nil
			}
			return nil, errors.New("no route")
		},
		Fly: func(context.Context, string) ([]byte, error) { return []byte(fly), nil },
	}
	var out bytes.Buffer
	now := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	err := Scan(t.Context(), &out, []string{"gru-1-ctl-1", "gru-1-ctl-2", "ts-sfo-1"}, []string{"ts-dashboard"}, 20*time.Minute, 2, now, fetch)
	if err == nil || !strings.Contains(err.Error(), "node ts-sfo-1: no route") {
		t.Fatalf("error %v", err)
	}
	report := regexp.MustCompile(` +`).ReplaceAllString(out.String(), " ")
	for _, want := range []string{
		"terrabase gru-1-ctl-1 2 0\n",
		"ts-auth gru-1-ctl-1 0 1\n",
		"ts-orchestrator gru-1-ctl-1 1 1\n",
		"ts-orchestrator gru-1-ctl-2 0 0\n",
		"ts-dashboard fly 1 2\n",
		"unreadable ts-sfo-1 - -\n",
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
	for _, args := range [][]string{
		{"--since", "0s", "--node", "gru-1-ctl-1"},
		{"--node", "gru-1-ctl-1", "extra"},
	} {
		if err := Run(t.Context(), args, &bytes.Buffer{}); err == nil {
			t.Errorf("Run(%q) accepted", args)
		}
	}
	var help bytes.Buffer
	if err := Run(t.Context(), []string{"--help"}, &help); err != nil || !strings.Contains(help.String(), "--fly-app") {
		t.Fatalf("help: %v %q", err, help.String())
	}
}

func TestServersAreThePeersNamedLikeCellServers(t *testing.T) {
	peers := map[string]string{}
	for _, name := range []string{"ts-gru-1", "ts-sfo-3", "gru-1-ctl-2", "gru-1-db-1", "gru-1-pool-app-3",
		"gru-1", "ts-ops", "delta", "mariogk-dev-ops", "ts-xyz-1"} {
		peers[name], peers[name+".nb.ts.internal"] = "10.200.0.1", "10.200.0.1"
	}
	want := []string{"gru-1-ctl-2", "gru-1-db-1", "gru-1-pool-app-3", "ts-gru-1", "ts-sfo-3"}
	if got := Servers(peers); !slices.Equal(got, want) {
		t.Fatalf("Servers = %q, want %q", got, want)
	}
}
