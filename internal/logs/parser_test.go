package logs

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestClassifyEveryFormat(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry Entry
		want  Record
	}{
		{"record v1 with service and error", Entry{Unit: "terrascale-orchestrator-host.service", Comm: "terrascale-orch",
			Message: `{"time":"2026-10-09T19:31:06Z","level":"WARN","msg":"rollout step 3 relay","component":"rollout","service":"ts-orchestrator","error":"nats: key 42 not found"}`},
			Record{Service: "ts-orchestrator", Level: LevelWarn, Component: "rollout", Message: "rollout step N relay: nats: key N not found"}},
		{"slog without service falls back to the unit", Entry{Unit: "terrascale-orchestrator-host.service", Comm: "terrascale-orch",
			Message: `{"level":"DEBUG","msg":"host regional session"}`},
			Record{Service: "ts-orchestrator", Level: LevelDebug, Message: "host regional session"}},
		{"NATS warning", Entry{Comm: "terrascale-orch", Message: "[976] [WRN] Slow consumer detected: 12 dropped"},
			Record{Service: "ts-orchestrator", Level: LevelWarn, Component: "nats", Message: "Slow consumer detected: N dropped"}},
		{"NATS fatal is an error", Entry{Comm: "terrascale-orch", Message: "[976] [FTL] Server exiting"},
			Record{Service: "ts-orchestrator", Level: LevelError, Component: "nats", Message: "Server exiting"}},
		{"NATS info", Entry{Comm: "terrascale-orch", Message: "[976] [INF] Route connection created"},
			Record{Service: "ts-orchestrator", Level: LevelInfo, Component: "nats", Message: "Route connection created"}},
		{"NetBird line", Entry{Unit: "netbird.service", Comm: "netbird",
			Message: "2026-10-09T19:31:06.680Z INFO [peer: ts-gru-1 10.200.0.1] client/internal/relay/relay.go:103: started new probe"},
			Record{Service: "netbird", Level: LevelInfo, Component: "client/internal/relay/relay.go", Message: "started new probe"}},
		{"NetBird error", Entry{Unit: "netbird.service", Comm: "netbird",
			Message: "2026-10-09T19:31:06.680Z ERRO client/internal/engine.go:9: probe timed out after 5s"},
			Record{Service: "netbird", Level: LevelError, Component: "client/internal/engine.go", Message: "probe timed out after Ns"}},
		{"other line takes its PRIORITY level", Entry{Unit: "terrascale-terrabase.service", Comm: "terrabase", Priority: "4",
			Message: "disk nearly full"},
			Record{Service: "terrascale-terrabase", Level: LevelWarn, Message: "disk nearly full"}},
		{"other line without PRIORITY is INFO", Entry{Unit: "ssh.service", Comm: "sshd", Message: "Accepted key"},
			Record{Service: "ssh", Level: LevelInfo, Message: "Accepted key"}},
		{"systemd's own line", Entry{Unit: "netbird.service", Comm: "systemd", Priority: "6", Message: "Started netbird.service."},
			Record{Service: "systemd", Level: LevelInfo, Message: "Started netbird.service."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Classify(tc.entry)
			if !ok {
				t.Fatal("not classified")
			}
			tc.want.Example = strings.TrimSpace(tc.entry.Message)
			if got != tc.want {
				t.Fatalf("Classify =\n%+v\nwant\n%+v", got, tc.want)
			}
		})
	}
}

func TestClassifyRejectsEmptyMessages(t *testing.T) {
	if _, ok := Classify(Entry{Comm: "terrabase", Message: "   "}); ok {
		t.Fatal("blank message classified")
	}
}

func TestClassifyTruncatesTheExampleAtAUTF8Boundary(t *testing.T) {
	got, _ := Classify(Entry{Comm: "x", Message: strings.Repeat("é", 300)})
	kept, marked := strings.CutSuffix(got.Example, "...")
	if len(got.Example) > 512 || !marked || !strings.HasPrefix(strings.Repeat("é", 300), kept) || len(kept)%2 != 0 {
		t.Fatalf("example is %d bytes, want at most 512 at a boundary", len(got.Example))
	}
}

func TestClassifyRedactsCredentialsFromMessageAndExample(t *testing.T) {
	line := "Authorization: Bearer abc.def.ghi token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln dialing nats://user:pass@host:4222"
	for _, entries := range [][]Entry{
		{{Comm: "terrabase", Priority: "4", Message: line}},
		dotnet("7", "warn: Dialer[1]", line),
	} {
		got := collect(&Parser{}, entries...)
		if len(got) != 1 {
			t.Fatalf("Parse = %+v, want one record", got)
		}
		for _, text := range []string{got[0].Message, got[0].Example} {
			for _, secret := range []string{"abc.def.ghi", "eyJhbGciOiJIUzI1NiJ9", "user:pass"} {
				if strings.Contains(text, secret) {
					t.Fatalf("credential %q kept in %+v", secret, got[0])
				}
			}
		}
	}
}

// dotnet is a .NET console record: its header line, then the indented message.
func dotnet(pid, header, message string) []Entry {
	return []Entry{{Comm: "terrabase", PID: pid, Message: header}, {Comm: "terrabase", PID: pid, Message: "      " + message}}
}

func collect(p *Parser, entries ...Entry) []Record {
	var out []Record
	for _, e := range entries {
		if r, ok := p.Parse(e); ok {
			out = append(out, r)
		}
	}
	return append(out, p.Flush()...)
}

func TestParsePairsDotnetRecordsAcrossInterleavedProcesses(t *testing.T) {
	var p Parser
	got := collect(&p,
		Entry{Comm: "terrabase", PID: "7137", Message: "warn: TerraBase.Replication.Sender[1858781747]"},
		Entry{Comm: "ts-auth", PID: "1342", Message: "fail: TerraScale.Auth.Envelope[0]"},
		Entry{Comm: "terrabase", PID: "7137", Message: "      Replication of 2 databases failed"},
		Entry{Comm: "ts-auth", PID: "1342", Message: "      Request failed with temporarily_unavailable"},
	)
	want := []Record{
		{Service: "terrabase", Level: LevelWarn, Component: "TerraBase.Replication.Sender", Message: "Replication of N databases failed",
			Example: "Replication of 2 databases failed"},
		{Service: "ts-auth", Level: LevelError, Component: "TerraScale.Auth.Envelope", Message: "Request failed with temporarily_unavailable",
			Example: "Request failed with temporarily_unavailable"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Parse =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseEmitsAHeaderWithoutItsMessageAlone(t *testing.T) {
	var p Parser
	got := collect(&p,
		Entry{Comm: "terrabase", PID: "7", Message: "warn: Sender[1]"},
		Entry{Comm: "terrabase", PID: "7", Message: "info: Other[2]"},
		Entry{Comm: "terrabase", PID: "7", Message: "crit: Last[3]"},
	)
	want := []Record{
		{Service: "terrabase", Level: LevelWarn, Component: "Sender"},
		{Service: "terrabase", Level: LevelInfo, Component: "Other"},
		{Service: "terrabase", Level: LevelError, Component: "Last"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Parse =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseKeepsALineThatFollowsADanglingHeader(t *testing.T) {
	var p Parser
	got := collect(&p,
		Entry{Comm: "terrabase", PID: "7", Message: "warn: Sender[1]"},
		Entry{Comm: "terrabase", PID: "7", Message: `{"level":"ERROR","msg":"store down"}`},
	)
	want := []Record{
		{Service: "terrabase", Level: LevelWarn, Component: "Sender"},
		{Service: "terrabase", Level: LevelError, Message: "store down", Example: `{"level":"ERROR","msg":"store down"}`},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Parse =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseCompletesRepeatedDotnetPairs(t *testing.T) {
	var p Parser
	var entries []Entry
	for range 3 {
		entries = append(entries, dotnet("9", "dbug: Cache[0]", "Cache warm")...)
	}
	got := collect(&p, entries...)
	if len(got) != 3 || got[0].Level != LevelDebug || got[0].Message != "Cache warm" {
		t.Fatalf("Parse = %+v", got)
	}
}

func TestParseSwallowsExceptionTextAfterADotnetMessage(t *testing.T) {
	var p Parser
	got := collect(&p,
		Entry{Comm: "terrabase", PID: "7", Message: "fail: TerraBase.Replication.Sender[1]"},
		Entry{Comm: "terrabase", PID: "7", Message: "      Replication of 2 databases failed"},
		Entry{Comm: "terrabase", PID: "7", Message: "      System.InvalidOperationException: pool exhausted"},
		Entry{Comm: "terrabase", PID: "7", Message: "         at Npgsql.Pool.Get() in /src/Pool.cs:line 42"},
		Entry{Comm: "terrabase", PID: "7", Message: "         at TerraBase.Replication.Sender.Run() in /src/Sender.cs:line 9"},
		Entry{Comm: "terrabase", PID: "7", Priority: "4", Message: "disk nearly full"},
	)
	want := []Record{
		{Service: "terrabase", Level: LevelError, Component: "TerraBase.Replication.Sender", Message: "Replication of N databases failed",
			Example: "Replication of 2 databases failed"},
		{Service: "terrabase", Level: LevelWarn, Message: "disk nearly full", Example: "disk nearly full"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Parse =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseKeepsDotnetContinuationsOutOfOtherProcessesRecords(t *testing.T) {
	var p Parser
	got := collect(&p,
		Entry{Comm: "terrabase", PID: "7", Message: "warn: TerraBase.Replication.Sender[1]"},
		Entry{Comm: "terrabase", PID: "7", Message: "      Replication failed"},
		Entry{Comm: "terrabase", PID: "9", Message: "info: TerraBase.Cache[2]"},
		Entry{Comm: "terrabase", PID: "7", Message: "      System.Exception: boom"},
		Entry{Comm: "terrabase", PID: "7", Message: "         at X.Run()"},
		Entry{Comm: "terrabase", PID: "9", Message: "      cache warm"},
		Entry{Comm: "terrabase", PID: "7", Message: "         at Y.Run()"},
		Entry{Comm: "terrabase", PID: "7", Message: "info: TerraBase.Next[3]"},
		Entry{Comm: "terrabase", PID: "7", Message: "      next done"},
	)
	want := []Record{
		{Service: "terrabase", Level: LevelWarn, Component: "TerraBase.Replication.Sender", Message: "Replication failed", Example: "Replication failed"},
		{Service: "terrabase", Level: LevelInfo, Component: "TerraBase.Cache", Message: "cache warm", Example: "cache warm"},
		{Service: "terrabase", Level: LevelInfo, Component: "TerraBase.Next", Message: "next done", Example: "next done"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Parse =\n%+v\nwant\n%+v", got, want)
	}
}

func TestDecodeJournalReadsTheFieldsAndSkipsBinaryMessages(t *testing.T) {
	e, ok := DecodeJournal([]byte(`{"_SYSTEMD_UNIT":"terrascale-orchestrator-host.service","_COMM":"terrascale-orch","_PID":"976","PRIORITY":"4","__REALTIME_TIMESTAMP":"1786000000123456","MESSAGE":"hello"}`))
	if !ok || e.Unit != "terrascale-orchestrator-host.service" || e.Comm != "terrascale-orch" || e.PID != "976" ||
		e.Priority != "4" || e.Message != "hello" || !e.At.Equal(time.UnixMicro(1786000000123456)) {
		t.Fatalf("DecodeJournal = %+v, %v", e, ok)
	}
	for _, line := range []string{`[104,105]`, `--`, ``, `{"_COMM":"x","MESSAGE":[104,105]}`} {
		if _, ok := DecodeJournal([]byte(line)); ok {
			t.Errorf("DecodeJournal(%q) accepted", line)
		}
	}
}

func TestPermissionViolationsOfOneCauseShareAClass(t *testing.T) {
	a, _ := Classify(Entry{Comm: "terrascale-orch", Message: `[976] [WRN] Publish Violation for client "ts-gru-1" in account ACME with JWT eyJhbGciOi`})
	b, _ := Classify(Entry{Comm: "terrascale-orch", Message: `[977] [WRN] Publish Violation for client "ts-sfo-2" in account BETA with JWT eyJzdWIiOi`})
	if a.Message != b.Message {
		t.Fatalf("violation classes %q and %q differ", a.Message, b.Message)
	}
	for _, part := range []string{"ts-gru-1", "ACME", "eyJ"} {
		if strings.Contains(a.Message, part) {
			t.Errorf("class %q keeps %q", a.Message, part)
		}
	}
}
