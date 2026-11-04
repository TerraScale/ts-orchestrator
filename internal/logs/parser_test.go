package logs

import (
	"strings"
	"testing"
	"time"
)

func TestClassifyRedactsCredentialsFromMessageAndExample(t *testing.T) {
	line := "Authorization: Bearer abc.def.ghi token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln dialing nats://user:pass@host:4222"
	for _, entries := range [][]Entry{
		{{Comm: "terrabase", Priority: "4", Message: line}},
		dotnet("7", "warn: Dialer[1]", line),
	} {
		got := journalRecords(t, entries...)
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

func TestJournalFieldsAndInvalidLinesThroughHTTP(t *testing.T) {
	got := journalRecords(t, Entry{Unit: "terrascale-orchestrator-host.service", Comm: "terrascale-orch", PID: "976", Priority: "4", At: time.UnixMicro(1786000000123456), Message: "hello"})
	if len(got) != 1 || got[0].Service != "ts-orchestrator" || got[0].Level != LevelWarn || got[0].Message != "hello" {
		t.Fatalf("journal HTTP records = %+v", got)
	}
}
