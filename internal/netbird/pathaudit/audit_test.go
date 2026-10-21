package pathaudit

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func observation(t *testing.T, ip string, change func(*snapshot)) []byte {
	t.Helper()
	var s snapshot
	s.Status.DaemonStatus = "Connected"
	s.Status.Management = endpoint{"https://netbird.terrascale.tech:443", true}
	s.Status.Signal = s.Status.Management
	if err := json.Unmarshal([]byte(`{"details":[{"uri":"stun:netbird.terrascale.tech:3478","available":true},{"uri":"rels://netbird.terrascale.tech:443","available":true,"transport":"ws"}]}`), &s.Status.Relays); err != nil {
		t.Fatal(err)
	}
	s.PID = "123"
	s.Addresses = ip + " STREAM netbird.terrascale.tech\n" + ip + " DGRAM\n"
	s.Sockets = `0 0 10.251.0.11:35140 ` + netip.AddrPortFrom(netip.MustParseAddr(ip), 443).String() + ` users:(("netbird",pid=123,fd=10))`
	if change != nil {
		change(&s)
	}
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRemoteCommandStreamsLargeSocketInventory(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("remote command requires jq")
	}
	var s snapshot
	if err := json.Unmarshal(observation(t, "10.250.10.155", nil), &s); err != nil {
		t.Fatal(err)
	}
	status, err := json.Marshal(s.Status)
	if err != nil {
		t.Fatal(err)
	}
	wanted := strings.Repeat(s.Sockets+"\n", 2048)
	if len(wanted) <= 128<<10 {
		t.Fatal("fixture must exceed Linux's single-argument limit")
	}
	unrelated := strings.ReplaceAll(s.Sockets, `("netbird",pid=123,`, `("nginx",pid=456,`)
	otherPID := strings.ReplaceAll(s.Sockets, "pid=123,", "pid=1234,")
	dir := t.TempDir()
	for name, body := range map[string][]byte{
		"status.json": status,
		"sockets.txt": []byte(strings.Repeat(unrelated+"\n", 4096) + otherPID + "\n" + wanted),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"netbird":   `cat "$TS676_TEST_STATUS"`,
		"systemctl": "printf '123\\n'",
		"getent":    "printf '10.250.10.155 STREAM netbird.terrascale.tech\\n'",
		"ss":        "cat \"$TS676_TEST_SOCKETS\"\nexit \"${TS676_TEST_SS_CODE:-0}\"",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, ssCode := range []string{"0", "1"} {
		command := exec.CommandContext(t.Context(), "sh", "-c", strings.Replace(RemoteCommand, "/usr/local/bin/netbird", "netbird", 1))
		command.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"TS676_TEST_STATUS="+filepath.Join(dir, "status.json"), "TS676_TEST_SOCKETS="+filepath.Join(dir, "sockets.txt"), "TS676_TEST_SS_CODE="+ssCode)
		body, err := command.Output()
		if ssCode != "0" {
			if err == nil {
				t.Fatal("failed socket inventory produced a successful observation")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := inspect(body, netip.MustParseAddr("10.250.10.155")); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &s); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(s.Sockets, "nginx") || strings.Contains(s.Sockets, "pid=1234,") || strings.Count(s.Sockets, "pid=123,") != 2048 {
			t.Fatal("observation lost NetBird sockets or included unrelated processes")
		}
	}
}

func TestInspectRequiresLiveConsistentDaemonEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		ip     string
		change func(*snapshot)
		bad    bool
	}{
		{name: "private", ip: "10.250.10.155"},
		{name: "public", ip: "163.176.73.79"},
		{name: "ipv6", ip: "2001:db8::1"},
		{name: "no STUN still relayed", change: func(s *snapshot) { s.Status.Relays.Details[0].Available = false }},
		{name: "disconnected", change: func(s *snapshot) { s.Status.Signal.Connected = false }, bad: true},
		{name: "other manager", change: func(s *snapshot) { s.Status.Management.URL = "https://api.netbird.io" }, bad: true},
		{name: "other relay", change: func(s *snapshot) { s.Status.Relays.Details[1].URI = "rels://other.example:443" }, bad: true},
		{name: "no relay", change: func(s *snapshot) { s.Status.Relays.Details[1].Available = false }, bad: true},
		{name: "QUIC relay", change: func(s *snapshot) { s.Status.Relays.Details[1].Transport = "quic" }, bad: true},
		{name: "unknown relay transport", change: func(s *snapshot) { s.Status.Relays.Details[1].Transport = "" }, bad: true},
		{name: "stale resolution", change: func(s *snapshot) { s.Addresses = "163.176.73.79 STREAM" }, bad: true},
		{name: "no sockets", change: func(s *snapshot) { s.Sockets = "" }, bad: true},
		{name: "wrong process", change: func(s *snapshot) { s.PID = "12" }, bad: true},
		{name: "mixed sockets", change: func(s *snapshot) {
			s.Sockets += "\n" + `0 0 10.251.0.11:35142 163.176.73.79:443 users:(("netbird",pid=123,fd=12))`
		}, bad: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.ip == "" {
				test.ip = "10.250.10.155"
			}
			err := inspect(observation(t, test.ip, test.change), netip.MustParseAddr(test.ip))
			if (err != nil) != test.bad {
				t.Fatalf("error = %v, want failure %v", err, test.bad)
			}
		})
	}
	if inspect([]byte(`{}`), netip.MustParseAddr("10.250.10.155")) == nil || inspect([]byte(`{`), netip.MustParseAddr("10.250.10.155")) == nil {
		t.Fatal("missing or malformed evidence passed")
	}
}

func TestAuditContinuesAfterFailureButCannotPassMissingOrMixedNodes(t *testing.T) {
	var visited []string
	var out bytes.Buffer
	err := Audit(t.Context(), &out, []string{"ts-gru-1", "ts-sjc-1"}, netip.MustParseAddr("10.250.10.155"),
		func(ctx context.Context, node string) ([]byte, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("SSH has no deadline")
			}
			visited = append(visited, node)
			if node == "ts-gru-1" {
				return nil, errors.New("unreachable")
			}
			return observation(t, "163.176.73.79", nil), nil
		})
	if err == nil || len(visited) != 2 || strings.Count(out.String(), "FAIL") != 2 {
		t.Fatalf("visited %v, output %s, error %v", visited, &out, err)
	}
	for _, nodes := range [][]string{nil, {"ts-gru-1", "ts-gru-1"}, {"ts-ops"}, {"gru-1"}, {"ts-gru-1;id"}} {
		if Audit(t.Context(), &out, nodes, netip.MustParseAddr("10.250.10.155"), nil) == nil {
			t.Fatalf("invalid server selection passed: %v", nodes)
		}
	}
}
