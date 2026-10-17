package pathaudit

import (
	"bytes"
	"encoding/json/v2"
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

func auditProcessEvidence(t *testing.T, expected string, evidence map[string][]byte, nodes []string) (string, error) {
	t.Helper()
	directory := t.TempDir()
	for node, wire := range evidence {
		if err := os.WriteFile(filepath.Join(directory, node+".json"), wire, 0600); err != nil {
			t.Fatal(err)
		}
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(directory, "netbird")
	body := `directory=$(dirname "$0")
case "$1" in
 status) printf '{"peers":{"details":[]}}';;
 ssh) node=${3#root@}; cat "$directory/$node.json";;
 *) exit 2;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--vault-id", "ocid1.vault.oc1.sa-saopaulo-1.integration", "--netbird", shell + " " + script, "--expected-ip", expected}
	for _, node := range nodes {
		args = append(args, "--node", node)
	}
	var out bytes.Buffer
	err = Run(t.Context(), args, &out)
	return out.String(), err
}

func TestAuditReadsProcessEvidenceAndRequiresConsistentDaemonState(t *testing.T) {
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
			_, err := auditProcessEvidence(t, test.ip, map[string][]byte{"ts-gru-1": observation(t, test.ip, test.change)}, []string{"ts-gru-1"})
			if (err != nil) != test.bad {
				t.Fatalf("error = %v, want failure %v", err, test.bad)
			}
		})
	}
	for _, wire := range []string{`{}`, `{`} {
		if _, err := auditProcessEvidence(t, "10.250.10.155", map[string][]byte{"ts-gru-1": []byte(wire)}, []string{"ts-gru-1"}); err == nil {
			t.Fatal("missing or malformed evidence passed")
		}
	}
}

func TestAuditContinuesAfterProcessFailureAndRejectsMissingOrMixedNodes(t *testing.T) {
	out, err := auditProcessEvidence(t, "10.250.10.155", map[string][]byte{"ts-sfo-1": observation(t, "163.176.73.79", nil)}, []string{"ts-gru-1", "ts-sfo-1"})
	if err == nil || strings.Count(out, "FAIL") != 2 || !strings.Contains(out, "ts-gru-1") || !strings.Contains(out, "ts-sfo-1") {
		t.Fatalf("incomplete audit: %s %v", out, err)
	}
	for _, nodes := range [][]string{nil, {"ts-gru-1", "ts-gru-1"}, {"ts-ops"}, {"gru-1"}, {"ts-gru-1;id"}} {
		var output bytes.Buffer
		if Audit(t.Context(), &output, nodes, netip.MustParseAddr("10.250.10.155"), nil) == nil {
			t.Fatalf("invalid server selection passed: %v", nodes)
		}
	}
}
