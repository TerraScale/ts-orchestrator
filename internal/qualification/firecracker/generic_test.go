package firecracker

import (
	"context"
	"encoding/json/v2"

	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"

	"strings"

	"testing"
	"time"
)

func nativeLab(t *testing.T) *Lab {
	t.Helper()
	root := t.TempDir()
	l := &Lab{Ctx: t.Context(), Root: root, Logs: filepath.Join(root, "logs"), Stage: filepath.Join(root, "stage"), Secrets: filepath.Join(root, "secrets"), Images: filepath.Join(root, "images"), Binary: "unused", OperatorConfig: "config", Bridge: "tsfabc123b", Addresses: map[string]string{"host": "198.19.7.14", "c1": "198.19.7.11", "c2": "198.19.7.12", "c3": "198.19.7.13"}, VMs: map[string]*VM{}}
	l.Subnet = netip.MustParsePrefix("198.19.7.0/24")
	l.defaults()
	for _, d := range []string{l.Logs, l.Stage, l.Secrets, l.Images} {
		if e := os.Mkdir(d, 0o700); e != nil {
			t.Fatal(e)
		}
	}
	return l
}
func marshal(v any) string {
	b, e := json.Marshal(v, json.Deterministic(true))
	if e != nil {
		panic(e)
	}
	return string(b)
}
func requireError(t *testing.T, e error, part string) {
	t.Helper()
	if e == nil || !strings.Contains(e.Error(), part) {
		t.Fatalf("got %v, want error containing %q", e, part)
	}
}
func requireEqual(t *testing.T, a, b any) {
	t.Helper()
	if !reflect.DeepEqual(a, b) && !jsonEqual(a, b) {
		t.Fatalf("got %#v, want %#v", a, b)
	}
}
func TestDeployRetryContract(t *testing.T) {
	submitted := func(id string) Object {
		return Object{"operationId": id, "fingerprint": "fingerprint-" + id, "status": "submitted"}
	}
	for _, tc := range []struct {
		name      string
		responses []Object
		attempts  int
		err       string
	}{{"fence", []Object{submitted("fc-one-node-loss-2"), {"status": "rejected", "error": PreAcceptanceFenced, "authorityEpoch": 1}, submitted("fc-one-node-loss-epoch-retry-2"), {"status": "accepted", "authorityEpoch": 2}}, 2, ""}} {
		t.Run(tc.name, func(t *testing.T) {
			l := nativeLab(t)
			calls := 0
			l.Command = func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
				attempt := "one-node-loss"
				if calls >= 2 {
					attempt += "-epoch-retry"
				}
				id := "fc-" + attempt + "-2"
				if calls%2 == 0 {
					requireEqual(t, argv[len(argv)-2:], []string{"--intent", filepath.Join(l.Stage, "intent-"+attempt+"-2.json")})
				} else {
					requireEqual(t, argv[len(argv)-4:], []string{"--operation-id", id, "--fingerprint", "fingerprint-" + id})
				}
				v := tc.responses[calls]
				calls++
				return CommandResult{Stdout: marshal(v)}, nil
			}
			e := l.Deploy(Object{"source": Object{}, "digest": "a", "manifestDigest": "m"}, 2, "one-node-loss", "deploy")
			if tc.err != "" {
				requireError(t, e, tc.err)
			} else if e != nil {
				t.Fatal(e)
			}
			if calls != len(tc.responses) {
				t.Fatal(calls)
			}
			entries, _ := os.ReadDir(l.Stage)
			if len(entries) != tc.attempts {
				t.Fatal(entries)
			}
			for _, entry := range entries {
				b, e := os.ReadFile(filepath.Join(l.Stage, entry.Name()))
				if e != nil {
					t.Fatal(e)
				}
				if strings.Contains(string(b), "authorityEpoch") {
					t.Fatal("stale epoch pinned")
				}
				intent, e := readObject(filepath.Join(l.Stage, entry.Name()))
				if e != nil {
					t.Fatal(e)
				}
				name := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "intent-"), ".json")
				requireEqual(t, intent["operationId"], "fc-"+name)
			}
			terminal := []string{}
			for _, event := range l.Events {
				if event["event"] == "terminal_receipt" {
					id := str(event["operation_id"])
					terminal = append(terminal, id)
					requireEqual(t, event["fingerprint"], "fingerprint-"+id)
					if tc.name == "fence" {
						requireEqual(t, event["authority_epoch"], 1)
					}
				}
			}
			want := []string{"fc-one-node-loss-2"}
			if tc.name == "second_fence" {
				want = append(want, "fc-one-node-loss-epoch-retry-2")
			}
			requireEqual(t, terminal, want)
		})
	}
}

func journalEntry(at time.Time, message string) string {
	return marshal(Object{"__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "MESSAGE": message})
}

func TestFenceBindsLatestSignedLeaseBeforeExpiry(t *testing.T) {
	expiry := time.Date(2026, 9, 24, 12, 0, 30, 0, time.UTC)
	hash := head(hashBytes([]byte("opaque-id")), 32)
	fenced := fmt.Sprintf("2026/09/24 12:00:25 INFO host session fenced session_id_hash=%s epoch=3 expires_at=%s cause_class=reserve_exhausted", hash, expiry.Format(time.RFC3339))
	for _, tc := range []struct {
		name, message string
		valid         bool
	}{{"matching", fenced, true}} {
		t.Run(tc.name, func(t *testing.T) {
			l := nativeLab(t)
			output := journalEntry(expiry.Add(-15*time.Second), "WARN host session exchange deferred") + "\n" + journalEntry(expiry.Add(-4500*time.Millisecond), tc.message)
			if tc.valid {
				for _, neighboring := range []string{strings.Replace(fenced, hash, strings.Repeat("0", 32), 1), strings.Replace(fenced, "epoch=3", "epoch=4", 1), fmt.Sprintf(`time=2026-09-24T12:00:25Z level=INFO msg="host session fenced" session_id_hash=%s epoch=3 expires_at=%s cause_class=reserve_exhausted`, hash, expiry.Format(time.RFC3339))} {
					output += "\n" + journalEntry(expiry.Add(-4500*time.Millisecond), neighboring)
				}
			}
			l.Command = func(context.Context, []string, CommandOptions) (CommandResult, error) {
				return CommandResult{Stdout: output}, nil
			}
			e := l.HostRenewalFailureEvidence(expiry.Add(-20*time.Second), hash, 3, expiry)
			if tc.valid {
				if e != nil {
					t.Fatal(e)
				}
				requireEqual(t, l.Events[0]["fence_cause_class"], "reserve_exhausted")
				if !l.Events[0]["actual_fence_started_at"].(time.Time).Equal(expiry.Add(-4500 * time.Millisecond)) {
					t.Fatal(l.Events[0])
				}
			} else {
				requireError(t, e, "matching fence")
			}
		})
	}
}
