package pathaudit

import (
	"encoding/json/v2"
	"net/netip"
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

func TestInspectRequiresLiveConsistentDaemonEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		ip     string
		change func(*snapshot)
		bad    bool
	}{
		{name: "private", ip: "10.250.10.155"},
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
