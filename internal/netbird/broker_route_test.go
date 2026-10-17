package netbird

import (
	"encoding/json/jsontext"
	"strings"
	"testing"
)

func TestBrokerRouteUsesExactMeshPeerWithoutGrantingIdentity(t *testing.T) {
	const wire = `{"daemonStatus":"Connected","netbirdIp":"100.100.0.1/10","fqdn":"ts-gru-1.nb.ts.internal",
		"management":{"url":"https://netbird.terrascale.tech","connected":true},"signal":{"connected":true},
		"peers":{"details":[{"fqdn":"ts-gru-2.nb.ts.internal","netbirdIp":"100.100.0.2","status":"Idle"}]}}`
	for _, row := range []struct{ name, want string }{{"ts-gru-1", "100.100.0.1"}, {"ts-gru-2", "100.100.0.2"}} {
		route, err := brokerRoute([]byte(wire), row.name)
		if err != nil || route.String() != row.want {
			t.Fatalf("broker locator %s = %s %v", row.name, route, err)
		}
	}
	for _, row := range []struct{ name, wire string }{
		{"missing", wire},
		{"ts-gru-2", strings.ReplaceAll(wire, "100.100.0.2", "10.251.0.12")},
		{"ts-gru-2", strings.ReplaceAll(wire, "100.100.0.2", "::ffff:100.100.0.2")},
		{"ts-gru-2", strings.ReplaceAll(wire, `"signal":{"connected":true}`, `"signal":{"connected":false}`)},
		{"ts-gru-2", strings.ReplaceAll(wire, "netbird.terrascale.tech", "other.example.com")},
		{"ts-gru-2", strings.ReplaceAll(wire, "ts-gru-1.nb.ts.internal", "ts-gru-2.nb.ts.internal")},
		{"ts-gru-2", strings.ReplaceAll(wire, `"status":"Idle"}`, `"status":"Idle"},{"fqdn":"ts-gru-2.nb.ts.internal","netbirdIp":"100.100.0.3"}`)},
	} {
		if !jsontext.Value(row.wire).IsValid() {
			t.Fatal("test routing status is not valid JSON")
		}
		if _, err := brokerRoute([]byte(row.wire), row.name); err == nil {
			t.Fatalf("accepted unavailable or ambiguous broker locator %s", row.name)
		}
	}
}
