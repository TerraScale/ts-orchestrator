package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go/jetstream"
)

func TestExpectedUsageKeepsHistoricalAdmissionsAndWithdrawals(t *testing.T) {
	c, _, _, mutations, key := testController(t)
	publish := func(kind authority.HostMutationKind, subjectKey string, value any) *jetstream.RawStreamMsg {
		t.Helper()
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(struct {
			Version     int                        `json:"version"`
			Kind        authority.HostMutationKind `json:"kind"`
			Scope       string                     `json:"scope"`
			SubjectKey  string                     `json:"subject_key"`
			OperationID string                     `json:"operation_id"`
			Epoch       uint64                     `json:"epoch"`
			Payload     []byte                     `json:"payload"`
		}{1, kind, "gru", subjectKey, "inventory-test", 1, payload})
		if err != nil {
			t.Fatal(err)
		}
		ack, err := mutations.js.Publish(t.Context(), "ts.control.gru.host."+string(kind)+"."+subjectKey, data)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := c.controlLog.GetMsg(t.Context(), ack.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		return entry
	}
	registration := Registration{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"api"},
		PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), NATSUserPublicKey: testNATSUserKey("node-a"), Generation: 1}
	first := publish(authority.MutationRegistration, "gru.node-a", registration)
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "api", AuthorityEpoch: 1, Generation: 1}
	active := publish(authority.MutationDesired, "gru.node-a.api", desired)
	from, to := first.Time, time.Now()
	check := func(from, to time.Time, want []string) {
		t.Helper()
		got, err := c.ExpectedUsage(t.Context(), from, to)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("inventory [%s,%s) = %v, %v; want %v", from, to, got, err, want)
		}
	}
	check(from, to, []string{"node-a", "node-a/api"})
	desired.Withdrawn = true
	desired.Generation++
	withdrawal := publish(authority.MutationDesired, "gru.node-a.api", desired)
	registration.Node = "node-b"
	registration.NATSUserPublicKey = testNATSUserKey("node-b")
	second := publish(authority.MutationRegistration, "gru.node-b", registration)
	desired.Node, desired.Withdrawn = "node-b", false
	publish(authority.MutationDesired, "gru.node-b.api", desired)
	// Today's admissions and withdrawal cannot rewrite an earlier answer.
	check(from, to, []string{"node-a", "node-a/api"})
	// Exact [from,to) boundaries and baseline state between commits.
	check(active.Time.Add(time.Nanosecond), withdrawal.Time, []string{"node-a", "node-a/api"})
	check(withdrawal.Time, second.Time, []string{"node-a"})
	check(second.Time, time.Now(), []string{"node-a", "node-b", "node-b/api"})
	// A stream read failure must not become an empty, complete inventory.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.ExpectedUsage(ctx, from, to); err == nil {
		t.Fatal("cancelled inventory query silently succeeded")
	}
}
