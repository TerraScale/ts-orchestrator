package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/nats-io/nats.go/jetstream"
)

func TestExpectedUsageKeepsHistoricalAdmissionsAndWithdrawals(t *testing.T) {
	c, _, _, mutations, key := testController(t)
	if err := c.InitializeUsageHistory(t.Context()); err != nil {
		t.Fatal(err)
	}
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
		if err != nil || !slices.Equal(usageIdentities(got), want) {
			t.Fatalf("inventory [%s,%s) = %v, %v; want %v", from, to, got, err, want)
		}
	}
	check(from, to, []string{"node-a", "node-a/api"})
	// Updating an active allocation must not split an unchanged identity's lifetime.
	desired.Generation++
	publish(authority.MutationDesired, "gru.node-a.api", desired)
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
	intervals, err := c.ExpectedUsage(t.Context(), from, withdrawal.Time)
	wantIntervals := []hostload.UsageInterval{
		{Node: "node-a", Environment: "production", From: from, To: withdrawal.Time},
		{Node: "node-a", Environment: "production", Role: "api", From: active.Time, To: withdrawal.Time},
	}
	if err != nil || !slices.Equal(intervals, wantIntervals) {
		t.Fatalf("allocation lifetime lost its exact boundaries: %v %v; want %v", intervals, err, wantIntervals)
	}
	// A stream read failure must not become an empty, complete inventory.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.ExpectedUsage(ctx, from, to); err == nil {
		t.Fatal("cancelled inventory query silently succeeded")
	}
}

func TestUsageInventoryLockHonorsRequestDeadline(t *testing.T) {
	c, _, _, _, _ := testController(t)
	if err := c.lockControlLog(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { <-c.controlLogInfoGate }()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := c.InitializeUsageHistory(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("inventory lock ignored request deadline: %v", err)
	}
}

func usageIdentities(intervals []hostload.UsageInterval) []string {
	identities := make([]string, 0, len(intervals))
	for _, interval := range intervals {
		identity := interval.Node
		if interval.Role != "" {
			identity += "/" + interval.Role
		}
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, strings.Compare)
	return slices.Compact(identities)
}
