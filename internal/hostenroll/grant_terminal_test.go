package hostenroll

import (
	"bytes"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const terminalTestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func terminalTestStore(t *testing.T) *GrantStore {
	t.Helper()

	broker, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		broker.Shutdown()
		broker.WaitForShutdown()
		t.Fatal("embedded NATS did not start")
	}
	t.Cleanup(func() {
		broker.Shutdown()
		broker.WaitForShutdown()
	})

	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenGrantStore(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func terminalTestGrant(instanceID string) Grant {
	return Grant{
		SchemaVersion: 1, InstanceID: instanceID, CreateKey: "0000000000B7W1E1H4V9EGD4XT",
		DescriptorSHA256: terminalTestDigest, Request: []byte("signed-enrollment-request"),
	}
}

func TestGrantStoreTerminalFenceCreatesDurableTombstone(t *testing.T) {
	store := terminalTestStore(t)
	candidate := terminalTestGrant("ocid1.instance.terminal-missing")
	expected := Grant{SchemaVersion: 1, InstanceID: candidate.InstanceID, CreateKey: candidate.CreateKey}
	operationID := entityid.Derive("test-terminal", "terminal-op-missing")

	fenced, revision, err := store.TerminalFence(t.Context(), expected, 0, operationID)
	if err != nil {
		t.Fatalf("TerminalFence() on an absent grant: %v", err)
	}
	if revision == 0 || !fenced.Disabled || fenced.TerminalOperationID != operationID ||
		fenced.InstanceID != expected.InstanceID || fenced.CreateKey != expected.CreateKey ||
		fenced.DescriptorSHA256 != "" || len(fenced.Request) != 0 {
		t.Fatalf("absent grant did not become the expected tombstone: grant=%+v revision=%d", fenced, revision)
	}
	readback, readRevision, err := store.Read(t.Context(), candidate.InstanceID)
	if err != nil || readRevision != revision || !readback.Disabled || readback.TerminalOperationID != operationID {
		t.Fatalf("tombstone was not durable: grant=%+v revision=%d err=%v", readback, readRevision, err)
	}

	// The runtime retries after reading an existing tombstone and supplies its
	// positive revision and complete stored snapshot.
	retried, retryRevision, err := store.TerminalFence(t.Context(), readback, readRevision, operationID)
	if err != nil || retryRevision != revision || !retried.Disabled || retried.TerminalOperationID != operationID {
		t.Fatalf("same-operation positive-revision tombstone retry: grant=%+v revision=%d err=%v", retried, retryRevision, err)
	}
	mismatchedTombstone := readback
	mismatchedTombstone.CreateKey = "0000000000KN642MZ7NB6BSMTV"
	if _, _, err := store.TerminalFence(t.Context(), mismatchedTombstone, readRevision, operationID); err == nil {
		t.Fatal("positive-revision tombstone retry accepted a foreign create key")
	}

	// A retry after a lost response uses the original create-if-absent request.
	retried, retryRevision, err = store.TerminalFence(t.Context(), expected, 0, operationID)
	if err != nil || retryRevision != revision || retried.TerminalOperationID != operationID {
		t.Fatalf("same-operation tombstone retry: grant=%+v revision=%d err=%v", retried, retryRevision, err)
	}
	if _, _, err := store.TerminalFence(t.Context(), expected, 0, "different-terminal-op"); err == nil {
		t.Fatal("a different operation took over an existing terminal tombstone")
	}

	if _, _, err := store.Claim(t.Context(), candidate); err == nil {
		t.Fatal("delayed enrollment claim re-enabled a terminal tombstone")
	}
	readback, readRevision, err = store.Read(t.Context(), candidate.InstanceID)
	if err != nil || readRevision != revision || !readback.Disabled || readback.TerminalOperationID != operationID {
		t.Fatalf("delayed claim changed the terminal tombstone: grant=%+v revision=%d err=%v", readback, readRevision, err)
	}
}

func TestGrantStoreTerminalFenceBlocksDelayedRenewalWork(t *testing.T) {
	store := terminalTestStore(t)
	candidate := terminalTestGrant("ocid1.instance.terminal-renewal")
	active, revision, err := store.Claim(t.Context(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	response, err := json.Marshal(Response{SchemaVersion: 1, Operation: "enroll", InstanceID: candidate.InstanceID,
		ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.Finish(t.Context(), active, revision, response)
	if err != nil {
		t.Fatal(err)
	}
	_, revision, err = store.Read(t.Context(), candidate.InstanceID)
	if err != nil {
		t.Fatal(err)
	}

	renewalRequest := []byte("signed-renewal-request")
	beforeRenewal, beforeRenewalRevision, err := store.Read(t.Context(), candidate.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	renewal, renewalRevision, err := store.ClaimRenew(t.Context(), candidate.InstanceID, renewalRequest, now)
	if err != nil {
		t.Fatalf("ClaimRenew() before the fence: %v", err)
	}
	operationID := entityid.Derive("test-terminal", "terminal-op-renewal")
	if _, _, err := store.TerminalFence(t.Context(), beforeRenewal, beforeRenewalRevision, operationID); err == nil {
		t.Fatal("stale terminal snapshot overwrote a renewal claim that won the revision race")
	}
	current, currentRevision, err := store.Read(t.Context(), candidate.InstanceID)
	if err != nil || currentRevision != renewalRevision || current.Disabled || !bytes.Equal(current.RenewalRequest, renewalRequest) {
		t.Fatalf("stale fence changed the winning renewal claim: grant=%+v revision=%d err=%v", current, currentRevision, err)
	}
	fenced, fencedRevision, err := store.TerminalFence(t.Context(), renewal, renewalRevision, operationID)
	if err != nil {
		t.Fatalf("TerminalFence() after a winning renewal claim: %v", err)
	}
	if !fenced.Disabled || fenced.TerminalOperationID != operationID ||
		!bytes.Equal(fenced.Response, completed.Response) || !bytes.Equal(fenced.RenewalRequest, renewalRequest) {
		t.Fatalf("terminal fence lost an earlier enrollment or renewal write: grant=%+v", fenced)
	}

	if err := store.FinishRenew(t.Context(), renewal, renewalRevision, []byte("late-renewal-response"), now); err == nil {
		t.Fatal("stale renewal finish succeeded after the terminal fence")
	}
	if _, _, err := store.ClaimRenew(t.Context(), candidate.InstanceID, []byte("delayed-renewal-request"), now); err == nil {
		t.Fatal("delayed renewal claim succeeded after the terminal fence")
	}
	readback, readRevision, err := store.Read(t.Context(), candidate.InstanceID)
	if err != nil || readRevision != fencedRevision || !readback.Disabled || readback.TerminalOperationID != operationID ||
		len(readback.RenewalResponse) != 0 {
		t.Fatalf("delayed renewal work changed the terminal grant: grant=%+v revision=%d err=%v", readback, readRevision, err)
	}
}
