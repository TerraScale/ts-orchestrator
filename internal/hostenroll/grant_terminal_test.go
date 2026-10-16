package hostenroll

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"strings"
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

func TestResetGrantRenewalRefusesOrdinaryIncompleteAndForgedProvenance(t *testing.T) {
	store := terminalTestStore(t)
	for _, fault := range []string{"ordinary incomplete", "invalid operation", "initial owner", "retired"} {
		t.Run(fault, func(t *testing.T) {
			grant := terminalTestGrant("ocid1.instance." + strings.ReplaceAll(fault, " ", "-"))
			grant.IdentityResetOperationID = entityid.Derive("test-reset", "operation")
			switch fault {
			case "ordinary incomplete":
				grant.IdentityResetOperationID = ""
			case "invalid operation":
				grant.IdentityResetOperationID = "not-an-operation"
			case "initial owner":
				grant.OwnerToken = "initial-enrollment-still-active"
			case "retired":
				grant.Disabled = true
			}
			wire, err := json.Marshal(grant)
			if err != nil {
				t.Fatal(err)
			}
			revision, err := store.kv.Create(t.Context(), grantKey(grant.InstanceID), wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.ClaimRenew(t.Context(), grant.InstanceID, []byte("verified renewal request"), time.Now()); err == nil {
				t.Fatal("incomplete grant acquired renewal authority")
			}
			entry, err := store.kv.Get(t.Context(), grantKey(grant.InstanceID))
			if err != nil || entry.Revision() != revision || !bytes.Equal(entry.Value(), wire) {
				t.Fatal("refusal changed grant")
			}
		})
	}
	if _, _, err := store.Claim(t.Context(), Grant{SchemaVersion: 1, InstanceID: "ocid1.instance.unreviewed", CreateKey: entityid.New(),
		DescriptorSHA256: terminalTestDigest, Request: []byte("request"), IdentityResetOperationID: entityid.New()}); err == nil {
		t.Fatal("ordinary enrollment fabricated root reset provenance")
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

func TestGrantStoreTerminalFenceRereadsGrantThatWinsCreateRace(t *testing.T) {
	store := terminalTestStore(t)
	candidate := terminalTestGrant("ocid1.instance.terminal-create-race")
	active, revision, err := store.Claim(t.Context(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	createOnly := Grant{SchemaVersion: 1, InstanceID: candidate.InstanceID, CreateKey: candidate.CreateKey}
	if _, _, err := store.TerminalFence(t.Context(), createOnly, 0, entityid.Derive("test-terminal", "terminal-op-create-race")); err == nil {
		t.Fatal("create-if-absent terminal fence replaced a grant that won the race")
	}
	current, currentRevision, err := store.Read(t.Context(), candidate.InstanceID)
	if err != nil || currentRevision != revision || current.Disabled || current.OwnerToken != active.OwnerToken {
		t.Fatalf("losing create-only fence changed the grant: grant=%+v revision=%d err=%v", current, currentRevision, err)
	}
	fenced, fencedRevision, err := store.TerminalFence(t.Context(), current, currentRevision, entityid.Derive("test-terminal", "terminal-op-create-race"))
	if err != nil || fencedRevision <= currentRevision || !fenced.Disabled ||
		fenced.TerminalOperationID != entityid.Derive("test-terminal", "terminal-op-create-race") || !bytes.Equal(fenced.Request, active.Request) {
		t.Fatalf("revalidated exact grant was not fenced: grant=%+v revision=%d err=%v", fenced, fencedRevision, err)
	}
}

func TestGrantStoreTerminalFenceCASDisablesExactGrant(t *testing.T) {
	store := terminalTestStore(t)
	candidate := terminalTestGrant("ocid1.instance.terminal-existing")
	active, revision, err := store.Claim(t.Context(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	operationID := entityid.Derive("test-terminal", "terminal-op-existing")

	fenced, fencedRevision, err := store.TerminalFence(t.Context(), active, revision, operationID)
	if err != nil {
		t.Fatalf("TerminalFence() on an exact grant: %v", err)
	}
	if fencedRevision <= revision || !fenced.Disabled || fenced.TerminalOperationID != operationID ||
		fenced.InstanceID != active.InstanceID || fenced.CreateKey != active.CreateKey ||
		fenced.DescriptorSHA256 != active.DescriptorSHA256 || !bytes.Equal(fenced.Request, active.Request) {
		t.Fatalf("terminal fence did not preserve and disable the exact grant: grant=%+v revision=%d", fenced, fencedRevision)
	}

	// A caller retrying after an ambiguous result must receive the same fence.
	retried, retryRevision, err := store.TerminalFence(t.Context(), active, revision, operationID)
	if err != nil || retryRevision != fencedRevision || retried.TerminalOperationID != operationID || !retried.Disabled {
		t.Fatalf("same-operation grant retry: grant=%+v revision=%d err=%v", retried, retryRevision, err)
	}

	response := []byte("late-signed-enrollment-response")
	if _, err := store.Finish(t.Context(), active, revision, response); err == nil {
		t.Fatal("stale enrollment finish succeeded after the terminal fence")
	} else if !IsGrantMutationNotApplied(err) {
		t.Fatalf("revision-mismatched Finish() was not classified as a known no-write: %v", err)
	}
	if _, _, err := store.Claim(t.Context(), candidate); err == nil {
		t.Fatal("an exact replay claim succeeded after the terminal fence")
	}
	readback, readRevision, err := store.Read(t.Context(), candidate.InstanceID)
	if err != nil || readRevision != fencedRevision || !readback.Disabled ||
		readback.TerminalOperationID != operationID || len(readback.Response) != 0 {
		t.Fatalf("stale enrollment work changed the terminal grant: grant=%+v revision=%d err=%v", readback, readRevision, err)
	}
}

func TestGrantMutationOutcomeClassifierLeavesCanceledKVWriteUncertain(t *testing.T) {
	store := terminalTestStore(t)
	candidate := terminalTestGrant("ocid1.instance.terminal-canceled-create")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := store.Claim(ctx, candidate); err == nil {
		t.Fatal("Claim() with a canceled context unexpectedly succeeded")
	} else if IsGrantMutationNotApplied(err) {
		t.Fatalf("canceled KV create was classified as proven not applied: %v", err)
	}
}

func TestGrantStoreTerminalFenceRejectsMismatchedAndCorruptSnapshots(t *testing.T) {
	store := terminalTestStore(t)
	candidate := terminalTestGrant("ocid1.instance.terminal-pins")
	active, revision, err := store.Claim(t.Context(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Grant)
	}{
		{name: "instance", mutate: func(grant *Grant) { grant.InstanceID += "-foreign" }},
		{name: "create key", mutate: func(grant *Grant) { grant.CreateKey = "0000000000KN642MZ7NB6BSMTV" }},
		{name: "descriptor digest", mutate: func(grant *Grant) { grant.DescriptorSHA256 = strings.Repeat("b", 64) }},
		{name: "request", mutate: func(grant *Grant) { grant.Request = []byte("foreign-request") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mismatched := active
			mismatched.Request = bytes.Clone(active.Request)
			test.mutate(&mismatched)
			if _, _, err := store.TerminalFence(t.Context(), mismatched, revision, entityid.Derive("test-terminal", "terminal-op-pins")); err == nil {
				t.Fatal("mismatched snapshot was fenced")
			}
			current, currentRevision, err := store.Read(t.Context(), candidate.InstanceID)
			if err != nil || currentRevision != revision || current.Disabled {
				t.Fatalf("mismatched snapshot changed the grant: grant=%+v revision=%d err=%v", current, currentRevision, err)
			}
		})
	}

	corruptRevision, err := store.kv.Update(t.Context(), grantKey(candidate.InstanceID), []byte("{"), revision)
	if err != nil {
		t.Fatal(err)
	}
	corruptBefore, err := store.kv.Get(t.Context(), grantKey(candidate.InstanceID))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.TerminalFence(t.Context(), active, corruptRevision, entityid.Derive("test-terminal", "terminal-op-corrupt")); err == nil {
		t.Fatal("corrupt grant was replaced by a terminal tombstone")
	}
	corruptAfter, err := store.kv.Get(t.Context(), grantKey(candidate.InstanceID))
	if err != nil || corruptAfter.Revision() != corruptBefore.Revision() || !bytes.Equal(corruptAfter.Value(), corruptBefore.Value()) {
		t.Fatalf("corrupt grant changed after a rejected fence: entry=%+v err=%v", corruptAfter, err)
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

func TestGrantStoreTerminalFencePreservesFinishWinners(t *testing.T) {
	store := terminalTestStore(t)
	ctx := t.Context()

	for _, operation := range []string{"enroll", "renew"} {
		t.Run(operation, func(t *testing.T) {
			candidate := terminalTestGrant("ocid1.instance.terminal-finish-" + operation)
			active, revision, err := store.Claim(ctx, candidate)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			staleSnapshot := active
			staleRevision := revision
			response, err := json.Marshal(Response{SchemaVersion: 1, Operation: operation, InstanceID: candidate.InstanceID,
				ExpiresAt: now.Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			if operation == "enroll" {
				if _, err := store.Finish(ctx, active, revision, response); err != nil {
					t.Fatal(err)
				}
			} else {
				// Renewal can finish only after the initial enrollment response is durable.
				initialResponse, err := json.Marshal(Response{SchemaVersion: 1, Operation: "enroll",
					InstanceID: candidate.InstanceID, ExpiresAt: now.Add(time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Finish(ctx, active, revision, initialResponse); err != nil {
					t.Fatal(err)
				}
				_, revision, err = store.Read(ctx, candidate.InstanceID)
				if err != nil {
					t.Fatal(err)
				}
				renewal, renewalRevision, err := store.ClaimRenew(ctx, candidate.InstanceID, []byte("signed-renewal"), now)
				if err != nil {
					t.Fatal(err)
				}
				staleSnapshot = renewal
				staleRevision = renewalRevision
				if err := store.FinishRenew(ctx, renewal, renewalRevision, response, now); err != nil {
					t.Fatal(err)
				}
			}

			if _, _, err := store.TerminalFence(ctx, staleSnapshot, staleRevision, entityid.Derive("test-terminal", "terminal-op-finish-"+operation)); err == nil {
				t.Fatalf("stale terminal snapshot overwrote a winning %s finish", operation)
			}
			completed, completedRevision, err := store.Read(ctx, candidate.InstanceID)
			if err != nil {
				t.Fatal(err)
			}
			fenced, fencedRevision, err := store.TerminalFence(ctx, completed, completedRevision, entityid.Derive("test-terminal", "terminal-op-finish-"+operation))
			if err != nil {
				t.Fatalf("TerminalFence() after winning %s finish: %v", operation, err)
			}
			if !fenced.Disabled || fenced.TerminalOperationID != entityid.Derive("test-terminal", "terminal-op-finish-"+operation) ||
				fencedRevision <= completedRevision {
				t.Fatalf("terminal fence did not disable the completed %s grant: grant=%+v revision=%d", operation, fenced, fencedRevision)
			}
			if operation == "enroll" && !bytes.Equal(fenced.Response, response) {
				t.Fatalf("enrollment finish that won first was lost: grant=%+v", fenced)
			}
			if operation == "renew" && !bytes.Equal(fenced.RenewalResponse, response) {
				t.Fatalf("renewal finish that won first was lost: grant=%+v", fenced)
			}
		})
	}
}
