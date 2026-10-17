package region

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"
)

// This extends the actual SDK/HTTP/disk foundation scenario. Serialized fixture
// records exercise storage retention without minting a privileged root proof.
func capacityJournalSDKScenario(t *testing.T, store *ObjectFoundationStore) {
	t.Helper()
	record, etag, err := store.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	writer := *record.FoundationWriter
	base := *writer.Policy
	base.PolicyID = "ocid1.policy.oc1..originalwriter"
	base.VerifiedAt = base.FirstAttemptAt.Add(time.Second)
	writer.Policy = &base
	record.FoundationWriter = &writer
	record.UpdatedAt = base.VerifiedAt
	etag, err = store.CompareAndSwap(t.Context(), record, etag)
	if err != nil {
		t.Fatal(err)
	}
	writerDigest, err := capacityWriterDigest(writer)
	if err != nil {
		t.Fatal(err)
	}
	purpose, err := json.Marshal(WorkerCapacityJournal{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	details, err := capacityJournalPolicy(writer)
	if err != nil {
		t.Fatal(err)
	}
	body, err := foundationWriterPolicyBody(details)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range details.Statements {
		if strings.Contains(statement, "OBJECT_CREATE") || strings.Contains(statement, "OBJECT_DELETE") || !strings.Contains(statement, "target.object.name=") {
			t.Fatal("capacity IAM escaped the existing exact objects")
		}
	}
	operation := digestSource([]byte(writerDigest + "\x00" + writer.GrantSHA256 + "\x00" + digestSource(purpose)))
	first := base.VerifiedAt.Add(time.Second)
	writer.CapacityJournal = &CapacityJournalPolicy{OperationID: operation, WriterSHA256: writerDigest,
		GrantSHA256: writer.GrantSHA256, Generation: writer.Generation, PurposeSHA256: digestSource(purpose), ExpiresAt: first.Add(time.Hour),
		Policy:   FoundationWriterPolicy{Request: details, RequestDigest: digestSource(body), RetryToken: digestSource([]byte(operation + "\x00" + digestSource(body))), FirstAttemptAt: first},
		Attempts: []time.Time{first}}
	record.FoundationWriter, record.UpdatedAt = &writer, first
	if _, err := store.CompareAndSwap(t.Context(), record, etag); err != nil {
		t.Fatal(err)
	}
	// An unknown policy create survives both a client restart and later CAS.
	restarted, err := NewObjectFoundationStore(store.client, store.namespace, store.bucket)
	if err != nil {
		t.Fatal(err)
	}
	record, etag, err = restarted.Load(t.Context(), "GRU")
	if err != nil || record.FoundationWriter == nil || !sameCapacityPolicy(record.FoundationWriter.CapacityJournal, writer.CapacityJournal) {
		t.Fatalf("unknown original policy reservation lost: %v", err)
	}
	for name, mutate := range map[string]func(*FoundationRecord){
		"remove_reservation": func(r *FoundationRecord) { r.FoundationWriter.CapacityJournal = nil },
		"erase_dispatch":     func(r *FoundationRecord) { r.FoundationWriter.CapacityJournal.Attempts = nil },
		"replace_grant":      func(r *FoundationRecord) { r.FoundationWriter.CapacityJournal.GrantSHA256 = strings.Repeat("f", 64) },
		"extend_expiry": func(r *FoundationRecord) {
			r.FoundationWriter.CapacityJournal.ExpiresAt = r.FoundationWriter.CapacityJournal.ExpiresAt.Add(time.Hour)
		},
		"replace_request": func(r *FoundationRecord) {
			r.FoundationWriter.CapacityJournal.Policy.Request.Statements = append(r.FoundationWriter.CapacityJournal.Policy.Request.Statements, "Allow any-user to manage objects in tenancy")
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, observed, err := restarted.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if _, err := restarted.CompareAndSwap(t.Context(), candidate, observed); err == nil {
				t.Fatal("protected original policy changed")
			}
			retained, current, err := restarted.Load(t.Context(), "GRU")
			if err != nil || current != etag || !sameCapacityPolicy(retained.FoundationWriter.CapacityJournal, writer.CapacityJournal) {
				t.Fatalf("rejected write changed durable policy: %v", err)
			}
		})
	}
	// Positive original identity and verification append evidence once.
	p := record.FoundationWriter.CapacityJournal
	p.ObservedPolicyID, p.ObservedAt = "ocid1.policy.oc1..capacityjournal", first.Add(time.Second)
	p.Policy.PolicyID, p.Policy.VerifiedAt = p.ObservedPolicyID, p.ObservedAt.Add(time.Second)
	record.UpdatedAt = p.Policy.VerifiedAt
	if _, err := restarted.CompareAndSwap(t.Context(), record, etag); err != nil {
		t.Fatal(err)
	}
	retained, observed, err := restarted.Load(t.Context(), "GRU")
	if err != nil || retained.FoundationWriter.CapacityJournal.Policy.PolicyID != p.Policy.PolicyID {
		t.Fatalf("original policy result lost: %v", err)
	}
	retained.FoundationWriter.CapacityJournal.ObservedPolicyID = "ocid1.policy.oc1..replacement"
	retained.FoundationWriter.CapacityJournal.Policy.PolicyID = "ocid1.policy.oc1..replacement"
	if _, err := restarted.CompareAndSwap(t.Context(), retained, observed); err == nil {
		t.Fatal("original observed policy identity replaced")
	}
}
