package region

import (
	"encoding/json/v2"
	"slices"
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
	// This is descriptive durable evidence, not an admitted HOME actor or IAM
	// installation. A map-only record must validate and survive real SDK/disk CAS.
	fourCells := []string{"AMS", "FRA", "GRU", "SFO"}
	fourScope, four := capacityScopePersistenceFixture(t, writer, digestSource(purpose), fourCells, base.VerifiedAt.Add(100*time.Millisecond))
	writer.CapacityJournalScopes = map[string]CapacityJournalPolicy{fourScope: four}
	record.FoundationWriter, record.UpdatedAt = &writer, four.Policy.VerifiedAt
	etag, err = store.CompareAndSwap(t.Context(), record, etag)
	if err != nil {
		t.Fatal(err)
	}
	mapOnly, mapETag, err := store.Load(t.Context(), "GRU")
	if err != nil || mapETag != etag || mapOnly.FoundationWriter.CapacityJournal != nil ||
		!sameCapacityPolicy(capacityPolicyAt(mapOnly.FoundationWriter, fourScope), &four) {
		t.Fatalf("map-only original scope lost: %v", err)
	}
	if got, err := capacityWriterDigest(*mapOnly.FoundationWriter); err != nil || got != writerDigest {
		t.Fatalf("capacity scopes changed original writer identity: %v", err)
	}
	// Exercise retention while the legacy pointer is still absent. Restoring
	// the old pointer-only early return must fail these real SDK CAS checks.
	mapOnlyWire, err := json.Marshal(mapOnly.FoundationWriter, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*FoundationWriterRecord){
		"map_only_remove": func(w *FoundationWriterRecord) { w.CapacityJournalScopes = nil },
		"map_only_rebind_expiry": func(w *FoundationWriterRecord) {
			p := w.CapacityJournalScopes[fourScope]
			p.ExpiresAt = p.ExpiresAt.Add(time.Hour)
			w.CapacityJournalScopes[fourScope] = p
		},
		"map_only_replace_cells": func(w *FoundationWriterRecord) {
			p := w.CapacityJournalScopes[fourScope]
			p.Cells = []string{"GRU"}
			w.CapacityJournalScopes[fourScope] = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			mutate(candidate.FoundationWriter)
			if _, err := store.CompareAndSwap(t.Context(), candidate, etag); err == nil {
				t.Fatal("map-only original scope changed")
			}
			retained, current, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(retained.FoundationWriter, json.Deterministic(true))
			if err != nil || current != mapETag || string(wire) != string(mapOnlyWire) {
				t.Fatalf("rejected map-only mutation changed durable bytes: %v", err)
			}
		})
	}
	if len(four.Policy.Request.Statements) != len(fourCells) {
		t.Fatal("four-cell scope did not produce four exact object clauses")
	}
	for i, statement := range four.Policy.Request.Statements {
		if !strings.Contains(statement, "target.object.name='"+foundationObjectPrefix+fourCells[i]+".json'") ||
			strings.Contains(statement, "OBJECT_CREATE") || strings.Contains(statement, "OBJECT_DELETE") || strings.Contains(statement, "*") {
			t.Fatal("new scope policy escaped its canonical exact object")
		}
	}
	for _, cells := range [][]string{nil, {"gru"}, {"ZZZ"}, {"GRU", "GRU"}, {"SFO", "GRU"}} {
		if _, _, err := capacityScopePolicy(writer, digestSource(purpose), cells); err == nil {
			t.Fatalf("noncanonical policy scope accepted: %v", cells)
		}
	}
	if _, _, err := capacityScopePolicy(writer, digestSource(purpose), []string{"GRU"}); err != nil {
		t.Fatal(err)
	}
	for i, cell := range []string{"GRU", "SFO", "FRA"} {
		if !strings.Contains(details.Statements[i], foundationObjectPrefix+cell+".json") {
			t.Fatal("legacy statement order changed")
		}
	}
	legacyBody, err := foundationWriterPolicyBody(details)
	if err != nil || string(legacyBody) != string(body) || *details.Name == *four.Policy.Request.Name {
		t.Fatalf("legacy request bytes or distinct scope identity changed: %v", err)
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
	// Append a smaller descriptive scope only after positive old outcomes. No
	// constructor/guard/install/rotation/dispatch execution is claimed here.
	retained, observed, err = restarted.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	smallScope, small := capacityScopePersistenceFixture(t, *retained.FoundationWriter, digestSource(purpose), []string{"SFO"}, first.Add(4*time.Second))
	small.ObservedPolicyID, small.ObservedAt = "", time.Time{}
	small.Policy.PolicyID, small.Policy.VerifiedAt = "", time.Time{}
	retained.FoundationWriter.CapacityJournalScopes[smallScope] = small
	retained.UpdatedAt = small.Policy.FirstAttemptAt
	observed, err = restarted.CompareAndSwap(t.Context(), retained, observed)
	if err != nil {
		t.Fatal(err)
	}
	baseline, baselineETag, err := restarted.Load(t.Context(), "GRU")
	if err != nil || baselineETag != observed {
		t.Fatal(err)
	}
	// An unresolved dispatch blocks another scope even when its own request is
	// structurally valid; no successor replacement can erase that uncertainty.
	thirdScope, third := capacityScopePersistenceFixture(t, *baseline.FoundationWriter, digestSource(purpose), []string{"GRU"}, first.Add(5*time.Second))
	baseline.FoundationWriter.CapacityJournalScopes[thirdScope] = third
	if _, err := restarted.CompareAndSwap(t.Context(), baseline, baselineETag); err == nil {
		t.Fatal("unresolved earlier dispatch admitted replacement scope")
	}
	for _, scope := range []string{fourScope, smallScope} {
		for name, mutate := range map[string]func(*FoundationWriterRecord, string){
			"remove_map":   func(w *FoundationWriterRecord, _ string) { w.CapacityJournalScopes = nil },
			"remove_entry": func(w *FoundationWriterRecord, key string) { delete(w.CapacityJournalScopes, key) },
			"replace_key": func(w *FoundationWriterRecord, key string) {
				p := w.CapacityJournalScopes[key]
				delete(w.CapacityJournalScopes, key)
				w.CapacityJournalScopes[strings.Repeat("f", 64)] = p
			},
			"replace_cells": func(w *FoundationWriterRecord, key string) {
				p := w.CapacityJournalScopes[key]
				p.Cells = []string{"GRU"}
				w.CapacityJournalScopes[key] = p
			},
			"erase_dispatch": func(w *FoundationWriterRecord, key string) {
				p := w.CapacityJournalScopes[key]
				p.Attempts = nil
				w.CapacityJournalScopes[key] = p
			},
			"replace_grant": func(w *FoundationWriterRecord, key string) {
				p := w.CapacityJournalScopes[key]
				p.GrantSHA256 = strings.Repeat("f", 64)
				p.OperationID = digestSource([]byte(p.WriterSHA256 + "\x00" + p.GrantSHA256 + "\x00" + p.PurposeSHA256 + "\x00" + key))
				p.Policy.RetryToken = digestSource([]byte(p.OperationID + "\x00" + p.Policy.RequestDigest))
				w.CapacityJournalScopes[key] = p
			},
			"extend_expiry": func(w *FoundationWriterRecord, key string) {
				p := w.CapacityJournalScopes[key]
				p.ExpiresAt = p.ExpiresAt.Add(time.Hour)
				w.CapacityJournalScopes[key] = p
			},
			"replace_request": func(w *FoundationWriterRecord, key string) {
				p := w.CapacityJournalScopes[key]
				p.Policy.Request.Statements = append(p.Policy.Request.Statements, "Allow any-user to manage objects in tenancy")
				w.CapacityJournalScopes[key] = p
			},
		} {
			t.Run(scope+"/"+name, func(t *testing.T) {
				candidate, etag, err := restarted.Load(t.Context(), "GRU")
				if err != nil {
					t.Fatal(err)
				}
				before := candidate.FoundationWriter
				beforeWire, err := json.Marshal(before, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				mutate(candidate.FoundationWriter, scope)
				if _, err := restarted.CompareAndSwap(t.Context(), candidate, etag); err == nil {
					t.Fatal("protected exact-scope history changed")
				}
				got, currentETag, err := restarted.Load(t.Context(), "GRU")
				if err != nil {
					t.Fatal(err)
				}
				gotWire, err := json.Marshal(got.FoundationWriter, json.Deterministic(true))
				if err != nil || currentETag != etag || string(beforeWire) != string(gotWire) {
					t.Fatalf("rejected scope mutation changed durable bytes: %v", err)
				}
			})
		}
	}
	// Positive exact outcome evidence is appended without rebinding deadlines.
	completed, completedETag, err := restarted.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	oldSmall := completed.FoundationWriter.CapacityJournalScopes[smallScope]
	small.ObservedPolicyID, small.ObservedAt = "ocid1.policy.oc1..scopesmall", first.Add(6*time.Second)
	small.Policy.PolicyID, small.Policy.VerifiedAt = small.ObservedPolicyID, first.Add(7*time.Second)
	completed.FoundationWriter.CapacityJournalScopes[smallScope] = small
	completed.UpdatedAt = small.Policy.VerifiedAt
	if _, err := restarted.CompareAndSwap(t.Context(), completed, completedETag); err != nil {
		t.Fatal(err)
	}
	finalStore, err := NewObjectFoundationStore(store.client, store.namespace, store.bucket)
	if err != nil {
		t.Fatal(err)
	}
	final, finalETag, err := finalStore.Load(t.Context(), "GRU")
	if err != nil || !sameCapacityPolicy(capacityPolicyAt(final.FoundationWriter, smallScope), &small) ||
		!sameCapacityPolicy(capacityPolicyAt(final.FoundationWriter, fourScope), &four) ||
		!slices.Equal(oldSmall.Attempts, small.Attempts) || !oldSmall.ExpiresAt.Equal(small.ExpiresAt) {
		t.Fatalf("scope outcome/history lost across restart: %v", err)
	}
	for _, scope := range []string{fourScope, smallScope} {
		candidate, etag, err := finalStore.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		p := candidate.FoundationWriter.CapacityJournalScopes[scope]
		p.ObservedPolicyID, p.Policy.PolicyID = "ocid1.policy.oc1..replacement", "ocid1.policy.oc1..replacement"
		candidate.FoundationWriter.CapacityJournalScopes[scope] = p
		if _, err := finalStore.CompareAndSwap(t.Context(), candidate, etag); err == nil {
			t.Fatal("completed exact-scope identity replaced")
		}
	}
	// Ordinary foundation generation/epoch writes preserve all original scope
	// requests and outcome evidence; they do not renew policy authority.
	final.Generation++
	final.Epoch++
	final.UpdatedAt = final.UpdatedAt.Add(time.Second)
	if _, err := finalStore.CompareAndSwap(t.Context(), final, finalETag); err != nil {
		t.Fatal(err)
	}
	renewed, _, err := finalStore.Load(t.Context(), "GRU")
	if err != nil || !sameCapacityValue(renewed.FoundationWriter, final.FoundationWriter) {
		t.Fatalf("ordinary generation write rebound scope history: %v", err)
	}

}

// These fields describe codec/persistence evidence only. They confer no admitted
// HOME/source proof and never execute a privileged actor or remote IAM request.
func capacityScopePersistenceFixture(t *testing.T, writer FoundationWriterRecord, purpose string, cells []string, first time.Time) (string, CapacityJournalPolicy) {
	t.Helper()
	details, scope, err := capacityScopePolicy(writer, purpose, cells)
	if err != nil {
		t.Fatal(err)
	}
	writerDigest, err := capacityWriterDigest(writer)
	if err != nil {
		t.Fatal(err)
	}
	body, err := foundationWriterPolicyBody(details)
	if err != nil {
		t.Fatal(err)
	}
	operation := digestSource([]byte(writerDigest + "\x00" + writer.GrantSHA256 + "\x00" + purpose + "\x00" + scope))
	id := "ocid1.policy.oc1..scope" + scope[:12]
	return scope, CapacityJournalPolicy{Cells: slices.Clone(cells), OperationID: operation, WriterSHA256: writerDigest,
		GrantSHA256: writer.GrantSHA256, Generation: writer.Generation, PurposeSHA256: purpose, ExpiresAt: first.Add(time.Hour),
		Policy: FoundationWriterPolicy{Request: details, RequestDigest: digestSource(body), RetryToken: digestSource([]byte(operation + "\x00" + digestSource(body))), FirstAttemptAt: first,
			PolicyID: id, VerifiedAt: first.Add(2 * time.Millisecond)},
		Attempts: []time.Time{first}, ObservedPolicyID: id, ObservedAt: first.Add(time.Millisecond)}
}
