package databaseadmission

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/oklog/ulid"
	"github.com/zeebo/blake3"
)

func envelopeFixture(source Record) RestoreAdmissionFacts {
	id, err := ulid.Parse(source.DatabaseID)
	if err != nil {
		panic(err)
	}
	incarnation := hex.EncodeToString(id[:])
	participants := []RestoreParticipantFacts{
		{ParticipantID: "shard-0000000000000001", DatabaseID: source.DatabaseID, JournalCut: 7, ManifestDigest: strings.Repeat("a", 64), Checksum: strings.Repeat("b", 64), RowCount: 3, CapturedAtMillis: 1000, RetainedUntilMillis: 2000},
		{ParticipantID: "shard-0000000000000002", DatabaseID: source.DatabaseID, JournalCut: 19, ManifestDigest: strings.Repeat("c", 64), Checksum: strings.Repeat("d", 64), RowCount: 5, CapturedAtMillis: 1100, RetainedUntilMillis: 2100},
	}
	logical := make([]byte, 0, 256)
	for _, participant := range participants {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(participant.ParticipantID)))
		logical = append(logical, length[:]...)
		logical = append(logical, participant.ParticipantID...)
		binary.BigEndian.PutUint64(length[:], uint64(len(participant.Checksum)))
		logical = append(logical, length[:]...)
		logical = append(logical, participant.Checksum...)
	}
	logicalHash := blake3.Sum256(append([]byte("terrabase-backup-envelope-logical-v1\x00"), logical...))
	digest := strings.Repeat("e", 64)
	return RestoreAdmissionFacts{
		SourceDigest: RestoreSourceDigest(source), CapturedAtMillis: 1100,
		Checksum: hex.EncodeToString(logicalHash[:]), RecoveryPointDigest: digest,
		RowCount: 8, PointID: digest, Provider: "oci", JournalCut: "19",
		Envelope: &RestoreEnvelopeFacts{EnvelopeDigest: digest, DatabaseID: source.DatabaseID, DatabaseIncarnation: incarnation, RouteGeneration: 4, Participants: participants},
	}
}

func TestAcceptRestorePersistsExactEnvelopeAndDoesNotAliasResolverSlices(t *testing.T) {
	journal := NewMemoryJournal()
	source := restoreSourceFixture(t, journal)
	config := pipelineConfig(t, journal)
	resolved := envelopeFixture(source)
	resolves := 0
	config.Restore = &RestoreConfig{
		Resolve: func(context.Context, Record, RestoreSelection) (RestoreAdmissionFacts, error) {
			resolves++
			return resolved, nil
		},
		Restore: func(context.Context, Record) ([]byte, error) { return nil, nil },
	}
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	request := restoreRequestFixture(source)
	record, err := pipeline.AcceptRestore(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if record.RestoreFacts.Envelope.Participants[0].JournalCut != 7 || record.RestoreFacts.Envelope.Participants[1].JournalCut != 19 {
		t.Fatalf("unequal participant cuts were projected: %+v", record.RestoreFacts.Envelope.Participants)
	}
	resolved.Envelope.Participants[0].JournalCut = 99
	resolved.Envelope.Participants[1].Checksum = strings.Repeat("f", 64)
	stored, found, err := journal.Load(t.Context(), ScopeKey(record.Request))
	if err != nil || !found {
		t.Fatalf("load persisted restore: found=%v err=%v", found, err)
	}
	if stored.RestoreFacts.Envelope.Participants[0].JournalCut != 7 || stored.RestoreFacts.Envelope.Participants[1].Checksum != strings.Repeat("d", 64) {
		t.Fatal("persisted envelope aliased resolver memory")
	}
	if _, err := pipeline.AcceptRestore(t.Context(), request); err != nil || resolves != 1 {
		t.Fatalf("replay re-resolved latest: err=%v resolves=%d", err, resolves)
	}
}

func TestRestoreEnvelopeRejectsIndependentFactMutations(t *testing.T) {
	journal := NewMemoryJournal()
	source := restoreSourceFixture(t, journal)
	facts := envelopeFixture(source)
	for name, mutate := range map[string]func(*RestoreAdmissionFacts){
		"order": func(f *RestoreAdmissionFacts) {
			f.Envelope.Participants[0], f.Envelope.Participants[1] = f.Envelope.Participants[1], f.Envelope.Participants[0]
		},
		"duplicate": func(f *RestoreAdmissionFacts) {
			f.Envelope.Participants[1].ParticipantID = f.Envelope.Participants[0].ParticipantID
		},
		"cut":         func(f *RestoreAdmissionFacts) { f.Envelope.Participants[1].JournalCut = 20 },
		"count":       func(f *RestoreAdmissionFacts) { f.Envelope.Participants[1].RowCount++ },
		"digest":      func(f *RestoreAdmissionFacts) { f.Envelope.EnvelopeDigest = strings.Repeat("f", 64) },
		"incarnation": func(f *RestoreAdmissionFacts) { f.Envelope.DatabaseIncarnation = strings.Repeat("1", 32) },
		"summary":     func(f *RestoreAdmissionFacts) { f.CapturedAtMillis = 1000 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneRestoreAdmissionFacts(facts)
			mutate(&changed)
			if validateRestoreEnvelope(&changed, source.DatabaseID) == nil {
				t.Fatalf("accepted mutated envelope: %+v", changed.Envelope)
			}
		})
	}
}

func TestRestoreAcknowledgementRejectsValidNonMaxCutMutation(t *testing.T) {
	journal := NewMemoryJournal()
	source := restoreSourceFixture(t, journal)
	facts := envelopeFixture(source)
	record := Record{
		DatabaseID:   "01ARZ3NDEKTSV4RRFFQ69G5FAX",
		Request:      Request{ParentDatabaseID: source.DatabaseID},
		Restore:      &RestoreRequest{SourceDatabaseID: source.DatabaseID},
		RestoreFacts: &facts,
	}
	ack := RestoreAcknowledgement{Version: 1, TargetDatabaseID: record.DatabaseID, SourceDatabaseID: source.DatabaseID, Facts: cloneRestoreAdmissionFacts(facts)}
	raw, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRestoreAcknowledgement(record, raw); err != nil {
		t.Fatalf("valid envelope acknowledgement rejected: %v", err)
	}
	ack.Facts.Envelope.Participants[0].JournalCut = 8
	if err := validateRestoreEnvelope(&ack.Facts, source.DatabaseID); err != nil {
		t.Fatalf("non-max cut should remain structurally valid: %v", err)
	}
	raw, err = json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRestoreAcknowledgement(record, raw); err == nil {
		t.Fatal("changed participant vector passed exact acknowledgement validation")
	}
}

func TestMalformedRestoreAcknowledgementCannotBePersisted(t *testing.T) {
	journal := NewMemoryJournal()
	source := restoreSourceFixture(t, journal)
	config := pipelineConfig(t, journal)
	facts := envelopeFixture(source)
	config.Restore = &RestoreConfig{Resolve: func(context.Context, Record, RestoreSelection) (RestoreAdmissionFacts, error) {
		return facts, nil
	}, Restore: func(context.Context, Record) ([]byte, error) { return nil, nil }}
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	record, err := pipeline.AcceptRestore(t.Context(), restoreRequestFixture(source))
	if err != nil {
		t.Fatal(err)
	}
	record.RestoreReceipt = []byte(`{"version":`)
	if _, err := journal.Save(t.Context(), ScopeKey(record.Request), record.Revision, record); err == nil {
		t.Fatal("persisted malformed acknowledgement")
	}
}
