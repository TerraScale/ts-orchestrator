package oci

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func TestVolumeTerminationProofRejectsDifferentOrCorruptScope(t *testing.T) {
	config, _ := testRegionConfig()
	const volumeID = "ocid1.volume.terminated"
	kv := testJournalBucket(t)
	journal, err := NewKVJournal(kv)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordVolumeTermination(t.Context(), config, volumeID); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordVolumeTermination(t.Context(), config, volumeID); err != nil {
		t.Fatalf("idempotent proof: %v", err)
	}
	key := ownershipKey("volume-termination", volumeID)
	valid, err := journal.read(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*journalEntry){
		"owner":       func(e *journalEntry) { e.VolumeTermination.Owner = "other" },
		"region":      func(e *journalEntry) { e.VolumeTermination.Region = RegionSJC },
		"compartment": func(e *journalEntry) { e.VolumeTermination.CompartmentID = "other" },
		"domain":      func(e *journalEntry) { e.VolumeTermination.AvailabilityDomain = "other" },
		"volume":      func(e *journalEntry) { e.VolumeTermination.VolumeID = "other" },
		"time":        func(e *journalEntry) { e.VolumeTermination.ObservedAt = time.Time{} },
		"kind":        func(e *journalEntry) { e.Kind = "operation" },
		"schema":      func(e *journalEntry) { e.SchemaVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			entry := valid
			change(&entry)
			wire, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := kv.Put(t.Context(), key, wire); err != nil {
				t.Fatal(err)
			}
			if gone, err := journal.volumeTerminated(t.Context(), config, volumeID); err == nil || gone {
				t.Fatalf("different/corrupt proof authorized deletion: gone=%v err=%v", gone, err)
			}
			if err := journal.RecordVolumeTermination(t.Context(), config, volumeID); err == nil {
				t.Fatal("conflicting proof overwritten")
			}
		})
	}
}

type failTerminationCreateKV struct{ jetstream.KeyValue }

func (kv failTerminationCreateKV) Create(context.Context, string, []byte, ...jetstream.KVCreateOpt) (uint64, error) {
	return 0, errors.New("termination proof write unavailable")
}

func TestVolumeTerminationProofRequiresSuccessfulWrite(t *testing.T) {
	config, _ := testRegionConfig()
	journal, err := NewKVJournal(failTerminationCreateKV{testJournalBucket(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordVolumeTermination(t.Context(), config, "ocid1.volume.terminated"); err == nil {
		t.Fatal("uncommitted proof accepted")
	}
	if gone, err := journal.volumeTerminated(t.Context(), config, "ocid1.volume.terminated"); err != nil || gone {
		t.Fatalf("failed write left proof: gone=%v err=%v", gone, err)
	}
}

func TestVolumeTerminationProofSurvivesBrokerRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cfg := authenticatedJournalConfig(t, "volume-termination")
	runtime, err := startAuthenticatedJournal(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(ctx, runtime.JetStream(), 1)
	if err != nil {
		_ = runtime.Close()
		t.Fatal(err)
	}
	config, _ := testRegionConfig()
	const volumeID = "ocid1.volume.terminated"
	if err := journal.RecordVolumeTermination(ctx, config, volumeID); err != nil {
		_ = runtime.Close()
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = startAuthenticatedJournal(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	journal, err = OpenJournal(ctx, runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if gone, err := journal.volumeTerminated(ctx, config, volumeID); err != nil || !gone {
		t.Fatalf("restarted broker lost proof: gone=%v err=%v", gone, err)
	}
	status, err := journal.kv.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expiring := status.Config()
	expiring.TTL = time.Hour
	if _, err := runtime.JetStream().UpdateKeyValue(ctx, expiring); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(ctx, runtime.JetStream(), 1); err == nil {
		t.Fatal("expiring journal accepted for permanent deletion evidence")
	}
}
