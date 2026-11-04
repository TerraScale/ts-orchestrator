package oci

import (
	"context"
	"testing"
	"time"
)

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
