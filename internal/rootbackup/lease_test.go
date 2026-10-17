package rootbackup

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go/jetstream"
)

func TestBackupLeaseRejectsWeakerControlDurability(t *testing.T) {
	runtime, err := natscell.Start(t.Context(), natscell.Config{Cell: "gru", Instance: "backup-lease", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if _, err := runtime.JetStream().CreateStream(t.Context(), jetstream.StreamConfig{Name: authority.ControlStreamName,
		Subjects: []string{"backup.lease.test"}, Storage: jetstream.FileStorage, Replicas: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := observeLease(t.Context(), runtime.JetStream(), "gru"); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("weak control stream acquired root backup authority: %v", err)
	}
}
