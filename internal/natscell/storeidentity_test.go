package natscell

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
)

func labController(t *testing.T, instance, dir string) Config {
	t.Helper()
	cfg := productionTestConfig(t, "gru", instance)
	cfg.Embedded.StoreDir = dir
	return cfg
}

func TestServerOptionsRefusesAStoreOfAnotherServerName(t *testing.T) {
	dir := t.TempDir()
	options, err := serverOptions(labController(t, "controller-a", dir))
	if err != nil || options.ServerName != "gru-1-ctl-1" {
		t.Fatalf("fresh store: options=%v err=%v", options, err)
	}
	if _, err := serverOptions(labController(t, "controller-a", dir)); err != nil {
		t.Fatalf("the recorded server name was refused: %v", err)
	}
	_, err = serverOptions(labController(t, "controller-b", dir))
	if !errors.Is(err, ErrStoreIdentity) || !strings.Contains(err.Error(), "the cell must be rebuilt (TS-470)") {
		t.Fatalf("gru-1-ctl-2 opened gru-1-ctl-1's store: %v", err)
	}
}

// A store written before the static names holds the JetStream state of
// gru-controller-a. Reopening it as gru-1-ctl-1 would change its Raft node ID,
// so the controller stops instead of claiming it.
func TestStartRefusesAPreSchemeStore(t *testing.T) {
	dir := t.TempDir()
	cfg := labController(t, "controller-a", dir)
	runtime, err := openTestBroker(t, t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.JetStream().CreateStream(t.Context(), jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state.>"}}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	// Drop the record, as a store from before it would lack one.
	if err := os.Remove(filepath.Join(dir, storeIdentityFile)); err != nil {
		t.Fatal(err)
	}
	_, err = Start(t.Context(), cfg)
	if !errors.Is(err, ErrStoreIdentity) || !strings.Contains(err.Error(), `"gru-controller-a"`) ||
		!strings.Contains(err.Error(), "the cell must be rebuilt (TS-470)") {
		t.Fatalf("a pre-scheme store was reopened under its new name: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, storeIdentityFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the refused store was claimed: %v", err)
	}
	// A lab instance outside the scheme keeps its name, so its store stays usable.
	lab := t.TempDir()
	if err := os.MkdirAll(filepath.Join(lab, "jetstream", "$SYS"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := serverOptions(labController(t, "placement", lab)); err != nil {
		t.Fatalf("an unchanged lab name was refused: %v", err)
	}
}
