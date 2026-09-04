package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testProgress(key string) Progress {
	return Progress{Key: key, Action: ActionCreate, Ref: key, Attempt: 1, Outcome: "pending", UpdatedAt: time.Now().UTC()}
}

func TestFileProgressStoreConcurrentWritersDoNotClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "progress.json")
	left, err := NewFileProgressStore(path)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewFileProgressStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const records = 32
	var group sync.WaitGroup
	for i, store := range []*FileProgressStore{left, right} {
		for n := 0; n < records; n++ {
			group.Add(1)
			go func(store *FileProgressStore, key string, outcome string) {
				defer group.Done()
				progress := testProgress(key)
				progress.Outcome = outcome
				if err := store.Save(context.Background(), progress); err != nil {
					t.Errorf("Save(%s): %v", key, err)
				}
			}(store, "record-"+string(rune('a'+i))+"-"+string(rune('a'+n)), "applied")
		}
	}
	group.Wait()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recordsOnDisk map[string]Progress
	if err := json.Unmarshal(data, &recordsOnDisk); err != nil {
		t.Fatal(err)
	}
	if len(recordsOnDisk) != records*2 {
		t.Fatalf("records on disk = %d, want %d", len(recordsOnDisk), records*2)
	}
	for key := range recordsOnDisk {
		if _, ok, err := left.Load(context.Background(), key); err != nil || !ok {
			t.Fatalf("Load(%s) = ok=%v err=%v", key, ok, err)
		}
	}
}

func TestFileProgressStoreRejectsMalformedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	store, err := NewFileProgressStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"bad":{"key":"bad","action":"create","ref":"bad","attempt":1,"outcome":"future","updatedAt":"2026-09-04T00:00:00Z"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "bad"); err == nil {
		t.Fatal("malformed outcome was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"bad":{"key":"bad","action":"create","ref":"bad","attempt":1,"outcome":"pending","updatedAt":"2026-09-04T00:00:00Z","unexpected":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "bad"); err == nil {
		t.Fatal("unknown progress field was accepted")
	}
	if err := store.Save(context.Background(), testProgress("ok")); err == nil {
		t.Fatal("Save should fail closed on a malformed existing journal")
	}
	if err := os.WriteFile(path, []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "bad"); err == nil {
		t.Fatal("a null top-level journal must fail closed")
	}
}

func TestFileProgressStoreCASRejectsStaleCrossProcessWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	left, err := NewFileProgressStore(path)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewFileProgressStore(path)
	if err != nil {
		t.Fatal(err)
	}
	initial := testProgress("cas")
	if err := left.CompareAndSwap(context.Background(), initial.Key, nil, initial); err != nil {
		t.Fatalf("initial CAS: %v", err)
	}
	observed, found, err := left.Load(context.Background(), initial.Key)
	if err != nil || !found {
		t.Fatalf("observe: found=%v err=%v", found, err)
	}

	newer := observed
	newer.Outcome = "applied"
	newer.UpdatedAt = newer.UpdatedAt.Add(time.Second)
	if err := right.CompareAndSwap(context.Background(), initial.Key, &observed, newer); err != nil {
		t.Fatalf("newer CAS: %v", err)
	}
	stale := observed
	stale.Outcome = "failed"
	if err := left.CompareAndSwap(context.Background(), initial.Key, &observed, stale); err == nil {
		t.Fatal("stale CAS unexpectedly succeeded")
	} else if err != ErrProgressConflict {
		t.Fatalf("stale CAS error = %v, want conflict", err)
	}
	current, found, err := left.Load(context.Background(), initial.Key)
	if err != nil || !found || current.Outcome != "applied" {
		t.Fatalf("stale CAS changed durable state: %+v found=%v err=%v", current, found, err)
	}
}

func TestFileProgressStorePendingAdmissionIsCrossProcessExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	left, _ := NewFileProgressStore(path)
	right, _ := NewFileProgressStore(path)
	first := testProgress("admission")
	if err := left.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := right.Save(context.Background(), first); err != ErrProgressConflict {
		t.Fatalf("duplicate pending admission = %v, want conflict", err)
	}
	second := first
	second.UpdatedAt = second.UpdatedAt.Add(time.Millisecond)
	if err := right.Save(context.Background(), second); err != ErrProgressConflict {
		t.Fatalf("second pending admission = %v, want conflict", err)
	}
}

func TestFileProgressStoreRejectsEqualAttemptTerminalOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	store, _ := NewFileProgressStore(path)
	first := testProgress("terminal")
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	first.Outcome = "applied"
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	stale := first
	stale.Outcome = "failed"
	stale.Detail = "stale worker"
	if err := store.Save(context.Background(), stale); err != ErrProgressConflict {
		t.Fatalf("equal-attempt terminal overwrite = %v, want conflict", err)
	}
}

func TestFileProgressStoreLockHonorsContextCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	first, _ := NewFileProgressStore(path)
	second, _ := NewFileProgressStore(path)
	if err := first.Save(context.Background(), testProgress("lock")); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := second.Load(ctx, "lock"); err == nil {
		t.Fatal("Load unexpectedly waited past context cancellation")
	}
}

func TestValidateProgressRejectsInvalidSchema(t *testing.T) {
	for _, value := range []Progress{
		{Key: "k", Action: ActionCreate, Ref: "r", Attempt: 1, Outcome: "pending"},
		{Key: "k", Action: ActionCreate, Ref: "r", Attempt: 0, Outcome: "pending", UpdatedAt: time.Now()},
		{Key: "k", Action: ActionKind("bad"), Ref: "r", Attempt: 1, Outcome: "pending", UpdatedAt: time.Now()},
	} {
		if err := validateProgress(value); err == nil {
			t.Fatalf("validateProgress(%+v) accepted invalid value", value)
		}
	}
}
