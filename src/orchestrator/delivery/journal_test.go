package delivery

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func journalTestRequest(id string) *Request {
	return &Request{
		SchemaVersion:         ContractVersion,
		OperationID:           id,
		Source:                &Source{Repository: "TerraScale/example", Commit: "abc", TreeDigest: "tree"},
		Artifact:              &Artifact{Digest: "sha256:artifact", ManifestDigest: "sha256:manifest", Kind: "binary", Architecture: "linux/arm64"},
		Target:                &Target{Service: "terrabase", Environment: "production", Regions: []string{"GRU", "SFO", "FRA"}},
		ConfigurationRevision: "config-1",
		RequestedBy:           "deploy",
		Reason:                "test",
	}
}

func journalTestReceipt(id, status string) *Receipt {
	return &Receipt{SchemaVersion: ContractVersion, OperationID: id, Status: status}
}

func TestJournalRecoversAcceptedAndTerminalOperationsAcrossRestart(t *testing.T) {
	store := NewInMemoryStore()
	first, err := NewDurableJournal(store)
	if err != nil {
		t.Fatalf("new journal: %v", err)
	}
	request := journalTestRequest("restart-safe")
	accepted, exists, err := first.Begin(request)
	if err != nil || exists {
		t.Fatalf("begin: operation=%+v exists=%v err=%v", accepted, exists, err)
	}

	// A new Journal has no process-local state, but sees the accepted record.
	second, err := NewJournalWithStore(store)
	if err != nil {
		t.Fatalf("restart journal: %v", err)
	}
	recovered, exists, err := second.Begin(request)
	if err != nil || !exists || recovered.State != OperationRunning {
		t.Fatalf("recovered begin: operation=%+v exists=%v err=%v", recovered, exists, err)
	}
	receipt := journalTestReceipt(request.OperationID, StatusSucceeded)
	if err := second.Finish(request.OperationID, accepted.RequestDigest, receipt); err != nil {
		t.Fatalf("finish: %v", err)
	}

	third, err := NewDurableJournal(store)
	if err != nil {
		t.Fatalf("second restart journal: %v", err)
	}
	operation, found, err := third.GetWithError(request.OperationID)
	if err != nil || !found || operation.State != OperationDone || operation.Receipt.Status != StatusSucceeded {
		t.Fatalf("recovered terminal operation=%+v found=%v err=%v", operation, found, err)
	}
	replayed, exists, err := third.Begin(request)
	if err != nil || !exists || replayed.Receipt.Status != StatusSucceeded {
		t.Fatalf("terminal replay: operation=%+v exists=%v err=%v", replayed, exists, err)
	}
}

func TestJournalAdmissionIsCreateOnlyAndIdempotent(t *testing.T) {
	store := NewInMemoryStore()
	journal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatalf("new journal: %v", err)
	}
	request := journalTestRequest("cas-admission")
	const callers = 32
	var wait sync.WaitGroup
	wait.Add(callers)
	created := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wait.Done()
			_, exists, beginErr := journal.Begin(request)
			if beginErr != nil {
				t.Errorf("concurrent begin: %v", beginErr)
				return
			}
			created <- !exists
		}()
	}
	wait.Wait()
	close(created)
	var admissions int
	for wasCreated := range created {
		if wasCreated {
			admissions++
		}
	}
	if admissions != 1 {
		t.Fatalf("create-only admissions = %d, want 1", admissions)
	}

	changed := journalTestRequest(request.OperationID)
	changed.Reason = "different request"
	if _, _, err := journal.Begin(changed); err == nil {
		t.Fatal("operation ID reuse with a different request must conflict")
	}
}

func TestJournalLeaseTakeoverFencesStaleOwner(t *testing.T) {
	store := NewInMemoryStore()
	journal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	journal.clock = func() time.Time { return now }
	request := journalTestRequest("lease-fence")
	ownerA := OperationLease{OwnerID: "owner-a", TTL: time.Minute}
	operation, exists, err := journal.Begin(request, ownerA)
	if err != nil || exists || operation.Generation != 1 {
		t.Fatalf("begin lease = %+v exists=%v err=%v", operation, exists, err)
	}
	if _, err := journal.Takeover(request.OperationID, operation.RequestDigest, OperationLease{OwnerID: "owner-b", TTL: time.Minute}); !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("live lease takeover = %v, want active lease", err)
	}
	now = now.Add(2 * time.Minute)
	ownerB := OperationLease{OwnerID: "owner-b", TTL: time.Minute}
	taken, err := journal.Takeover(request.OperationID, operation.RequestDigest, ownerB)
	if err != nil || taken.Generation != 2 {
		t.Fatalf("expired lease takeover = %+v err=%v", taken, err)
	}
	if err := journal.Renew(request.OperationID, operation.RequestDigest, ownerA, operation.Generation); !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("stale owner renewal = %v, want active lease", err)
	}
	if err := journal.Finish(request.OperationID, operation.RequestDigest, journalTestReceipt(request.OperationID, StatusFailed), ownerA); !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("stale owner finish = %v, want active lease", err)
	}
}

func TestJournalRecoveryRejectsLiveLease(t *testing.T) {
	store := NewInMemoryStore()
	journal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(200, 0).UTC()
	journal.clock = func() time.Time { return now }
	request := journalTestRequest("live-recovery")
	if _, _, err := journal.Begin(request, OperationLease{OwnerID: "owner", TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RecoverUnknown(request.OperationID); !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("live recovery = %v, want active lease", err)
	}
	now = now.Add(2 * time.Minute)
	receipt, err := journal.RecoverUnknown(request.OperationID)
	if err != nil || receipt == nil || receipt.Error == nil || receipt.Error.Code == nil || *receipt.Error.Code != "operation_unknown" {
		t.Fatalf("expired recovery = %+v err=%v", receipt, err)
	}
}

func TestJournalRecoveryFencesExpiredOwnerGeneration(t *testing.T) {
	store := NewInMemoryStore()
	journal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(300, 0).UTC()
	journal.clock = func() time.Time { return now }
	request := journalTestRequest("recovery-generation")
	owner := OperationLease{OwnerID: "owner-a", TTL: time.Minute}
	operation, _, err := journal.Begin(request, owner)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	receipt, err := journal.RecoverUnknown(request.OperationID)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if receipt == nil || receipt.Error == nil || receipt.Error.Code == nil || *receipt.Error.Code != "operation_unknown" {
		t.Fatalf("recovery receipt = %+v", receipt)
	}
	current, found, err := journal.GetWithError(request.OperationID)
	if err != nil || !found {
		t.Fatalf("read recovered operation: found=%v err=%v", found, err)
	}
	if current.Generation != operation.Generation+1 || current.OwnerID == operation.OwnerID || !current.LeaseUntil.IsZero() {
		t.Fatalf("recovery did not install a terminal fence: %+v", current)
	}
	if err := journal.Renew(request.OperationID, operation.RequestDigest, owner, operation.Generation); !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("stale renew = %v, want lease fence", err)
	}
	if err := journal.Finish(request.OperationID, operation.RequestDigest, journalTestReceipt(request.OperationID, StatusFailed), owner); !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("stale finish = %v, want lease fence", err)
	}
}

func TestJournalRecoveryRejectsLegacyUnleasedOperation(t *testing.T) {
	journal := NewJournal()
	request := journalTestRequest("legacy-recovery")
	if _, _, err := journal.Begin(request); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RecoverUnknown(request.OperationID); !errors.Is(err, ErrOperationLeaseActive) {
		t.Fatalf("legacy recovery = %v, want lease fence", err)
	}
}

func TestJournalFinishUsesCASAndAllowsOnlyExactReceiptReplay(t *testing.T) {
	store := NewInMemoryStore()
	journal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatalf("new journal: %v", err)
	}
	request := journalTestRequest("cas-finish")
	operation, _, err := journal.Begin(request)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	receipt := journalTestReceipt(request.OperationID, StatusFailed)
	const callers = 32
	var wait sync.WaitGroup
	wait.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wait.Done()
			if finishErr := journal.Finish(request.OperationID, operation.RequestDigest, receipt); finishErr != nil {
				t.Errorf("concurrent finish: %v", finishErr)
			}
		}()
	}
	wait.Wait()
	if err := journal.Finish(request.OperationID, operation.RequestDigest, receipt); err != nil {
		t.Fatalf("exact receipt replay: %v", err)
	}
	changed := journalTestReceipt(request.OperationID, StatusSucceeded)
	if err := journal.Finish(request.OperationID, operation.RequestDigest, changed); err == nil {
		t.Fatal("terminal receipt transition must be immutable")
	}
}

func TestJournalFailsClosedOnStoreErrors(t *testing.T) {
	store := &failingJournalStore{err: errors.New("JetStream unavailable")}
	journal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatalf("new journal: %v", err)
	}
	if _, _, err := journal.Begin(journalTestRequest("store-outage")); err == nil {
		t.Fatal("admission must fail when persistence is unavailable")
	}
	if _, found, err := journal.GetWithError("store-outage"); err == nil || found {
		t.Fatalf("read outage = found=%v err=%v", found, err)
	}
	if operations, err := journal.SnapshotWithError(); err == nil || operations != nil {
		t.Fatalf("snapshot outage = operations=%v err=%v", operations, err)
	}
}

func TestInMemoryStoreCompareAndSet(t *testing.T) {
	store := NewInMemoryStore()
	created, err := store.Create("key", []byte("one"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.Create("key", []byte("two")); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("duplicate create error = %v", err)
	}
	if _, err := store.Update("key", created.Revision+1, []byte("two")); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("wrong revision error = %v", err)
	}
	updated, err := store.Update("key", created.Revision, []byte("two"))
	if err != nil || updated.Revision <= created.Revision {
		t.Fatalf("update = %+v err=%v", updated, err)
	}
}

func TestJournalSnapshotIsDeterministic(t *testing.T) {
	store := NewInMemoryStore()
	journal, err := NewDurableJournal(store)
	if err != nil {
		t.Fatalf("new journal: %v", err)
	}
	now := time.Unix(100, 0).UTC()
	journal.clock = func() time.Time { return now }
	for _, id := range []string{"b", "a"} {
		if _, _, err := journal.Begin(journalTestRequest(id)); err != nil {
			t.Fatalf("begin %s: %v", id, err)
		}
	}
	operations, err := journal.SnapshotWithError()
	if err != nil || len(operations) != 2 || operations[0].OperationID != "a" || operations[1].OperationID != "b" {
		t.Fatalf("snapshot=%+v err=%v", operations, err)
	}
}

type failingJournalStore struct{ err error }

func (s *failingJournalStore) Get(string) (StoreEntry, error) { return StoreEntry{}, s.err }

func (s *failingJournalStore) Create(string, []byte) (StoreEntry, error) {
	return StoreEntry{}, s.err
}

func (s *failingJournalStore) Update(string, uint64, []byte) (StoreEntry, error) {
	return StoreEntry{}, s.err
}

func (s *failingJournalStore) List(string) ([]StoreEntry, error) { return nil, s.err }
