package restoredrill

import (
	"context"
	"testing"
)

type keyedFactsJournal struct {
	*fakeJournal
	keys map[string]string
}

func (j *keyedFactsJournal) Facts(ctx context.Context, database, item string) (JournalFacts, error) {
	j.keys[database] = item
	return j.fakeJournal.Facts(ctx, database, item)
}

func TestNativeCaptureIdentityAndCutReachAtomicBranchAndRestore(t *testing.T) {
	drill, backup, branches, journal, _ := drillFixture()
	for database, facts := range journal.facts {
		facts.RecoveryPointID = "point-" + database
		journal.facts[database] = facts
	}
	keyed := &keyedFactsJournal{fakeJournal: journal, keys: map[string]string{}}
	drill.journal = keyed
	run, err := drill.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, created := range branches.created {
		expected := journal.facts[created.SourceDatabaseID]
		if created.RecoveryPointID != expected.RecoveryPointID || created.JournalCut != expected.JournalCut || keyed.keys[created.SourceDatabaseID] != run.ID+"/"+created.SourceDatabaseID {
			t.Fatalf("atomic restore changed source capture: %+v", created)
		}
	}
	for _, restored := range backup.restores {
		expected := journal.facts[restored.SourceDatabaseID]
		if restored.RecoveryPointID != expected.RecoveryPointID || restored.JournalCut != expected.JournalCut || restored.IdempotencyKey != keyed.keys[restored.SourceDatabaseID] {
			t.Fatalf("restore verification changed source capture: %+v", restored)
		}
	}
}
