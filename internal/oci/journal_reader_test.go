package oci

import "testing"

func TestJournalReaderRequiresExistingJournal(t *testing.T) {
	if (JournalReader{}).Valid() || (JournalReader{journal: &KVJournal{}}).Valid() {
		t.Fatal("an empty journal handle admitted a root fleet binding")
	}
	reader := JournalReader{journal: &KVJournal{kv: testJournalBucket(t)}}
	if !reader.Valid() {
		t.Fatal("an existing durable journal was refused")
	}
}
