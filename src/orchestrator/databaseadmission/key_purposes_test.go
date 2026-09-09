package databaseadmission

import (
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

func TestPurposeProgressPreservesCompletedKeys(t *testing.T) {
	journal := NewMemoryJournal()
	r := journalFixture(t)
	key := ScopeKey(r.Request)
	var err error
	r.Revision, err = journal.Save(t.Context(), key, 0, r)
	if err != nil {
		t.Fatal(err)
	}
	all := journalWrapped(r)
	r.Wrapped = all[:1]
	r.Revision, err = journal.Save(t.Context(), key, r.Revision, r)
	if err != nil {
		t.Fatal("completed purpose was not persisted", err)
	}
	changed := r
	changed.Wrapped = append([]keylease.Entry(nil), r.Wrapped...)
	changed.Wrapped[0].Ciphertext = "replacement"
	if _, err := journal.Save(t.Context(), key, r.Revision, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("replaced persisted key", err)
	}
	config := pipelineConfig(t, journal)
	if err := keylease.WriteCatalog(config.CatalogPath, keylease.Catalog{Version: 1, Entries: all}); err != nil {
		t.Fatal(err)
	}
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.provisionKeys(t.Context(), &r); err != nil {
		t.Fatal(err)
	}
	if r.State != "keys_provisioned" || len(r.Wrapped) != 3 || r.Wrapped[0] != all[0] {
		t.Fatal("restart lost completed purpose", r.State)
	}
}

func TestHostRequiresEveryPurpose(t *testing.T) {
	r := journalFixture(t)
	target := r.Targets[0]
	c := HostConfig{Environment: r.Request.Environment, Region: target.Region, MemberID: target.MemberID}
	request := installRequest{Admission: Admission{Request: r.Request, CreatedAt: r.CreatedAt.UnixMilli(), DatabaseID: r.DatabaseID, KeyVersion: r.KeyVersion, Region: target.Region, MemberID: target.MemberID}, Entries: journalWrapped(r)}
	if err := validateInstall(c, request); err != nil {
		t.Fatal(err)
	}
	request.Entries = request.Entries[:1]
	if validateInstall(c, request) == nil {
		t.Fatal("admitted missing backup and checkpoint keys")
	}
	request.Entries = journalWrapped(r)
	c.Region = "SFO"
	if validateInstall(c, request) == nil {
		t.Fatal("admitted install for a different host region")
	}
}
