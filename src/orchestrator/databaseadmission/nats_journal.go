package databaseadmission

import (
	"cmp"
	"context"
	"slices"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

// NATSJournalConfig uses the same authenticated connection and exact live GRU
// global election identity as placement publication. State and the live lease
// share the R3 ORCH_LEADERS stream, including the CAS sequence and read barrier.
type NATSJournalConfig struct {
	Connection     *nats.Conn
	CandidateID    string
	AuthorityEpoch uint64
	LeaseID        string
}
type NATSJournal struct {
	journal *authorityjournal.Journal[journalState]
}

func NewNATSJournal(config NATSJournalConfig) (*NATSJournal, error) {
	journal, err := authorityjournal.New(authorityjournal.Config{Connection: config.Connection, CandidateID: config.CandidateID, AuthorityEpoch: config.AuthorityEpoch, LeaseID: config.LeaseID, StateKey: "database.admission"}, func() journalState { return newJournalState() }, validateJournalState)
	if err != nil {
		return nil, err
	}
	return &NATSJournal{journal: journal}, nil
}
func (journal *NATSJournal) Load(ctx context.Context, key string) (record Record, found bool, err error) {
	if journal == nil || journal.journal == nil {
		return record, false, ErrJournalUnavailable
	}
	err = journal.journal.Transact(ctx, false, func(state *journalState) error { record, found = state.Records[key]; return nil })
	if err != nil {
		return Record{}, false, err
	}
	return record, found, nil
}
func (journal *NATSJournal) Save(ctx context.Context, key string, expected uint64, record Record) (uint64, error) {
	if journal == nil || journal.journal == nil {
		return 0, ErrJournalUnavailable
	}
	var revision uint64
	err := journal.journal.Transact(ctx, true, func(state *journalState) error {
		var err error
		revision, err = saveRecord(state, key, expected, record)
		return err
	})
	if err != nil {
		return 0, err
	}
	return revision, nil
}
func (journal *NATSJournal) List(ctx context.Context) ([]Record, error) {
	if journal == nil || journal.journal == nil {
		return nil, ErrJournalUnavailable
	}
	var records []Record
	err := journal.journal.Transact(ctx, false, func(state *journalState) error {
		records = make([]Record, 0, len(state.Records))
		for _, record := range state.Records {
			records = append(records, record)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(records, func(a, b Record) int { return cmp.Compare(ScopeKey(a.Request), ScopeKey(b.Request)) })
	return records, nil
}

var _ Journal = (*NATSJournal)(nil)
