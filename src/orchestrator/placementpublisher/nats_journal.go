package placementpublisher

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

const (
	placementJournalStream            = "KV_ORCH_LEADERS"
	placementLeaseSubject             = "$KV.ORCH_LEADERS.authority.global"
	placementStateSubject             = "$KV.ORCH_LEADERS.placement.proposal.state"
	maximumPlacementJournalStateBytes = authorityjournal.MaximumStateBytes
)

var (
	ErrPlacementJournalUnavailable = authorityjournal.ErrUnavailable
	ErrPlacementJournalConflict    = authorityjournal.ErrConflict
)

type NATSJournalConfig struct {
	Connection     *nats.Conn
	CandidateID    string
	AuthorityEpoch uint64
	LeaseID        string
}
type NATSJournal struct {
	journal *authorityjournal.Journal[placementJournalState]
}
type placementJournalState struct{ Hosts map[string]Record }

func NewNATSJournal(config NATSJournalConfig) (*NATSJournal, error) {
	journal, err := authorityjournal.New(authorityjournal.Config{Connection: config.Connection, CandidateID: config.CandidateID, AuthorityEpoch: config.AuthorityEpoch, LeaseID: config.LeaseID, StateKey: "placement.proposal"}, func() placementJournalState { return placementJournalState{Hosts: map[string]Record{}} }, func(state placementJournalState) error {
		if state.Hosts == nil {
			return ErrInvalidConfig
		}
		return nil
	})
	if errors.Is(err, authorityjournal.ErrInvalidConfig) {
		return nil, ErrInvalidConfig
	}
	if err != nil {
		return nil, err
	}
	return &NATSJournal{journal: journal}, nil
}
func (journal *NATSJournal) transact(ctx context.Context, write bool, change func(*placementJournalState) error) error {
	if journal == nil || journal.journal == nil {
		return ErrPlacementJournalUnavailable
	}
	err := journal.journal.Transact(ctx, write, change)
	if errors.Is(err, authorityjournal.ErrFenced) {
		return ErrPlacementEpochFenced
	}
	if errors.Is(err, authorityjournal.ErrInvalidConfig) {
		return ErrInvalidConfig
	}
	return err
}

// Accept refuses to replace an unresolved host operation. The next expected
// engine revision comes only from its durable pending receipt.
func (journal *NATSJournal) Accept(ctx context.Context, record Record) error {
	request, err := decodeRecord(record)
	if err != nil || len(record.Receipt) != 0 {
		return ErrInvalidConfig
	}
	return journal.transact(ctx, true, func(state *placementJournalState) error {
		if old, found := state.Hosts[record.ServerIdentity]; found {
			prior, err := decodeRecord(old)
			if err != nil {
				return err
			}
			if sameIntent(old, record) {
				return nil
			}
			if old.OperationID == record.OperationID || len(old.Receipt) == 0 {
				return ErrPlacementJournalConflict
			}
			receipt := new(pb.PlacementProposalResponse)
			if proto.Unmarshal(old.Receipt, receipt) != nil {
				return ErrInvalidConfig
			}
			if request.ExpectedRevision != receipt.Revision || request.Proposal.Generation <= prior.Proposal.Generation || request.Proposal.Epoch <= prior.Proposal.Epoch {
				return ErrPlacementJournalConflict
			}
		} else if request.ExpectedRevision != 0 || len(state.Hosts) >= 128 {
			return ErrPlacementJournalConflict
		}
		state.Hosts[record.ServerIdentity] = record
		// Reserve the corresponding receipt before accepting an intent. An
		// admitted proposal must not become unacknowledgeable at the state cap.
		reserved := placementJournalState{Hosts: make(map[string]Record, len(state.Hosts))}
		for host, item := range state.Hosts {
			if len(item.Receipt) == 0 {
				item.Receipt = make([]byte, len(item.Request)+64)
			}
			reserved.Hosts[host] = item
		}
		encoded, err := json.Marshal(reserved)
		if err != nil || len(encoded) > maximumPlacementJournalStateBytes {
			return ErrInvalidConfig
		}
		return nil
	})
}
func (journal *NATSJournal) Load(ctx context.Context, serverIdentity string) (record Record, err error) {
	if !validIdentity(serverIdentity) {
		return record, ErrInvalidConfig
	}
	err = journal.transact(ctx, false, func(state *placementJournalState) error {
		var found bool
		record, found = state.Hosts[serverIdentity]
		if !found {
			return ErrIntentMissing
		}
		_, err := decodeRecord(record)
		return err
	})
	return
}
func (journal *NATSJournal) Acknowledge(ctx context.Context, record Record, receipt *pb.PlacementProposalResponse) error {
	request, err := decodeRecord(record)
	if err != nil {
		return err
	}
	if receipt.GetRevision() != request.ExpectedRevision+1 || request.ExpectedRevision == ^uint64(0) {
		return ErrInvalidConfig
	}
	if err := tbep.ValidatePlacementReceipt(receipt, request.Proposal); err != nil {
		return err
	}
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(receipt)
	if err != nil {
		return err
	}
	return journal.transact(ctx, true, func(state *placementJournalState) error {
		old, found := state.Hosts[record.ServerIdentity]
		if !found || !sameIntent(old, record) {
			return ErrPlacementJournalConflict
		}
		if len(old.Receipt) > 0 && !bytes.Equal(old.Receipt, data) {
			return ErrPlacementJournalConflict
		}
		old.Receipt = data
		state.Hosts[record.ServerIdentity] = old
		return nil
	})
}
