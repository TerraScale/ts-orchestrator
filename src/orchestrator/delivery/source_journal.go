package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type SourceJournalDisposition uint8

const (
	SourceUnspecified SourceJournalDisposition = iota
	SourceRecorded
	SourceDuplicate
	SourceStaleAuthority
	SourceStaleSequence
	SourceIdentityConflict
	SourceUnprotectedBranch
)

type SourceJournalReceipt struct{ Disposition SourceJournalDisposition }
type SourceJournal struct{ Ledger Ledger }

func NewSourceJournal(l Ledger) *SourceJournal { return &SourceJournal{Ledger: l} }
func (j *SourceJournal) Observe(ctx context.Context, o BranchObservation, epoch, sequence int64) (SourceJournalReceipt, error) {
	if j == nil || j.Ledger == nil {
		return SourceJournalReceipt{}, errors.New("source journal ledger is missing")
	}
	if epoch <= 0 || sequence <= 0 {
		return SourceJournalReceipt{}, errors.New("source authority and sequence must be positive")
	}
	if !o.Protected {
		return SourceJournalReceipt{Disposition: SourceUnprotectedBranch}, nil
	}
	if !ValidRepository(o.Revision.Repository) || o.Branch != "develop" && o.Branch != "main" || !objectID(o.Revision.Commit) || allZero(o.Revision.Commit) || !objectID(o.Revision.Tree) || allZero(o.Revision.Tree) {
		return SourceJournalReceipt{}, errors.New("invalid branch observation")
	}
	d := sourceDocument{SchemaVersion: 1, SourceKey: "forgejo-source:" + o.Revision.Repository + ":" + o.Branch, Repository: o.Revision.Repository, Branch: o.Branch, Commit: o.Revision.Commit, Tree: o.Revision.Tree, SignatureVerified: o.Revision.SignatureVerified, Protected: true, AuthorityEpoch: epoch, PollSequence: sequence}
	b, _ := json.Marshal(d)
	key := "source." + hash(d.SourceKey)
	for i := 0; i < 8; i++ {
		cur, e := j.Ledger.Get(ctx, key)
		if e != nil {
			return SourceJournalReceipt{}, e
		}
		if cur == nil {
			if _, e = j.Ledger.Create(ctx, key, b); e == nil {
				return SourceJournalReceipt{Disposition: SourceRecorded}, nil
			}
			if errors.Is(e, ErrLedgerConflict) {
				continue
			}
			return SourceJournalReceipt{}, e
		}
		var old sourceDocument
		if e = json.Unmarshal(cur.Value, &old); e != nil {
			return SourceJournalReceipt{}, fmt.Errorf("invalid source journal: %w", e)
		}
		if old.SourceKey != d.SourceKey {
			return SourceJournalReceipt{}, errors.New("source journal identity changed")
		}
		if epoch < old.AuthorityEpoch {
			return SourceJournalReceipt{Disposition: SourceStaleAuthority}, nil
		}
		if epoch == old.AuthorityEpoch && sequence < old.PollSequence {
			return SourceJournalReceipt{Disposition: SourceStaleSequence}, nil
		}
		if epoch == old.AuthorityEpoch && sequence == old.PollSequence {
			if sameSource(old, d) {
				return SourceJournalReceipt{Disposition: SourceDuplicate}, nil
			}
			return SourceJournalReceipt{Disposition: SourceIdentityConflict}, nil
		}
		if _, e = j.Ledger.Update(ctx, key, b, cur.Revision); e == nil {
			return SourceJournalReceipt{Disposition: SourceRecorded}, nil
		}
		if !errors.Is(e, ErrLedgerConflict) {
			return SourceJournalReceipt{}, e
		}
	}
	return SourceJournalReceipt{}, errors.New("source journal conflicts exceeded")
}

type sourceDocument struct {
	SchemaVersion                               int `json:"schemaVersion"`
	SourceKey, Repository, Branch, Commit, Tree string
	SignatureVerified, Protected                bool
	AuthorityEpoch, PollSequence                int64
}

func sameSource(a, b sourceDocument) bool {
	return a.Repository == b.Repository && a.Branch == b.Branch && strings.EqualFold(a.Commit, b.Commit) && strings.EqualFold(a.Tree, b.Tree) && a.SignatureVerified == b.SignatureVerified && a.Protected == b.Protected
}

type AuthoritySnapshot struct {
	Ready, Leader bool
	Epoch         int64
}
type Poller struct {
	Client     *SourceClient
	Journal    *SourceJournal
	Authority  func() AuthoritySnapshot
	Interval   time.Duration
	completion chan struct{}
	cancel     context.CancelFunc
	once       sync.Once
}
