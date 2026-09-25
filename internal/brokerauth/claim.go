// Package brokerauth binds regional NATS account claims to the fenced control log.
package brokerauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

const maxAccountJWTBytes = 64 << 10

var (
	ErrNoClaim      = errors.New("regional broker account claim is not committed")
	ErrClaimChanged = errors.New("regional broker account claim changed")
	brokerToken     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// Claim is the exact signed account JWT currently committed by the regional
// authority. Sequence is the R3 control-log sequence, not a local file version.
type Claim struct {
	Cell      string
	Account   string
	JWT       string
	Hash      string
	Sequence  uint64
	Epoch     uint64
	IssuedAt  int64
	Committed time.Time
}

type claimRecord struct {
	Version  int    `json:"version"`
	Cell     string `json:"cell"`
	Account  string `json:"account"`
	JWT      string `json:"jwt"`
	Epoch    uint64 `json:"epoch"`
	IssuedAt int64  `json:"issuedAt"`
}

// Store shares the authority stream's global CAS order with lease changes.
// One process must use one Store for both issuance and claim commits: mu stops
// an old-claim ticket from being signed after a local revocation commit.
type Store struct {
	js     jetstream.JetStream
	stream jetstream.Stream
	cell   string
	fencer authority.Fencer
	mu     sync.Mutex
}

func OpenStore(ctx context.Context, js jetstream.JetStream, cell string, fencer authority.Fencer) (*Store, error) {
	if js == nil || !brokerToken.MatchString(cell) {
		return nil, errors.New("broker claim store requires a regional JetStream cell")
	}
	stream, err := js.Stream(ctx, authority.ControlStreamName)
	if err != nil {
		return nil, fmt.Errorf("open broker claim control log: %w", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect broker claim control log: %w", err)
	}
	if info.Config.Name != authority.ControlStreamName || info.Config.AllowDirect ||
		!info.Config.DenyDelete || !info.Config.DenyPurge ||
		info.Config.Retention != jetstream.LimitsPolicy || info.Config.Storage != jetstream.FileStorage ||
		info.Config.MaxMsgs != -1 || info.Config.MaxBytes != -1 || info.Config.MaxMsgsPerSubject != -1 ||
		info.Config.MaxAge != 0 || info.Config.Discard != jetstream.DiscardOld ||
		info.Config.DiscardNewPerSubject || info.Config.AllowRollup ||
		info.Config.Metadata["terrascale-contract"] != "authority-log-v1" ||
		len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != "ts.control.*.>" {
		return nil, errors.New("broker claim control log is not durable and leader-read")
	}
	return &Store{js: js, stream: stream, cell: cell, fencer: fencer}, nil
}

func claimSubject(cell, account string) string {
	return "ts.control." + cell + ".broker.claim." + account
}

// DecodeAccountJWT verifies the NATS signature and validates the account key.
// Whitespace is forbidden so hashes always address the exact resolver bytes.
func DecodeAccountJWT(raw, account string) (*jwt.AccountClaims, error) {
	if len(raw) == 0 || len(raw) > maxAccountJWTBytes || !nkeys.IsValidPublicAccountKey(account) {
		return nil, errors.New("invalid broker account JWT size or account key")
	}
	for _, character := range raw {
		if character <= ' ' || character > '~' {
			return nil, errors.New("broker account JWT must be one exact ASCII token")
		}
	}
	claim, err := jwt.DecodeAccountClaims(raw)
	if err != nil {
		return nil, fmt.Errorf("verify broker account JWT: %w", err)
	}
	if claim.Subject != account || claim.IssuedAt <= 0 {
		return nil, errors.New("broker account JWT subject or issued-at is invalid")
	}
	results := &jwt.ValidationResults{}
	claim.Validate(results)
	if results.IsBlocking(false) {
		return nil, fmt.Errorf("broker account JWT validation: %v", results.Errors())
	}
	return claim, nil
}

func (s *Store) Read(ctx context.Context, account string) (Claim, error) {
	if s == nil || s.stream == nil || !nkeys.IsValidPublicAccountKey(account) {
		return Claim{}, ErrNoClaim
	}
	entry, err := s.stream.GetLastMsgForSubject(ctx, claimSubject(s.cell, account))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return Claim{}, ErrNoClaim
	}
	if err != nil {
		return Claim{}, fmt.Errorf("read current broker claim: %w", err)
	}
	var record claimRecord
	if len(entry.Data) == 0 || len(entry.Data) > maxAccountJWTBytes+4096 ||
		json.Unmarshal(entry.Data, &record, json.RejectUnknownMembers(true)) != nil ||
		record.Version != 1 || record.Cell != s.cell || record.Account != account || record.Epoch == 0 {
		return Claim{}, errors.New("durable broker claim record is invalid")
	}
	decoded, err := DecodeAccountJWT(record.JWT, account)
	if err != nil || decoded.IssuedAt != record.IssuedAt {
		return Claim{}, errors.New("durable broker claim JWT is invalid")
	}
	digest := sha256.Sum256([]byte(record.JWT))
	return Claim{Cell: s.cell, Account: account, JWT: record.JWT,
		Hash: hex.EncodeToString(digest[:]), Sequence: entry.Sequence, Epoch: record.Epoch,
		IssuedAt: record.IssuedAt, Committed: entry.Time}, nil
}

// Commit appends one higher-iAT account claim under the current authority
// lease. A global sequence CAS prevents an old epoch from writing past a new
// lease barrier. Repeating the exact prior JWT is idempotent.
func (s *Store) Commit(ctx context.Context, epoch uint64, account, raw string, expectedSequence uint64) (Claim, error) {
	if s == nil || s.fencer == nil || epoch == 0 {
		return Claim{}, authority.ErrNotLeader
	}
	decoded, err := DecodeAccountJWT(raw, account)
	if err != nil {
		return Claim{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for range 8 {
		if err := s.fencer.Guard(ctx, epoch); err != nil {
			return Claim{}, err
		}
		snapshot := s.fencer.Current()
		if !snapshot.CanMutate() || snapshot.Scope != s.cell || snapshot.Epoch != epoch {
			return Claim{}, authority.ErrFenced
		}
		prior, err := s.Read(ctx, account)
		if err != nil && !errors.Is(err, ErrNoClaim) {
			return Claim{}, err
		}
		if prior.Sequence != 0 {
			if prior.JWT == raw {
				return prior, nil
			}
		}
		if prior.Sequence != expectedSequence {
			return Claim{}, authority.ErrConflict
		}
		if prior.Sequence != 0 {
			if decoded.IssuedAt <= prior.IssuedAt {
				return Claim{}, errors.New("replacement account JWT issued-at must strictly increase")
			}
		}
		info, err := s.stream.Info(ctx)
		if err != nil {
			return Claim{}, err
		}
		observed, err := authority.Observe(ctx, s.js, s.cell)
		if err != nil || !observed.Ready || observed.Epoch != epoch ||
			observed.CandidateID != snapshot.CandidateID || observed.OwnerID != snapshot.OwnerID ||
			observed.Revision > info.State.LastSeq {
			return Claim{}, authority.ErrFenced
		}
		record := claimRecord{Version: 1, Cell: s.cell, Account: account, JWT: raw,
			Epoch: epoch, IssuedAt: decoded.IssuedAt}
		data, err := json.Marshal(record)
		if err != nil {
			return Claim{}, err
		}
		message := &nats.Msg{Subject: claimSubject(s.cell, account), Data: data}
		ack, err := s.js.PublishMsg(ctx, message,
			jetstream.WithExpectLastSequence(info.State.LastSeq),
			jetstream.WithExpectLastSequenceForSubject(expectedSequence, message.Subject))
		if err != nil {
			if ctx.Err() != nil {
				return Claim{}, ctx.Err()
			}
			// A competing lease or claim append requires a fresh Guard. No
			// uncertain publish is reported successful without read-back.
			current, readErr := s.Read(ctx, account)
			if readErr == nil && current.Sequence > expectedSequence {
				if bytes.Equal([]byte(current.JWT), []byte(raw)) && current.Epoch == epoch {
					return current, nil
				}
				return Claim{}, authority.ErrConflict
			}
			continue
		}
		current, err := s.Read(ctx, account)
		if err != nil || current.Sequence != ack.Sequence || current.JWT != raw || current.Epoch != epoch {
			return Claim{}, authority.ErrOutcomeUnknown
		}
		return current, nil
	}
	return Claim{}, authority.ErrConflict
}
