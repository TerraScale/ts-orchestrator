package rootfoundation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/nats-io/nats.go/jetstream"
)

type ocirJournal struct {
	store    region.FoundationStore
	cell     string
	original region.FoundationRecord
	scope    region.VerifiedOCIRIssuer
	deadline time.Time
	guard    func(context.Context) error
}

func (s *ocirJournal) read(ctx context.Context) (region.FoundationRecord, string, error) {
	if err := s.guard(ctx); err != nil {
		return region.FoundationRecord{}, "", err
	}
	record, etag, err := s.store.Load(ctx, s.cell)
	if err != nil {
		return region.FoundationRecord{}, "", err
	}
	if err := ocirRecordCurrent(record, s.original, s.scope); err != nil {
		return region.FoundationRecord{}, "", err
	}
	if err := s.guard(ctx); err != nil {
		return region.FoundationRecord{}, "", err
	}
	return record, etag, nil
}

func (s *ocirJournal) Load(ctx context.Context, key string) (region.OCIRIssuanceState, uint64, error) {
	expected, err := s.scope.JournalKey()
	if err != nil || expected != key {
		return region.OCIRIssuanceState{}, 0, ErrScope
	}
	record, _, err := s.read(ctx)
	if err != nil {
		return region.OCIRIssuanceState{}, 0, err
	}
	entry, ok := record.OCIRIssuances[key]
	if !ok {
		return region.OCIRIssuanceState{}, 0, jetstream.ErrKeyNotFound
	}
	if err := entry.State.Validate(key); err != nil {
		return region.OCIRIssuanceState{}, 0, err
	}
	return entry.State, entry.Revision, nil
}

func (s *ocirJournal) CompareAndSwap(ctx context.Context, key string, state region.OCIRIssuanceState, revision uint64) (uint64, error) {
	expected, err := s.scope.JournalKey()
	if err != nil || expected != key {
		return 0, ErrScope
	}
	if err := state.Validate(key); err != nil {
		return 0, err
	}
	record, etag, err := s.read(ctx)
	if err != nil {
		return 0, err
	}
	previous, exists := record.OCIRIssuances[key]
	if exists && previous.Revision != revision || !exists && revision != 0 || state.Generation != s.scope.Generation() || state.GrantDigest != s.scope.GrantDigest() {
		return 0, ErrScope
	}
	if exists && (previous.State.OperationID != state.OperationID || previous.State.ScopeHash != state.ScopeHash ||
		previous.State.UserID != "" && previous.State.UserID != state.UserID || previous.State.RepositoryID != "" && previous.State.RepositoryID != state.RepositoryID ||
		previous.State.GroupID != "" && previous.State.GroupID != state.GroupID || previous.State.PolicyID != "" && previous.State.PolicyID != state.PolicyID ||
		previous.State.MembershipID != "" && previous.State.MembershipID != state.MembershipID || previous.State.SecretID != "" && previous.State.SecretID != state.SecretID) {
		return 0, ErrScope
	}
	if previous.State.TokenOperation != "" && state.TokenOperation != "" && previous.State.TokenOperation != state.TokenOperation {
		return 0, ErrScope
	}
	origin := previous.Origin
	if !exists {
		origin = region.OCIRIssuanceOrigin{GrantSHA256: state.GrantDigest, Generation: state.Generation, FoundationOperation: s.original.OperationID, Epoch: s.original.Epoch, LeaseID: state.LeaseID, ExpiresAt: s.deadline}
	}
	entry := region.OCIRIssuanceEntry{Origin: origin, Revision: revision + 1, State: state, Requests: maps.Clone(previous.Requests), Attempts: maps.Clone(previous.Attempts)}
	if entry.Revision == 0 {
		return 0, ErrScope
	}
	if entry.Attempts == nil {
		entry.Attempts = map[string]region.OCIRCredentialAttempt{}
	}
	if err := s.retainAttempt(&entry, previous); err != nil {
		return 0, err
	}
	wire, err := json.Marshal(entry)
	if err != nil || len(wire) > 32<<10 {
		return 0, errors.New("OCIR protected issuance entry exceeds fixed 32 KiB bound")
	}
	record.OCIRIssuances = maps.Clone(record.OCIRIssuances)
	if record.OCIRIssuances == nil {
		record.OCIRIssuances = map[string]region.OCIRIssuanceEntry{}
	}
	record.OCIRIssuances[key] = entry
	// Preserve all siblings and original request history in one non-retried CAS.
	ctx = ociclient.WithAuthority(ctx, s.guard)
	ctx = ociclient.WithWireAttempt(ctx, func(*http.Request) (func(*http.Response, error, bool) error, error) {
		return func(*http.Response, error, bool) error { return nil }, nil
	})
	if err := s.guard(ctx); err != nil {
		return 0, err
	}
	if _, err := s.store.CompareAndSwap(ctx, record, etag); err != nil {
		return 0, err
	}
	if err := s.guard(ctx); err != nil {
		return 0, err
	}
	return entry.Revision, nil
}

func (s *ocirJournal) retainAttempt(entry *region.OCIRIssuanceEntry, previous region.OCIRIssuanceEntry) error {
	next, old := entry.State, previous.State
	operation := next.TokenOperation
	if operation == "" {
		operation = old.TokenOperation
	}
	if operation == "" {
		return nil
	}
	attempt, found := entry.Attempts[operation]
	if !found {
		if operation != next.TokenOperation || len(entry.Attempts) >= 64 {
			return ErrScope
		}
		body, err := json.Marshal(struct {
			Description string `json:"description"`
		}{"terrascale-ocir:" + operation})
		if err != nil {
			return err
		}
		request := sha256.Sum256(append([]byte(next.UserID+"\n"), body...))
		attempt = region.OCIRCredentialAttempt{OperationID: next.OperationID, GrantSHA256: next.GrantDigest, Generation: next.Generation,
			FoundationOperation: s.original.OperationID, Epoch: s.original.Epoch, LeaseID: next.LeaseID, LeaseUntil: next.LeaseUntil, ExpiresAt: next.TokenExpires, TokenOperation: operation, TokenStarted: next.TokenStarted,
			BeforeTokens: slices.Clone(next.BeforeTokens), RequestSHA256: hex.EncodeToString(request[:]), VaultID: s.scope.Intent().VaultTarget.VaultID, SecretName: s.scope.Intent().SecretName}
	}
	if next.TokenOperation == operation {
		if !attempt.TokenStarted.Equal(next.TokenStarted) || !attempt.ExpiresAt.Equal(next.TokenExpires) || !slices.Equal(attempt.BeforeTokens, next.BeforeTokens) {
			return ErrScope
		}
		if next.Stage == "vault-pending" {
			if attempt.TokenID != "" && attempt.TokenID != next.TokenID || attempt.PendingHash != "" && attempt.PendingHash != next.PendingHash {
				return ErrScope
			}
			attempt.TokenID, attempt.PendingHash = next.TokenID, next.PendingHash
		}
	} else if next.Stage == "ready" {
		if next.TokenID == attempt.TokenID && next.Hash != "" && next.Version > old.Version {
			attempt.SecretID, attempt.Version, attempt.Hash, attempt.PublishedAt = next.SecretID, next.Version, next.Hash, next.PublishedAt
		} else {
			attempt.RetiredAt = time.Now().UTC()
		}
	}
	entry.Attempts[operation] = attempt
	return nil
}
