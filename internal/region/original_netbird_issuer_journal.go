package region

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

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/nats-io/nats.go/jetstream"
)

// OriginalNetBirdIssuerJournal uses only the GRU original manager child. It
// retains the existing OCIR operation, credential and wire history protocol.
type OriginalNetBirdIssuerJournal struct {
	session *OriginalNetBirdOCIRSession
	scope   VerifiedOCIRIssuer
}

func (s *OriginalNetBirdIssuerJournal) read(ctx context.Context) (FoundationRecord, string, error) {
	if s == nil || s.session == nil {
		return FoundationRecord{}, "", ErrOriginalSourceProducerHold
	}
	return s.session.read(ctx, s.scope)
}

func originalNetBirdIssuances(record FoundationRecord) map[string]OCIRIssuanceEntry {
	return record.OriginalFoundationCompartments.Regions[0].NetBirdManager.OCIRIssuances
}

func (s *OriginalNetBirdIssuerJournal) Load(ctx context.Context, key string) (OCIRIssuanceState, uint64, error) {
	if s == nil {
		return OCIRIssuanceState{}, 0, ErrOriginalSourceProducerHold
	}
	expected, err := s.scope.JournalKey()
	if err != nil || expected != key {
		return OCIRIssuanceState{}, 0, ErrOriginalSourceProducerHold
	}
	record, _, err := s.read(ctx)
	if err != nil {
		return OCIRIssuanceState{}, 0, err
	}
	entry, ok := originalNetBirdIssuances(record)[key]
	if !ok {
		return OCIRIssuanceState{}, 0, jetstream.ErrKeyNotFound
	}
	if err := entry.State.Validate(key); err != nil {
		return OCIRIssuanceState{}, 0, err
	}
	return entry.State, entry.Revision, nil
}

func (s *OriginalNetBirdIssuerJournal) CompareAndSwap(ctx context.Context, key string, state OCIRIssuanceState, revision uint64) (uint64, error) {
	if s == nil {
		return 0, ErrOriginalSourceProducerHold
	}
	expected, err := s.scope.JournalKey()
	if err != nil || expected != key {
		return 0, ErrOriginalSourceProducerHold
	}
	if err := state.Validate(key); err != nil {
		return 0, err
	}
	record, etag, err := s.read(ctx)
	if err != nil {
		return 0, err
	}
	previous, exists := originalNetBirdIssuances(record)[key]
	if exists && previous.Revision != revision || !exists && revision != 0 || state.Generation != s.scope.Generation() || state.GrantDigest != s.scope.GrantDigest() {
		return 0, ErrOriginalSourceProducerHold
	}
	if exists && (previous.State.OperationID != state.OperationID || previous.State.ScopeHash != state.ScopeHash ||
		previous.State.UserID != "" && previous.State.UserID != state.UserID || previous.State.RepositoryID != "" && previous.State.RepositoryID != state.RepositoryID ||
		previous.State.GroupID != "" && previous.State.GroupID != state.GroupID || previous.State.PolicyID != "" && previous.State.PolicyID != state.PolicyID ||
		previous.State.MembershipID != "" && previous.State.MembershipID != state.MembershipID || previous.State.SecretID != "" && previous.State.SecretID != state.SecretID) {
		return 0, ErrOriginalSourceProducerHold
	}
	if previous.State.TokenOperation != "" && state.TokenOperation != "" && previous.State.TokenOperation != state.TokenOperation {
		return 0, ErrOriginalSourceProducerHold
	}
	origin := previous.Origin
	if !exists {
		origin = OCIRIssuanceOrigin{GrantSHA256: state.GrantDigest, Generation: state.Generation, FoundationOperation: record.OperationID, Epoch: record.Epoch, LeaseID: state.LeaseID, ExpiresAt: s.session.deadline}
	}
	entry := OCIRIssuanceEntry{Origin: origin, Revision: revision + 1, State: state, Requests: maps.Clone(previous.Requests), Attempts: maps.Clone(previous.Attempts)}
	if entry.Revision == 0 {
		return 0, ErrOriginalSourceProducerHold
	}
	if entry.Attempts == nil {
		entry.Attempts = map[string]OCIRCredentialAttempt{}
	}
	if err := s.retainAttempt(&entry, previous); err != nil {
		return 0, err
	}
	wire, err := json.Marshal(entry)
	if err != nil || len(wire) > 32<<10 {
		return 0, errors.New("OCIR protected issuance entry exceeds fixed 32 KiB bound")
	}
	manager := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	manager.OCIRIssuances = maps.Clone(manager.OCIRIssuances)
	if manager.OCIRIssuances == nil {
		manager.OCIRIssuances = map[string]OCIRIssuanceEntry{}
	}
	manager.OCIRIssuances[key] = entry
	if err := s.write(ctx, record, etag); err != nil {
		return 0, err
	}
	return entry.Revision, nil
}

func (s *OriginalNetBirdIssuerJournal) write(ctx context.Context, record FoundationRecord, etag string) error {
	guard := func(ctx context.Context) error { return s.session.Guard(ctx, s.scope) }
	ctx = ociclient.WithAuthority(ociclient.CheckpointContext(ctx), guard)
	ctx = ociclient.WithWireAttempt(ctx, func(*http.Request) (func(*http.Response, error, bool) error, error) {
		return func(*http.Response, error, bool) error { return nil }, nil
	})
	if err := guard(ctx); err != nil {
		return err
	}
	// One whole-record CAS preserves siblings; an unknown outcome is reread.
	record.UpdatedAt = time.Now().UTC()
	if _, err := s.session.authority.resolver.Store.CompareAndSwap(ctx, record, etag); err != nil {
		return err
	}
	return guard(ctx)
}

func (s *OriginalNetBirdIssuerJournal) retainAttempt(entry *OCIRIssuanceEntry, previous OCIRIssuanceEntry) error {
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
			return ErrOriginalSourceProducerHold
		}
		body, err := json.Marshal(struct {
			Description string `json:"description"`
		}{"terrascale-ocir:" + operation})
		if err != nil {
			return err
		}
		request := sha256.Sum256(append([]byte(next.UserID+"\n"), body...))
		attempt = OCIRCredentialAttempt{OperationID: next.OperationID, GrantSHA256: next.GrantDigest, Generation: next.Generation,
			FoundationOperation: s.session.original.OperationID, Epoch: s.session.original.Epoch, LeaseID: next.LeaseID, LeaseUntil: next.LeaseUntil, ExpiresAt: next.TokenExpires, TokenOperation: operation, TokenStarted: next.TokenStarted,
			BeforeTokens: slices.Clone(next.BeforeTokens), RequestSHA256: hex.EncodeToString(request[:]), VaultID: s.scope.Intent().VaultTarget.VaultID, SecretName: s.scope.Intent().SecretName}
	}
	if next.TokenOperation == operation {
		if !attempt.TokenStarted.Equal(next.TokenStarted) || !attempt.ExpiresAt.Equal(next.TokenExpires) || !slices.Equal(attempt.BeforeTokens, next.BeforeTokens) {
			return ErrOriginalSourceProducerHold
		}
		if next.Stage == "vault-pending" {
			if attempt.TokenID != "" && attempt.TokenID != next.TokenID || attempt.PendingHash != "" && attempt.PendingHash != next.PendingHash {
				return ErrOriginalSourceProducerHold
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

func validateOriginalNetBirdOCIRJournal(manager *OriginalFoundationNetBirdManager) error {
	if manager == nil {
		return nil
	}
	if len(manager.OCIRIssuances) > 3 {
		return ErrOriginalSourceProducerHold
	}
	if len(manager.OCIRIssuances) == 0 {
		return nil
	}
	if manager.Intent.Material == nil || manager.Intent.Components == nil {
		return ErrOriginalSourceProducerHold
	}
	material := manager.Intent.Material.Context
	allowed := map[string]OCIRIssuerIntent{}
	for _, component := range *manager.Intent.Components {
		key, err := (VerifiedOCIRIssuer{intent: component.Issuer, tenancyID: material.TenancyID, installationID: material.InstallationID, generation: 1, grantDigest: manager.GrantSHA256}).JournalKey()
		if err != nil {
			return err
		}
		allowed[key] = component.Issuer
	}
	if len(allowed) != 3 {
		return ErrOriginalSourceProducerHold
	}
	operation := entityid.Derive("regional-foundation", material.TenancyID, "GRU", "1")
	for key, entry := range manager.OCIRIssuances {
		issuer, ok := allowed[key]
		if !ok || entry.Origin.GrantSHA256 != manager.GrantSHA256 || entry.Origin.Generation != 1 || entry.Origin.Epoch != 1 || entry.Origin.FoundationOperation != operation ||
			entry.State.GrantDigest != manager.GrantSHA256 || entry.State.Generation != 1 {
			return ErrOriginalSourceProducerHold
		}
		if entry.State.TokenOperation != "" {
			attempt, found := entry.Attempts[entry.State.TokenOperation]
			if !found || attempt.OperationID != entry.State.OperationID || !attempt.TokenStarted.Equal(entry.State.TokenStarted) ||
				!attempt.ExpiresAt.Equal(entry.State.TokenExpires) || !slices.Equal(attempt.BeforeTokens, entry.State.BeforeTokens) {
				return ErrOriginalSourceProducerHold
			}
		}
		for _, request := range entry.Requests {
			if request.GrantSHA256 != manager.GrantSHA256 || request.Epoch != 1 || request.Deadline.After(entry.Origin.ExpiresAt) {
				return ErrOriginalSourceProducerHold
			}
		}
		for _, attempt := range entry.Attempts {
			if attempt.GrantSHA256 != manager.GrantSHA256 || attempt.Generation != 1 || attempt.FoundationOperation != operation || attempt.Epoch != 1 ||
				attempt.VaultID != issuer.VaultTarget.VaultID || attempt.SecretName != issuer.SecretName {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	return (FoundationRecord{Generation: 1, OCIRIssuances: manager.OCIRIssuances}).validateOCIRIssuances()
}

func retainOriginalNetBirdOCIRJournal(old, next *OriginalFoundationNetBirdManager) error {
	if old == nil {
		if next != nil && len(next.OCIRIssuances) != 0 {
			return ErrOriginalSourceProducerHold
		}
		return validateOriginalNetBirdOCIRJournal(next)
	}
	if next == nil {
		return ErrOriginalSourceProducerHold
	}
	if err := validateOriginalNetBirdOCIRJournal(next); err != nil {
		return err
	}
	return (FoundationRecord{OCIRIssuances: old.OCIRIssuances}).retainOCIRIssuances(FoundationRecord{OCIRIssuances: next.OCIRIssuances})
}
