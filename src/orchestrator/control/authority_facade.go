package control

import (
	"context"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/authority"
)

type AuthorityStatus = authority.AuthorityStatus
type AuthorityCasOutcome = authority.AuthorityCasOutcome
type AuthorityErrorCode = authority.AuthorityErrorCode
type AuthorityError = authority.AuthorityError
type AuthorityLease = authority.AuthorityLease
type AuthorityObservation = authority.AuthorityObservation
type AuthorityHealth = authority.AuthorityHealth
type AuthorityCommand = authority.AuthorityCommand
type AuthorityCommandBase = authority.AuthorityCommandBase
type AcquireAuthority = authority.AcquireAuthority
type RenewAuthority = authority.RenewAuthority
type ReleaseAuthority = authority.ReleaseAuthority
type RequestAuthorityRead = authority.RequestAuthorityRead
type ObserveAuthorityCas = authority.ObserveAuthorityCas
type ObserveAuthorityDelete = authority.ObserveAuthorityDelete
type ObserveAuthorityRead = authority.ObserveAuthorityRead
type EvaluateMutationAuthority = authority.EvaluateMutationAuthority
type AuthorityIntent = authority.AuthorityIntent
type AuthorityIntentBase = authority.AuthorityIntentBase
type CompareAndSetLeaseIntent = authority.CompareAndSetLeaseIntent
type CompareAndDeleteLeaseIntent = authority.CompareAndDeleteLeaseIntent
type ReadAuthorityIntent = authority.ReadAuthorityIntent
type MutationAuthorityPermit = authority.MutationAuthorityPermit
type PendingAuthoritySet = authority.PendingAuthoritySet
type PendingAuthorityDelete = authority.PendingAuthorityDelete
type AuthorityEvent = authority.AuthorityEvent
type AuthorityEventBase = authority.AuthorityEventBase
type AuthoritySetRequested = authority.AuthoritySetRequested
type AuthoritySetConfirmed = authority.AuthoritySetConfirmed
type AuthoritySetRejected = authority.AuthoritySetRejected
type AuthorityDeleteRequested = authority.AuthorityDeleteRequested
type AuthorityDeleteConfirmed = authority.AuthorityDeleteConfirmed
type AuthorityReadRequested = authority.AuthorityReadRequested
type AuthorityReadConfirmed = authority.AuthorityReadConfirmed
type AuthorityHeld = authority.AuthorityHeld
type AuthorityFencedEvent = authority.AuthorityFencedEvent
type AuthorityState = authority.AuthorityState
type AuthorityDecision = authority.AuthorityDecision
type RegionalAuthoritySnapshot = authority.RegionalAuthoritySnapshot
type RegionalAuthorityLeaseDocument = authority.RegionalAuthorityLeaseDocument
type RegionalAuthorityCoordinator = authority.RegionalAuthorityCoordinator

const (
	AuthorityStatusFollower           = authority.AuthorityStatusFollower
	AuthorityStatusAcquisitionPending = authority.AuthorityStatusAcquisitionPending
	AuthorityStatusLeader             = authority.AuthorityStatusLeader
	AuthorityStatusRenewalPending     = authority.AuthorityStatusRenewalPending
	AuthorityStatusReleasePending     = authority.AuthorityStatusReleasePending
	AuthorityStatusReadOnlyHeld       = authority.AuthorityStatusReadOnlyHeld
	AuthorityStatusFenced             = authority.AuthorityStatusFenced

	AuthorityCasOutcomeSucceeded = authority.AuthorityCasOutcomeSucceeded
	AuthorityCasOutcomeConflict  = authority.AuthorityCasOutcomeConflict
	AuthorityCasOutcomeFailed    = authority.AuthorityCasOutcomeFailed
	AuthorityCasOutcomeUncertain = authority.AuthorityCasOutcomeUncertain

	AuthorityErrorCodeInvalidInput            = authority.AuthorityErrorCodeInvalidInput
	AuthorityErrorCodeInvalidJournal          = authority.AuthorityErrorCodeInvalidJournal
	AuthorityErrorCodeConflictingJournalEvent = authority.AuthorityErrorCodeConflictingJournalEvent
	AuthorityErrorCodeInvalidTransition       = authority.AuthorityErrorCodeInvalidTransition
	AuthorityErrorCodeIdentityMismatch        = authority.AuthorityErrorCodeIdentityMismatch
	AuthorityErrorCodeRevisionMismatch        = authority.AuthorityErrorCodeRevisionMismatch
	AuthorityErrorCodeEpochMismatch           = authority.AuthorityErrorCodeEpochMismatch
	AuthorityErrorCodeStaleObservation        = authority.AuthorityErrorCodeStaleObservation
	AuthorityErrorCodeLeaseActive             = authority.AuthorityErrorCodeLeaseActive
	AuthorityErrorCodeLeaseExpired            = authority.AuthorityErrorCodeLeaseExpired
	AuthorityErrorCodePartitionUncertain      = authority.AuthorityErrorCodePartitionUncertain
	AuthorityErrorCodeClockAnomaly            = authority.AuthorityErrorCodeClockAnomaly
	AuthorityErrorCodeCasConflict             = authority.AuthorityErrorCodeCasConflict
	AuthorityErrorCodeCasFailed               = authority.AuthorityErrorCodeCasFailed
	AuthorityErrorCodeCasUncertain            = authority.AuthorityErrorCodeCasUncertain
	AuthorityErrorCodeArithmeticOverflow      = authority.AuthorityErrorCodeArithmeticOverflow
	AuthorityErrorCodeFenced                  = authority.AuthorityErrorCodeFenced
)

var (
	AuthorityDigestEmptyJournalDigest = authority.AuthorityDigestEmptyJournalDigest
	AuthorityDigest                   = authority.AuthorityDigest
	AuthorityEngine                   = authority.AuthorityEngine
	AuthorityStateEmpty               = authority.AuthorityStateEmpty
)

func NewAcquireAuthority(
	authorityId, candidateId, requestId, leaseId string,
	baseline *AuthorityObservation,
	health *AuthorityHealth,
	leaseDuration time.Duration,
) *AcquireAuthority {
	return authority.NewAcquireAuthority(
		authorityId, candidateId, requestId, leaseId, baseline, health, leaseDuration)
}

func NewRenewAuthority(
	authorityId, candidateId, requestId string,
	current *AuthorityObservation,
	health *AuthorityHealth,
	leaseDuration time.Duration,
) *RenewAuthority {
	return authority.NewRenewAuthority(
		authorityId, candidateId, requestId, current, health, leaseDuration)
}

func NewReleaseAuthority(
	authorityId, candidateId, requestId string,
	current *AuthorityObservation,
	health *AuthorityHealth,
) *ReleaseAuthority {
	return authority.NewReleaseAuthority(authorityId, candidateId, requestId, current, health)
}

func NewRequestAuthorityRead(authorityId, candidateId, requestId string) *RequestAuthorityRead {
	return authority.NewRequestAuthorityRead(authorityId, candidateId, requestId)
}

func NewObserveAuthorityCas(
	authorityId, candidateId, requestId string,
	outcome AuthorityCasOutcome,
	observation *AuthorityObservation,
	health *AuthorityHealth,
) *ObserveAuthorityCas {
	return authority.NewObserveAuthorityCas(
		authorityId, candidateId, requestId, outcome, observation, health)
}

func NewObserveAuthorityDelete(
	authorityId, candidateId, requestId string,
	outcome AuthorityCasOutcome,
	observation *AuthorityObservation,
	health *AuthorityHealth,
) *ObserveAuthorityDelete {
	return authority.NewObserveAuthorityDelete(
		authorityId, candidateId, requestId, outcome, observation, health)
}

func NewObserveAuthorityRead(
	authorityId, candidateId, requestId string,
	outcome AuthorityCasOutcome,
	observation *AuthorityObservation,
	health *AuthorityHealth,
) *ObserveAuthorityRead {
	return authority.NewObserveAuthorityRead(
		authorityId, candidateId, requestId, outcome, observation, health)
}

func NewEvaluateMutationAuthority(
	authorityId, candidateId, requestId string,
	observation *AuthorityObservation,
	health *AuthorityHealth,
) *EvaluateMutationAuthority {
	return authority.NewEvaluateMutationAuthority(
		authorityId, candidateId, requestId, observation, health)
}

func NewCompareAndSetLeaseIntent(
	authorityId, requestId string,
	expectedRevision, expectedEpoch, proposedEpoch int64,
	proposedLease AuthorityLease,
) *CompareAndSetLeaseIntent {
	return authority.NewCompareAndSetLeaseIntent(
		authorityId, requestId, expectedRevision, expectedEpoch, proposedEpoch, proposedLease)
}

func NewCompareAndDeleteLeaseIntent(
	authorityId, requestId string,
	expectedRevision, expectedEpoch int64,
	expectedLease AuthorityLease,
) *CompareAndDeleteLeaseIntent {
	return authority.NewCompareAndDeleteLeaseIntent(
		authorityId, requestId, expectedRevision, expectedEpoch, expectedLease)
}

func NewReadAuthorityIntent(
	request *RequestAuthorityRead,
	state *AuthorityState,
	resumeStatus AuthorityStatus,
) *ReadAuthorityIntent {
	return authority.NewReadAuthorityIntent(request, state, resumeStatus)
}

func NewMutationAuthorityPermit(authorizingCommand AuthorityCommand) (*MutationAuthorityPermit, error) {
	return authority.NewMutationAuthorityPermit(authorizingCommand)
}

func NewAuthorityDecision(
	state *AuthorityState,
	events []AuthorityEvent,
	intents []AuthorityIntent,
	errors []AuthorityError,
	mutationPermit *MutationAuthorityPermit,
) *AuthorityDecision {
	return authority.NewAuthorityDecision(state, events, intents, errors, mutationPermit)
}

func RegionalAuthorityLeaseDocumentFrom(
	authorityId string,
	epoch int64,
	lease AuthorityLease,
) RegionalAuthorityLeaseDocument {
	return authority.RegionalAuthorityLeaseDocumentFrom(authorityId, epoch, lease)
}

func RegionalAuthorityCoordinatorStartAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	cell string,
	instance string,
) (*RegionalAuthorityCoordinator, error) {
	return authority.RegionalAuthorityCoordinatorStartAsync(ctx, store, cell, instance)
}

func RegionalAuthorityCoordinatorStartGlobalAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	cell string,
	instance string,
) (*RegionalAuthorityCoordinator, error) {
	return authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, store, cell, instance)
}

func RegionalAuthorityCoordinatorHealth(now time.Time, confirmedLeaseAge time.Duration) AuthorityHealth {
	return authority.RegionalAuthorityCoordinatorHealth(now, confirmedLeaseAge)
}
