// Facade aliases keep the historical control.* identifiers working after the
// authority extraction. New code should import the sub-package directly.
package control

import "terrascale.tech/orchestrator/src/orchestrator/control/authority"

const (
	AuthorityCasOutcomeConflict               = authority.AuthorityCasOutcomeConflict
	AuthorityCasOutcomeFailed                 = authority.AuthorityCasOutcomeFailed
	AuthorityCasOutcomeSucceeded              = authority.AuthorityCasOutcomeSucceeded
	AuthorityCasOutcomeUncertain              = authority.AuthorityCasOutcomeUncertain
	AuthorityErrorCodeArithmeticOverflow      = authority.AuthorityErrorCodeArithmeticOverflow
	AuthorityErrorCodeCasConflict             = authority.AuthorityErrorCodeCasConflict
	AuthorityErrorCodeCasFailed               = authority.AuthorityErrorCodeCasFailed
	AuthorityErrorCodeCasUncertain            = authority.AuthorityErrorCodeCasUncertain
	AuthorityErrorCodeClockAnomaly            = authority.AuthorityErrorCodeClockAnomaly
	AuthorityErrorCodeConflictingJournalEvent = authority.AuthorityErrorCodeConflictingJournalEvent
	AuthorityErrorCodeEpochMismatch           = authority.AuthorityErrorCodeEpochMismatch
	AuthorityErrorCodeFenced                  = authority.AuthorityErrorCodeFenced
	AuthorityErrorCodeIdentityMismatch        = authority.AuthorityErrorCodeIdentityMismatch
	AuthorityErrorCodeInvalidInput            = authority.AuthorityErrorCodeInvalidInput
	AuthorityErrorCodeInvalidJournal          = authority.AuthorityErrorCodeInvalidJournal
	AuthorityErrorCodeInvalidTransition       = authority.AuthorityErrorCodeInvalidTransition
	AuthorityErrorCodeLeaseActive             = authority.AuthorityErrorCodeLeaseActive
	AuthorityErrorCodeLeaseExpired            = authority.AuthorityErrorCodeLeaseExpired
	AuthorityErrorCodePartitionUncertain      = authority.AuthorityErrorCodePartitionUncertain
	AuthorityErrorCodeRevisionMismatch        = authority.AuthorityErrorCodeRevisionMismatch
	AuthorityErrorCodeStaleObservation        = authority.AuthorityErrorCodeStaleObservation
	AuthorityStatusAcquisitionPending         = authority.AuthorityStatusAcquisitionPending
	AuthorityStatusFenced                     = authority.AuthorityStatusFenced
	AuthorityStatusFollower                   = authority.AuthorityStatusFollower
	AuthorityStatusLeader                     = authority.AuthorityStatusLeader
	AuthorityStatusReadOnlyHeld               = authority.AuthorityStatusReadOnlyHeld
	AuthorityStatusReleasePending             = authority.AuthorityStatusReleasePending
	AuthorityStatusRenewalPending             = authority.AuthorityStatusRenewalPending
)

var (
	RegionalAuthorityCoordinatorForSnapshot      = authority.RegionalAuthorityCoordinatorForSnapshot
	NewAcquireAuthority                          = authority.NewAcquireAuthority
	NewAuthorityDecision                         = authority.NewAuthorityDecision
	NewCompareAndDeleteLeaseIntent               = authority.NewCompareAndDeleteLeaseIntent
	NewCompareAndSetLeaseIntent                  = authority.NewCompareAndSetLeaseIntent
	NewEvaluateMutationAuthority                 = authority.NewEvaluateMutationAuthority
	NewMutationAuthorityPermit                   = authority.NewMutationAuthorityPermit
	NewObserveAuthorityCas                       = authority.NewObserveAuthorityCas
	NewObserveAuthorityDelete                    = authority.NewObserveAuthorityDelete
	NewObserveAuthorityRead                      = authority.NewObserveAuthorityRead
	NewReadAuthorityIntent                       = authority.NewReadAuthorityIntent
	NewReleaseAuthority                          = authority.NewReleaseAuthority
	NewRenewAuthority                            = authority.NewRenewAuthority
	NewRequestAuthorityRead                      = authority.NewRequestAuthorityRead
	RegionalAuthorityCoordinatorHealth           = authority.RegionalAuthorityCoordinatorHealth
	RegionalAuthorityCoordinatorStartAsync       = authority.RegionalAuthorityCoordinatorStartAsync
	RegionalAuthorityCoordinatorStartGlobalAsync = authority.RegionalAuthorityCoordinatorStartGlobalAsync
	RegionalAuthorityLeaseDocumentFrom           = authority.RegionalAuthorityLeaseDocumentFrom
	AuthorityDigest                              = authority.AuthorityDigest
	AuthorityDigestEmptyJournalDigest            = authority.AuthorityDigestEmptyJournalDigest
	AuthorityEngine                              = authority.AuthorityEngine
	AuthorityStateEmpty                          = authority.AuthorityStateEmpty
)

type (
	AcquireAuthority               = authority.AcquireAuthority
	AuthorityCasOutcome            = authority.AuthorityCasOutcome
	AuthorityCommand               = authority.AuthorityCommand
	AuthorityCommandBase           = authority.AuthorityCommandBase
	AuthorityDecision              = authority.AuthorityDecision
	AuthorityDeleteConfirmed       = authority.AuthorityDeleteConfirmed
	AuthorityDeleteRequested       = authority.AuthorityDeleteRequested
	AuthorityError                 = authority.AuthorityError
	AuthorityErrorCode             = authority.AuthorityErrorCode
	AuthorityEvent                 = authority.AuthorityEvent
	AuthorityEventBase             = authority.AuthorityEventBase
	AuthorityFencedEvent           = authority.AuthorityFencedEvent
	AuthorityHealth                = authority.AuthorityHealth
	AuthorityHeld                  = authority.AuthorityHeld
	AuthorityIntent                = authority.AuthorityIntent
	AuthorityIntentBase            = authority.AuthorityIntentBase
	AuthorityLease                 = authority.AuthorityLease
	AuthorityObservation           = authority.AuthorityObservation
	AuthorityReadConfirmed         = authority.AuthorityReadConfirmed
	AuthorityReadRequested         = authority.AuthorityReadRequested
	AuthoritySetConfirmed          = authority.AuthoritySetConfirmed
	AuthoritySetRejected           = authority.AuthoritySetRejected
	AuthoritySetRequested          = authority.AuthoritySetRequested
	AuthorityState                 = authority.AuthorityState
	AuthorityStatus                = authority.AuthorityStatus
	CompareAndDeleteLeaseIntent    = authority.CompareAndDeleteLeaseIntent
	CompareAndSetLeaseIntent       = authority.CompareAndSetLeaseIntent
	EvaluateMutationAuthority      = authority.EvaluateMutationAuthority
	MutationAuthorityPermit        = authority.MutationAuthorityPermit
	ObserveAuthorityCas            = authority.ObserveAuthorityCas
	ObserveAuthorityDelete         = authority.ObserveAuthorityDelete
	ObserveAuthorityRead           = authority.ObserveAuthorityRead
	PendingAuthorityDelete         = authority.PendingAuthorityDelete
	PendingAuthoritySet            = authority.PendingAuthoritySet
	ReadAuthorityIntent            = authority.ReadAuthorityIntent
	RegionalAuthorityCoordinator   = authority.RegionalAuthorityCoordinator
	RegionalAuthorityLeaseDocument = authority.RegionalAuthorityLeaseDocument
	RegionalAuthoritySnapshot      = authority.RegionalAuthoritySnapshot
	RegionalControllerStatus       = authority.RegionalControllerStatus
	ReleaseAuthority               = authority.ReleaseAuthority
	RenewAuthority                 = authority.RenewAuthority
	RequestAuthorityRead           = authority.RequestAuthorityRead
)
