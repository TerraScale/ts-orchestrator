// Port of src/TerraScale.Orchestrator/ControlPlane/Authority/AuthorityContracts.cs
package control

import "time"

type AuthorityStatus int

const (
	AuthorityStatusFollower AuthorityStatus = iota
	AuthorityStatusAcquisitionPending
	AuthorityStatusLeader
	AuthorityStatusRenewalPending
	AuthorityStatusReleasePending
	AuthorityStatusReadOnlyHeld
	AuthorityStatusFenced
)

func (s AuthorityStatus) String() string {
	switch s {
	case AuthorityStatusFollower:
		return "Follower"
	case AuthorityStatusAcquisitionPending:
		return "AcquisitionPending"
	case AuthorityStatusLeader:
		return "Leader"
	case AuthorityStatusRenewalPending:
		return "RenewalPending"
	case AuthorityStatusReleasePending:
		return "ReleasePending"
	case AuthorityStatusReadOnlyHeld:
		return "ReadOnlyHeld"
	case AuthorityStatusFenced:
		return "Fenced"
	default:
		return "AuthorityStatus"
	}
}

func authorityStatusIsDefined(s AuthorityStatus) bool {
	return s >= AuthorityStatusFollower && s <= AuthorityStatusFenced
}

type AuthorityCasOutcome int

const (
	AuthorityCasOutcomeSucceeded AuthorityCasOutcome = iota
	AuthorityCasOutcomeConflict
	AuthorityCasOutcomeFailed
	AuthorityCasOutcomeUncertain
)

func (o AuthorityCasOutcome) String() string {
	switch o {
	case AuthorityCasOutcomeSucceeded:
		return "Succeeded"
	case AuthorityCasOutcomeConflict:
		return "Conflict"
	case AuthorityCasOutcomeFailed:
		return "Failed"
	case AuthorityCasOutcomeUncertain:
		return "Uncertain"
	default:
		return "AuthorityCasOutcome"
	}
}

func authorityCasOutcomeIsDefined(o AuthorityCasOutcome) bool {
	return o >= AuthorityCasOutcomeSucceeded && o <= AuthorityCasOutcomeUncertain
}

type AuthorityErrorCode int

const (
	AuthorityErrorCodeInvalidInput AuthorityErrorCode = iota
	AuthorityErrorCodeInvalidJournal
	AuthorityErrorCodeConflictingJournalEvent
	AuthorityErrorCodeInvalidTransition
	AuthorityErrorCodeIdentityMismatch
	AuthorityErrorCodeRevisionMismatch
	AuthorityErrorCodeEpochMismatch
	AuthorityErrorCodeStaleObservation
	AuthorityErrorCodeLeaseActive
	AuthorityErrorCodeLeaseExpired
	AuthorityErrorCodePartitionUncertain
	AuthorityErrorCodeClockAnomaly
	AuthorityErrorCodeCasConflict
	AuthorityErrorCodeCasFailed
	AuthorityErrorCodeCasUncertain
	AuthorityErrorCodeArithmeticOverflow
	AuthorityErrorCodeFenced
)

func (c AuthorityErrorCode) String() string {
	switch c {
	case AuthorityErrorCodeInvalidInput:
		return "InvalidInput"
	case AuthorityErrorCodeInvalidJournal:
		return "InvalidJournal"
	case AuthorityErrorCodeConflictingJournalEvent:
		return "ConflictingJournalEvent"
	case AuthorityErrorCodeInvalidTransition:
		return "InvalidTransition"
	case AuthorityErrorCodeIdentityMismatch:
		return "IdentityMismatch"
	case AuthorityErrorCodeRevisionMismatch:
		return "RevisionMismatch"
	case AuthorityErrorCodeEpochMismatch:
		return "EpochMismatch"
	case AuthorityErrorCodeStaleObservation:
		return "StaleObservation"
	case AuthorityErrorCodeLeaseActive:
		return "LeaseActive"
	case AuthorityErrorCodeLeaseExpired:
		return "LeaseExpired"
	case AuthorityErrorCodePartitionUncertain:
		return "PartitionUncertain"
	case AuthorityErrorCodeClockAnomaly:
		return "ClockAnomaly"
	case AuthorityErrorCodeCasConflict:
		return "CasConflict"
	case AuthorityErrorCodeCasFailed:
		return "CasFailed"
	case AuthorityErrorCodeCasUncertain:
		return "CasUncertain"
	case AuthorityErrorCodeArithmeticOverflow:
		return "ArithmeticOverflow"
	case AuthorityErrorCodeFenced:
		return "Fenced"
	default:
		return "AuthorityErrorCode"
	}
}

func authorityErrorCodeIsDefined(c AuthorityErrorCode) bool {
	return c >= AuthorityErrorCodeInvalidInput && c <= AuthorityErrorCodeFenced
}

type AuthorityError struct {
	Code        AuthorityErrorCode
	Requirement string
	Message     string
}

func (e AuthorityError) Equal(other AuthorityError) bool {
	return e.Code == other.Code && e.Requirement == other.Requirement && e.Message == other.Message
}

type AuthorityLease struct {
	CandidateId   string
	LeaseId       string
	ServerIssuedAt time.Time
	Duration      time.Duration
}

// Equal mirrors C# record value equality for leases (instants compare by UTC
// instant, like DateTimeOffset equality).
func (l AuthorityLease) Equal(other AuthorityLease) bool {
	return l.CandidateId == other.CandidateId &&
		l.LeaseId == other.LeaseId &&
		dotNetTimeEquals(l.ServerIssuedAt, other.ServerIssuedAt) &&
		l.Duration == other.Duration
}

type AuthorityObservation struct {
	AuthorityId    string
	KvRevision     int64
	Epoch          int64
	ObservationId  string
	Lease          *AuthorityLease
}

// Equal mirrors C# record value equality (deep, lease included).
func (o AuthorityObservation) Equal(other AuthorityObservation) bool {
	if o.AuthorityId != other.AuthorityId || o.KvRevision != other.KvRevision ||
		o.Epoch != other.Epoch || o.ObservationId != other.ObservationId {
		return false
	}
	if (o.Lease == nil) != (other.Lease == nil) {
		return false
	}
	if o.Lease != nil && !o.Lease.Equal(*other.Lease) {
		return false
	}
	return true
}

type AuthorityHealth struct {
	ServerTime        time.Time
	MonotonicElapsed  time.Duration
	PartitionCertain  bool
	ClockCertain      bool
}

// AuthorityCommand is the Go form of the abstract AuthorityCommand record.
// The unexported marker keeps the hierarchy closed, like the C# internal
// constructors.
type AuthorityCommand interface {
	authorityCommandCommon() *AuthorityCommandBase
}

type AuthorityCommandBase struct {
	AuthorityId string
	CandidateId string
	RequestId   string
}

func (b *AuthorityCommandBase) authorityCommandCommon() *AuthorityCommandBase { return b }

func authorityCommandAuthorityId(command AuthorityCommand) string {
	return command.authorityCommandCommon().AuthorityId
}

func authorityCommandCandidateId(command AuthorityCommand) string {
	return command.authorityCommandCommon().CandidateId
}

func authorityCommandRequestId(command AuthorityCommand) string {
	return command.authorityCommandCommon().RequestId
}

type AcquireAuthority struct {
	AuthorityCommandBase
	LeaseId       string
	Baseline      *AuthorityObservation
	Health        *AuthorityHealth
	LeaseDuration time.Duration
}

func NewAcquireAuthority(authorityId, candidateId, requestId, leaseId string,
	baseline *AuthorityObservation, health *AuthorityHealth, leaseDuration time.Duration) *AcquireAuthority {
	return &AcquireAuthority{
		AuthorityCommandBase: AuthorityCommandBase{AuthorityId: authorityId, CandidateId: candidateId, RequestId: requestId},
		LeaseId:              leaseId,
		Baseline:             baseline,
		Health:               health,
		LeaseDuration:        leaseDuration,
	}
}

type RenewAuthority struct {
	AuthorityCommandBase
	Current       *AuthorityObservation
	Health        *AuthorityHealth
	LeaseDuration time.Duration
}

func NewRenewAuthority(authorityId, candidateId, requestId string, current *AuthorityObservation,
	health *AuthorityHealth, leaseDuration time.Duration) *RenewAuthority {
	return &RenewAuthority{
		AuthorityCommandBase: AuthorityCommandBase{AuthorityId: authorityId, CandidateId: candidateId, RequestId: requestId},
		Current:              current,
		Health:               health,
		LeaseDuration:        leaseDuration,
	}
}

type ReleaseAuthority struct {
	AuthorityCommandBase
	Current *AuthorityObservation
	Health  *AuthorityHealth
}

func NewReleaseAuthority(authorityId, candidateId, requestId string, current *AuthorityObservation,
	health *AuthorityHealth) *ReleaseAuthority {
	return &ReleaseAuthority{
		AuthorityCommandBase: AuthorityCommandBase{AuthorityId: authorityId, CandidateId: candidateId, RequestId: requestId},
		Current:              current,
		Health:               health,
	}
}

type RequestAuthorityRead struct {
	AuthorityCommandBase
}

func NewRequestAuthorityRead(authorityId, candidateId, requestId string) *RequestAuthorityRead {
	return &RequestAuthorityRead{
		AuthorityCommandBase: AuthorityCommandBase{AuthorityId: authorityId, CandidateId: candidateId, RequestId: requestId},
	}
}

type ObserveAuthorityCas struct {
	AuthorityCommandBase
	Outcome     AuthorityCasOutcome
	Observation *AuthorityObservation
	Health      *AuthorityHealth
}

func NewObserveAuthorityCas(authorityId, candidateId, requestId string, outcome AuthorityCasOutcome,
	observation *AuthorityObservation, health *AuthorityHealth) *ObserveAuthorityCas {
	return &ObserveAuthorityCas{
		AuthorityCommandBase: AuthorityCommandBase{AuthorityId: authorityId, CandidateId: candidateId, RequestId: requestId},
		Outcome:              outcome,
		Observation:          observation,
		Health:               health,
	}
}

type ObserveAuthorityDelete struct {
	AuthorityCommandBase
	Outcome     AuthorityCasOutcome
	Observation *AuthorityObservation
	Health      *AuthorityHealth
}

func NewObserveAuthorityDelete(authorityId, candidateId, requestId string, outcome AuthorityCasOutcome,
	observation *AuthorityObservation, health *AuthorityHealth) *ObserveAuthorityDelete {
	return &ObserveAuthorityDelete{
		AuthorityCommandBase: AuthorityCommandBase{AuthorityId: authorityId, CandidateId: candidateId, RequestId: requestId},
		Outcome:              outcome,
		Observation:          observation,
		Health:               health,
	}
}

type ObserveAuthorityRead struct {
	AuthorityCommandBase
	Outcome     AuthorityCasOutcome
	Observation *AuthorityObservation
	Health      *AuthorityHealth
}

func NewObserveAuthorityRead(authorityId, candidateId, requestId string, outcome AuthorityCasOutcome,
	observation *AuthorityObservation, health *AuthorityHealth) *ObserveAuthorityRead {
	return &ObserveAuthorityRead{
		AuthorityCommandBase: AuthorityCommandBase{AuthorityId: authorityId, CandidateId: candidateId, RequestId: requestId},
		Outcome:              outcome,
		Observation:          observation,
		Health:               health,
	}
}

type EvaluateMutationAuthority struct {
	AuthorityCommandBase
	Observation *AuthorityObservation
	Health      *AuthorityHealth
}

func NewEvaluateMutationAuthority(authorityId, candidateId, requestId string,
	observation *AuthorityObservation, health *AuthorityHealth) *EvaluateMutationAuthority {
	return &EvaluateMutationAuthority{
		AuthorityCommandBase: AuthorityCommandBase{AuthorityId: authorityId, CandidateId: candidateId, RequestId: requestId},
		Observation:          observation,
		Health:               health,
	}
}

// AuthorityIntent is the Go form of the abstract AuthorityIntent record.
type AuthorityIntent interface {
	authorityIntentCommon() *AuthorityIntentBase
}

type AuthorityIntentBase struct {
	AuthorityId string
	RequestId   string
}

func (b *AuthorityIntentBase) authorityIntentCommon() *AuthorityIntentBase { return b }

type CompareAndSetLeaseIntent struct {
	AuthorityIntentBase
	ExpectedRevision int64
	ExpectedEpoch    int64
	ProposedEpoch    int64
	ProposedLease    AuthorityLease
}

func NewCompareAndSetLeaseIntent(authorityId, requestId string, expectedRevision, expectedEpoch, proposedEpoch int64,
	proposedLease AuthorityLease) *CompareAndSetLeaseIntent {
	return &CompareAndSetLeaseIntent{
		AuthorityIntentBase: AuthorityIntentBase{AuthorityId: authorityId, RequestId: requestId},
		ExpectedRevision:    expectedRevision,
		ExpectedEpoch:       expectedEpoch,
		ProposedEpoch:       proposedEpoch,
		ProposedLease:       proposedLease,
	}
}

type CompareAndDeleteLeaseIntent struct {
	AuthorityIntentBase
	ExpectedRevision int64
	ExpectedEpoch    int64
	ExpectedLease    AuthorityLease
}

func NewCompareAndDeleteLeaseIntent(authorityId, requestId string, expectedRevision, expectedEpoch int64,
	expectedLease AuthorityLease) *CompareAndDeleteLeaseIntent {
	return &CompareAndDeleteLeaseIntent{
		AuthorityIntentBase: AuthorityIntentBase{AuthorityId: authorityId, RequestId: requestId},
		ExpectedRevision:    expectedRevision,
		ExpectedEpoch:       expectedEpoch,
		ExpectedLease:       expectedLease,
	}
}

type ReadAuthorityIntent struct {
	AuthorityIntentBase
	CandidateId                    string
	ResumeStatus                   AuthorityStatus
	ExpectedHighestEpoch           int64
	ExpectedHighestKvRevision      int64
	ExpectedConfirmedObservation   *AuthorityObservation
}

func NewReadAuthorityIntent(request *RequestAuthorityRead, state *AuthorityState, resumeStatus AuthorityStatus) *ReadAuthorityIntent {
	return &ReadAuthorityIntent{
		AuthorityIntentBase:           AuthorityIntentBase{AuthorityId: request.AuthorityId, RequestId: request.RequestId},
		CandidateId:                   request.CandidateId,
		ResumeStatus:                  resumeStatus,
		ExpectedHighestEpoch:          state.HighestEpoch,
		ExpectedHighestKvRevision:     state.HighestKvRevision,
		ExpectedConfirmedObservation:  state.Confirmed,
	}
}

type MutationAuthorityPermit struct {
	authorizingCommand        AuthorityCommand
	AuthorityId               string
	CandidateId               string
	LeaseId                   string
	Epoch                     int64
	KvRevision                int64
	ObservationId             string
	EvaluatedServerTime       time.Time
	EvaluatedMonotonicElapsed time.Duration
}

// NewMutationAuthorityPermit mirrors the internal C# constructor: only an
// accepted CAS, read, or evaluation command carrying lease evidence may mint
// a permit.
func NewMutationAuthorityPermit(authorizingCommand AuthorityCommand) (*MutationAuthorityPermit, error) {
	var observation *AuthorityObservation
	var health *AuthorityHealth
	var lease *AuthorityLease
	switch accepted := authorizingCommand.(type) {
	case *ObserveAuthorityCas:
		if accepted.Outcome == AuthorityCasOutcomeSucceeded && accepted.Observation != nil && accepted.Observation.Lease != nil {
			observation, health, lease = accepted.Observation, accepted.Health, accepted.Observation.Lease
		}
	case *ObserveAuthorityRead:
		if accepted.Outcome == AuthorityCasOutcomeSucceeded && accepted.Observation != nil && accepted.Observation.Lease != nil {
			observation, health, lease = accepted.Observation, accepted.Health, accepted.Observation.Lease
		}
	case *EvaluateMutationAuthority:
		if accepted.Observation != nil && accepted.Observation.Lease != nil {
			observation, health, lease = accepted.Observation, accepted.Health, accepted.Observation.Lease
		}
	}
	if observation == nil || health == nil || lease == nil {
		return nil, invalidArgument(
			"A mutation permit requires an accepted CAS, read, or evaluation command with lease evidence.")
	}
	return &MutationAuthorityPermit{
		authorizingCommand:        authorizingCommand,
		AuthorityId:               authorityCommandAuthorityId(authorizingCommand),
		CandidateId:               authorityCommandCandidateId(authorizingCommand),
		LeaseId:                   lease.LeaseId,
		Epoch:                     observation.Epoch,
		KvRevision:                observation.KvRevision,
		ObservationId:             observation.ObservationId,
		EvaluatedServerTime:       health.ServerTime,
		EvaluatedMonotonicElapsed: health.MonotonicElapsed,
	}, nil
}

func (p *MutationAuthorityPermit) AuthorizingCommand() AuthorityCommand {
	return p.authorizingCommand
}

func (p *MutationAuthorityPermit) RequestId() string {
	return authorityCommandRequestId(p.authorizingCommand)
}

type PendingAuthoritySet struct {
	RequestId           string
	ExpectedRevision    int64
	ExpectedEpoch       int64
	ProposedEpoch       int64
	ProposedLease       AuthorityLease
	ExpectedObservation *AuthorityObservation
	RequestedAtHealth   *AuthorityHealth
	IsRenewal           bool
}

type PendingAuthorityDelete struct {
	RequestId         string
	ExpectedRevision  int64
	ExpectedEpoch     int64
	ExpectedLease     AuthorityLease
	RequestedAtHealth *AuthorityHealth
}

// AuthorityEvent is the Go form of the abstract AuthorityEvent record.
type AuthorityEvent interface {
	authorityEventCommon() *AuthorityEventBase
}

type AuthorityEventBase struct {
	Sequence       int64
	PreviousDigest string
	EventDigest    string
	AuthorityId    string
	CandidateId    string
	RequestId      string
}

func (b *AuthorityEventBase) authorityEventCommon() *AuthorityEventBase { return b }

type AuthoritySetRequested struct {
	AuthorityEventBase
	Pending PendingAuthoritySet
}

type AuthoritySetConfirmed struct {
	AuthorityEventBase
	Observation *AuthorityObservation
	Health      *AuthorityHealth
	WasRenewal  bool
}

type AuthoritySetRejected struct {
	AuthorityEventBase
	Outcome     AuthorityCasOutcome
	Observation *AuthorityObservation
	Error       AuthorityError
}

type AuthorityDeleteRequested struct {
	AuthorityEventBase
	Pending PendingAuthorityDelete
}

type AuthorityDeleteConfirmed struct {
	AuthorityEventBase
	Observation *AuthorityObservation
}

type AuthorityReadRequested struct {
	AuthorityEventBase
	ResumeStatus AuthorityStatus
}

type AuthorityReadConfirmed struct {
	AuthorityEventBase
	Observation *AuthorityObservation
	Health      *AuthorityHealth
}

type AuthorityHeld struct {
	AuthorityEventBase
	HeldFrom    AuthorityStatus
	Observation *AuthorityObservation
	Error       AuthorityError
}

type AuthorityFencedEvent struct {
	AuthorityEventBase
	Observation *AuthorityObservation
	Error       AuthorityError
}

type AuthorityState struct {
	AuthorityId            *string
	CandidateId            *string
	Status                 AuthorityStatus
	LastSequence           int64
	JournalDigest          string
	HighestEpoch           int64
	HighestKvRevision      int64
	Confirmed              *AuthorityObservation
	PendingSet             *PendingAuthoritySet
	PendingDelete          *PendingAuthorityDelete
	PendingReadRequestId   *string
	PendingReadCandidateId *string
	ReadResumeStatus       *AuthorityStatus
	LastCompletedRequestId *string
	LastError              *AuthorityError
}

// AuthorityStateEmpty mirrors AuthorityState.Empty.
var AuthorityStateEmpty = &AuthorityState{
	Status:        AuthorityStatusFollower,
	JournalDigest: AuthorityDigestEmptyJournalDigest,
}

func stringPointer(value string) *string { return &value }

func statusPointer(value AuthorityStatus) *AuthorityStatus { return &value }

type AuthorityDecision struct {
	State          *AuthorityState
	EventsToAppend []AuthorityEvent
	Intents        []AuthorityIntent
	Errors         []AuthorityError
	MutationPermit *MutationAuthorityPermit
	DecisionDigest string
}

// NewAuthorityDecision mirrors AuthorityDecision.Create; nil collections are
// normalized to empty lists like the C# optional arguments.
func NewAuthorityDecision(state *AuthorityState, events []AuthorityEvent, intents []AuthorityIntent,
	errors []AuthorityError, mutationPermit *MutationAuthorityPermit) *AuthorityDecision {
	if events == nil {
		events = []AuthorityEvent{}
	}
	if intents == nil {
		intents = []AuthorityIntent{}
	}
	if errors == nil {
		errors = []AuthorityError{}
	}
	return &AuthorityDecision{
		State:          state,
		EventsToAppend: events,
		Intents:        intents,
		Errors:         errors,
		MutationPermit: mutationPermit,
		DecisionDigest: AuthorityDigest.Decision(state, events, intents, errors, mutationPermit),
	}
}
