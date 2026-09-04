// Package provider contains the regional, least-authority provider boundary.
// It intentionally has no dependency on control or an OCI SDK: SDKs are hidden
// behind small interfaces so that authorization remains deterministic and testable.
package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const (
	MaximumOperationEvidenceCount = 4096
	MaximumApprovalCount          = 64
	MaximumCompensationCount      = 64
	MaximumHandoffInventoryCount  = 4096
)

type InvalidOperationError struct{ Message string }

func (e *InvalidOperationError) Error() string { return e.Message }

type InvalidDataError struct{ Message string }

func (e *InvalidDataError) Error() string { return e.Message }

var tokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
var nativePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/=+@-]{0,255}$`)

func canonicalToken(value, param string) (string, error) {
	if len(value) < 1 || len(value) > 96 || !tokenPattern.MatchString(value) {
		return "", &errs.Argument{Param: param, Message: "provider identity must be a bounded canonical token"}
	}
	return value, nil
}
func nativeToken(value, param string) (string, error) {
	if len(value) < 1 || len(value) > 256 || !nativePattern.MatchString(value) {
		return "", &errs.Argument{Param: param, Message: "provider-native identity must be bounded and canonical"}
	}
	return value, nil
}

// Provider token types make accidental cross-resource identity use impossible.
type ProviderOperationId struct{ Value string }
type ProviderCellId struct{ Value string }
type ProviderCompartmentId struct{ Value string }
type ProviderResourceId struct{ Value string }
type ProviderCreateKey struct{ Value string }
type ProviderTemplateId struct{ Value string }
type ProviderPlacementId struct{ Value string }
type ProviderBackendId struct{ Value string }
type ProviderIdempotencyKey struct{ Value string }
type ProviderWorkRequestId struct{ Value string }

// Upper-case ID aliases ease integration with Go code that uses initialisms.
type ProviderOperationID = ProviderOperationId
type ProviderCellID = ProviderCellId
type ProviderCompartmentID = ProviderCompartmentId
type ProviderResourceID = ProviderResourceId
type ProviderCreateID = ProviderCreateKey
type ProviderTemplateID = ProviderTemplateId
type ProviderPlacementID = ProviderPlacementId
type ProviderBackendID = ProviderBackendId
type ProviderIdempotencyID = ProviderIdempotencyKey
type ProviderWorkRequestID = ProviderWorkRequestId

func newToken(dst *string, value, param string, native bool) error {
	var err error
	if native {
		value, err = nativeToken(value, param)
	} else {
		value, err = canonicalToken(value, param)
	}
	if err == nil {
		*dst = value
	}
	return err
}
func NewProviderOperationId(v string) (ProviderOperationId, error) {
	var x ProviderOperationId
	return x, newToken(&x.Value, v, "value", false)
}
func NewProviderCellId(v string) (ProviderCellId, error) {
	var x ProviderCellId
	return x, newToken(&x.Value, v, "value", false)
}
func NewProviderCompartmentId(v string) (ProviderCompartmentId, error) {
	var x ProviderCompartmentId
	return x, newToken(&x.Value, v, "value", true)
}
func NewProviderResourceId(v string) (ProviderResourceId, error) {
	var x ProviderResourceId
	return x, newToken(&x.Value, v, "value", true)
}
func NewProviderCreateKey(v string) (ProviderCreateKey, error) {
	var x ProviderCreateKey
	return x, newToken(&x.Value, v, "value", false)
}
func NewProviderTemplateId(v string) (ProviderTemplateId, error) {
	var x ProviderTemplateId
	return x, newToken(&x.Value, v, "value", false)
}
func NewProviderPlacementId(v string) (ProviderPlacementId, error) {
	var x ProviderPlacementId
	return x, newToken(&x.Value, v, "value", false)
}
func NewProviderBackendId(v string) (ProviderBackendId, error) {
	var x ProviderBackendId
	return x, newToken(&x.Value, v, "value", true)
}
func NewProviderIdempotencyKey(v string) (ProviderIdempotencyKey, error) {
	var x ProviderIdempotencyKey
	return x, newToken(&x.Value, v, "value", false)
}
func NewProviderWorkRequestId(v string) (ProviderWorkRequestId, error) {
	var x ProviderWorkRequestId
	return x, newToken(&x.Value, v, "value", true)
}
func NewProviderOperationID(v string) (ProviderOperationID, error) { return NewProviderOperationId(v) }
func NewProviderCellID(v string) (ProviderCellID, error)           { return NewProviderCellId(v) }
func NewProviderCompartmentID(v string) (ProviderCompartmentID, error) {
	return NewProviderCompartmentId(v)
}
func NewProviderResourceID(v string) (ProviderResourceID, error)   { return NewProviderResourceId(v) }
func NewProviderTemplateID(v string) (ProviderTemplateID, error)   { return NewProviderTemplateId(v) }
func NewProviderPlacementID(v string) (ProviderPlacementID, error) { return NewProviderPlacementId(v) }
func NewProviderBackendID(v string) (ProviderBackendID, error)     { return NewProviderBackendId(v) }
func NewProviderWorkRequestID(v string) (ProviderWorkRequestID, error) {
	return NewProviderWorkRequestId(v)
}

func (v ProviderOperationId) String() string    { return v.Value }
func (v ProviderCellId) String() string         { return v.Value }
func (v ProviderCompartmentId) String() string  { return v.Value }
func (v ProviderResourceId) String() string     { return v.Value }
func (v ProviderCreateKey) String() string      { return v.Value }
func (v ProviderTemplateId) String() string     { return v.Value }
func (v ProviderPlacementId) String() string    { return v.Value }
func (v ProviderBackendId) String() string      { return v.Value }
func (v ProviderIdempotencyKey) String() string { return v.Value }
func (v ProviderWorkRequestId) String() string  { return v.Value }

type ProviderGeneration struct{ Value uint64 }
type ProviderEpoch struct{ Value uint64 }
type ProviderByteCount struct{ Value uint64 }

func NewProviderGeneration(v uint64) (ProviderGeneration, error) {
	if v == 0 {
		return ProviderGeneration{}, &errs.ArgumentOutOfRangeError{Param: "value"}
	}
	return ProviderGeneration{v}, nil
}
func NewProviderEpoch(v uint64) (ProviderEpoch, error) {
	if v == 0 {
		return ProviderEpoch{}, &errs.ArgumentOutOfRangeError{Param: "value"}
	}
	return ProviderEpoch{v}, nil
}
func NewProviderByteCount(v uint64) (ProviderByteCount, error) {
	if v == 0 {
		return ProviderByteCount{}, &errs.ArgumentOutOfRangeError{Param: "value"}
	}
	return ProviderByteCount{v}, nil
}

type ProviderBootstrapEnvelopeDigest struct{ Sha256 string }

func NewProviderBootstrapEnvelopeDigest(value string) (ProviderBootstrapEnvelopeDigest, error) {
	if len(value) != 64 || strings.ToLower(value) != value {
		return ProviderBootstrapEnvelopeDigest{}, &errs.Argument{Param: "sha256", Message: "bootstrap envelope digest must be canonical SHA-256"}
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ProviderBootstrapEnvelopeDigest{}, &errs.Argument{Param: "sha256", Message: "bootstrap envelope digest must be canonical SHA-256"}
	}
	return ProviderBootstrapEnvelopeDigest{value}, nil
}

type ProviderResourceKind int

const (
	ResourceNode ProviderResourceKind = iota + 1
	ResourceVolume
	ResourceAttachment
	ResourceBackend
)

type ProviderAction int

const (
	ActionCreateNode ProviderAction = iota + 1
	ActionObserve
	ActionStartNode
	ActionStopNode
	ActionTerminateNode
	ActionCreateVolume
	ActionExpandVolume
	ActionChangeVolumePerformance
	ActionAttachVolume
	ActionDetachVolume
	ActionRegisterBackend
	ActionDeregisterBackend
)

type ProviderTerminalState int

const (
	TerminalPresent ProviderTerminalState = iota + 1
	TerminalRunning
	TerminalStopped
	TerminalTerminated
	TerminalExpanded
	TerminalPerformanceChanged
	TerminalAttached
	TerminalDetached
	TerminalRegistered
	TerminalDeregistered
)

type ProviderApproval int

const (
	ApprovalRegionalAuthority ProviderApproval = iota + 1
	ApprovalDestructiveMutation
	ApprovalStatefulController
	ApprovalCostBudget
	ApprovalSecurityReview
)

type ProviderCompensation int

const (
	CompensationObserveOnly ProviderCompensation = iota + 1
	CompensationStopCreatedNode
	CompensationTerminateCreatedNode
	CompensationDetachNewAttachment
	CompensationDeregisterNewBackend
)

type ProviderVolumePerformance int

const (
	PerformanceBalanced ProviderVolumePerformance = iota + 1
	PerformanceThroughput
	PerformanceIops
)

type DeadlineEvidenceStatus int

const (
	DeadlineValid DeadlineEvidenceStatus = iota + 1
	DeadlineExpired
	DeadlineUnknown
)

type ProviderObservedState int

const (
	ObservedAbsent ProviderObservedState = iota + 1
	ObservedPresent
	ObservedRunning
	ObservedStopped
	ObservedTerminated
)

type ProviderObservationCompleteness int

const (
	EvidenceComplete ProviderObservationCompleteness = iota + 1
	EvidenceIncomplete
)

type ProviderCallStatus int

const (
	CallNotCalled ProviderCallStatus = iota + 1
	CallAccepted
	CallResponseLost
	CallCompleted
)

// Alternate names keep call sites readable.
const (
	ProviderResourceKindNode                = ResourceNode
	ProviderResourceKindVolume              = ResourceVolume
	ProviderResourceKindAttachment          = ResourceAttachment
	ProviderResourceKindBackend             = ResourceBackend
	ProviderActionCreateNode                = ActionCreateNode
	ProviderActionObserve                   = ActionObserve
	ProviderActionStartNode                 = ActionStartNode
	ProviderActionStopNode                  = ActionStopNode
	ProviderActionTerminateNode             = ActionTerminateNode
	ProviderActionCreateVolume              = ActionCreateVolume
	ProviderActionExpandVolume              = ActionExpandVolume
	ProviderActionChangeVolumePerformance   = ActionChangeVolumePerformance
	ProviderActionAttachVolume              = ActionAttachVolume
	ProviderActionDetachVolume              = ActionDetachVolume
	ProviderActionRegisterBackend           = ActionRegisterBackend
	ProviderActionDeregisterBackend         = ActionDeregisterBackend
	ProviderTerminalStatePresent            = TerminalPresent
	ProviderTerminalStateRunning            = TerminalRunning
	ProviderTerminalStateStopped            = TerminalStopped
	ProviderTerminalStateTerminated         = TerminalTerminated
	ProviderTerminalStateExpanded           = TerminalExpanded
	ProviderTerminalStatePerformanceChanged = TerminalPerformanceChanged
	ProviderTerminalStateAttached           = TerminalAttached
	ProviderTerminalStateDetached           = TerminalDetached
	ProviderTerminalStateRegistered         = TerminalRegistered
	ProviderTerminalStateDeregistered       = TerminalDeregistered
	ProviderObservedStateAbsent             = ObservedAbsent
	ProviderObservedStatePresent            = ObservedPresent
	ProviderObservedStateRunning            = ObservedRunning
	ProviderObservedStateStopped            = ObservedStopped
	ProviderObservedStateTerminated         = ObservedTerminated
)

type DeadlineEvidence struct {
	Status             DeadlineEvidenceStatus
	EvidenceGeneration ProviderGeneration
}

type ProviderTarget interface {
	providerTarget()
	projection() string
}
type ExistingProviderResource struct{ Id ProviderResourceId }

func (ExistingProviderResource) providerTarget()      {}
func (v ExistingProviderResource) projection() string { return "resource:" + v.Id.Value }

type IdempotentProviderCreate struct{ Key ProviderCreateKey }

func (IdempotentProviderCreate) providerTarget()      {}
func (v IdempotentProviderCreate) projection() string { return "create:" + v.Key.Value }

type ProviderActionParameters interface {
	providerParameters()
	projection() string
}
type ObserveProviderParameters struct{}

func (ObserveProviderParameters) providerParameters() {}
func (ObserveProviderParameters) projection() string  { return "observe" }

type StartNodeProviderParameters struct{}

func (StartNodeProviderParameters) providerParameters() {}
func (StartNodeProviderParameters) projection() string  { return "start-node" }

type StopNodeProviderParameters struct{}

func (StopNodeProviderParameters) providerParameters() {}
func (StopNodeProviderParameters) projection() string  { return "stop-node" }

type TerminateNodeProviderParameters struct{}

func (TerminateNodeProviderParameters) providerParameters() {}
func (TerminateNodeProviderParameters) projection() string  { return "terminate-node" }

type DetachVolumeProviderParameters struct{}

func (DetachVolumeProviderParameters) providerParameters() {}
func (DetachVolumeProviderParameters) projection() string  { return "detach-volume" }

type CreateNodeProviderParameters struct {
	TemplateId              ProviderTemplateId
	PlacementId             ProviderPlacementId
	BootstrapEnvelopeDigest ProviderBootstrapEnvelopeDigest
}

func (CreateNodeProviderParameters) providerParameters() {}
func (v CreateNodeProviderParameters) projection() string {
	return "create-node|" + v.TemplateId.Value + "|" + v.PlacementId.Value + "|" + v.BootstrapEnvelopeDigest.Sha256
}

type CreateVolumeProviderParameters struct {
	Size        ProviderByteCount
	Performance ProviderVolumePerformance
}

func (CreateVolumeProviderParameters) providerParameters() {}
func (v CreateVolumeProviderParameters) projection() string {
	return "create-volume|" + strconv.FormatUint(v.Size.Value, 10) + "|" + strconv.Itoa(int(v.Performance))
}

type ExpandVolumeProviderParameters struct{ NewSize ProviderByteCount }

func (ExpandVolumeProviderParameters) providerParameters() {}
func (v ExpandVolumeProviderParameters) projection() string {
	return "expand-volume|" + strconv.FormatUint(v.NewSize.Value, 10)
}

type ChangeVolumePerformanceProviderParameters struct{ Performance ProviderVolumePerformance }

func (ChangeVolumePerformanceProviderParameters) providerParameters() {}
func (v ChangeVolumePerformanceProviderParameters) projection() string {
	return "change-volume-performance|" + strconv.Itoa(int(v.Performance))
}

type AttachVolumeProviderParameters struct{ VolumeId, NodeId ProviderResourceId }

func (AttachVolumeProviderParameters) providerParameters() {}
func (v AttachVolumeProviderParameters) projection() string {
	return "attach-volume|" + v.VolumeId.Value + "|" + v.NodeId.Value
}

type RegisterBackendProviderParameters struct{ BackendId ProviderBackendId }

func (RegisterBackendProviderParameters) providerParameters() {}
func (v RegisterBackendProviderParameters) projection() string {
	return "register-backend|" + v.BackendId.Value
}

type DeregisterBackendProviderParameters struct{ BackendId ProviderBackendId }

func (DeregisterBackendProviderParameters) providerParameters() {}
func (v DeregisterBackendProviderParameters) projection() string {
	return "deregister-backend|" + v.BackendId.Value
}

type ProviderOperationContext struct {
	OperationId            ProviderOperationId
	CellId                 ProviderCellId
	CompartmentId          ProviderCompartmentId
	ControllerEpoch        ProviderEpoch
	ResourceKind           ProviderResourceKind
	Action                 ProviderAction
	Target                 ProviderTarget
	ExpectedGeneration     ProviderGeneration
	ExpectedObservedState  ProviderObservedState
	DesiredTerminalState   ProviderTerminalState
	Approvals              []ProviderApproval
	DeadlineEvidence       DeadlineEvidence
	IdempotencyKey         ProviderIdempotencyKey
	PermittedCompensations []ProviderCompensation
	ActionParameters       ProviderActionParameters
}

func (c ProviderOperationContext) fingerprint() string {
	if c.Target == nil || c.ActionParameters == nil {
		return ""
	}
	var a, b []string
	for _, v := range c.Approvals {
		a = append(a, strconv.Itoa(int(v)))
	}
	for _, v := range c.PermittedCompensations {
		b = append(b, strconv.Itoa(int(v)))
	}
	return strings.Join([]string{c.OperationId.Value, c.CellId.Value, c.CompartmentId.Value, strconv.FormatUint(c.ControllerEpoch.Value, 10), strconv.Itoa(int(c.ResourceKind)), strconv.Itoa(int(c.Action)), c.Target.projection(), strconv.FormatUint(c.ExpectedGeneration.Value, 10), strconv.Itoa(int(c.ExpectedObservedState)), strconv.Itoa(int(c.DesiredTerminalState)), strings.Join(a, ","), strconv.Itoa(int(c.DeadlineEvidence.Status)), strconv.FormatUint(c.DeadlineEvidence.EvidenceGeneration.Value, 10), c.IdempotencyKey.Value, strings.Join(b, ","), c.ActionParameters.projection()}, "|")
}
func (c ProviderOperationContext) Fingerprint() string { return c.fingerprint() }

type RegionalProviderAuthority struct {
	CellId        ProviderCellId
	CompartmentId ProviderCompartmentId
	CurrentEpoch  ProviderEpoch
}
type ProviderOwnershipRecord struct {
	ResourceId    ProviderResourceId
	CellId        ProviderCellId
	CompartmentId ProviderCompartmentId
	Generation    ProviderGeneration
}
type ProviderInventoryTagEvidence struct {
	ResourceId    ProviderResourceId
	CellId        ProviderCellId
	CompartmentId ProviderCompartmentId
	OperationId   ProviderOperationId
	Generation    ProviderGeneration
}
type ProviderResourceObservation struct {
	ResourceId ProviderResourceId
	Generation ProviderGeneration
	State      ProviderObservedState
}
type ProviderCreateObservation struct {
	CreateKey          ProviderCreateKey
	CellId             ProviderCellId
	CompartmentId      ProviderCompartmentId
	Generation         ProviderGeneration
	State              ProviderObservedState
	ResolvedResourceId *ProviderResourceId
}
type ProviderCallEvidence struct {
	Context       ProviderOperationContext
	Status        ProviderCallStatus
	WorkRequestId *ProviderWorkRequestId
}
type DurableProviderAuthorization struct {
	fingerprint  string
	OperationId  ProviderOperationId
	Terminal     ProviderTerminalState
	Irreversible bool
}

func (d DurableProviderAuthorization) Fingerprint() string { return d.fingerprint }

type ProviderAuthorizationRequest struct {
	Context                 ProviderOperationContext
	Authority               *RegionalProviderAuthority
	OwnershipRecords        []ProviderOwnershipRecord
	Tags                    []ProviderInventoryTagEvidence
	ObservationCompleteness ProviderObservationCompleteness
	Observations            []ProviderResourceObservation
	CreateObservations      []ProviderCreateObservation
	RequiredApprovals       []ProviderApproval
	PriorAuthorization      *DurableProviderAuthorization
	CallEvidence            ProviderCallEvidence
}

type ProviderDecisionCode int

const (
	DecisionEvidenceComplete ProviderDecisionCode = iota + 1
	DecisionEvidenceUnique
	DecisionEvidenceConsistent
	DecisionAuthorityPresent
	DecisionScopeMatches
	DecisionEpochCurrentOrDurablyResumable
	DecisionOwnershipMatches
	DecisionGenerationMatches
	DecisionDeadlineValid
	DecisionApprovalsComplete
	DecisionPriorAuthorizationCompatible
	DecisionActionResourceCompatible
	DecisionTagsConsistent
	DecisionTagsNotAuthority
	DecisionHandoffInventoryUnique
	DecisionHandoffInventoryExact
	DecisionHandoffScopeMatches
	DecisionHandoffRetainUnmanage
	DecisionHandoffJournalReceipt
	DecisionHandoffProviderReady
	DecisionHandoffTrustReady
	DecisionHandoffBackupReady
	DecisionHandoffFenceActivated
	DecisionCallEvidenceMatches
	DecisionHandoffGenerationNotRollback
)

type ProviderDecisionOutcome int

const (
	DecisionPassed ProviderDecisionOutcome = iota + 1
	DecisionRejected
	DecisionHeld
	DecisionNotApplicable
)

type ProviderDecisionReason struct {
	Code               ProviderDecisionCode
	Outcome            ProviderDecisionOutcome
	Observed, Required uint64
}

type ProviderIntent interface {
	intent()
	ContextValue() ProviderOperationContext
}
type intentBase struct{ Context ProviderOperationContext }

func (i intentBase) ContextValue() ProviderOperationContext { return i.Context }

type ObserveProviderResourceIntent struct{ intentBase }

func (ObserveProviderResourceIntent) intent() {}

type ObserveResolvedProviderCreateIntent struct {
	intentBase
	CreateKey          ProviderCreateKey
	CellId             ProviderCellId
	CompartmentId      ProviderCompartmentId
	ResolvedResourceId ProviderResourceId
}

func (ObserveResolvedProviderCreateIntent) intent() {}

type ReadProviderWorkRequestIntent struct {
	intentBase
	WorkRequestId ProviderWorkRequestId
}

func (ReadProviderWorkRequestIntent) intent() {}

type CreateNodeProviderIntent struct {
	intentBase
	Parameters CreateNodeProviderParameters
}

func (CreateNodeProviderIntent) intent() {}

type StartNodeProviderIntent struct {
	intentBase
	Parameters StartNodeProviderParameters
}

func (StartNodeProviderIntent) intent() {}

type StopNodeProviderIntent struct {
	intentBase
	Parameters StopNodeProviderParameters
}

func (StopNodeProviderIntent) intent() {}

type TerminateNodeProviderIntent struct {
	intentBase
	Parameters TerminateNodeProviderParameters
}

func (TerminateNodeProviderIntent) intent() {}

type CreateVolumeProviderIntent struct {
	intentBase
	Parameters CreateVolumeProviderParameters
}

func (CreateVolumeProviderIntent) intent() {}

type ExpandVolumeProviderIntent struct {
	intentBase
	Parameters ExpandVolumeProviderParameters
}

func (ExpandVolumeProviderIntent) intent() {}

type ChangeVolumePerformanceProviderIntent struct {
	intentBase
	Parameters ChangeVolumePerformanceProviderParameters
}

func (ChangeVolumePerformanceProviderIntent) intent() {}

type AttachVolumeProviderIntent struct {
	intentBase
	Parameters AttachVolumeProviderParameters
}

func (AttachVolumeProviderIntent) intent() {}

type DetachVolumeProviderIntent struct {
	intentBase
	Parameters DetachVolumeProviderParameters
}

func (DetachVolumeProviderIntent) intent() {}

type RegisterBackendProviderIntent struct {
	intentBase
	Parameters RegisterBackendProviderParameters
}

func (RegisterBackendProviderIntent) intent() {}

type DeregisterBackendProviderIntent struct {
	intentBase
	Parameters DeregisterBackendProviderParameters
}

func (DeregisterBackendProviderIntent) intent() {}

type ProviderAuthorizationDecision struct {
	Authorized bool
	Trace      []ProviderDecisionReason
	Intents    []ProviderIntent
	accepted   *ProviderOperationContext
}

func (d ProviderAuthorizationDecision) CaptureDurableAuthorization() (DurableProviderAuthorization, error) {
	if !d.Authorized || d.accepted == nil {
		return DurableProviderAuthorization{}, &InvalidOperationError{Message: "only an exact provider-accepted operation may be captured durably"}
	}
	return DurableProviderAuthorization{fingerprint: d.accepted.fingerprint(), OperationId: d.accepted.OperationId, Terminal: d.accepted.DesiredTerminalState, Irreversible: true}, nil
}

type HandoffInventoryItem struct {
	ResourceId ProviderResourceId
	Kind       ProviderResourceKind
	Generation ProviderGeneration
}
type HandoffInventoryFingerprint struct{ Value string }
type FreshBootstrapInventory struct{ Expected, Pulumi, Regional []HandoffInventoryItem }
type HandoffScope struct {
	CellId               ProviderCellId
	CompartmentId        ProviderCompartmentId
	BootstrapGeneration  ProviderGeneration
	OperationId          ProviderOperationId
	InventoryFingerprint HandoffInventoryFingerprint
}
type HandoffEvidenceStatus int

const (
	HandoffVerified HandoffEvidenceStatus = iota + 1
	HandoffMissing
	HandoffConflicting
)

type HandoffProof struct {
	Scope  HandoffScope
	Status HandoffEvidenceStatus
}
type HandoffEvidence struct{ RetainUnmanage, RegionalJournalReceipt, ProviderReady, TrustReady, BackupReady, RegionalFenceActivated HandoffProof }
type HandoffRequest struct {
	Inventory                          FreshBootstrapInventory
	ExpectedScope                      HandoffScope
	CurrentAcceptedBootstrapGeneration ProviderGeneration
	Evidence                           HandoffEvidence
}
type EnableRegionalSelfManagementIntent struct {
	Inventory                          FreshBootstrapInventory
	Scope                              HandoffScope
	CurrentAcceptedBootstrapGeneration ProviderGeneration
}
type HandoffDecision struct {
	Ready  bool
	Trace  []ProviderDecisionReason
	Intent *EnableRegionalSelfManagementIntent
}

func digestProjection(items []HandoffInventoryItem) string {
	cp := append([]HandoffInventoryItem(nil), items...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].ResourceId.Value != cp[j].ResourceId.Value {
			return cp[i].ResourceId.Value < cp[j].ResourceId.Value
		}
		if cp[i].Kind != cp[j].Kind {
			return cp[i].Kind < cp[j].Kind
		}
		return cp[i].Generation.Value < cp[j].Generation.Value
	})
	var b strings.Builder
	for _, x := range cp {
		fmt.Fprintf(&b, "%s|%d|%d;", x.ResourceId.Value, x.Kind, x.Generation.Value)
	}
	s := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(s[:])
}
func newFingerprint(items []HandoffInventoryItem) HandoffInventoryFingerprint {
	return HandoffInventoryFingerprint{digestProjection(items)}
}
func (s HandoffScope) Fingerprint() string { return s.InventoryFingerprint.Value }
