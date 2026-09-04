package provider

import (
	"sort"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func definedResourceKind(v ProviderResourceKind) bool {
	return v >= ResourceNode && v <= ResourceBackend
}
func definedAction(v ProviderAction) bool {
	return v >= ActionCreateNode && v <= ActionDeregisterBackend
}
func definedTerminal(v ProviderTerminalState) bool {
	return v >= TerminalPresent && v <= TerminalDeregistered
}
func definedObserved(v ProviderObservedState) bool {
	return v >= ObservedAbsent && v <= ObservedTerminated
}
func definedPerformance(v ProviderVolumePerformance) bool {
	return v >= PerformanceBalanced && v <= PerformanceIops
}
func definedCallStatus(v ProviderCallStatus) bool {
	return v >= CallNotCalled && v <= CallCompleted
}
func copyApprovals(in []ProviderApproval) ([]ProviderApproval, error) {
	if len(in) > MaximumApprovalCount {
		return nil, &errs.Argument{Param: "approvals", Message: "provider approval input exceeds its bound"}
	}
	out := append([]ProviderApproval(nil), in...)
	seen := map[ProviderApproval]bool{}
	for _, v := range out {
		if v < ApprovalRegionalAuthority || v > ApprovalSecurityReview || seen[v] {
			return nil, &errs.Argument{Param: "approvals", Message: "provider approvals must be defined and unique"}
		}
		seen[v] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
func copyCompensations(in []ProviderCompensation) ([]ProviderCompensation, error) {
	if len(in) > MaximumCompensationCount {
		return nil, &errs.Argument{Param: "permittedCompensations", Message: "provider compensation input exceeds its bound"}
	}
	out := append([]ProviderCompensation(nil), in...)
	seen := map[ProviderCompensation]bool{}
	for _, v := range out {
		if v < CompensationObserveOnly || v > CompensationDeregisterNewBackend || seen[v] {
			return nil, &errs.Argument{Param: "permittedCompensations", Message: "provider compensations must be defined and unique"}
		}
		seen[v] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func NewProviderOperationContext(operationID ProviderOperationId, cellID ProviderCellId, compartmentID ProviderCompartmentId, epoch ProviderEpoch, kind ProviderResourceKind, action ProviderAction, target ProviderTarget, generation ProviderGeneration, observed ProviderObservedState, terminal ProviderTerminalState, approvals []ProviderApproval, deadline DeadlineEvidence, idempotency ProviderIdempotencyKey, compensations []ProviderCompensation, params ProviderActionParameters) (ProviderOperationContext, error) {
	if _, err := canonicalToken(operationID.Value, "operationId"); err != nil {
		return ProviderOperationContext{}, err
	}
	if _, err := canonicalToken(cellID.Value, "cellId"); err != nil {
		return ProviderOperationContext{}, err
	}
	if _, err := nativeToken(compartmentID.Value, "compartmentId"); err != nil {
		return ProviderOperationContext{}, err
	}
	if _, err := canonicalToken(idempotency.Value, "idempotencyKey"); err != nil {
		return ProviderOperationContext{}, err
	}
	if operationID.Value == "" || cellID.Value == "" || compartmentID.Value == "" || epoch.Value == 0 || generation.Value == 0 || idempotency.Value == "" || target == nil || params == nil {
		return ProviderOperationContext{}, &errs.Argument{Message: "provider operation context is incomplete"}
	}
	if !definedResourceKind(kind) || !definedAction(action) || !definedObserved(observed) || !definedTerminal(terminal) || deadline.EvidenceGeneration.Value == 0 {
		return ProviderOperationContext{}, &errs.ArgumentOutOfRangeError{Param: "context"}
	}
	if err := validateProviderParameters(params); err != nil {
		return ProviderOperationContext{}, err
	}
	a, err := copyApprovals(approvals)
	if err != nil {
		return ProviderOperationContext{}, err
	}
	c, err := copyCompensations(compensations)
	if err != nil {
		return ProviderOperationContext{}, err
	}
	isCreate := action == ActionCreateNode || action == ActionCreateVolume
	switch t := target.(type) {
	case ExistingProviderResource:
		if _, err := nativeToken(t.Id.Value, "resourceId"); err != nil {
			return ProviderOperationContext{}, err
		}
	case IdempotentProviderCreate:
		if _, err := canonicalToken(t.Key.Value, "createKey"); err != nil {
			return ProviderOperationContext{}, err
		}
	}
	if isCreate {
		if _, ok := target.(IdempotentProviderCreate); !ok {
			return ProviderOperationContext{}, &errs.Argument{Message: "create actions require a create key"}
		}
	} else if _, ok := target.(ExistingProviderResource); !ok {
		return ProviderOperationContext{}, &errs.Argument{Message: "non-create actions require an existing resource target"}
	}
	return ProviderOperationContext{operationID, cellID, compartmentID, epoch, kind, action, target, generation, observed, terminal, a, deadline, idempotency, c, params}, nil
}

func validateProviderParameters(params ProviderActionParameters) error {
	switch p := params.(type) {
	case CreateNodeProviderParameters:
		if _, err := canonicalToken(p.TemplateId.Value, "templateId"); err != nil {
			return err
		}
		if _, err := canonicalToken(p.PlacementId.Value, "placementId"); err != nil {
			return err
		}
		if _, err := NewProviderBootstrapEnvelopeDigest(p.BootstrapEnvelopeDigest.Sha256); err != nil {
			return err
		}
	case CreateVolumeProviderParameters:
		if p.Size.Value == 0 || !definedPerformance(p.Performance) {
			return &errs.ArgumentOutOfRangeError{Param: "createVolumeParameters"}
		}
	case ExpandVolumeProviderParameters:
		if p.NewSize.Value == 0 {
			return &errs.ArgumentOutOfRangeError{Param: "newSize"}
		}
	case ChangeVolumePerformanceProviderParameters:
		if !definedPerformance(p.Performance) {
			return &errs.ArgumentOutOfRangeError{Param: "performance"}
		}
	case AttachVolumeProviderParameters:
		if _, err := nativeToken(p.VolumeId.Value, "volumeId"); err != nil {
			return err
		}
		if _, err := nativeToken(p.NodeId.Value, "nodeId"); err != nil {
			return err
		}
	case RegisterBackendProviderParameters:
		if _, err := nativeToken(p.BackendId.Value, "backendId"); err != nil {
			return err
		}
	case DeregisterBackendProviderParameters:
		if _, err := nativeToken(p.BackendId.Value, "backendId"); err != nil {
			return err
		}
	case ObserveProviderParameters, StartNodeProviderParameters, StopNodeProviderParameters, TerminateNodeProviderParameters, DetachVolumeProviderParameters:
	default:
		return &errs.Argument{Message: "unsupported provider action parameters"}
	}
	return nil
}

func NewDeadlineEvidence(status DeadlineEvidenceStatus, generation ProviderGeneration) (DeadlineEvidence, error) {
	if status < DeadlineValid || status > DeadlineUnknown || generation.Value == 0 {
		return DeadlineEvidence{}, &errs.ArgumentOutOfRangeError{Param: "deadline"}
	}
	return DeadlineEvidence{status, generation}, nil
}

func snapshot[T any](in []T, max int, param string) ([]T, error) {
	if len(in) > max {
		return nil, &errs.Argument{Param: param, Message: "provider evidence input exceeds its bound"}
	}
	return append([]T(nil), in...), nil
}
func NewProviderAuthorizationRequest(context ProviderOperationContext, authority *RegionalProviderAuthority, ownership []ProviderOwnershipRecord, tags []ProviderInventoryTagEvidence, completeness ProviderObservationCompleteness, observations []ProviderResourceObservation, creates []ProviderCreateObservation, required []ProviderApproval, prior *DurableProviderAuthorization, call ProviderCallEvidence) (ProviderAuthorizationRequest, error) {
	if completeness != EvidenceComplete && completeness != EvidenceIncomplete {
		return ProviderAuthorizationRequest{}, &errs.ArgumentOutOfRangeError{Param: "observationCompleteness"}
	}
	o, err := snapshot(ownership, MaximumOperationEvidenceCount, "ownershipRecords")
	if err != nil {
		return ProviderAuthorizationRequest{}, err
	}
	t, err := snapshot(tags, MaximumOperationEvidenceCount, "tags")
	if err != nil {
		return ProviderAuthorizationRequest{}, err
	}
	r, err := snapshot(observations, MaximumOperationEvidenceCount, "observations")
	if err != nil {
		return ProviderAuthorizationRequest{}, err
	}
	c, err := snapshot(creates, MaximumOperationEvidenceCount, "createObservations")
	if err != nil {
		return ProviderAuthorizationRequest{}, err
	}
	a, err := copyApprovals(required)
	if err != nil {
		return ProviderAuthorizationRequest{}, err
	}
	return ProviderAuthorizationRequest{context, authority, o, t, completeness, r, c, a, prior, call}, nil
}

func NewDurableProviderAuthorization(context ProviderOperationContext, irreversible bool) DurableProviderAuthorization {
	return DurableProviderAuthorization{fingerprint: context.fingerprint(), OperationId: context.OperationId, Terminal: context.DesiredTerminalState, Irreversible: irreversible}
}

func compatible(c ProviderOperationContext) bool {
	switch {
	case c.Action == ActionCreateNode && c.ResourceKind == ResourceNode && c.DesiredTerminalState == TerminalPresent:
		_, ok := c.ActionParameters.(CreateNodeProviderParameters)
		return ok
	case c.Action == ActionStartNode && c.ResourceKind == ResourceNode && c.DesiredTerminalState == TerminalRunning:
		_, ok := c.ActionParameters.(StartNodeProviderParameters)
		return ok
	case c.Action == ActionStopNode && c.ResourceKind == ResourceNode && c.DesiredTerminalState == TerminalStopped:
		_, ok := c.ActionParameters.(StopNodeProviderParameters)
		return ok
	case c.Action == ActionTerminateNode && c.ResourceKind == ResourceNode && c.DesiredTerminalState == TerminalTerminated:
		_, ok := c.ActionParameters.(TerminateNodeProviderParameters)
		return ok
	case c.Action == ActionObserve && c.DesiredTerminalState >= TerminalPresent && c.DesiredTerminalState <= TerminalDeregistered:
		_, ok := c.ActionParameters.(ObserveProviderParameters)
		return ok
	case c.Action == ActionCreateVolume && c.ResourceKind == ResourceVolume && c.DesiredTerminalState == TerminalPresent:
		_, ok := c.ActionParameters.(CreateVolumeProviderParameters)
		return ok
	case c.Action == ActionExpandVolume && c.ResourceKind == ResourceVolume && c.DesiredTerminalState == TerminalExpanded:
		_, ok := c.ActionParameters.(ExpandVolumeProviderParameters)
		return ok
	case c.Action == ActionChangeVolumePerformance && c.ResourceKind == ResourceVolume && c.DesiredTerminalState == TerminalPerformanceChanged:
		_, ok := c.ActionParameters.(ChangeVolumePerformanceProviderParameters)
		return ok
	case c.Action == ActionAttachVolume && c.ResourceKind == ResourceAttachment && c.DesiredTerminalState == TerminalAttached:
		_, ok := c.ActionParameters.(AttachVolumeProviderParameters)
		return ok
	case c.Action == ActionDetachVolume && c.ResourceKind == ResourceAttachment && c.DesiredTerminalState == TerminalDetached:
		_, ok := c.ActionParameters.(DetachVolumeProviderParameters)
		return ok
	case c.Action == ActionRegisterBackend && c.ResourceKind == ResourceBackend && c.DesiredTerminalState == TerminalRegistered:
		_, ok := c.ActionParameters.(RegisterBackendProviderParameters)
		return ok
	case c.Action == ActionDeregisterBackend && c.ResourceKind == ResourceBackend && c.DesiredTerminalState == TerminalDeregistered:
		_, ok := c.ActionParameters.(DeregisterBackendProviderParameters)
		return ok
	}
	return false
}
func groupsDuplicate[T any, K comparable](items []T, key func(T) K) (int, map[K][]T) {
	m := map[K][]T{}
	for _, x := range items {
		k := key(x)
		m[k] = append(m[k], x)
	}
	n := 0
	for _, v := range m {
		if len(v) > 1 {
			n += len(v) - 1
		}
	}
	return n, m
}
func authReason(code ProviderDecisionCode, outcome ProviderDecisionOutcome, observed, required uint64) ProviderDecisionReason {
	return ProviderDecisionReason{code, outcome, observed, required}
}
func passReject(code ProviderDecisionCode, ok bool, held bool, observed, required uint64) ProviderDecisionReason {
	if ok {
		return authReason(code, DecisionPassed, observed, required)
	}
	if held {
		return authReason(code, DecisionHeld, observed, required)
	}
	return authReason(code, DecisionRejected, observed, required)
}

// Authorize performs all checks before producing a typed actuator intent. Any
// ambiguous evidence is held and can never produce a mutation intent.
func Authorize(request ProviderAuthorizationRequest) ProviderAuthorizationDecision {
	c := request.Context
	// ProviderAuthorizationRequest is intentionally a value type and callers
	// can bypass the constructors with a struct literal.  Treat the evaluator
	// as a trust boundary too: no malformed context may reach nextIntent and
	// become an external mutation.
	if !validProviderOperationContext(c) || !validProviderEvidence(request) {
		return ProviderAuthorizationDecision{Trace: []ProviderDecisionReason{
			authReason(DecisionActionResourceCompatible, DecisionRejected, 0, 1),
		}}
	}
	_, og := groupsDuplicate(request.OwnershipRecords, func(x ProviderOwnershipRecord) string { return x.ResourceId.Value })
	_, rg := groupsDuplicate(request.Observations, func(x ProviderResourceObservation) string { return x.ResourceId.Value })
	_, cg := groupsDuplicate(request.CreateObservations, func(x ProviderCreateObservation) string { return x.CreateKey.Value })
	_, tg := groupsDuplicate(request.Tags, func(x ProviderInventoryTagEvidence) string { return x.ResourceId.Value })
	dup := 0
	for _, items := range [][]int{{len(request.OwnershipRecords), len(og)}, {len(request.Observations), len(rg)}, {len(request.CreateObservations), len(cg)}, {len(request.Tags), len(tg)}} {
		dup += items[0] - items[1]
	}
	conflicts := 0
	for _, v := range og {
		if len(v) > 1 {
			for _, x := range v[1:] {
				if x.CellId != v[0].CellId || x.CompartmentId != v[0].CompartmentId || x.Generation != v[0].Generation {
					conflicts++
					break
				}
			}
		}
	}
	for _, v := range rg {
		if len(v) > 1 {
			for _, x := range v[1:] {
				if x.Generation != v[0].Generation || x.State != v[0].State {
					conflicts++
					break
				}
			}
		}
	}
	for _, v := range cg {
		if len(v) > 1 {
			for _, x := range v[1:] {
				if x.CellId != v[0].CellId || x.CompartmentId != v[0].CompartmentId || x.Generation != v[0].Generation || x.State != v[0].State || idPtr(x.ResolvedResourceId) != idPtr(v[0].ResolvedResourceId) {
					conflicts++
					break
				}
			}
		}
	}
	for _, v := range tg {
		if len(v) > 1 {
			for _, x := range v[1:] {
				if x.CellId != v[0].CellId || x.CompartmentId != v[0].CompartmentId || x.OperationId != v[0].OperationId || x.Generation != v[0].Generation {
					conflicts++
					break
				}
			}
		}
	}
	trace := []ProviderDecisionReason{passReject(DecisionEvidenceComplete, request.ObservationCompleteness == EvidenceComplete, true, boolToU(request.ObservationCompleteness == EvidenceComplete), 1), passReject(DecisionEvidenceUnique, dup == 0, true, uint64(dup), 0), passReject(DecisionEvidenceConsistent, conflicts == 0, true, uint64(conflicts), 0), passReject(DecisionAuthorityPresent, request.Authority != nil, true, boolToU(request.Authority != nil), 1)}
	for _, r := range trace {
		if r.Outcome == DecisionHeld {
			return ProviderAuthorizationDecision{Trace: append(trace, heldTail()...)}
		}
	}
	if request.Authority == nil {
		return ProviderAuthorizationDecision{Trace: trace}
	}
	a := request.Authority
	scope := a.CellId == c.CellId && a.CompartmentId == c.CompartmentId
	priorExact := request.PriorAuthorization != nil && request.PriorAuthorization.fingerprint == c.fingerprint()
	durable := priorExact && request.PriorAuthorization.Irreversible && c.ControllerEpoch.Value < a.CurrentEpoch.Value
	epoch := c.ControllerEpoch.Value == a.CurrentEpoch.Value || durable
	trace = append(trace, passReject(DecisionScopeMatches, scope, false, boolToU(scope), 1), passReject(DecisionEpochCurrentOrDurablyResumable, epoch, false, c.ControllerEpoch.Value, a.CurrentEpoch.Value))
	ownership, generation := true, true
	if target, ok := c.Target.(ExistingProviderResource); ok {
		rec := singleOwnership(og[target.Id.Value])
		obs := singleObservation(rg[target.Id.Value])
		ownership = rec != nil && rec.CellId == c.CellId && rec.CompartmentId == c.CompartmentId
		generation = rec != nil && obs != nil && rec.Generation == c.ExpectedGeneration && obs.Generation == c.ExpectedGeneration && obs.State == c.ExpectedObservedState
	} else if target, ok := c.Target.(IdempotentProviderCreate); ok {
		obs := singleCreate(cg[target.Key.Value])
		ownership = len(request.OwnershipRecords) == 0
		generation = obs != nil && obs.CellId == c.CellId && obs.CompartmentId == c.CompartmentId && obs.Generation == c.ExpectedGeneration && obs.State == c.ExpectedObservedState
	}
	trace = append(trace, passReject(DecisionOwnershipMatches, ownership, false, boolToU(ownership), 1), passReject(DecisionGenerationMatches, generation, false, boolToU(generation)*c.ExpectedGeneration.Value, c.ExpectedGeneration.Value))
	deadline := request.Context.DeadlineEvidence.Status
	trace = append(trace, map[DeadlineEvidenceStatus]ProviderDecisionReason{DeadlineValid: authReason(DecisionDeadlineValid, DecisionPassed, 1, 1), DeadlineExpired: authReason(DecisionDeadlineValid, DecisionRejected, 0, 1), DeadlineUnknown: authReason(DecisionDeadlineValid, DecisionHeld, 0, 1)}[deadline])
	approved := true
	count := 0
	for _, need := range request.RequiredApprovals {
		for _, have := range c.Approvals {
			if need == have {
				count++
				break
			}
		}
		if !containsApproval(c.Approvals, need) {
			approved = false
		}
	}
	callMatch := providerCallEvidenceMatches(request.CallEvidence, c)
	priorOK := request.PriorAuthorization == nil || priorExact
	tagsOK := tagsConsistent(request, tg)
	trace = append(trace, passReject(DecisionApprovalsComplete, approved, false, uint64(count), uint64(len(request.RequiredApprovals))), passReject(DecisionCallEvidenceMatches, callMatch, false, boolToU(callMatch), 1), passReject(DecisionPriorAuthorizationCompatible, priorOK, false, boolToU(priorOK), 1), passReject(DecisionActionResourceCompatible, compatible(c), false, boolToU(compatible(c)), 1), passReject(DecisionTagsConsistent, tagsOK, false, boolToU(tagsOK), 1), authReason(DecisionTagsNotAuthority, DecisionNotApplicable, uint64(len(request.Tags)), 0))
	for _, r := range trace {
		if r.Outcome == DecisionRejected || r.Outcome == DecisionHeld {
			return ProviderAuthorizationDecision{Trace: trace}
		}
	}
	intent := nextIntent(request, cg)
	var accepted *ProviderOperationContext
	if c.Action != ActionObserve && (request.CallEvidence.Status == CallAccepted || request.CallEvidence.Status == CallResponseLost || request.CallEvidence.Status == CallCompleted) {
		accepted = &c
	}
	return ProviderAuthorizationDecision{Authorized: true, Trace: trace, Intents: []ProviderIntent{intent}, accepted: accepted}
}

func validProviderOperationContext(c ProviderOperationContext) bool {
	if _, err := canonicalToken(c.OperationId.Value, "operationId"); err != nil {
		return false
	}
	if _, err := canonicalToken(c.CellId.Value, "cellId"); err != nil {
		return false
	}
	if _, err := nativeToken(c.CompartmentId.Value, "compartmentId"); err != nil {
		return false
	}
	if _, err := canonicalToken(c.IdempotencyKey.Value, "idempotencyKey"); err != nil {
		return false
	}
	if c.ControllerEpoch.Value == 0 || c.ExpectedGeneration.Value == 0 ||
		!definedResourceKind(c.ResourceKind) || !definedAction(c.Action) ||
		!definedObserved(c.ExpectedObservedState) || !definedTerminal(c.DesiredTerminalState) ||
		c.DeadlineEvidence.Status < DeadlineValid || c.DeadlineEvidence.Status > DeadlineUnknown ||
		c.DeadlineEvidence.EvidenceGeneration.Value == 0 || c.Target == nil || c.ActionParameters == nil {
		return false
	}
	if _, err := copyApprovals(c.Approvals); err != nil {
		return false
	}
	if _, err := copyCompensations(c.PermittedCompensations); err != nil {
		return false
	}
	if err := validateProviderParameters(c.ActionParameters); err != nil {
		return false
	}
	switch target := c.Target.(type) {
	case ExistingProviderResource:
		if _, err := nativeToken(target.Id.Value, "resourceId"); err != nil {
			return false
		}
	case IdempotentProviderCreate:
		if _, err := canonicalToken(target.Key.Value, "createKey"); err != nil {
			return false
		}
	default:
		return false
	}
	isCreate := c.Action == ActionCreateNode || c.Action == ActionCreateVolume
	if isCreate {
		if _, ok := c.Target.(IdempotentProviderCreate); !ok {
			return false
		}
	} else if _, ok := c.Target.(ExistingProviderResource); !ok {
		return false
	}
	return compatible(c)
}

func validProviderEvidence(request ProviderAuthorizationRequest) bool {
	for _, record := range request.OwnershipRecords {
		if _, err := nativeToken(record.ResourceId.Value, "resourceId"); err != nil {
			return false
		}
		if _, err := canonicalToken(record.CellId.Value, "cellId"); err != nil {
			return false
		}
		if _, err := nativeToken(record.CompartmentId.Value, "compartmentId"); err != nil || record.Generation.Value == 0 {
			return false
		}
	}
	for _, observation := range request.Observations {
		if _, err := nativeToken(observation.ResourceId.Value, "resourceId"); err != nil || observation.Generation.Value == 0 || !definedObserved(observation.State) {
			return false
		}
	}
	for _, observation := range request.CreateObservations {
		if _, err := canonicalToken(observation.CreateKey.Value, "createKey"); err != nil {
			return false
		}
		if _, err := canonicalToken(observation.CellId.Value, "cellId"); err != nil {
			return false
		}
		if _, err := nativeToken(observation.CompartmentId.Value, "compartmentId"); err != nil || observation.Generation.Value == 0 || !definedObserved(observation.State) {
			return false
		}
		if observation.ResolvedResourceId != nil {
			if _, err := nativeToken(observation.ResolvedResourceId.Value, "resourceId"); err != nil {
				return false
			}
		}
	}
	for _, tag := range request.Tags {
		if _, err := nativeToken(tag.ResourceId.Value, "resourceId"); err != nil {
			return false
		}
		if _, err := canonicalToken(tag.CellId.Value, "cellId"); err != nil {
			return false
		}
		if _, err := nativeToken(tag.CompartmentId.Value, "compartmentId"); err != nil {
			return false
		}
		if _, err := canonicalToken(tag.OperationId.Value, "operationId"); err != nil || tag.Generation.Value == 0 {
			return false
		}
	}
	if _, err := copyApprovals(request.RequiredApprovals); err != nil {
		return false
	}
	return true
}

// providerCallEvidenceMatches validates the complete call outcome before an
// intent is emitted. Unknown status values (or malformed work-request IDs)
// must never fall through nextIntent and become a fresh provider mutation.
func providerCallEvidenceMatches(evidence ProviderCallEvidence, expected ProviderOperationContext) bool {
	if !definedCallStatus(evidence.Status) || evidence.Context.fingerprint() != expected.fingerprint() {
		return false
	}
	if evidence.WorkRequestId == nil {
		return true
	}
	if evidence.Status != CallAccepted && evidence.Status != CallResponseLost {
		return false
	}
	_, err := nativeToken(evidence.WorkRequestId.Value, "workRequestId")
	return err == nil
}
func boolToU(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}
func idPtr(v *ProviderResourceId) string {
	if v == nil {
		return "-"
	}
	return v.Value
}
func containsApproval(a []ProviderApproval, v ProviderApproval) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}
func singleOwnership(v []ProviderOwnershipRecord) *ProviderOwnershipRecord {
	if len(v) != 1 {
		return nil
	}
	return &v[0]
}
func singleObservation(v []ProviderResourceObservation) *ProviderResourceObservation {
	if len(v) != 1 {
		return nil
	}
	return &v[0]
}
func singleCreate(v []ProviderCreateObservation) *ProviderCreateObservation {
	if len(v) != 1 {
		return nil
	}
	return &v[0]
}
func heldTail() []ProviderDecisionReason {
	codes := []ProviderDecisionCode{DecisionScopeMatches, DecisionEpochCurrentOrDurablyResumable, DecisionOwnershipMatches, DecisionGenerationMatches, DecisionDeadlineValid, DecisionApprovalsComplete, DecisionCallEvidenceMatches, DecisionPriorAuthorizationCompatible, DecisionActionResourceCompatible, DecisionTagsConsistent, DecisionTagsNotAuthority}
	out := make([]ProviderDecisionReason, len(codes))
	for i, c := range codes {
		out[i] = authReason(c, DecisionHeld, 0, 0)
	}
	return out
}
func tagsConsistent(r ProviderAuthorizationRequest, tags map[string][]ProviderInventoryTagEvidence) bool {
	target, ok := r.Context.Target.(ExistingProviderResource)
	if !ok {
		return len(r.Tags) == 0
	}
	v := tags[target.Id.Value]
	if len(v) == 0 {
		return true
	}
	if len(v) != 1 {
		return false
	}
	x := v[0]
	return x.CellId == r.Context.CellId && x.CompartmentId == r.Context.CompartmentId && x.OperationId == r.Context.OperationId && x.Generation == r.Context.ExpectedGeneration
}
func nextIntent(r ProviderAuthorizationRequest, creates map[string][]ProviderCreateObservation) ProviderIntent {
	if (r.CallEvidence.Status == CallAccepted || r.CallEvidence.Status == CallResponseLost) && r.CallEvidence.WorkRequestId != nil {
		return ReadProviderWorkRequestIntent{intentBase{r.Context}, *r.CallEvidence.WorkRequestId}
	}
	if r.CallEvidence.Status == CallAccepted || r.CallEvidence.Status == CallResponseLost || r.CallEvidence.Status == CallCompleted {
		return ObserveProviderResourceIntent{intentBase{r.Context}}
	}
	if target, ok := r.Context.Target.(IdempotentProviderCreate); ok {
		if o := singleCreate(creates[target.Key.Value]); o != nil && o.ResolvedResourceId != nil {
			return ObserveResolvedProviderCreateIntent{intentBase{r.Context}, target.Key, o.CellId, o.CompartmentId, *o.ResolvedResourceId}
		}
	}
	switch r.Context.Action {
	case ActionCreateNode:
		return CreateNodeProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(CreateNodeProviderParameters)}
	case ActionStartNode:
		return StartNodeProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(StartNodeProviderParameters)}
	case ActionStopNode:
		return StopNodeProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(StopNodeProviderParameters)}
	case ActionTerminateNode:
		return TerminateNodeProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(TerminateNodeProviderParameters)}
	case ActionCreateVolume:
		return CreateVolumeProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(CreateVolumeProviderParameters)}
	case ActionExpandVolume:
		return ExpandVolumeProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(ExpandVolumeProviderParameters)}
	case ActionChangeVolumePerformance:
		return ChangeVolumePerformanceProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(ChangeVolumePerformanceProviderParameters)}
	case ActionAttachVolume:
		return AttachVolumeProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(AttachVolumeProviderParameters)}
	case ActionDetachVolume:
		return DetachVolumeProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(DetachVolumeProviderParameters)}
	case ActionRegisterBackend:
		return RegisterBackendProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(RegisterBackendProviderParameters)}
	case ActionDeregisterBackend:
		return DeregisterBackendProviderIntent{intentBase{r.Context}, r.Context.ActionParameters.(DeregisterBackendProviderParameters)}
	default:
		return ObserveProviderResourceIntent{intentBase{r.Context}}
	}
}

func NewHandoffScope(cell ProviderCellId, compartment ProviderCompartmentId, generation ProviderGeneration, operation ProviderOperationId, inventory FreshBootstrapInventory) HandoffScope {
	return HandoffScope{cell, compartment, generation, operation, newFingerprint(inventory.Expected)}
}
func NewFreshBootstrapInventory(expected, regional []HandoffInventoryItem) (FreshBootstrapInventory, error) {
	for _, x := range [][]HandoffInventoryItem{expected, regional} {
		if len(x) > MaximumHandoffInventoryCount {
			return FreshBootstrapInventory{}, &errs.Argument{Message: "handoff inventory exceeds its bound"}
		}
		for _, item := range x {
			if !validHandoffInventoryItem(item) {
				return FreshBootstrapInventory{}, &errs.Argument{Message: "handoff inventory contains an invalid resource"}
			}
		}
	}
	return FreshBootstrapInventory{Expected: append([]HandoffInventoryItem(nil), expected...), Regional: append([]HandoffInventoryItem(nil), regional...)}, nil
}
func EvaluateHandoff(r HandoffRequest) HandoffDecision {
	all := [][]HandoffInventoryItem{r.Inventory.Expected, r.Inventory.Regional}
	inventoryValid := validHandoffInventory(r.Inventory)
	dups := 0
	for _, items := range all {
		seen := map[string]bool{}
		for _, x := range items {
			// A resource may occur only once in each inventory projection. A
			// duplicate with a different kind/generation is still ambiguous.
			k := x.ResourceId.Value
			if seen[k] {
				dups++
			}
			seen[k] = true
		}
	}
	expectedDigest := digestProjection(r.Inventory.Expected)
	exact := inventoryValid && expectedDigest == digestProjection(r.Inventory.Regional)
	scope := validHandoffScope(r.ExpectedScope) && r.ExpectedScope.InventoryFingerprint.Value == expectedDigest
	notRollback := r.CurrentAcceptedBootstrapGeneration.Value > 0 && r.ExpectedScope.BootstrapGeneration.Value >= r.CurrentAcceptedBootstrapGeneration.Value
	tr := []ProviderDecisionReason{passReject(DecisionHandoffInventoryUnique, inventoryValid && dups == 0, false, uint64(dups), 0), passReject(DecisionHandoffInventoryExact, exact, false, boolToU(exact), 1), passReject(DecisionHandoffScopeMatches, scope, false, boolToU(scope), 1), passReject(DecisionHandoffGenerationNotRollback, notRollback, false, r.ExpectedScope.BootstrapGeneration.Value, r.CurrentAcceptedBootstrapGeneration.Value)}
	proofs := []struct {
		c ProviderDecisionCode
		p HandoffProof
	}{{DecisionHandoffRetainUnmanage, r.Evidence.RetainUnmanage}, {DecisionHandoffJournalReceipt, r.Evidence.RegionalJournalReceipt}, {DecisionHandoffProviderReady, r.Evidence.ProviderReady}, {DecisionHandoffTrustReady, r.Evidence.TrustReady}, {DecisionHandoffBackupReady, r.Evidence.BackupReady}, {DecisionHandoffFenceActivated, r.Evidence.RegionalFenceActivated}}
	for _, x := range proofs {
		out := DecisionRejected
		if scope && x.p.Scope == r.ExpectedScope {
			switch x.p.Status {
			case HandoffVerified:
				out = DecisionPassed
			case HandoffMissing:
				out = DecisionHeld
			}
		}
		tr = append(tr, authReason(x.c, out, boolToU(out == DecisionPassed), 1))
	}
	ready := true
	for _, x := range tr {
		if x.Outcome != DecisionPassed {
			ready = false
			break
		}
	}
	var in *EnableRegionalSelfManagementIntent
	if ready {
		in = &EnableRegionalSelfManagementIntent{r.Inventory, r.ExpectedScope, r.CurrentAcceptedBootstrapGeneration}
	}
	return HandoffDecision{ready, tr, in}
}

func validHandoffInventoryItem(item HandoffInventoryItem) bool {
	_, resourceErr := nativeToken(item.ResourceId.Value, "resourceId")
	return resourceErr == nil && definedResourceKind(item.Kind) && item.Generation.Value > 0
}

func validHandoffInventory(inventory FreshBootstrapInventory) bool {
	for _, items := range [][]HandoffInventoryItem{inventory.Expected, inventory.Regional} {
		if len(items) > MaximumHandoffInventoryCount {
			return false
		}
		for _, item := range items {
			if !validHandoffInventoryItem(item) {
				return false
			}
		}
	}
	return true
}

func validHandoffScope(scope HandoffScope) bool {
	if _, err := canonicalToken(scope.CellId.Value, "cellId"); err != nil {
		return false
	}
	if _, err := nativeToken(scope.CompartmentId.Value, "compartmentId"); err != nil {
		return false
	}
	if _, err := canonicalToken(scope.OperationId.Value, "operationId"); err != nil {
		return false
	}
	return scope.BootstrapGeneration.Value > 0 && len(scope.InventoryFingerprint.Value) == 64 && strings.ToLower(scope.InventoryFingerprint.Value) == scope.InventoryFingerprint.Value && isLowerHex(scope.InventoryFingerprint.Value)
}

func isLowerHex(value string) bool {
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func fmtUint(v uint64) string { return strconv.FormatUint(v, 10) }
