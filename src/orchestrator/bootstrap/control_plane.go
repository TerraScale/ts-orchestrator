package bootstrap

// This file contains the control-topology part of bootstrap and add-region.
// It deliberately knows nothing about OCI, NATS, Cloudflare, or credentials.
// A provider implements ControlPlaneProvider and is called only with an
// idempotency key and a bounded, non-secret request.  Keeping the transition
// pure up to the provider boundary is what makes dry-runs and crash recovery
// equivalent to a normal retry.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type ControlTopology string

const (
	ControlTopologyEmpty       ControlTopology = "empty"
	ControlTopologyTemporaryR1 ControlTopology = "temporary-r1"
	ControlTopologyGlobalR3    ControlTopology = "global-r3"
	ControlTopologyRemote      ControlTopology = "remote-managed"
	ControlTopologyRegionalR3  ControlTopology = "regional-r3"
)

type ControlPhase string

const (
	ControlPhaseEmpty      ControlPhase = "empty"
	ControlPhaseR1         ControlPhase = "r1"
	ControlPhasePromoting  ControlPhase = "promoting"
	ControlPhaseR3         ControlPhase = "r3"
	ControlPhaseRemote     ControlPhase = "remote"
	ControlPhaseRegionalR3 ControlPhase = "regional-r3"
)

var (
	ErrControlInvalid              = errors.New("control bootstrap state is invalid")
	ErrControlAuthorityRevoked     = errors.New("bootstrap authority has been revoked")
	ErrControlEpochRegression      = errors.New("control epoch would regress")
	ErrControlPromotionNotReady    = errors.New("global R3 promotion requires two synchronized candidates")
	ErrControlQuorumNotVerified    = errors.New("global R3 quorum was not verified")
	ErrControlMembersBelowFloor    = errors.New("control region requires at least two member hosts")
	ErrControlRegionalMembersFloor = errors.New("regional R3 requires at least three eligible hosts")
	ErrControlCustomersPresent     = errors.New("temporary R1 is only permitted before customers")
	ErrControlJournalUnavailable   = errors.New("control bootstrap requires an authoritative durable journal")
)

// CandidateEvidence is the only evidence accepted for a synchronized
// candidate. Every field is a provider observation; none contains a secret.
type CandidateEvidence struct {
	Region         string `json:"region"`
	IdentityDigest string `json:"identityDigest"`
	StorageDigest  string `json:"storageDigest"`
	HealthDigest   string `json:"healthDigest"`
	CaughtUp       bool   `json:"caughtUp"`
	IdentityReady  bool   `json:"identityReady"`
	StorageReady   bool   `json:"storageReady"`
	HealthReady    bool   `json:"healthReady"`
}

func (c CandidateEvidence) Ready() bool {
	return c.Region != "" && c.CaughtUp && c.IdentityReady && c.StorageReady && c.HealthReady &&
		c.IdentityDigest != "" && c.StorageDigest != "" && c.HealthDigest != ""
}

type ControlPlaneState struct {
	Topology            ControlTopology     `json:"topology"`
	Phase               ControlPhase        `json:"phase"`
	Epoch               uint64              `json:"epoch"`
	BootstrapAuthorized bool                `json:"bootstrapAuthorized"`
	CustomersPresent    bool                `json:"customersPresent"`
	MemberHosts         int                 `json:"memberHosts"`
	ControlRegions      []string            `json:"controlRegions,omitempty"`
	Candidates          []CandidateEvidence `json:"candidates,omitempty"`
}

func (s ControlPlaneState) normalize() ControlPlaneState {
	if s.Topology == "" {
		s.Topology = ControlTopologyEmpty
	}
	if s.Phase == "" {
		s.Phase = ControlPhaseEmpty
	}
	s.ControlRegions = append([]string(nil), s.ControlRegions...)
	s.Candidates = append([]CandidateEvidence(nil), s.Candidates...)
	sort.Strings(s.ControlRegions)
	sort.Slice(s.Candidates, func(i, j int) bool { return s.Candidates[i].Region < s.Candidates[j].Region })
	return s
}

func (s ControlPlaneState) Validate() error {
	s = s.normalize()
	if s.Epoch == 0 && s.Phase != ControlPhaseEmpty {
		return ErrControlInvalid
	}
	if s.MemberHosts < 0 || len(s.ControlRegions) > 20 {
		return ErrControlInvalid
	}
	seen := map[string]bool{}
	for _, region := range s.ControlRegions {
		if !validControlRegion(region) || seen[region] {
			return ErrControlInvalid
		}
		seen[region] = true
	}
	seen = map[string]bool{}
	for _, candidate := range s.Candidates {
		if !validControlRegion(candidate.Region) || seen[candidate.Region] {
			return ErrControlInvalid
		}
		seen[candidate.Region] = true
	}
	if s.Topology == ControlTopologyGlobalR3 && (s.Phase != ControlPhaseR3 || len(s.ControlRegions) != 3 || s.Epoch == 0) {
		return ErrControlInvalid
	}
	if s.Topology == ControlTopologyTemporaryR1 && s.Phase != ControlPhaseR1 {
		return ErrControlInvalid
	}
	if s.Topology == ControlTopologyEmpty && s.Phase != ControlPhaseEmpty {
		return ErrControlInvalid
	}
	return nil
}

func validControlRegion(region string) bool {
	if region == "" || len(region) > 63 || strings.ContainsAny(region, "\r\n\x00") {
		return false
	}
	for _, r := range region {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

type ControlOperation string

const (
	ControlOperationBootstrap    ControlOperation = "bootstrap-gru-r1"
	ControlOperationAddRegion    ControlOperation = "add-region"
	ControlOperationPromoteR3    ControlOperation = "promote-global-r3"
	ControlOperationHandoff      ControlOperation = "authority-handoff"
	ControlOperationRemoteManage ControlOperation = "remote-manage-region"
	ControlOperationRegionalR3   ControlOperation = "regional-r3"
)

type ControlTransitionRequest struct {
	Operation          ControlOperation
	Region             string
	MemberHosts        int
	EligibleHosts      int
	RegionalControl    bool
	CustomerDataExists bool
	Candidate          CandidateEvidence
}

type ControlActionKind string

const (
	ControlActionStartTemporaryR1 ControlActionKind = "start-temporary-r1"
	ControlActionFenceR1          ControlActionKind = "fence-r1"
	ControlActionStartCandidate   ControlActionKind = "start-candidate"
	ControlActionSyncCandidate    ControlActionKind = "sync-candidate"
	ControlActionVerifyCandidate  ControlActionKind = "verify-candidate"
	ControlActionPromoteR3        ControlActionKind = "promote-global-r3"
	ControlActionVerifyQuorum     ControlActionKind = "verify-r3-quorum"
	ControlActionRevokeBootstrap  ControlActionKind = "revoke-bootstrap"
	ControlActionRemoteManage     ControlActionKind = "remote-manage"
	ControlActionStartRegionalR3  ControlActionKind = "start-regional-r3"
)

type ControlAction struct {
	ID             string            `json:"id"`
	Kind           ControlActionKind `json:"kind"`
	Region         string            `json:"region,omitempty"`
	ExpectedEpoch  uint64            `json:"expectedEpoch"`
	TargetEpoch    uint64            `json:"targetEpoch"`
	IdempotencyKey string            `json:"idempotencyKey"`
}

type ControlPlan struct {
	Operation   ControlOperation  `json:"operation"`
	From        ControlPlaneState `json:"from"`
	To          ControlPlaneState `json:"to"`
	Actions     []ControlAction   `json:"actions"`
	Fingerprint string            `json:"fingerprint"`
}

func (p ControlPlan) Validate() error {
	if p.Operation == "" || p.Fingerprint == "" || len(p.Actions) == 0 {
		return ErrControlInvalid
	}
	if err := p.From.Validate(); err != nil {
		return err
	}
	if err := p.To.Validate(); err != nil {
		return err
	}
	copyPlan := p
	copyPlan.Fingerprint = ""
	raw, err := json.Marshal(copyPlan)
	if err != nil {
		return ErrControlInvalid
	}
	sum := sha256.Sum256(raw)
	if p.Fingerprint != hex.EncodeToString(sum[:]) {
		return ErrControlInvalid
	}
	seen := map[string]bool{}
	for _, action := range p.Actions {
		if action.ID == "" || action.IdempotencyKey == "" || seen[action.ID] {
			return ErrControlInvalid
		}
		seen[action.ID] = true
	}
	return nil
}

// PlanControlTransition is pure. It rejects stale authority, never lowers an
// epoch, and only puts the global group into R3 after both SFO and FRA have
// supplied ready candidate evidence.
func PlanControlTransition(state ControlPlaneState, request ControlTransitionRequest) (ControlPlan, error) {
	state = state.normalize()
	if err := state.Validate(); err != nil {
		return ControlPlan{}, err
	}
	if request.MemberHosts < 0 || request.EligibleHosts < 0 || (request.Region != "" && !validControlRegion(request.Region)) {
		return ControlPlan{}, ErrControlInvalid
	}
	if request.CustomerDataExists {
		state.CustomersPresent = true
	}
	if request.Operation == "" {
		if state.Phase == ControlPhaseEmpty {
			request.Operation = ControlOperationBootstrap
		} else {
			request.Operation = ControlOperationAddRegion
		}
	}
	if request.Operation != ControlOperationBootstrap && !state.BootstrapAuthorized && state.Phase != ControlPhaseR3 && state.Phase != ControlPhaseRegionalR3 {
		return ControlPlan{}, ErrControlAuthorityRevoked
	}
	if state.CustomersPresent && state.Phase == ControlPhaseR1 {
		return ControlPlan{}, ErrControlCustomersPresent
	}

	to := state
	to.MemberHosts = maxInt(state.MemberHosts, request.MemberHosts)
	actions := []ControlAction{}
	add := func(kind ControlActionKind, region string, target uint64) {
		id := string(kind)
		if region != "" {
			id += "-" + region
		}
		id += fmt.Sprintf("-%d", len(actions)+1)
		actions = append(actions, ControlAction{ID: id, Kind: kind, Region: region, ExpectedEpoch: state.Epoch, TargetEpoch: target, IdempotencyKey: controlActionKey(request.Operation, id, state.Epoch, target)})
	}

	switch request.Operation {
	case ControlOperationBootstrap:
		if state.Phase != ControlPhaseEmpty || state.Topology != ControlTopologyEmpty || state.Epoch != 0 || state.CustomersPresent || request.Region != "gru" || request.MemberHosts != 2 {
			return ControlPlan{}, ErrControlInvalid
		}
		to = ControlPlaneState{Topology: ControlTopologyTemporaryR1, Phase: ControlPhaseR1, Epoch: 1, BootstrapAuthorized: true, MemberHosts: 2, ControlRegions: []string{"gru"}}
		add(ControlActionStartTemporaryR1, "gru", 1)
		add(ControlActionFenceR1, "gru", 1)

	case ControlOperationAddRegion:
		if request.Region == "" || request.MemberHosts < 2 {
			return ControlPlan{}, ErrControlMembersBelowFloor
		}
		if request.RegionalControl {
			if request.EligibleHosts < 3 {
				return ControlPlan{}, ErrControlRegionalMembersFloor
			}
			to.Topology, to.Phase = ControlTopologyRegionalR3, ControlPhaseRegionalR3
			to.Epoch = maxUint64(state.Epoch, state.Epoch+1)
			add(ControlActionStartRegionalR3, request.Region, to.Epoch)
			break
		}
		if request.Region != "sfo" && request.Region != "fra" {
			to.Topology, to.Phase = ControlTopologyRemote, ControlPhaseRemote
			add(ControlActionRemoteManage, request.Region, state.Epoch)
			break
		}
		if state.Phase != ControlPhaseR1 && state.Phase != ControlPhasePromoting {
			return ControlPlan{}, ErrControlInvalid
		}
		candidate := request.Candidate
		candidate.Region = request.Region
		to.Candidates = mergeCandidate(to.Candidates, candidate)
		add(ControlActionStartCandidate, request.Region, state.Epoch)
		add(ControlActionSyncCandidate, request.Region, state.Epoch)
		add(ControlActionVerifyCandidate, request.Region, state.Epoch)
		ready := readyCandidateRegions(to.Candidates)
		if ready["sfo"] && ready["fra"] {
			to.Topology, to.Phase = ControlTopologyGlobalR3, ControlPhaseR3
			to.Epoch = state.Epoch + 1
			to.BootstrapAuthorized = false
			to.ControlRegions = []string{"gru", "sfo", "fra"}
			add(ControlActionPromoteR3, "", to.Epoch)
			add(ControlActionVerifyQuorum, "", to.Epoch)
			add(ControlActionRevokeBootstrap, "gru", to.Epoch)
		}

	case ControlOperationPromoteR3:
		if state.Phase != ControlPhaseR1 && state.Phase != ControlPhasePromoting || state.Epoch == 0 {
			return ControlPlan{}, ErrControlInvalid
		}
		if !readyCandidateRegions(state.Candidates)["sfo"] || !readyCandidateRegions(state.Candidates)["fra"] {
			return ControlPlan{}, ErrControlPromotionNotReady
		}
		to.Topology, to.Phase = ControlTopologyGlobalR3, ControlPhaseR3
		to.Epoch, to.BootstrapAuthorized = state.Epoch+1, false
		to.ControlRegions = []string{"gru", "sfo", "fra"}
		add(ControlActionPromoteR3, "", to.Epoch)
		add(ControlActionVerifyQuorum, "", to.Epoch)
		add(ControlActionRevokeBootstrap, "gru", to.Epoch)

	case ControlOperationHandoff:
		if state.Phase != ControlPhaseR3 || state.Epoch == 0 || state.BootstrapAuthorized {
			if state.Phase == ControlPhaseR3 && !state.BootstrapAuthorized {
				return ControlPlan{}, ErrControlAuthorityRevoked
			}
			return ControlPlan{}, ErrControlInvalid
		}
		return ControlPlan{}, ErrControlAuthorityRevoked

	case ControlOperationRemoteManage:
		if request.Region == "" || request.MemberHosts < 2 {
			return ControlPlan{}, ErrControlMembersBelowFloor
		}
		to.Topology, to.Phase = ControlTopologyRemote, ControlPhaseRemote
		add(ControlActionRemoteManage, request.Region, state.Epoch)

	default:
		return ControlPlan{}, ErrControlInvalid
	}

	to = to.normalize()
	plan := ControlPlan{Operation: request.Operation, From: state, To: to, Actions: actions}
	raw, err := json.Marshal(plan)
	if err != nil {
		return ControlPlan{}, ErrControlInvalid
	}
	sum := sha256.Sum256(raw)
	plan.Fingerprint = hex.EncodeToString(sum[:])
	return plan, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
func controlActionKey(op ControlOperation, id string, from, to uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d/%d", op, id, from, to)))
	return "control-" + hex.EncodeToString(sum[:])[:48]
}
func mergeCandidate(all []CandidateEvidence, candidate CandidateEvidence) []CandidateEvidence {
	result := append([]CandidateEvidence(nil), all...)
	for i := range result {
		if result[i].Region == candidate.Region {
			result[i] = candidate
			return result
		}
	}
	return append(result, candidate)
}
func readyCandidateRegions(all []CandidateEvidence) map[string]bool {
	ready := map[string]bool{}
	for _, candidate := range all {
		if candidate.Ready() {
			ready[candidate.Region] = true
		}
	}
	return ready
}

type ControlActionRequest struct {
	Action          ControlAction
	State           ControlPlaneState
	PlanFingerprint string
}
type ControlReceipt struct {
	ID string `json:"id,omitempty"`
}
type ControlPlaneProvider interface {
	StartTemporaryR1(context.Context, ControlActionRequest) (ControlReceipt, error)
	FenceTemporaryR1(context.Context, ControlActionRequest) (ControlReceipt, error)
	StartCandidate(context.Context, ControlActionRequest) (ControlReceipt, error)
	SyncCandidate(context.Context, ControlActionRequest) (ControlReceipt, error)
	VerifyCandidate(context.Context, ControlActionRequest) (CandidateEvidence, error)
	PromoteGlobalR3(context.Context, ControlActionRequest) (ControlReceipt, error)
	VerifyGlobalR3(context.Context, ControlActionRequest) error
	RevokeBootstrapAuthority(context.Context, ControlActionRequest) (ControlReceipt, error)
	RemoteManageRegion(context.Context, ControlActionRequest) (ControlReceipt, error)
	StartRegionalR3(context.Context, ControlActionRequest) (ControlReceipt, error)
}

type ControlJournalRecord struct {
	PlanFingerprint string            `json:"planFingerprint"`
	State           ControlPlaneState `json:"state"`
	Completed       []string          `json:"completed,omitempty"`
}
type ControlJournal interface {
	AuthoritativeDurable() bool
	Load(context.Context) (ControlJournalRecord, error)
	Save(context.Context, ControlJournalRecord) error
}

type ControlStateMachine struct {
	Provider ControlPlaneProvider
	Journal  ControlJournal
	Retry    RetryPolicy
}
type ControlExecutionResult struct {
	State     ControlPlaneState
	Completed []string
	Skipped   []string
}

func NewControlStateMachine(provider ControlPlaneProvider, journal ControlJournal, retry RetryPolicy) (*ControlStateMachine, error) {
	if provider == nil || journal == nil || !journal.AuthoritativeDurable() {
		return nil, ErrControlJournalUnavailable
	}
	if err := retry.Validate(); err != nil {
		return nil, err
	}
	return &ControlStateMachine{Provider: provider, Journal: journal, Retry: retry}, nil
}

func (m *ControlStateMachine) Execute(ctx context.Context, state ControlPlaneState, request ControlTransitionRequest) (ControlExecutionResult, error) {
	result := ControlExecutionResult{State: state.normalize()}
	if m == nil || m.Provider == nil || m.Journal == nil || !m.Journal.AuthoritativeDurable() {
		return result, ErrControlJournalUnavailable
	}
	if ctx == nil {
		return result, errors.New("control bootstrap context is nil")
	}
	if err := state.Validate(); err != nil {
		return result, err
	}
	prior, err := m.Journal.Load(ctx)
	if err != nil {
		return result, err
	}
	if prior.PlanFingerprint != "" && prior.State.Epoch > state.Epoch {
		state = prior.State
		result.State = state
	}
	plan, err := PlanControlTransition(state, request)
	if err != nil {
		return result, err
	}
	if prior.PlanFingerprint != "" && prior.PlanFingerprint != plan.Fingerprint {
		return result, ErrControlInvalid
	}
	completed := map[string]bool{}
	for _, id := range prior.Completed {
		completed[id] = true
	}
	if len(completed) == len(plan.Actions) {
		result.State = plan.To
		result.Skipped = sortedKeys(completed)
		return result, nil
	}
	for _, action := range plan.Actions {
		if completed[action.ID] {
			result.Skipped = append(result.Skipped, action.ID)
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		var callErr error
		for attempt := 1; attempt <= m.Retry.MaxAttempts; attempt++ {
			callErr = m.call(ctx, action, plan)
			if callErr == nil || !retryable(callErr) || attempt == m.Retry.MaxAttempts {
				break
			}
			if m.Retry.Backoff != nil {
				if waitErr := m.Retry.Backoff(ctx, attempt); waitErr != nil {
					return result, waitErr
				}
			}
		}
		if callErr != nil {
			return result, callErr
		}
		completed[action.ID] = true
		// Keep the pre-transition state until every action is recorded. A
		// restart can therefore reconstruct the exact same plan and reuse
		// each provider idempotency key.
		prior = ControlJournalRecord{PlanFingerprint: plan.Fingerprint, State: plan.From, Completed: sortedKeys(completed)}
		if err := m.Journal.Save(ctx, prior); err != nil {
			return result, err
		}
		result.Completed = append(result.Completed, action.ID)
	}
	prior = ControlJournalRecord{PlanFingerprint: plan.Fingerprint, State: plan.To, Completed: sortedKeys(completed)}
	if err := m.Journal.Save(ctx, prior); err != nil {
		return result, err
	}
	result.State = plan.To
	return result, nil
}

func (m *ControlStateMachine) call(ctx context.Context, action ControlAction, plan ControlPlan) error {
	req := ControlActionRequest{Action: action, State: plan.From, PlanFingerprint: plan.Fingerprint}
	var err error
	switch action.Kind {
	case ControlActionStartTemporaryR1:
		_, err = m.Provider.StartTemporaryR1(ctx, req)
	case ControlActionFenceR1:
		_, err = m.Provider.FenceTemporaryR1(ctx, req)
	case ControlActionStartCandidate:
		_, err = m.Provider.StartCandidate(ctx, req)
	case ControlActionSyncCandidate:
		_, err = m.Provider.SyncCandidate(ctx, req)
	case ControlActionVerifyCandidate:
		_, err = m.Provider.VerifyCandidate(ctx, req)
	case ControlActionPromoteR3:
		_, err = m.Provider.PromoteGlobalR3(ctx, req)
	case ControlActionVerifyQuorum:
		err = m.Provider.VerifyGlobalR3(ctx, req)
	case ControlActionRevokeBootstrap:
		_, err = m.Provider.RevokeBootstrapAuthority(ctx, req)
	case ControlActionRemoteManage:
		_, err = m.Provider.RemoteManageRegion(ctx, req)
	case ControlActionStartRegionalR3:
		_, err = m.Provider.StartRegionalR3(ctx, req)
	default:
		return ErrControlInvalid
	}
	return err
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// MemoryControlJournal is useful for local providers and deterministic tests.
// It is still authoritative within the lifetime of the process; production
// should use FileControlJournal or the JetStream-backed implementation.
type MemoryControlJournal struct {
	mu      sync.Mutex
	Record  ControlJournalRecord
	Durable bool
}

func (j *MemoryControlJournal) AuthoritativeDurable() bool { return j != nil && j.Durable }
func (j *MemoryControlJournal) Load(ctx context.Context) (ControlJournalRecord, error) {
	if ctx == nil {
		return ControlJournalRecord{}, ErrControlJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ControlJournalRecord{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Record, nil
}
func (j *MemoryControlJournal) Save(ctx context.Context, record ControlJournalRecord) error {
	if ctx == nil {
		return ErrControlJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Record = record
	return nil
}

type FileControlJournal struct {
	mu     sync.Mutex
	path   string
	record ControlJournalRecord
}

func NewFileControlJournal(path string) (*FileControlJournal, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
		return nil, ErrControlJournalUnavailable
	}
	j := &FileControlJournal{path: path}
	if raw, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(raw, &j.record) != nil {
			return nil, ErrControlJournalUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrControlJournalUnavailable
	}
	return j, nil
}
func (j *FileControlJournal) AuthoritativeDurable() bool { return j != nil && j.path != "" }
func (j *FileControlJournal) Load(ctx context.Context) (ControlJournalRecord, error) {
	if ctx == nil {
		return ControlJournalRecord{}, ErrControlJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ControlJournalRecord{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.record, nil
}
func (j *FileControlJournal) Save(ctx context.Context, record ControlJournalRecord) error {
	if ctx == nil {
		return ErrControlJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	raw, err := json.Marshal(record)
	if err != nil {
		return ErrControlJournalUnavailable
	}
	dir := filepath.Dir(j.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ErrControlJournalUnavailable
	}
	tmp, err := os.CreateTemp(dir, ".control-journal-")
	if err != nil {
		return ErrControlJournalUnavailable
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return ErrControlJournalUnavailable
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return ErrControlJournalUnavailable
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return ErrControlJournalUnavailable
	}
	if err := tmp.Close(); err != nil {
		return ErrControlJournalUnavailable
	}
	if err := os.Rename(name, j.path); err != nil {
		return ErrControlJournalUnavailable
	}
	j.record = record
	return nil
}
