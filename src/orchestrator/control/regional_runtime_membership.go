package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// RegionalRuntimeMember mirrors the C# record. JSON tags mirror the C#
// source-generated context (default options: PascalCase property names).
type RegionalRuntimeMember struct {
	SchemaVersion     int       `json:"SchemaVersion"`
	Cell              string    `json:"Cell"`
	Cluster           string    `json:"Cluster"`
	Instance          string    `json:"Instance"`
	SessionId         string    `json:"SessionId"`
	Build             string    `json:"Build"`
	Capabilities      []string  `json:"Capabilities"`
	StartedAt         time.Time `json:"StartedAt"`
	ObservedAt        time.Time `json:"ObservedAt"`
	LeaseExpiresAt    time.Time `json:"LeaseExpiresAt"`
	AuthorityState    string    `json:"AuthorityState"`
	IsAuthorityLeader bool      `json:"IsAuthorityLeader"`
	AuthorityEpoch    int64     `json:"AuthorityEpoch"`
	AuthorityRevision int64     `json:"AuthorityRevision"`
	IdentityKeyId     string    `json:"IdentityKeyId"`
	IdentityPublicKey string    `json:"IdentityPublicKey"`
	IdentitySignature string    `json:"IdentitySignature"`
}

// IsValidFor mirrors the C# IsValidFor.
func (m RegionalRuntimeMember) IsValidFor(expectedCell string, now time.Time) bool {
	return m.SchemaVersion == 1 &&
		m.Cell == expectedCell &&
		m.Cluster == "orchestrator-control-"+expectedCell &&
		strings.TrimSpace(m.Instance) != "" &&
		isDotNetGuidNoHyphens(m.SessionId) &&
		strings.TrimSpace(m.Build) != "" &&
		len(m.Capabilities) > 0 &&
		allCapabilitiesBounded(m.Capabilities) &&
		isOrdinallySortedAndDistinct(m.Capabilities) &&
		!m.StartedAt.After(m.ObservedAt) &&
		!m.ObservedAt.After(now.Add(time.Minute)) &&
		m.LeaseExpiresAt.After(m.ObservedAt) &&
		!m.LeaseExpiresAt.After(m.ObservedAt.Add(time.Minute)) &&
		(m.AuthorityState == "leader" || m.AuthorityState == "follower") &&
		m.IsAuthorityLeader == (m.AuthorityState == "leader") &&
		m.AuthorityEpoch > 0 && m.AuthorityRevision > 0 &&
		m.HasWellFormedIdentityMaterial()
}

// HasWellFormedIdentityMaterial mirrors the C# shape check: the cryptographic
// verification is VerifySignedIdentity.
func (m RegionalRuntimeMember) HasWellFormedIdentityMaterial() bool {
	if len(m.IdentityKeyId) != 32 || !isLowercaseHex(m.IdentityKeyId) {
		return false
	}

	if len(m.IdentityPublicKey) == 0 || len(m.IdentityPublicKey) > 256 ||
		len(m.IdentitySignature) == 0 || len(m.IdentitySignature) > 256 {
		return false
	}

	return isBase64Shape(m.IdentityPublicKey) && isBase64Shape(m.IdentitySignature)
}

// VerifySignedIdentity mirrors the C# full signed-identity verification.
func (m RegionalRuntimeMember) VerifySignedIdentity() bool {
	return RegionalRuntimeMembershipIdentityVerify(m)
}

// CanonicalMaterial mirrors the C# CanonicalMaterial: every record field in a
// fixed order with fixed separators, timestamps as invariant Unix milliseconds.
func (m RegionalRuntimeMember) CanonicalMaterial() string {
	return strings.Join([]string{
		fmt.Sprintf("%d", m.SchemaVersion),
		m.Cell,
		m.Cluster,
		m.Instance,
		m.SessionId,
		m.Build,
		strings.Join(m.Capabilities, "\x1f"),
		fmt.Sprintf("%d", m.StartedAt.UnixMilli()),
		fmt.Sprintf("%d", m.ObservedAt.UnixMilli()),
		fmt.Sprintf("%d", m.LeaseExpiresAt.UnixMilli()),
		m.AuthorityState,
		map[bool]string{true: "1", false: "0"}[m.IsAuthorityLeader],
		fmt.Sprintf("%d", m.AuthorityEpoch),
		fmt.Sprintf("%d", m.AuthorityRevision),
	}, "\n")
}

// RegionalRuntimeMembershipCondition mirrors the C# enum (serialized as
// strings by the C# JsonStringEnumConverter).
type RegionalRuntimeMembershipCondition int

const (
	RegionalRuntimeMembershipConditionUnavailable RegionalRuntimeMembershipCondition = 0
	RegionalRuntimeMembershipConditionDegraded    RegionalRuntimeMembershipCondition = 1
	RegionalRuntimeMembershipConditionHealthy     RegionalRuntimeMembershipCondition = 2
)

func (c RegionalRuntimeMembershipCondition) String() string {
	switch c {
	case RegionalRuntimeMembershipConditionUnavailable:
		return "Unavailable"
	case RegionalRuntimeMembershipConditionDegraded:
		return "Degraded"
	case RegionalRuntimeMembershipConditionHealthy:
		return "Healthy"
	default:
		return fmt.Sprintf("%d", int(c))
	}
}

// RegionalRuntimeMembershipHealth mirrors the C# record.
type RegionalRuntimeMembershipHealth struct {
	ExpectedControllers             int                                `json:"ExpectedControllers"`
	ActiveControllers               int                                `json:"ActiveControllers"`
	StaleControllers                int                                `json:"StaleControllers"`
	MissingControllers              int                                `json:"MissingControllers"`
	UnexpectedControllers           int                                `json:"UnexpectedControllers"`
	ConflictingControllers          int                                `json:"ConflictingControllers"`
	RejectedRecords                 int64                              `json:"RejectedRecords"`
	AuthorityLeaders                int                                `json:"AuthorityLeaders"`
	QuorumAvailable                 bool                               `json:"QuorumAvailable"`
	MaximumHeartbeatAgeMilliseconds int64                              `json:"MaximumHeartbeatAgeMilliseconds"`
	Condition                       RegionalRuntimeMembershipCondition `json:"Condition"`
	ObservedAt                      time.Time                          `json:"ObservedAt"`
}

// RegionalRuntimeMembershipHealthEvaluate mirrors the static Evaluate. The
// conflictingControllers count is the CURRENT number of conflicting sessions: a
// gauge bounded by the observed slots, never a lifetime counter.
func RegionalRuntimeMembershipHealthEvaluate(
	cell string,
	expectedControllers int,
	records []RegionalRuntimeMember,
	rejectedRecords int64,
	observedAt time.Time,
	conflictingControllers int,
) (RegionalRuntimeMembershipHealth, error) {
	if strings.TrimSpace(cell) == "" {
		return RegionalRuntimeMembershipHealth{}, errors.New(
			"The value cannot be an empty string or composed entirely of whitespace. (Parameter 'cell')")
	}

	switch expectedControllers {
	case 1, 3, 5:
	default:
		return RegionalRuntimeMembershipHealth{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'expectedControllers')\nActual value was %d.",
			expectedControllers)
	}

	if rejectedRecords < 0 {
		return RegionalRuntimeMembershipHealth{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'rejectedRecords')\nActual value was %d.",
			rejectedRecords)
	}

	if conflictingControllers < 0 {
		return RegionalRuntimeMembershipHealth{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'conflictingControllers')\nActual value was %d.",
			conflictingControllers)
	}

	valid := make([]RegionalRuntimeMember, 0, len(records))
	for _, member := range records {
		if member.IsValidFor(cell, observedAt) {
			valid = append(valid, member)
		}
	}

	active := make([]RegionalRuntimeMember, 0, len(valid))
	for _, member := range valid {
		if member.LeaseExpiresAt.After(observedAt) {
			active = append(active, member)
		}
	}

	stale := len(valid) - len(active)
	missing := maxInt(0, expectedControllers-len(active))
	unexpected := maxInt(0, len(active)-expectedControllers)
	leaders := 0
	for _, member := range active {
		if member.IsAuthorityLeader {
			leaders++
		}
	}

	quorum := len(active) >= (expectedControllers/2)+1
	maximumAge := int64(0)
	for _, member := range active {
		age := observedAt.Sub(member.ObservedAt).Milliseconds()
		if age < 0 {
			age = 0
		}

		if age > maximumAge {
			maximumAge = age
		}
	}

	condition := RegionalRuntimeMembershipConditionDegraded
	if len(active) == 0 {
		condition = RegionalRuntimeMembershipConditionUnavailable
	} else if len(active) == expectedControllers && stale == 0 && unexpected == 0 && leaders == 1 {
		condition = RegionalRuntimeMembershipConditionHealthy
	}

	return RegionalRuntimeMembershipHealth{
		ExpectedControllers:             expectedControllers,
		ActiveControllers:               len(active),
		StaleControllers:                stale,
		MissingControllers:              missing,
		UnexpectedControllers:           unexpected,
		ConflictingControllers:          conflictingControllers,
		RejectedRecords:                 rejectedRecords,
		AuthorityLeaders:                leaders,
		QuorumAvailable:                 quorum,
		MaximumHeartbeatAgeMilliseconds: maximumAge,
		Condition:                       condition,
		ObservedAt:                      observedAt,
	}, nil
}

// Validate mirrors the C# Validate (panics with the C# message on invalid
// state, mirroring the InvalidOperationException).
func (h RegionalRuntimeMembershipHealth) Validate() {
	expectedMissing := maxInt(0, h.ExpectedControllers-h.ActiveControllers)
	expectedUnexpected := maxInt(0, h.ActiveControllers-h.ExpectedControllers)
	expectedQuorum := h.ActiveControllers >= (h.ExpectedControllers/2)+1
	expectedCondition := RegionalRuntimeMembershipConditionDegraded
	if h.ActiveControllers == 0 {
		expectedCondition = RegionalRuntimeMembershipConditionUnavailable
	} else if h.ActiveControllers == h.ExpectedControllers && h.StaleControllers == 0 &&
		h.UnexpectedControllers == 0 && h.AuthorityLeaders == 1 {
		expectedCondition = RegionalRuntimeMembershipConditionHealthy
	}

	validShape := h.ExpectedControllers == 1 || h.ExpectedControllers == 3 || h.ExpectedControllers == 5
	if !validShape || h.ActiveControllers < 0 || h.StaleControllers < 0 ||
		h.MissingControllers != expectedMissing || h.UnexpectedControllers != expectedUnexpected ||
		h.ConflictingControllers < 0 ||
		h.ConflictingControllers > h.ActiveControllers+h.StaleControllers ||
		h.RejectedRecords < 0 || h.AuthorityLeaders < 0 || h.AuthorityLeaders > h.ActiveControllers ||
		h.QuorumAvailable != expectedQuorum || h.MaximumHeartbeatAgeMilliseconds < 0 ||
		h.Condition != expectedCondition || h.ObservedAt.IsZero() ||
		h.ObservedAt.After(time.Now().UTC().Add(time.Minute)) {
		panic("The regional runtime membership health projection is invalid.")
	}
}

// Equal mirrors C# record equality over the health projection.
func (h RegionalRuntimeMembershipHealth) Equal(other RegionalRuntimeMembershipHealth) bool {
	return h.ExpectedControllers == other.ExpectedControllers &&
		h.ActiveControllers == other.ActiveControllers &&
		h.StaleControllers == other.StaleControllers &&
		h.MissingControllers == other.MissingControllers &&
		h.UnexpectedControllers == other.UnexpectedControllers &&
		h.ConflictingControllers == other.ConflictingControllers &&
		h.RejectedRecords == other.RejectedRecords &&
		h.AuthorityLeaders == other.AuthorityLeaders &&
		h.QuorumAvailable == other.QuorumAvailable &&
		h.MaximumHeartbeatAgeMilliseconds == other.MaximumHeartbeatAgeMilliseconds &&
		h.Condition == other.Condition &&
		h.ObservedAt.Equal(other.ObservedAt)
}

// RegionalRuntimeMembershipSnapshot mirrors the C# record.
type RegionalRuntimeMembershipSnapshot struct {
	SchemaVersion int                             `json:"SchemaVersion"`
	Cell          string                          `json:"Cell"`
	ObservedAt    time.Time                       `json:"ObservedAt"`
	Health        RegionalRuntimeMembershipHealth `json:"Health"`
	Members       []RegionalRuntimeMember         `json:"Members"`
}

// Validate mirrors the C# Validate.
func (s *RegionalRuntimeMembershipSnapshot) Validate(expectedCell string) error {
	s.Health.Validate()
	if s.SchemaVersion != 2 || s.Cell != expectedCell ||
		s.ObservedAt.After(time.Now().UTC().Add(time.Minute)) ||
		!s.Health.ObservedAt.Equal(s.ObservedAt) ||
		s.Health.ActiveControllers != len(s.Members) ||
		len(s.Members) == 0 {
		return errors.New("The regional runtime membership response is invalid.")
	}

	instances := map[string]struct{}{}
	for _, member := range s.Members {
		if !member.IsValidFor(expectedCell, s.ObservedAt) || !member.LeaseExpiresAt.After(s.ObservedAt) {
			return errors.New("The regional runtime membership response is invalid.")
		}

		if _, duplicate := instances[member.Instance]; duplicate {
			return errors.New("The regional runtime membership response is invalid.")
		}

		instances[member.Instance] = struct{}{}
	}

	ordered := append([]RegionalRuntimeMember(nil), s.Members...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Instance < ordered[j].Instance })
	for index := range ordered {
		if ordered[index].Instance != s.Members[index].Instance {
			return errors.New("The regional runtime membership response is invalid.")
		}
	}

	return nil
}

// RegionalRuntimeMembership mirrors the C# class: one controller's renewable
// KV registration and the watched, active peer view.
type RegionalRuntimeMembership struct {
	HeartbeatInterval time.Duration
	LeaseDuration     time.Duration

	store        jetstream.KeyValue
	topology     *NatsTopology
	key          string
	sessionId    string
	build        string
	capabilities []string
	startedAt    time.Time
	authority    func() RegionalAuthoritySnapshot
	identity     *RegionalRuntimeMembershipIdentity
	ownsIdentity bool

	membersMu       sync.Mutex
	members         map[string]RegionalRuntimeMember
	previousMembers map[string]RegionalRuntimeMember
	identityPins    map[string]string
	rejectedRecords int64

	stopping         context.CancelFunc
	stoppingCtx      context.Context
	watchLoopDone    chan struct{}
	heartbeatDone    chan struct{}
	selfObserved     chan struct{}
	selfOnce         sync.Once
	heartbeatStartMu sync.Mutex
	marshal          func(any) ([]byte, error)
	heartbeatTicks   <-chan time.Time
	heartbeatFailure atomic.Pointer[errorBox]
	revisionMu       sync.Mutex
	revision         uint64
	watchStarted     int32
	disposed         int32
	heartbeatStarted int32
}

// RegionalRuntimeMembershipStartAsync mirrors the C# StartAsync.
func RegionalRuntimeMembershipStartAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	topology *NatsTopology,
	build string,
	capabilities []string,
	startedAt time.Time,
	authority func() RegionalAuthoritySnapshot,
	identity *RegionalRuntimeMembershipIdentity,
) (*RegionalRuntimeMembership, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if store == nil || topology == nil {
		return nil, errors.New("(Parameter 'store')")
	}

	if strings.TrimSpace(build) == "" {
		return nil, errors.New(
			"The value cannot be an empty string or composed entirely of whitespace. (Parameter 'build')")
	}

	if authority == nil {
		return nil, errors.New("(Parameter 'authority')")
	}

	if len(capabilities) == 0 || !isOrdinallySortedAndDistinct(capabilities) ||
		anyStringWhitespace(capabilities) {
		return nil, errors.New(
			"Runtime capabilities must be non-empty, unique, and ordinally sorted. (Parameter 'capabilities')")
	}

	// A supplied identity remains caller-owned; identities generated here are
	// released when membership is disposed.
	ownsIdentity := identity == nil
	if identity == nil {
		generated, err := RegionalRuntimeMembershipIdentityCreate()
		if err != nil {
			return nil, err
		}

		identity = generated
	}

	sessionBytes := make([]byte, 16)
	if _, err := rand.Read(sessionBytes); err != nil {
		return nil, err
	}

	stoppingCtx, stopping := context.WithCancel(context.Background())
	membership := &RegionalRuntimeMembership{
		HeartbeatInterval: 5 * time.Second,
		LeaseDuration:     20 * time.Second,
		store:             store,
		topology:          topology,
		key:               "controller." + topology.Instance,
		sessionId:         hex.EncodeToString(sessionBytes),
		build:             build,
		capabilities:      append([]string(nil), capabilities...),
		startedAt:         startedAt,
		authority:         authority,
		identity:          identity,
		ownsIdentity:      ownsIdentity,
		members:           map[string]RegionalRuntimeMember{},
		previousMembers:   map[string]RegionalRuntimeMember{},
		identityPins:      map[string]string{},
		stopping:          stopping,
		stoppingCtx:       stoppingCtx,
		watchLoopDone:     make(chan struct{}),
		heartbeatDone:     make(chan struct{}),
		selfObserved:      make(chan struct{}),
		marshal:           json.Marshal,
	}

	if err := membership.claim(ctx); err != nil {
		_ = membership.Dispose()
		return nil, err
	}

	// Mark the watcher started before launching it so Dispose can distinguish a
	// live lifecycle from claim failures that occur before any goroutine exists.
	atomic.StoreInt32(&membership.watchStarted, 1)
	go membership.watchLoop()

	select {
	case <-membership.selfObserved:
	case <-time.After(5 * time.Second):
		_ = membership.Dispose()
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		_ = membership.Dispose()
		return nil, ctx.Err()
	}

	// Mark the loop started before launching it so Dispose cannot race with
	// goroutine startup and skip the completion wait.
	membership.heartbeatStartMu.Lock()
	atomic.StoreInt32(&membership.heartbeatStarted, 1)
	go membership.heartbeatLoop()
	membership.heartbeatStartMu.Unlock()

	return membership, nil
}

// Completion mirrors the C# Completion: the first loop to stop completes the
// membership.
func (m *RegionalRuntimeMembership) Completion() <-chan struct{} {
	if m == nil || m.watchLoopDone == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		var heartbeat <-chan struct{}
		if atomic.LoadInt32(&m.heartbeatStarted) != 0 {
			heartbeat = m.heartbeatDone
		}

		select {
		case <-m.watchLoopDone:
		case <-heartbeat:
		}

		close(done)
	}()

	return done
}

// Snapshot mirrors the C# Snapshot property.
func (m *RegionalRuntimeMembership) Snapshot() RegionalRuntimeMembershipSnapshot {
	if m == nil || m.topology == nil {
		return RegionalRuntimeMembershipSnapshot{}
	}
	now := time.Now().UTC()
	m.membersMu.Lock()
	records := make([]RegionalRuntimeMember, 0, len(m.members))
	for _, member := range m.members {
		// Once this process can no longer renew its own record, that record is
		// no longer a trustworthy representation of a live controller. Keep the
		// failure visible in health immediately instead of waiting for lease
		// expiry or a watcher update.
		if member.Instance == m.topology.Instance && m.LastFailure() != nil {
			continue
		}

		records = append(records, cloneRegionalRuntimeMember(member))
	}

	previous := make(map[string]RegionalRuntimeMember, len(m.previousMembers))
	for key, value := range m.previousMembers {
		previous[key] = value
	}

	rejected := atomic.LoadInt64(&m.rejectedRecords)
	m.membersMu.Unlock()

	active := make([]RegionalRuntimeMember, 0, len(records))
	for _, member := range records {
		if member.IsValidFor(m.topology.Cell, now) && member.LeaseExpiresAt.After(now) {
			active = append(active, member)
		}
	}

	sort.Slice(active, func(i, j int) bool { return active[i].Instance < active[j].Instance })

	// Conflicting sessions are a CURRENT gauge derived from the live records.
	conflicting := 0
	for _, member := range records {
		prior, exists := previous["controller."+member.Instance]
		if !exists {
			continue
		}

		if RegionalRuntimeMembershipReader.Classify(
			m.topology.Cell, member.Instance, nil, &prior, &member, now) ==
			RegionalRuntimeMembershipRecordClassConflictingSession {
			conflicting++
		}
	}

	health, err := RegionalRuntimeMembershipHealthEvaluate(
		m.topology.Cell, m.topology.Replicas, records, rejected, now, conflicting)
	if err != nil {
		panic(err)
	}

	return RegionalRuntimeMembershipSnapshot{
		SchemaVersion: 2,
		Cell:          m.topology.Cell,
		ObservedAt:    now,
		Health:        health,
		Members:       active,
	}
}

// Health mirrors the C# Health property.
func (m *RegionalRuntimeMembership) Health() RegionalRuntimeMembershipHealth {
	return m.Snapshot().Health
}

// LastFailure returns the terminal background-loop error, if any. Cancellation
// during normal disposal is not a failure.
func (m *RegionalRuntimeMembership) LastFailure() error {
	if m == nil {
		return nil
	}
	if boxed := m.heartbeatFailure.Load(); boxed != nil {
		return boxed.err
	}

	return nil
}

// Dispose mirrors the C# DisposeAsync.
func (m *RegionalRuntimeMembership) Dispose() error {
	if m == nil {
		return nil
	}
	if !atomic.CompareAndSwapInt32(&m.disposed, 0, 1) {
		return nil
	}
	if m.ownsIdentity && m.identity != nil {
		defer m.identity.Dispose()
	}

	if m.stopping != nil {
		m.stopping()
	}
	if atomic.LoadInt32(&m.watchStarted) != 0 {
		<-m.watchLoopDone
	}
	m.heartbeatStartMu.Lock()
	heartbeatStarted := atomic.LoadInt32(&m.heartbeatStarted) != 0
	m.heartbeatStartMu.Unlock()
	if heartbeatStarted {
		<-m.heartbeatDone
	}

	// The pure rule: only this session's own record, only under the
	// compare-and-swap revision this process still holds. A newer owner must
	// never lose its registration to a departing peer.
	revision := m.currentRevision()
	if revision != 0 {
		m.membersMu.Lock()
		current, hasCurrent := m.members[m.key]
		m.membersMu.Unlock()

		if hasCurrent && RegionalRuntimeMembershipMutation.MayDeleteCurrentRecord(
			m.sessionId, &current, revision) {
			deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := m.store.Delete(deleteCtx, m.key, jetstream.LastRevision(revision))
			cancel()
			if err != nil &&
				!errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
				if failure := m.LastFailure(); failure != nil {
					return failure
				}

				return err
			}
		}
	}
	return m.LastFailure()
}

func (m *RegionalRuntimeMembership) claim(ctx context.Context) error {
	document, err := m.document(time.Now().UTC())
	if err != nil {
		return err
	}

	value, err := json.Marshal(document)
	if err != nil {
		return err
	}

	revision, err := m.store.Create(ctx, m.key, value)
	if err == nil {
		m.setRevision(revision)
		return nil
	}

	if !errors.Is(err, jetstream.ErrKeyExists) && !errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return err
	}

	// The slot already exists. Re-read, decide, and execute under the observed
	// revision; a lost compare-and-swap race re-reads the winner and re-decides.
	for attempt := 0; ; attempt++ {
		entry, err := m.store.Get(ctx, m.key)
		if err != nil {
			return err
		}

		existing, err := regionalRuntimeMembershipDeserialize(string(entry.Value()))
		if err != nil {
			return err
		}

		now := time.Now().UTC()
		if !existing.IsValidFor(m.topology.Cell, now) || existing.Instance != m.topology.Instance {
			return fmt.Errorf(
				"The regional runtime membership key '%s' contains a record that is invalid or bound to "+
					"another instance. The record's own lease is the first recovery path; if the key stays wedged "+
					"past it, an operator must purge '%s' from the %s bucket after the "+
					"record's lease has lapsed, and this instance will then claim the empty slot.",
				m.key, m.key, m.topology.Runtime().Bucket)
		}

		decision := RegionalRuntimeMembershipMutation.Decide(
			m.topology.Cell, m.topology.Instance, document, &existing, now)
		switch decision {
		case RegionalRuntimeMembershipMutationClassTakeOverExpiredLease:
			// Healing: the previous semantic lease has fully lapsed, so the
			// slot is safely reclaimable under the observed revision.
			revision, err := m.store.Update(ctx, m.key, value, entry.Revision())
			if err == nil {
				m.setRevision(revision)
				return nil
			}

			if errors.Is(err, jetstream.ErrKeyRevisionMismatch) && attempt < 2 {
				continue
			}

			return err
		case RegionalRuntimeMembershipMutationClassHoldForLiveForeignLease:
			return fmt.Errorf(
				"Controller instance '%s' already has an active membership lease.", m.topology.Instance)
		default:
			return fmt.Errorf(
				"The regional runtime membership claim was refused (%s).", decision)
		}
	}
}

func (m *RegionalRuntimeMembership) heartbeatLoop() {
	defer close(m.heartbeatDone)

	var ticks <-chan time.Time
	var stopTicker func()
	if m.heartbeatTicks != nil {
		ticks = m.heartbeatTicks
	} else {
		ticker := time.NewTicker(m.HeartbeatInterval)
		ticks = ticker.C
		stopTicker = ticker.Stop
	}
	if stopTicker != nil {
		defer stopTicker()
	}

	for {
		select {
		case <-m.stoppingCtx.Done():
			return
		case <-ticks:
		}

		if err := m.heartbeatOnce(); err != nil {
			if !errors.Is(err, context.Canceled) {
				m.heartbeatFailure.Store(&errorBox{err: err})
				if m.stopping != nil {
					m.stopping()
				}
			}

			return
		}
	}
}

func (m *RegionalRuntimeMembership) heartbeatOnce() error {
	document, err := m.document(time.Now().UTC())
	if err != nil {
		return err
	}

	marshal := m.marshal
	if marshal == nil {
		marshal = json.Marshal
	}
	value, err := marshal(document)
	if err != nil {
		return err
	}

	currentRevision := m.currentRevision()
	revision, err := m.store.Update(m.stoppingCtx, m.key, value, currentRevision)
	if err != nil {
		return err
	}

	m.setRevision(revision)
	return nil
}

func (m *RegionalRuntimeMembership) currentRevision() uint64 {
	m.revisionMu.Lock()
	defer m.revisionMu.Unlock()
	return m.revision
}

func (m *RegionalRuntimeMembership) setRevision(revision uint64) {
	m.revisionMu.Lock()
	m.revision = revision
	m.revisionMu.Unlock()
}

func (m *RegionalRuntimeMembership) watchLoop() {
	defer close(m.watchLoopDone)

	for {
		watcher, err := m.store.Watch(m.stoppingCtx, "controller.>")
		if err != nil {
			select {
			case <-m.stoppingCtx.Done():
				return
			case <-time.After(time.Second):
			}

			continue
		}

		for entry := range watcher.Updates() {
			if entry == nil {
				continue
			}

			key := entry.Key()
			deleted := entry.Value() == nil ||
				entry.Operation() != jetstream.KeyValuePut

			if deleted {
				m.removeMember(key)
				continue
			}

			member, err := regionalRuntimeMembershipDeserialize(string(entry.Value()))
			if err != nil {
				m.rejectMember(key)
				continue
			}

			if !member.IsValidFor(m.topology.Cell, time.Now().UTC()) ||
				key != "controller."+member.Instance {
				m.rejectMember(key)
				continue
			}

			if !member.VerifySignedIdentity() {
				m.rejectMember(key)
				continue
			}

			m.membersMu.Lock()
			pinnedKey, pinned := m.identityPins[key]
			if !pinned {
				m.identityPins[key] = member.IdentityPublicKey
				pinnedKey = member.IdentityPublicKey
			}
			m.membersMu.Unlock()

			if pinnedKey != member.IdentityPublicKey {
				// Key continuity: a different key is only accepted as a healing
				// takeover once the previously observed record's lease has
				// fully lapsed.
				m.membersMu.Lock()
				pinnedPrevious, hasPrevious := m.members[key]
				m.membersMu.Unlock()

				if !hasPrevious || pinnedPrevious.LeaseExpiresAt.After(time.Now().UTC()) {
					m.rejectMember(key)
					continue
				}

				m.membersMu.Lock()
				m.identityPins[key] = member.IdentityPublicKey
				m.membersMu.Unlock()
			}

			// Stash the outgoing record unconditionally: the snapshot's CURRENT
			// conflicting-session gauge classifies the live record against the
			// immediately preceding one.
			m.membersMu.Lock()
			if previous, exists := m.members[key]; exists {
				m.previousMembers[key] = previous
			}

			m.members[key] = member
			m.membersMu.Unlock()

			if key == m.key && member.SessionId == m.sessionId {
				m.selfOnce.Do(func() { close(m.selfObserved) })
			}
		}

		watcher.Stop()
		select {
		case <-m.stoppingCtx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (m *RegionalRuntimeMembership) removeMember(key string) {
	m.membersMu.Lock()
	delete(m.members, key)
	delete(m.previousMembers, key)
	delete(m.identityPins, key)
	m.membersMu.Unlock()
}

func (m *RegionalRuntimeMembership) rejectMember(key string) {
	atomic.AddInt64(&m.rejectedRecords, 1)
	m.removeMember(key)
}

func (m *RegionalRuntimeMembership) document(observedAt time.Time) (RegionalRuntimeMember, error) {
	authoritySnapshot := m.authority()
	if !authoritySnapshot.Ready() {
		return RegionalRuntimeMember{}, errors.New(
			"A controller cannot advertise membership without current regional authority state.")
	}

	unsigned := RegionalRuntimeMember{
		SchemaVersion:     1,
		Cell:              m.topology.Cell,
		Cluster:           "orchestrator-control-" + m.topology.Cell,
		Instance:          m.topology.Instance,
		SessionId:         m.sessionId,
		Build:             m.build,
		Capabilities:      append([]string(nil), m.capabilities...),
		StartedAt:         m.startedAt,
		ObservedAt:        observedAt,
		LeaseExpiresAt:    observedAt.Add(m.LeaseDuration),
		AuthorityState:    authoritySnapshot.State,
		IsAuthorityLeader: authoritySnapshot.IsLeader,
		AuthorityEpoch:    authoritySnapshot.Epoch,
		AuthorityRevision: authoritySnapshot.KvRevision,
		IdentityKeyId:     m.identity.KeyId,
		IdentityPublicKey: m.identity.PublicKey,
		IdentitySignature: "",
	}
	unsigned.IdentitySignature = m.identity.Sign(unsigned)

	return unsigned, nil
}

func regionalRuntimeMembershipDeserialize(value string) (RegionalRuntimeMember, error) {
	var member RegionalRuntimeMember
	if err := json.Unmarshal([]byte(value), &member); err != nil {
		return RegionalRuntimeMember{}, err
	}

	return member, nil
}

// cloneRegionalRuntimeMember prevents callers of Snapshot from retaining the
// internal capabilities backing array. Without this copy, a caller mutating a
// returned snapshot could race the heartbeat serializer or alter the next
// membership record.
func cloneRegionalRuntimeMember(member RegionalRuntimeMember) RegionalRuntimeMember {
	member.Capabilities = append([]string(nil), member.Capabilities...)
	return member
}

func isOrdinallySortedAndDistinct(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}

	return true
}

func allCapabilitiesBounded(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}

	return true
}

func anyStringWhitespace(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}

	return false
}

func isDotNetGuidNoHyphens(value string) bool {
	if len(value) != 32 {
		return false
	}

	return isLowercaseHexOrUpperHex(value)
}

func isLowercaseHexOrUpperHex(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= '0' && character <= '9' ||
			character >= 'a' && character <= 'f' ||
			character >= 'A' && character <= 'F' {
			continue
		}

		return false
	}

	return true
}

func isLowercaseHex(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}

		return false
	}

	return true
}

func isBase64Shape(value string) bool {
	if len(value)%4 != 0 {
		return false
	}

	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '+' || character == '/' || character == '=' {
			continue
		}

		return false
	}

	return true
}

func maxInt(first, second int) int {
	if first > second {
		return first
	}

	return second
}
