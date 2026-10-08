package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/artifact"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Controller holds the durable host authority and serves restricted host RPCs.
// Administrative callers own admission of Register and ApplyDesired operations.
type Controller struct {
	cell                   string
	conn                   *nats.Conn
	sessionRead            func(context.Context, string) (session, uint64, bool, error)
	state                  jetstream.KeyValue
	controlLog             jetstream.Stream
	readOnly               bool
	mutations              authority.HostMutationStore
	quarantines            map[string]retirementQuarantineEntry
	managedVerifier        ManagedRegistrationVerifier
	managedDesiredVerifier ManagedDesiredVerifier
	managedEffectGate      func(context.Context, uint64, authority.WorkloadScope) (func(), error)
	materialProvider       ManagedMaterialProvider
	credentialFloor        func(context.Context, Registration) (uint64, error)
	volumeInspector        ManagedVolumeInspector
	terraBaseCA            *terrabase.CA
	roleIdentity           RoleIdentityIssuer
	nodeAddress            func(string) string
	restartGate            func(context.Context, string, Desired) (bool, error)
	artifacts              ArtifactStore
	responseKey            ed25519.PrivateKey
	registrationMu         sync.Mutex
	controlLogInfoOnce     sync.Once
	controlLogInfoGate     chan struct{}
	usageHistory           authority.HostHistory
	// retireMu orders RetireIdle against this process's desired commits,
	// which hold it for reading; the ordered log retains retirement marks
	// so a later leader enforces them too.
	retireMu        sync.RWMutex
	ready           chan struct{}
	readyOnce       sync.Once
	cacheMu         sync.Mutex
	workloadCache   artifactCache
	netbirdCache    artifactCache
	cacheClosed     bool
	cacheCancel     context.CancelFunc
	cacheContext    context.Context
	sessionDiagMu   sync.Mutex
	sessionDiagAt   map[string]time.Time
	authorityEpoch  func() uint64
	authorityGuard  func(context.Context, uint64) error
	authorityLeader func() bool
	// loadSink, when set, accepts "load" host telemetry; see SetLoadSink.
	loadSink atomic.Pointer[LoadSink]
	// rolloutSink, when set, serves host self-updates; see SetRolloutSink.
	rolloutSink atomic.Pointer[RolloutSink]
	netbirdSink atomic.Pointer[NetBirdSink]
}

func NewController(ctx context.Context, cfg ControllerConfig) (*Controller, error) {
	if err := validateToken(cfg.Cell, "cell"); err != nil {
		return nil, err
	}
	if cfg.Conn == nil || cfg.JS == nil || cfg.Artifacts == nil || cfg.HostMutations == nil || len(cfg.ResponseKey) != ed25519.PrivateKeySize {
		return nil, errors.New("controller requires NATS, JetStream, ordered host mutations, artifact store and Ed25519 response key")
	}
	if cfg.AuthorityEpoch == nil || cfg.AuthorityGuard == nil {
		return nil, errors.New("controller requires authority epoch and guard")
	}
	managedEffectGate := cfg.ManagedEffectGate
	if managedEffectGate == nil {
		if gate, ok := cfg.HostMutations.(interface {
			BeginActiveWorkloadEffect(context.Context, uint64, authority.WorkloadScope) (func(), error)
		}); ok {
			managedEffectGate = gate.BeginActiveWorkloadEffect
		}
	}
	if cfg.ManagedRegistrationVerifier != nil && managedEffectGate == nil {
		return nil, errors.New("managed host registration requires a terminal effect gate")
	}
	replicas := cfg.StateReplicas
	if replicas == 0 {
		replicas = 3
	}
	if replicas < 1 || replicas > 5 {
		return nil, errors.New("invalid host state replica count")
	}
	state := cfg.State
	if state == nil {
		var err error
		state, err = cfg.JS.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: stateBucket, History: 2, MaxValueSize: 64 << 10, MaxBytes: 256 << 20, Storage: jetstream.FileStorage, Replicas: replicas})
		if err != nil {
			return nil, fmt.Errorf("open host state: %w", err)
		}
	}
	status, err := state.Status(ctx)
	if err != nil {
		return nil, err
	}
	if status.Config().Replicas != replicas {
		return nil, fmt.Errorf("host state has %d replicas, requires %d", status.Config().Replicas, replicas)
	}
	quarantines, err := loadRetirementQuarantines(ctx, cfg.Conn, state, cfg.Cell)
	if err != nil {
		return nil, err
	}
	controlLog := cfg.ControlLog
	if controlLog == nil {
		controlLog, err = cfg.JS.Stream(ctx, "TS_CONTROL_LOG")
		if err != nil {
			return nil, fmt.Errorf("open ordered control log: %w", err)
		}
	}
	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	return &Controller{cell: cfg.Cell, conn: cfg.Conn, state: state, controlLog: controlLog, mutations: cfg.HostMutations,
		quarantines:     quarantines,
		managedVerifier: cfg.ManagedRegistrationVerifier, managedDesiredVerifier: cfg.ManagedDesiredVerifier,
		managedEffectGate: managedEffectGate, materialProvider: cfg.ManagedMaterialProvider,
		credentialFloor: cfg.ManagedCredentialFloor, volumeInspector: cfg.ManagedVolumeInspector,
		terraBaseCA: cfg.TerraBaseCA, roleIdentity: cfg.RoleIdentity, nodeAddress: cfg.NodeAddress, restartGate: cfg.RestartGate, artifacts: cfg.Artifacts, responseKey: cfg.ResponseKey, ready: make(chan struct{}),
		authorityEpoch: cfg.AuthorityEpoch, authorityGuard: cfg.AuthorityGuard, authorityLeader: cfg.AuthorityLeader,
		cacheContext: cacheCtx, cacheCancel: cacheCancel}, nil
}

// Ready closes once all host request subscriptions are accepted by NATS.
func (c *Controller) Ready() <-chan struct{} { return c.ready }

func (c *Controller) guard(ctx context.Context, epoch uint64) error {
	if c.authorityGuard == nil {
		return nil
	}
	if epoch == 0 || c.authorityEpoch() != epoch {
		return fmt.Errorf("%w: host authority epoch is stale", authority.ErrFenced)
	}
	return c.authorityGuard(ctx, epoch)
}

func sessionKey(cell, node string) string       { return "session." + cell + "." + node }
func desiredKey(cell, node, role string) string { return "desired." + cell + "." + node + "." + role }
func reportKey(cell, node, role string) string  { return "report." + cell + "." + node + "." + role }
func cycleKey(cell, node, role string) string   { return "cycle." + cell + "." + node + "." + role }

func (c *Controller) get(ctx context.Context, key string, destination any) (uint64, bool, error) {
	if c.conn != nil {
		return c.readLeaderState(ctx, key, destination)
	}
	// Only package tests construct a Controller without the connection required
	// by NewController and NewReader.
	entry, err := c.state.Get(ctx, key)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if entry.Operation() != jetstream.KeyValuePut {
		return 0, false, errors.New("host state has a tombstone")
	}
	if err := decodeStrict(entry.Value(), destination); err != nil {
		return 0, false, fmt.Errorf("corrupt host state %s: %w", key, err)
	}
	return entry.Revision(), true, nil
}

func (c *Controller) cas(ctx context.Context, key string, value any, revision uint64) (uint64, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	if len(data) > 64<<10 {
		return 0, errors.New("host state value too large")
	}
	if revision == 0 {
		return c.state.Create(ctx, key, data)
	}
	return c.state.Update(ctx, key, data, revision)
}

// sessionSnapshot uses the stream leader because KV.Get can read a lagging
// replica when the bucket has direct reads enabled.
func (c *Controller) sessionSnapshot(ctx context.Context, key string) (session, uint64, bool, error) {
	if c.sessionRead != nil {
		return c.sessionRead(ctx, key)
	}
	return c.readLeaderSession(ctx, key)
}

func (c *Controller) readLeaderSession(ctx context.Context, key string) (session, uint64, bool, error) {
	var s session
	revision, exists, err := c.readLeaderState(ctx, key, &s)
	return s, revision, exists, err
}

func (c *Controller) reportSnapshot(ctx context.Context, key string) (Report, uint64, bool, error) {
	var report Report
	revision, exists, err := c.readLeaderState(ctx, key, &report)
	return report, revision, exists, err
}

func (c *Controller) readLeaderState(ctx context.Context, key string, destination any) (uint64, bool, error) {
	if c.conn == nil { // Only package tests construct a controller without Conn.
		return c.get(ctx, key, destination)
	}
	js, err := c.conn.JetStream()
	if err != nil {
		return 0, false, err
	}
	subject := "$KV." + stateBucket + "." + key
	msg, err := js.GetLastMsg("KV_"+stateBucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if msg == nil || msg.Subject != subject || msg.Sequence == 0 {
		return 0, false, errors.New("invalid host state")
	}
	if operation := msg.Header.Get("KV-Operation"); operation != "" {
		if operation == "DEL" || operation == "PURGE" {
			return 0, false, nil
		}
		return 0, false, errors.New("invalid host state operation")
	}
	if marker := msg.Header.Get(jetstream.MarkerReasonHeader); marker != "" {
		if marker == "MaxAge" || marker == "Purge" || marker == "Remove" {
			return 0, false, nil
		}
		return 0, false, errors.New("invalid host state marker")
	}
	if len(msg.Data) > 64<<10 {
		return 0, false, errors.New("invalid host state")
	}
	if err := decodeStrict(msg.Data, destination); err != nil {
		return 0, false, fmt.Errorf("corrupt host state %s: %w", key, err)
	}
	return msg.Sequence, true, nil
}

// Register admits a public host key and role scope. A generation is immutable.
func (c *Controller) Register(ctx context.Context, r Registration) (Receipt, error) {
	id := entityid.Derive("host", r.Cell, r.Node)
	if r.ID != "" && r.ID != id {
		return Receipt{}, errors.New("host ID differs from its node identity")
	}
	r.ID = id
	if err := validateRegistration(r, c.cell); err != nil {
		return Receipt{}, err
	}
	if _, quarantined := c.quarantines[r.Node]; quarantined {
		return Receipt{}, ErrHostRetiring
	}
	if r.ManagedOCI != nil && r.ManagedPlacement == nil {
		return Receipt{}, errors.New("managed host registration requires current schema-3 placement pins")
	}
	authorityEpoch := c.authorityEpoch()
	if err := c.guard(ctx, authorityEpoch); err != nil {
		return Receipt{}, err
	}
	if r.ManagedMember != nil {
		if c.managedEffectGate == nil || r.ManagedPlacement == nil {
			return Receipt{}, errors.New("managed host registration requires a terminal effect gate and placement scope")
		}
		release, err := c.managedEffectGate(ctx, authorityEpoch, authority.WorkloadScope{
			DatabaseID: r.ManagedPlacement.DatabaseID, PartitionID: r.ManagedPlacement.PartitionID,
		})
		if err != nil {
			return Receipt{}, err
		}
		defer release()
	}
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	payload, operationID, err := mutationPayload(r)
	if err != nil {
		return Receipt{}, err
	}
	key := registrationSubjectKey(c.cell, r.Node)
	for range 8 {
		if r.ManagedMember != nil {
			if c.managedVerifier == nil {
				return Receipt{}, errors.New("managed host registration requires a current placement verifier")
			}
			if err := c.managedVerifier.VerifyManagedRegistration(ctx, r); err != nil {
				return Receipt{}, fmt.Errorf("verify managed host registration: %w", err)
			}
			if err := c.requireExclusiveManagedMember(ctx, r); err != nil {
				return Receipt{}, err
			}
		}
		current, revision, exists, err := c.readRegistration(ctx, r.Node)
		if err != nil {
			return Receipt{}, err
		}
		if exists {
			if (current.ManagedOCI == nil) != (r.ManagedOCI == nil) ||
				current.ManagedOCI != nil && (current.ManagedMember == nil || *current.ManagedOCI != *r.ManagedOCI ||
					*current.ManagedMember != *r.ManagedMember || current.FailureDomain != r.FailureDomain) {
				return Receipt{}, errors.New("host managed binding cannot be retargeted")
			}
			if r.Generation < current.Generation {
				return Receipt{}, errors.New("registration generation moved backward")
			}
			if r.Generation == current.Generation {
				if !sameJSON(r, current) {
					return Receipt{}, errors.New("registration changed without a generation increase")
				}
				return Receipt{r.Generation, revision}, nil
			}
		}
		if err := c.guard(ctx, authorityEpoch); err != nil {
			return Receipt{}, err
		}
		written, err := c.mutations.CommitHostMutation(ctx, authorityEpoch, authority.MutationRegistration, key, operationID, revision, payload)
		if err == nil {
			return Receipt{r.Generation, written}, nil
		}
		if !errors.Is(err, authority.ErrConflict) {
			return Receipt{}, err
		}
	}
	return Receipt{}, errors.New("registration contention")
}

func (c *Controller) requireExclusiveManagedMember(ctx context.Context, candidate Registration) error {
	if c.controlLog == nil {
		return errors.New("managed member exclusivity requires ordered control log")
	}
	prefix := protocol.Control(c.cell, "host", "registration", c.cell) + "."
	info, err := c.controlLogSubjects(ctx, prefix+"*")
	if err != nil {
		return err
	}
	for subject := range info.State.Subjects {
		node, ok := strings.CutPrefix(subject, prefix)
		if !ok || validateToken(node, "node") != nil {
			return errors.New("managed member registration subject is invalid")
		}
		if node == candidate.Node {
			continue
		}
		other, _, exists, err := c.readRegistration(ctx, node)
		if err != nil {
			return err
		}
		if exists && other.ManagedMember != nil && sameLogicalMember(other.ManagedMember.Scope, candidate.ManagedMember.Scope) {
			// A replacement host carries the next host attempt of the same
			// logical member. The verifier has already bound the candidate to
			// the seat's current durable attempt, which the placement
			// controller only advances through its fenced, evidence-gated
			// replacement once the previous host is proven lost. An older
			// attempt's registration therefore no longer owns the member;
			// an equal or newer one still does.
			if other.ManagedMember.HostAttempt < candidate.ManagedMember.HostAttempt {
				continue
			}
			return errors.New("managed member is already bound to another host")
		}
	}
	return nil
}

func sameLogicalMember(a, b MemberScope) bool {
	return a.ClusterID == b.ClusterID && a.TenantID == b.TenantID && a.DatabaseID == b.DatabaseID &&
		a.ShardID == b.ShardID && a.MemberID == b.MemberID
}

// ApplyDesired persists one exact node/role target. It never rewrites a generation.
func (c *Controller) ApplyDesired(ctx context.Context, d Desired) (Receipt, error) {
	if err := c.guard(ctx, d.AuthorityEpoch); err != nil {
		return Receipt{}, err
	}
	c.retireMu.RLock()
	defer c.retireMu.RUnlock()
	if !d.Withdrawn {
		retired, err := c.retired(ctx, d.Node)
		if err != nil {
			return Receipt{}, err
		}
		if retired {
			return Receipt{}, fmt.Errorf("%w: %s", ErrHostRetiring, d.Node)
		}
	}
	r, _, exists, err := c.readRegistration(ctx, d.Node)
	if err != nil {
		return Receipt{}, err
	}
	if !exists {
		return Receipt{}, errors.New("host is not registered")
	}
	if err := validateDesired(d, c.cell, r); err != nil {
		return Receipt{}, err
	}
	if d.ManagedMember != nil && !d.Withdrawn {
		if c.managedEffectGate == nil || r.ManagedPlacement == nil || c.managedDesiredVerifier == nil {
			return Receipt{}, errors.New("managed desired requires a terminal effect gate, placement scope and durable verifier")
		}
		release, err := c.managedEffectGate(ctx, d.AuthorityEpoch, authority.WorkloadScope{
			DatabaseID: r.ManagedPlacement.DatabaseID, PartitionID: r.ManagedPlacement.PartitionID,
		})
		if err != nil {
			return Receipt{}, err
		}
		defer release()
	}
	bucket := ""
	if !d.Withdrawn {
		info, err := c.artifacts.GetInfo(ctx, "sha256-"+d.Digest)
		if err != nil {
			return Receipt{}, err
		}
		if info.Deleted || info.Opts != nil && info.Opts.Link != nil || info.Size == 0 || info.Size > maxArtifactBytes {
			return Receipt{}, errors.New("artifact is absent, linked or outside size limit")
		}
		bucket = info.Bucket
	}
	payload, operationID, err := mutationPayload(d)
	if err != nil {
		return Receipt{}, err
	}
	key := desiredSubjectKey(c.cell, d.Node, d.Role)
	for range 8 {
		currentRegistration, _, registered, err := c.readRegistration(ctx, d.Node)
		if err != nil {
			return Receipt{}, err
		}
		if !registered || validateDesired(d, c.cell, currentRegistration) != nil {
			return Receipt{}, errors.New("registration changed before desired commit")
		}
		current, revision, exists, err := c.readDesired(ctx, d.Node, d.Role)
		if err != nil {
			return Receipt{}, err
		}
		if exists {
			if (current.ManagedMember == nil) != (d.ManagedMember == nil) {
				return Receipt{}, fmt.Errorf("%w: managed desired kind changed", ErrDesiredConflict)
			}
			if current.ManagedMember != nil && d.ManagedMember != nil &&
				(current.ManagedMember.Member != d.ManagedMember.Member || current.ManagedMember.OCI != d.ManagedMember.OCI ||
					current.ManagedMember.VolumeID != d.ManagedMember.VolumeID || current.ManagedMember.AttachmentID != d.ManagedMember.AttachmentID) {
				return Receipt{}, fmt.Errorf("%w: managed member or attachment retargeted", ErrDesiredConflict)
			}
			if d.AuthorityEpoch < current.AuthorityEpoch || d.Generation < current.Generation {
				return Receipt{}, fmt.Errorf("%w: generation or epoch moved backward", ErrDesiredConflict)
			}
			if d.Generation == current.Generation {
				if !sameDesiredTarget(d, current) {
					return Receipt{}, fmt.Errorf("%w: target changed within a generation", ErrDesiredConflict)
				}
				if d.AuthorityEpoch == current.AuthorityEpoch {
					return Receipt{d.Generation, revision}, nil
				}
			}
		}
		// The artifact collector deletes only metadata nobody touched since
		// it chose the artifact, so it cannot delete the bytes this desired
		// is about to name.
		if bucket != "" && c.conn != nil {
			js, err := c.conn.JetStream()
			if err != nil {
				return Receipt{}, err
			}
			if err := artifact.Touch(ctx, js, bucket, "sha256-"+d.Digest); err != nil {
				return Receipt{}, fmt.Errorf("pin desired artifact: %w", err)
			}
		}
		if err := c.guard(ctx, d.AuthorityEpoch); err != nil {
			return Receipt{}, err
		}
		var written uint64
		if d.ManagedMember != nil && !d.Withdrawn {
			verified, ok := c.mutations.(authority.VerifiedHostMutationStore)
			if !ok {
				return Receipt{}, errors.New("managed desired mutation store lacks a final verifier fence")
			}
			verify := func(verifyCtx context.Context) error {
				return c.managedDesiredVerifier(verifyCtx, d, currentRegistration, current, exists)
			}
			written, err = verified.CommitHostMutationVerified(ctx, d.AuthorityEpoch, authority.MutationDesired,
				key, operationID, revision, payload, verify)
		} else {
			written, err = c.mutations.CommitHostMutation(ctx, d.AuthorityEpoch, authority.MutationDesired,
				key, operationID, revision, payload)
		}
		if err == nil {
			return Receipt{d.Generation, written}, nil
		}
		if !errors.Is(err, authority.ErrConflict) {
			return Receipt{}, err
		}
	}
	return Receipt{}, errors.New("desired contention")
}

// ErrHostRetiring refuses a new allocation on a host that is being
// terminated.
var ErrHostRetiring = errors.New("host is being retired")

// retirement is a node's retirement state in the ordered control log.
type retirement struct {
	Retired bool `json:"retired"`
}

func (c *Controller) retired(ctx context.Context, node string) (bool, error) {
	if _, quarantined := c.quarantines[node]; quarantined {
		return true, nil
	}
	mark, _, err := c.readRetirement(ctx, node)
	return mark.Retired, err
}

func (c *Controller) markRetired(ctx context.Context, epoch uint64, node string, retired bool) error {
	if err := c.guard(ctx, epoch); err != nil {
		return err
	}
	if _, quarantined := c.quarantines[node]; quarantined {
		return ErrHostRetiring
	} else if err := c.requireRetirementCutover(ctx); err != nil {
		return err
	}
	data, operation, err := mutationPayload(retirement{Retired: retired})
	if err != nil {
		return err
	}
	for range 8 {
		mark, revision, err := c.readRetirement(ctx, node)
		if err != nil {
			return err
		}
		if mark.Retired == retired {
			return nil
		}
		_, err = c.mutations.CommitHostMutation(ctx, epoch, authority.MutationRetirement, registrationSubjectKey(c.cell, node), operation, revision, data)
		if err == nil {
			return nil
		}
		if !errors.Is(err, authority.ErrConflict) {
			return fmt.Errorf("mark %s retired=%t: %w", node, retired, err)
		}
	}
	return errors.New("host retirement contention")
}

// RetireIdle retires node if it holds no active allocation and reports
// whether it did. A retired node takes no new allocation until Unretire,
// also from a later leader: the mark is in the log and every desired
// commit reads it. Withdrawals still apply. The process lock excludes desired
// commits during the idle check; the captured epoch fences leadership changes.
func (c *Controller) RetireIdle(ctx context.Context, node string) (bool, error) {
	c.retireMu.Lock()
	defer c.retireMu.Unlock()
	epoch := c.authorityEpoch()
	if err := c.guard(ctx, epoch); err != nil {
		return false, err
	}
	desired, err := c.ListDesired(ctx, "")
	if err != nil {
		return false, err
	}
	for _, d := range desired {
		if d.Node == node && !d.Withdrawn {
			return false, nil
		}
	}
	if err := c.markRetired(ctx, epoch, node, true); err != nil {
		return false, err
	}
	return true, nil
}

// Unretire lets node take allocations again: a new host under a retired
// host's name.
func (c *Controller) Unretire(ctx context.Context, node string) error {
	c.retireMu.Lock()
	defer c.retireMu.Unlock()
	return c.markRetired(ctx, c.authorityEpoch(), node, false)
}

func sameDesiredTarget(a, b Desired) bool {
	a.AuthorityEpoch = 0
	b.AuthorityEpoch = 0
	return sameJSON(a, b)
}

func sameJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

func casConflict(err error) bool {
	return errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch)
}

// controlLogSubjects reads the control log's state for the subjects matching
// filter. jetstream's Stream.Info caches its reply in the shared handle
// without a lock; Info and history GetMsg calls share this lock because
// GetMsg reads that cached configuration too.
func (c *Controller) controlLogSubjects(ctx context.Context, filter string) (*jetstream.StreamInfo, error) {
	if err := c.lockControlLog(ctx); err != nil {
		return nil, err
	}
	defer func() { <-c.controlLogInfoGate }()
	return c.controlLog.Info(ctx, jetstream.WithSubjectFilter(filter))
}

func (c *Controller) lockControlLog(ctx context.Context) error {
	c.controlLogInfoOnce.Do(func() { c.controlLogInfoGate = make(chan struct{}, 1) })
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.controlLogInfoGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Controller) ListHosts(ctx context.Context) ([]HostStatus, error) {
	if c.controlLog == nil {
		return nil, errors.New("ordered control log is required for host discovery")
	}
	prefix := protocol.Control(c.cell, "host", "registration", c.cell) + "."
	info, err := c.controlLogSubjects(ctx, prefix+"*")
	if err != nil {
		return nil, err
	}
	var hosts []HostStatus
	for subject := range info.State.Subjects {
		node, ok := strings.CutPrefix(subject, prefix)
		if !ok || validateToken(node, "node") != nil {
			return nil, errors.New("host registration subject is invalid")
		}
		r, registrationRevision, exists, err := c.readRegistration(ctx, node)
		if err != nil {
			return nil, err
		} else if !exists {
			continue
		}
		retirement, retirementRevision, err := c.readRetirement(ctx, node)
		if err != nil {
			return nil, err
		}
		status := HostStatus{Registration: r, Retired: retirement.Retired, Verified: !c.readOnly}
		s, _, exists, err := c.sessionSnapshot(ctx, sessionKey(c.cell, r.Node))
		if err != nil {
			return nil, err
		}
		if exists && s.RegistrationGeneration == r.Generation && time.Now().Before(s.ExpiresAt) {
			status.SessionExpiresAt = s.ExpiresAt
			for _, role := range r.Roles {
				report, _, ok, err := c.reportSnapshot(ctx, reportKey(c.cell, r.Node, role))
				if err != nil {
					return nil, err
				}
				if !ok || report.Cell != c.cell || report.Node != r.Node || report.Environment != r.Environment || report.Role != role ||
					report.SessionID != s.SessionID || report.Epoch != s.Epoch || time.Since(report.ObservedAt) >= ReportMaxAge || report.ObservedAt.After(time.Now().Add(maxClockSkew)) {
					continue
				}
				desired, desiredRevision, ok, err := c.readDesired(ctx, r.Node, role)
				if err != nil {
					return nil, err
				}
				if !ok || report.Generation != desired.Generation || report.Digest != desired.Digest || desired.Withdrawn && report.State == "running" ||
					validateManagedReportForDesired(report, desired) != nil {
					continue
				}
				confirmed, confirmedRevision, ok, err := c.readDesired(ctx, r.Node, role)
				if err != nil || !ok || confirmedRevision != desiredRevision || !sameJSON(confirmed, desired) {
					return nil, errors.New("desired changed during host status read")
				}
				check, _, ok, err := c.reportSnapshot(ctx, reportKey(c.cell, r.Node, role))
				if err != nil || !ok || check.ObservedAt.Before(report.ObservedAt) || !sameReportMeaning(check, report) ||
					check.SessionID != s.SessionID || check.Epoch != s.Epoch || check.Generation != desired.Generation || check.Digest != desired.Digest ||
					validateManagedReportForDesired(check, desired) != nil ||
					time.Since(check.ObservedAt) >= ReportMaxAge || check.ObservedAt.After(time.Now().Add(maxClockSkew)) || desired.Withdrawn && check.State == "running" {
					return nil, errors.New("report changed during host status read")
				}
				status.Reports = append(status.Reports, check)
			}
			check, _, ok, err := c.sessionSnapshot(ctx, sessionKey(c.cell, r.Node))
			if err != nil || !ok || check.RegistrationGeneration != r.Generation || check.SessionID != s.SessionID || check.Epoch != s.Epoch || !time.Now().Before(check.ExpiresAt) {
				return nil, errors.New("session changed during host status read")
			}
			status.SessionExpiresAt = check.ExpiresAt
		}
		confirmed, confirmedRevision, ok, err := c.readRegistration(ctx, node)
		if err != nil || !ok || confirmedRevision != registrationRevision || !sameJSON(confirmed, r) {
			return nil, errors.New("registration changed during host status read")
		}
		if _, revision, err := c.readRetirement(ctx, node); err != nil || revision != retirementRevision {
			return nil, errors.New("retirement changed during host status read")
		}
		hosts = append(hosts, status)
	}
	slices.SortFunc(hosts, func(a, b HostStatus) int { return strings.Compare(a.Registration.Node, b.Registration.Node) })
	return hosts, nil
}

func sameReportMeaning(a, b Report) bool {
	a.ObservedAt = time.Time{}
	b.ObservedAt = time.Time{}
	if a.Managed != nil && a.Managed.ServingProof != nil {
		managed, proof := *a.Managed, *a.Managed.ServingProof
		proof.Nonce = ""
		managed.ServingProof = &proof
		a.Managed = &managed
	}
	if b.Managed != nil && b.Managed.ServingProof != nil {
		managed, proof := *b.Managed, *b.Managed.ServingProof
		proof.Nonce = ""
		managed.ServingProof = &proof
		b.Managed = &managed
	}
	return sameJSON(a, b)
}

// hostOperations are the host request subjects a leader serves.
var hostOperations = []string{"session", "desired", "artifact", "material", "cycle", "report",
	"drain-command", "drain-result", "backup-command", "backup-result", "volume-init", "load", "terrabase-peer", "terrabase-format",
	"role-identity", "rollout", "rollout-binary", "netbird", "netbird-binary"}

// hostLeaderPoll is how often Run follows authority leadership.
const hostLeaderPoll = 500 * time.Millisecond

// Run serves exact host requests until ctx ends. Every controller runs it, but
// only the authority leader subscribes: NATS delivers a queue request to a
// subscriber on the publisher's own server first, so a follower subscription
// would capture, and deny, every request of the hosts connected to it.
func (c *Controller) Run(ctx context.Context) error {
	var subscriptions []*nats.Subscription
	importPending := len(c.quarantines) > 0
	var nextImport time.Time
	unsubscribe := func() {
		for _, sub := range subscriptions {
			_ = sub.Unsubscribe()
		}
		subscriptions = nil
	}
	defer func() {
		unsubscribe()
		c.closeCache()
	}()
	ticker := time.NewTicker(hostLeaderPoll)
	defer ticker.Stop()
	for {
		leader := c.authorityLeader == nil || c.authorityLeader()
		if !leader {
			importPending = len(c.quarantines) > 0
		} else if importPending && !time.Now().Before(nextImport) {
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.importRetirementQuarantines(attempt)
			cancel()
			if err == nil {
				importPending = false
			} else {
				slog.Warn("retirement quarantine import deferred", "cell", c.cell, "error", err)
				nextImport = time.Now().Add(5 * time.Second)
			}
		}
		if leader && subscriptions == nil {
			var err error
			if subscriptions, err = c.subscribeHostRequests(ctx); err != nil {
				return err
			}
		} else if !leader && subscriptions != nil {
			unsubscribe()
		}
		c.readyOnce.Do(func() { close(c.ready) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Controller) subscribeHostRequests(ctx context.Context) ([]*nats.Subscription, error) {
	subscriptions := make([]*nats.Subscription, 0, len(hostOperations))
	for _, operation := range hostOperations {
		sub, err := c.conn.QueueSubscribe(protocol.AgentObservation(c.cell, "*", operation), "host-controller-"+operation, func(msg *nats.Msg) { c.handle(ctx, msg) })
		if err == nil {
			subscriptions = append(subscriptions, sub)
			continue
		}
		for _, existing := range subscriptions {
			_ = existing.Unsubscribe()
		}
		return nil, err
	}
	flushCtx, flushCancel := context.WithTimeout(ctx, 5*time.Second)
	err := c.conn.FlushWithContext(flushCtx)
	flushCancel()
	if err != nil {
		for _, sub := range subscriptions {
			_ = sub.Unsubscribe()
		}
		return nil, fmt.Errorf("flush host subscriptions: %w", err)
	}
	return subscriptions, nil
}

func (c *Controller) handle(parent context.Context, msg *nats.Msg) {
	if msg.Reply == "" || len(msg.Data) > 64<<10 {
		return
	}
	deadline := 4 * time.Second
	if len(msg.Data) > 0 && (strings.Contains(msg.Subject, ".material") ||
		strings.Contains(msg.Subject, ".drain-command") || strings.Contains(msg.Subject, ".drain-result") ||
		strings.Contains(msg.Subject, ".backup-command") || strings.Contains(msg.Subject, ".backup-result") ||
		strings.Contains(msg.Subject, ".volume-init")) {
		deadline = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(msg.Data, &envelope, 64<<10); err != nil {
		return
	}
	var req request
	if err := protocol.DecodeStrict([]byte(envelope.Payload), &req, 64<<10); err != nil {
		return
	}
	req.Envelope = envelope
	expectedSubject, err := protocol.AgentObservationSubject(c.cell, req.NATSUserPublicKey, req.Operation)
	if err != nil || expectedSubject != msg.Subject || envelope.Actor != req.Node || envelope.Kind != "host."+req.Operation {
		return
	}
	registration, err := c.registration(ctx, req.Node)
	if err != nil || registration.NATSUserPublicKey != req.NATSUserPublicKey {
		return
	}
	result := response{Nonce: req.Nonce, Node: req.Node, SessionID: req.SessionID, Epoch: req.Epoch, Operation: req.Operation}
	var payload any
	switch req.Operation {
	case "session":
		payload, err = c.handleSession(ctx, req)
	case "desired", "artifact", "cycle", "report", "material", "drain-command", "drain-result", "backup-command", "backup-result", "volume-init", "load", "terrabase-peer", "terrabase-format",
		"role-identity", "rollout", "rollout-binary", "netbird", "netbird-binary":
		payload, err = c.handleAuthorized(ctx, req)
	default:
		err = errors.New("unknown host operation")
	}
	if err != nil {
		result.Error = err.Error()
		if req.Operation == "session" {
			result.Retryable = transientSessionTransport(err) || errors.Is(err, errSessionContention)
		} else {
			result.Retryable = errors.Is(err, errArtifactPreparing) || errors.Is(err, errSessionContention)
		}
	} else if payload != nil {
		result.Payload, _ = json.Marshal(payload)
	}
	data, err := protocol.EncodeJSON(result)
	if err != nil {
		return
	}
	issued := time.Now().UTC()
	signed, err := protocol.SignEnvelope(data, protocol.EnvelopeScope{Region: c.cell, Kind: "host.response." + req.Operation, Actor: "controller", OperationID: req.Nonce, Epoch: req.Epoch}, issued, issued.Add(requestTTL), c.responseKey)
	if err != nil {
		return
	}
	wire, err := protocol.EncodeJSON(signed)
	if err != nil {
		return
	}
	_ = msg.Respond(wire)
}

func (c *Controller) registration(ctx context.Context, node string) (Registration, error) {
	if _, quarantined := c.quarantines[node]; quarantined {
		return Registration{}, ErrHostRetiring
	}
	r, _, exists, err := c.readRegistration(ctx, node)
	if err != nil {
		return Registration{}, err
	}
	if !exists {
		return Registration{}, errors.New("host is not registered")
	}
	return r, nil
}

func (c *Controller) handleSession(ctx context.Context, req request) (payload any, resultErr error) {
	stage := "decode"
	defer func() {
		if resultErr != nil {
			c.logSessionFailure(stage, resultErr)
		}
	}()
	var operation struct {
		Kind string `json:"kind"`
	}
	if err := decodeStrict(req.Payload, &operation); err != nil {
		return nil, err
	}
	stateKey := sessionKey(c.cell, req.Node)
	for attempt := range 8 {
		stage = "registration"
		r, err := c.registration(ctx, req.Node)
		if err != nil {
			return nil, err
		}
		key, err := decodePublicKey(r.PublicKey)
		if err != nil {
			return nil, err
		}
		stage = "verify"
		if err := verifyRequest(req, key, c.cell, time.Now().UTC()); err != nil {
			return nil, err
		}
		if err := c.verifyCredentialProtocol(ctx, req, r); err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		stage = "session_read"
		old, revision, exists, err := c.sessionSnapshot(ctx, stateKey)
		if err != nil {
			return nil, err
		}
		if exists && exactSessionReplay(old, r, req, operation.Kind, now) {
			stage = "session_write"
			if _, err := c.cas(ctx, stateKey, old, revision); err == nil {
				return old, nil
			} else if casConflict(err) {
				if err := waitSessionConflict(ctx, attempt); err != nil {
					return nil, err
				}
				continue
			} else {
				return nil, err
			}
		}
		var next session
		stage = "session_validate"
		switch operation.Kind {
		case "acquire":
			if req.Epoch != 0 {
				return nil, errors.New("acquire requires epoch zero")
			}
			if exists && sessionHeld(old, r, now) {
				return nil, errSessionOwned
			}
			next = session{RegistrationGeneration: r.Generation, SessionID: req.SessionID, Epoch: 1, ExpiresAt: req.IssuedAt.Add(sessionTTL), LastNonce: req.Nonce, LastIssuedAt: req.IssuedAt}
			if exists {
				if old.Epoch == ^uint64(0) {
					return nil, errors.New("session epoch exhausted")
				}
				next.Epoch = old.Epoch + 1
			}
		case "renew":
			if !exists || !renewableSession(old, r, req, now) {
				return nil, errors.New("session is no longer renewable")
			}
			next = old
			next.ExpiresAt = req.IssuedAt.Add(sessionTTL)
			next.LastNonce = req.Nonce
			next.LastIssuedAt = req.IssuedAt
		default:
			return nil, errors.New("unknown session operation")
		}
		stage = "session_write"
		written, err := c.cas(ctx, stateKey, next, revision)
		if err == nil && written > 0 {
			return next, nil
		}
		if !casConflict(err) {
			return nil, err
		}
		if err := waitSessionConflict(ctx, attempt); err != nil {
			return nil, err
		}
	}
	stage = "registration"
	r, err := c.registration(ctx, req.Node)
	if err != nil {
		return nil, err
	}
	key, err := decodePublicKey(r.PublicKey)
	if err != nil {
		return nil, err
	}
	stage = "verify"
	if err := verifyRequest(req, key, c.cell, time.Now().UTC()); err != nil {
		return nil, err
	}
	stage = "session_read"
	old, revision, exists, err := c.sessionSnapshot(ctx, stateKey)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if exists && exactSessionReplay(old, r, req, operation.Kind, now) {
		stage = "session_write"
		if _, err := c.cas(ctx, stateKey, old, revision); err == nil {
			return old, nil
		} else if !casConflict(err) {
			return nil, err
		}
		return nil, errSessionContention
	}
	stage = "session_validate"
	switch operation.Kind {
	case "acquire":
		if req.Epoch != 0 {
			return nil, errors.New("acquire requires epoch zero")
		}
		if exists && sessionHeld(old, r, now) {
			return nil, errSessionOwned
		}
	case "renew":
		if !exists || !renewableSession(old, r, req, now) {
			return nil, errors.New("session is no longer renewable")
		}
	default:
		return nil, errors.New("unknown session operation")
	}
	return nil, errSessionContention
}

func (c *Controller) logSessionFailure(stage string, err error) {
	class := sessionErrorClass(err)
	key := stage + ":" + class
	c.sessionDiagMu.Lock()
	if c.sessionDiagAt == nil {
		c.sessionDiagAt = make(map[string]time.Time)
	}
	now := time.Now()
	if now.Sub(c.sessionDiagAt[key]) < 10*time.Second {
		c.sessionDiagMu.Unlock()
		return
	}
	c.sessionDiagAt[key] = now
	c.sessionDiagMu.Unlock()
	slog.Warn("host session request deferred", "stage", stage, "cause_class", class)
}

func exactSessionReplay(old session, r Registration, req request, kind string, now time.Time) bool {
	replayEpoch := kind == "acquire" && req.Epoch == 0 || kind == "renew" && req.Epoch == old.Epoch
	return replayEpoch && old.RegistrationGeneration == r.Generation && old.SessionID == req.SessionID &&
		old.LastNonce == req.Nonce && old.LastIssuedAt.Equal(req.IssuedAt) && now.Before(old.ExpiresAt)
}

// sessionHeld reports whether an unexpired session keeps the node from a
// new acquire. A controller-launched managed host's next generation takes
// over at once. Any other host's next generation, for example a static C#
// TerraBase host replacement that registered itself, waits until the
// previous generation's session expires: that host can still be running
// its members until its lease runs out.
func sessionHeld(old session, r Registration, now time.Time) bool {
	return now.Before(old.ExpiresAt) && (old.RegistrationGeneration == r.Generation || r.ManagedOCI == nil)
}

func renewableSession(old session, r Registration, req request, now time.Time) bool {
	return old.RegistrationGeneration == r.Generation && old.SessionID == req.SessionID && old.Epoch == req.Epoch &&
		now.Before(old.ExpiresAt) && req.IssuedAt.After(old.LastIssuedAt)
}

func currentAuthorizedSession(s session, r Registration, req request, now time.Time) bool {
	return s.RegistrationGeneration == r.Generation && s.SessionID == req.SessionID && s.Epoch == req.Epoch &&
		now.Before(s.ExpiresAt) && !req.IssuedAt.Before(s.LastIssuedAt.Add(-requestTTL))
}

func (c *Controller) authorize(ctx context.Context, req request) (Registration, session, error) {
	stateKey := sessionKey(c.cell, req.Node)
	for attempt := range 8 {
		r, err := c.registration(ctx, req.Node)
		if err != nil {
			return Registration{}, session{}, err
		}
		key, err := decodePublicKey(r.PublicKey)
		if err != nil {
			return Registration{}, session{}, err
		}
		if err := verifyRequest(req, key, c.cell, time.Now().UTC()); err != nil {
			return Registration{}, session{}, err
		}
		if err := c.verifyCredentialProtocol(ctx, req, r); err != nil {
			return Registration{}, session{}, err
		}
		s, revision, exists, err := c.sessionSnapshot(ctx, stateKey)
		if err != nil {
			return Registration{}, session{}, err
		}
		if !exists || !currentAuthorizedSession(s, r, req, time.Now()) {
			return Registration{}, session{}, errors.New("host session is not current")
		}
		if _, err := c.cas(ctx, stateKey, s, revision); err == nil {
			return r, s, nil
		} else if !casConflict(err) {
			return Registration{}, session{}, fmt.Errorf("host session changed: %w", err)
		}
		if err := waitSessionConflict(ctx, attempt); err != nil {
			return Registration{}, session{}, err
		}
	}
	r, err := c.registration(ctx, req.Node)
	if err != nil {
		return Registration{}, session{}, err
	}
	key, err := decodePublicKey(r.PublicKey)
	if err != nil {
		return Registration{}, session{}, err
	}
	if err := verifyRequest(req, key, c.cell, time.Now().UTC()); err != nil {
		return Registration{}, session{}, err
	}
	if err := c.verifyCredentialProtocol(ctx, req, r); err != nil {
		return Registration{}, session{}, err
	}
	s, _, exists, err := c.sessionSnapshot(ctx, stateKey)
	if err != nil {
		return Registration{}, session{}, err
	}
	if !exists || !currentAuthorizedSession(s, r, req, time.Now()) {
		return Registration{}, session{}, errors.New("host session is not current")
	}
	return Registration{}, session{}, errSessionContention
}

var errSessionContention = errors.New("session contention")

func waitSessionConflict(ctx context.Context, attempt int) error {
	timer := time.NewTimer(time.Duration(attempt+1) * 2 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Controller) handleAuthorized(ctx context.Context, req request) (any, error) {
	r, s, err := c.authorize(ctx, req)
	if err != nil {
		return nil, err
	}
	switch req.Operation {
	case "desired":
		registration, registrationRevision, exists, err := c.readRegistration(ctx, req.Node)
		if err != nil {
			return nil, err
		}
		if !exists || !sameJSON(registration, r) || registration.Generation != s.RegistrationGeneration {
			return nil, errors.New("host registration changed during desired request")
		}
		var query struct {
			Role string `json:"role"`
		}
		if err := decodeStrict(req.Payload, &query); err != nil {
			return nil, err
		}
		if !slices.Contains(r.Roles, query.Role) {
			return nil, errors.New("role is not registered")
		}
		desired, revision, exists, err := c.readDesired(ctx, req.Node, query.Role)
		if err != nil {
			return nil, err
		}
		if !exists {
			return desiredReply{Registration: &registration, RegistrationRevision: registrationRevision}, nil
		}
		return desiredReply{Desired: &desired, Revision: revision, Registration: &registration, RegistrationRevision: registrationRevision}, nil
	case "artifact":
		return c.serveArtifact(ctx, req, r)
	case "material":
		return c.serveMaterial(ctx, req, r, s)
	case "volume-init":
		return c.serveVolumeInit(ctx, req, r, s)
	case "drain-command":
		return c.serveManagedDrainCommand(ctx, req, r)
	case "drain-result":
		return c.storeManagedDrainResult(ctx, req, r)
	case "backup-command":
		return c.serveManagedBackupCommand(ctx, req, r)
	case "backup-result":
		return c.storeManagedBackupResult(ctx, req, r)
	case "cycle":
		return c.serveCycle(ctx, req, r, s)
	case "report":
		return c.storeReport(ctx, req, r, s)
	case "load":
		return c.storeLoad(ctx, req, r)
	case "rollout", "rollout-binary":
		return c.serveRollout(ctx, req, r)
	case "netbird", "netbird-binary":
		return c.serveNetBird(ctx, req, r)
	case "terrabase-peer":
		return c.serveTerraBasePeer(ctx, req, r)
	case "terrabase-format":
		return c.serveTerraBaseFormat(ctx, req, r)
	case "role-identity":
		return c.serveRoleIdentity(ctx, req, r)
	}
	return nil, errors.New("unknown host operation")
}

func (c *Controller) serveArtifact(ctx context.Context, req request, r Registration) (any, error) {
	var query artifactQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if !slices.Contains(r.Roles, query.Role) || validateDigest(query.Digest) != nil || query.Offset < 0 || query.Length < 1 || query.Length > artifactChunkBytes {
		return nil, errors.New("invalid artifact query")
	}
	d, _, exists, err := c.readDesired(ctx, req.Node, query.Role)
	if err != nil {
		return nil, err
	}
	if !exists || d.Withdrawn || d.Digest != query.Digest {
		return nil, errors.New("artifact is not desired for this host")
	}
	data, total, err := c.readArtifactChunk(ctx, query.Digest, query.Offset, query.Length)
	if err != nil {
		return nil, err
	}
	current, _, exists, err := c.readDesired(ctx, req.Node, query.Role)
	if err != nil {
		return nil, err
	}
	if !exists || current.Withdrawn || current.Digest != query.Digest || current.Generation != d.Generation || current.AuthorityEpoch != d.AuthorityEpoch {
		return nil, errors.New("artifact target changed")
	}
	if _, _, err := c.authorize(ctx, req); err != nil {
		return nil, err
	}
	return artifactReply{Digest: query.Digest, Offset: query.Offset, Total: total, Data: data}, nil
}
