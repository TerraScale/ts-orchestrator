package host

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nats-io/nkeys"
)

const sessionExecutionReserve = 5 * time.Second

var errSessionExecutionReserve = errors.New("host session execution reserve exhausted")

type Agent struct {
	cfg              AgentConfig
	runner           Runner
	mu               sync.RWMutex
	session          session
	sessionSafeUntil time.Time
	processID        string
	pending          map[string]pendingCycle
	sessionLost      atomic.Bool
	sessionFailOnce  sync.Once
	diagMu           sync.Mutex
	diagAt           time.Time
	diagClass        string
	diagFailed       bool
	nativeRootMu     sync.Mutex
	nativeRoots      map[string]*managedNativeRoot
	nativeDesired    map[string]nativeRootDesired
	memoryCheck      func(Registration) error
	wallNow          func() time.Time
	watchdogTicks    <-chan time.Time
}

// An open cycle has no outcome until work has succeeded or failed. A transient
// session conflict must not turn that open cycle into a failed outcome.
type pendingCycle struct {
	query        cycleQuery
	outcomeReady bool
}

func NewAgent(cfg AgentConfig) (*Agent, error) {
	for name, value := range map[string]string{"cell": cfg.Cell, "node": cfg.Node, "environment": cfg.Environment} {
		if err := validateToken(value, name); err != nil {
			return nil, err
		}
	}
	if cfg.Conn == nil || len(cfg.Identity) != ed25519.PrivateKeySize || len(cfg.ControllerPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("agent requires NATS connection, Ed25519 identity and pinned controller public key")
	}
	if !nkeys.IsValidPublicUserKey(cfg.NATSUserPublicKey) {
		return nil, errors.New("agent requires its authenticated NATS user public key")
	}
	if cfg.ClockCheck == nil {
		return nil, errors.New("agent requires a fresh host clock health check")
	}
	if len(cfg.Roles) == 0 || len(cfg.Roles) > 32 {
		return nil, errors.New("agent requires roles")
	}
	for i, role := range cfg.Roles {
		if err := validateToken(role, "role"); err != nil {
			return nil, err
		}
		if slices.Contains(cfg.Roles[:i], role) {
			return nil, errors.New("duplicate agent role")
		}
	}
	if err := ValidateWorkloadPaths(cfg.InstallRoot, cfg.StateRoot, cfg.WorkloadIdentity); err != nil {
		return nil, err
	}
	if err := ValidatePrivateHostState(cfg.StateRoot, cfg.Cell, cfg.Node); err != nil {
		return nil, err
	}
	if cfg.ManagedRuntimeRoot != "" {
		if !filepath.IsAbs(cfg.ManagedRuntimeRoot) || filepath.Clean(cfg.ManagedRuntimeRoot) != cfg.ManagedRuntimeRoot ||
			cfg.ManagedRuntimeRoot == cfg.InstallRoot || cfg.ManagedRuntimeRoot == cfg.StateRoot ||
			strings.HasPrefix(cfg.ManagedRuntimeRoot, cfg.InstallRoot+string(filepath.Separator)) ||
			strings.HasPrefix(cfg.ManagedRuntimeRoot, cfg.StateRoot+string(filepath.Separator)) ||
			strings.HasPrefix(cfg.InstallRoot, cfg.ManagedRuntimeRoot+string(filepath.Separator)) ||
			strings.HasPrefix(cfg.StateRoot, cfg.ManagedRuntimeRoot+string(filepath.Separator)) {
			return nil, errors.New("managed runtime root must be clean, absolute and separate from host roots")
		}
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.PollInterval < 100*time.Millisecond {
		return nil, errors.New("agent poll interval is too short")
	}
	runner := cfg.Runner
	if runner == nil {
		runner = NewProcessRunner(filepath.Join(cfg.StateRoot, cfg.Cell, cfg.Node), cfg.WorkloadIdentity)
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, runner: runner, processID: id, pending: make(map[string]pendingCycle),
		nativeRoots: make(map[string]*managedNativeRoot)}, nil
}

// ValidateWorkloadPaths rejects roots that could expose supervisor state or
// prevent the dedicated workload identity from reaching installed artifacts.
// It does not change unrelated ancestors of the install root.
func ValidateWorkloadPaths(installRoot, stateRoot string, identity WorkloadIdentity) error {
	if identity.UID == 0 || identity.GID == 0 {
		return errors.New("host workload_uid and workload_gid must be nonzero")
	}
	if !filepath.IsAbs(installRoot) || !filepath.IsAbs(stateRoot) ||
		filepath.Clean(installRoot) != installRoot || filepath.Clean(stateRoot) != stateRoot {
		return errors.New("agent installation and state roots must be clean absolute paths")
	}
	if installRoot == string(filepath.Separator) || stateRoot == string(filepath.Separator) {
		return errors.New("agent installation and state roots cannot be the filesystem root")
	}
	if installRoot == stateRoot || strings.HasPrefix(installRoot, stateRoot+string(filepath.Separator)) ||
		strings.HasPrefix(stateRoot, installRoot+string(filepath.Separator)) {
		return errors.New("agent installation and state roots must not overlap")
	}
	if err := inspectWorkloadPath(filepath.Dir(installRoot), identity, true, false, false); err != nil {
		return fmt.Errorf("install root parent: %w", err)
	}
	if err := inspectWorkloadPath(installRoot, identity, false, true, false); err != nil {
		return fmt.Errorf("install root: %w", err)
	}
	if info, err := os.Lstat(installRoot); err == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
			return errors.New("install root must be supervisor-owned and not tenant-writable")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect install root: %w", err)
	}
	if err := inspectWorkloadPath(stateRoot, identity, false, true, true); err != nil {
		return fmt.Errorf("state root: %w", err)
	}
	if err := inspectPrivateStateDirectory(stateRoot); err != nil {
		return err
	}
	return nil
}

// ValidatePrivateHostState checks the host-owned state subtree before the
// runtime probe. Missing descendants are created privately by the runner.
func ValidatePrivateHostState(stateRoot, cell, node string) error {
	for name, value := range map[string]string{"cell": cell, "node": node} {
		if err := validateToken(value, name); err != nil {
			return err
		}
	}
	for _, path := range []string{stateRoot, filepath.Join(stateRoot, cell), filepath.Join(stateRoot, cell, node)} {
		if err := inspectPrivateStateDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func inspectPrivateStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state directory %s must be private and supervisor-owned", path)
	}
	return nil
}

func inspectWorkloadPath(path string, identity WorkloadIdentity, tenantTraverse, allowMissing, privateState bool) error {
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), current) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if err != nil {
			if allowMissing && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("inspect %s: %w", current, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be a directory without symlinks", current)
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot inspect owner of %s", current)
		}
		if os.Geteuid() == 0 && owner.Uid != 0 {
			return fmt.Errorf("host path ancestor %s must be root-owned", current)
		}
		permissions := info.Mode().Perm()
		search := permissions & 0001
		write := permissions & 0002
		if owner.Gid == identity.GID {
			search, write = permissions&0010, permissions&0020
		}
		if owner.Uid == identity.UID {
			search, write = permissions&0100, permissions&0200
		}
		if tenantTraverse && search == 0 {
			return fmt.Errorf("workload identity cannot traverse %s", current)
		}
		if privateState && os.Geteuid() == 0 && permissions&0022 != 0 {
			return fmt.Errorf("state path ancestor %s is group- or world-writable", current)
		}
		if identity.UID != uint32(os.Geteuid()) && write != 0 &&
			(privateState || info.Mode()&os.ModeSticky == 0 || owner.Uid != 0) {
			return fmt.Errorf("workload identity can replace host path under %s", current)
		}
	}
	return nil
}

// Run recovers native ownership before remote admission, then maintains the
// session while reconciling every admitted role. Session loss stops workloads.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.runner.Recover(ctx); err != nil {
		return fmt.Errorf("recover native workloads: %w", err)
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = a.runner.Close(stopCtx)
	}()
	defer a.stopAllManagedNativeRoots()
	if err := a.checkClock(); err != nil {
		return err
	}
	if err := a.waitForSession(work); err != nil {
		return err
	}
	lost := make(chan error, 1)
	go a.maintainSession(work, cancel, lost)
	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()
	type roleFailure struct {
		class string
		at    time.Time
	}
	failures := make(map[string]roleFailure)
	for {
		for _, role := range a.cfg.Roles {
			if err := work.Err(); err != nil {
				break
			}
			if a.sessionLost.Load() {
				break
			}
			err := a.reconcile(work, role)
			if a.cfg.ManagedRuntimeRoot == "" || work.Err() != nil || a.sessionLost.Load() {
				continue
			}
			if err == nil {
				if _, failed := failures[role]; failed {
					slog.Info("managed host reconciliation recovered", "role", role)
					delete(failures, role)
				}
				continue
			}
			class := managedReconcileErrorClass(err)
			previous := failures[role]
			if class != previous.class || time.Since(previous.at) >= 10*time.Second {
				slog.Warn("managed host reconciliation deferred", "role", role, "cause_class", class)
				failures[role] = roleFailure{class: class, at: time.Now()}
			}
		}
		select {
		case err := <-lost:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-work.Done():
			if a.sessionLost.Load() {
				// Session loss cancels work before workload shutdown finishes.
				// Wait for its reason so a supervisor sees a failed host.
				return <-lost
			}
			return work.Err()
		case <-ticker.C:
		}
	}
}

// Keep untrusted material paths and error details out of host logs. The exact
// failure is retained in the signed host report after desired validation.
func managedReconcileErrorClass(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "managed allocatable memory"):
		return "capacity"
	case strings.Contains(message, "mount"), strings.Contains(message, "filesystem"), strings.Contains(message, "block device"):
		return "volume"
	case strings.Contains(message, "material"), strings.Contains(message, "certificate"), strings.Contains(message, "authority"):
		return "material"
	case strings.Contains(message, "artifact"):
		return "artifact"
	case strings.Contains(message, "cgroup"), strings.Contains(message, "native workload"):
		return "native_launch"
	case strings.Contains(message, "member status"):
		return "member_status"
	case strings.Contains(message, "desired"):
		return "desired"
	case strings.Contains(message, "report"):
		return "report"
	case strings.Contains(message, "session"):
		return "session"
	default:
		return "other"
	}
}

func (a *Agent) makeRequest(operation string, payload any) (request, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return request{}, err
	}
	nonce, err := randomID()
	if err != nil {
		return request{}, err
	}
	a.mu.RLock()
	s := a.session
	a.mu.RUnlock()
	r := request{Version: 1, CredentialProtocol: 1, Node: a.cfg.Node, NATSUserPublicKey: a.cfg.NATSUserPublicKey, Operation: operation, SessionID: a.processID, Epoch: s.Epoch, Nonce: nonce, IssuedAt: time.Now().UTC(), Payload: data}
	if err := signRequest(&r, a.cfg.Identity, a.cfg.Cell); err != nil {
		return request{}, err
	}
	return r, nil
}

func (a *Agent) acquire(ctx context.Context) error {
	if err := a.checkClock(); err != nil {
		return err
	}
	r, err := a.makeRequest("session", struct {
		Kind string `json:"kind"`
	}{"acquire"})
	if err != nil {
		return err
	}
	r.Epoch = 0
	if err := signRequest(&r, a.cfg.Identity, a.cfg.Cell); err != nil {
		return err
	}
	var s session
	if err := exchange(ctx, a.cfg.Conn, a.cfg.Cell, a.cfg.ControllerPublicKey, r, &s); err != nil {
		return fmt.Errorf("acquire host session: %w", err)
	}
	if s.SessionID != a.processID || s.Epoch == 0 {
		return errors.New("invalid acquired host session")
	}
	if err := a.acceptSession(s); err != nil {
		return err
	}
	a.logSessionAccepted("acquire", s)
	return nil
}

func (a *Agent) waitForSession(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := a.acquire(ctx); err == nil {
			a.sessionRecovered()
			return nil
		} else if !retrySessionExchange(err) && !errors.Is(err, errSessionOwned) {
			a.logSessionFailure("acquire", err, 0)
			return err
		} else {
			a.logSessionFailure("acquire", err, 0)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func retrySessionExchange(err error) bool {
	return errors.Is(err, errSessionBackendUnavailable) || errors.Is(err, errSessionContention) || transientSessionTransport(err)
}

func sessionUsableUntil(s session, now time.Time) bool {
	return now.Before(s.ExpiresAt.Add(-sessionExecutionReserve))
}

func (a *Agent) checkClock() error {
	if a.cfg.ClockCheck == nil {
		return errors.New("host clock health check is absent")
	}
	if err := a.cfg.ClockCheck(); err != nil {
		return fmt.Errorf("host clock is unhealthy: %w", err)
	}
	return nil
}

func (a *Agent) wallTime() time.Time {
	if a.wallNow != nil {
		return a.wallNow()
	}
	return time.Now()
}

func (a *Agent) acceptSession(s session) error {
	if err := a.checkClock(); err != nil {
		return err
	}
	receivedAt := time.Now()
	remaining := s.ExpiresAt.Sub(a.wallTime()) - sessionExecutionReserve
	if remaining <= 0 || remaining > sessionTTL-sessionExecutionReserve+maxClockSkew {
		return errors.New("signed host session has no execution reserve")
	}
	// receivedAt carries Go's monotonic reading. A later wall-clock step cannot
	// extend this locally bounded execution lease.
	deadline := receivedAt.Add(min(remaining, sessionTTL-sessionExecutionReserve))
	a.mu.Lock()
	a.session = s
	a.sessionSafeUntil = deadline
	a.mu.Unlock()
	return nil
}

func (a *Agent) executionLease() (session, time.Time, error) {
	if err := a.checkClock(); err != nil {
		return session{}, time.Time{}, err
	}
	a.mu.RLock()
	s, deadline := a.session, a.sessionSafeUntil
	a.mu.RUnlock()
	if deadline.IsZero() || !time.Now().Before(deadline) || !sessionUsableUntil(s, a.wallTime()) {
		return session{}, time.Time{}, errSessionExecutionReserve
	}
	return s, deadline, nil
}

func (a *Agent) maintainSession(ctx context.Context, cancel context.CancelFunc, lost chan<- error) {
	watchCtx, stopWatch := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticks := a.watchdogTicks
		if ticks == nil {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			ticks = ticker.C
		}
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticks:
				if _, _, err := a.executionLease(); err != nil {
					a.failSession(cancel, lost, err)
					return
				}
			}
		}
	}()
	defer func() {
		stopWatch()
		<-watchDone
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		current, deadline, err := a.executionLease()
		if err != nil {
			a.failSession(cancel, lost, err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current, deadline, err = a.executionLease()
		if err != nil {
			a.failSession(cancel, lost, err)
			return
		}
		r, err := a.makeRequest("session", struct {
			Kind string `json:"kind"`
		}{"renew"})
		if err == nil {
			var next session
			renewCtx, renewCancel := context.WithDeadline(ctx, deadline)
			err = exchange(renewCtx, a.cfg.Conn, a.cfg.Cell, a.cfg.ControllerPublicKey, r, &next)
			renewCancel()
			if err == nil {
				if next.SessionID != current.SessionID || next.Epoch != current.Epoch || !next.ExpiresAt.After(current.ExpiresAt) {
					err = errors.New("renewed session binding mismatch")
				} else if _, _, err = a.executionLease(); err == nil {
					if err = a.acceptSession(next); err == nil && a.cfg.SessionTrace {
						a.logSessionAccepted("renew", next)
					}
				}
			}
		}
		_, _, leaseErr := a.executionLease()
		if leaseErr != nil {
			a.failSession(cancel, lost, leaseErr)
			return
		}
		if err != nil && retrySessionExchange(err) {
			a.logSessionFailure("renew", err, time.Until(deadline))
			continue
		}
		if err != nil {
			a.logSessionFailure("renew", err, time.Until(deadline))
			a.failSession(cancel, lost, fmt.Errorf("host session renewal failed: %w", err))
			return
		}
		a.sessionRecovered()
	}
}

// logSessionAccepted is called only after exchange has verified the signed
// controller reply and the agent has accepted its session binding. Renewal
// events are opt-in and capped by the one-second renewal ticker per host.
func (a *Agent) logSessionAccepted(phase string, accepted session) {
	digest := sha256.Sum256([]byte(accepted.SessionID))
	slog.Info("host session accepted", "phase", phase,
		"session_id_hash", hex.EncodeToString(digest[:16]), "epoch", accepted.Epoch,
		"expires_at", accepted.ExpiresAt.UTC().Format(time.RFC3339Nano))
}

func (a *Agent) logSessionFailure(stage string, err error, remaining time.Duration) {
	class := sessionErrorClass(err)
	key := stage + ":" + class
	a.diagMu.Lock()
	now := time.Now()
	if key == a.diagClass && now.Sub(a.diagAt) < 10*time.Second {
		a.diagMu.Unlock()
		return
	}
	a.diagClass, a.diagAt, a.diagFailed = key, now, true
	a.diagMu.Unlock()
	endpoint := ""
	if parsed, parseErr := url.Parse(a.cfg.Conn.ConnectedUrl()); parseErr == nil {
		endpoint = parsed.Host
	}
	slog.Warn("host session exchange deferred", "stage", stage, "cause_class", class,
		"endpoint", endpoint, "remaining_seconds", max(0, int(remaining.Seconds())))
}

func (a *Agent) sessionRecovered() {
	a.diagMu.Lock()
	wasFailing := a.diagFailed
	a.diagFailed = false
	a.diagClass = ""
	a.diagMu.Unlock()
	if wasFailing {
		slog.Info("host session exchange recovered")
	}
}

func (a *Agent) failSession(cancel context.CancelFunc, lost chan<- error, reason error) {
	a.sessionFailOnce.Do(func() { a.stopForLostSession(cancel, lost, reason) })
}

func (a *Agent) stopForLostSession(cancel context.CancelFunc, lost chan<- error, reason error) {
	a.sessionLost.Store(true)
	cancel()
	if err := a.stopAllManagedNativeRoots(); err != nil {
		reason = errors.Join(reason, err)
	}
	if a.cfg.SessionTrace {
		a.mu.RLock()
		accepted := a.session
		a.mu.RUnlock()
		if accepted.SessionID != "" && accepted.Epoch != 0 {
			cause := "renewal_failed"
			if errors.Is(reason, errSessionExecutionReserve) {
				cause = "reserve_exhausted"
			}
			digest := sha256.Sum256([]byte(accepted.SessionID))
			slog.Info("host session fenced", "session_id_hash", hex.EncodeToString(digest[:16]),
				"epoch", accepted.Epoch, "expires_at", accepted.ExpiresAt.UTC().Format(time.RFC3339Nano),
				"cause_class", cause)
		}
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), sessionExecutionReserve-time.Second)
	if err := a.runner.Close(stopCtx); err != nil {
		reason = errors.Join(reason, fmt.Errorf("stop native workloads after session loss: %w", err))
	}
	stopCancel()
	lost <- reason
}

func (a *Agent) request(ctx context.Context, operation string, payload, out any) error {
	r, err := a.makeRequest(operation, payload)
	if err != nil {
		return err
	}
	return exchange(ctx, a.cfg.Conn, a.cfg.Cell, a.cfg.ControllerPublicKey, r, out)
}

func (a *Agent) reconcile(ctx context.Context, role string) (resultErr error) {
	if a.sessionLost.Load() {
		return errors.New("host session was lost")
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	pending, hasPending := a.pending[role]
	if hasPending && pending.outcomeReady {
		if err := a.flushCycle(ctx, role); err != nil {
			return err
		}
		hasPending = false
	}
	var target desiredReply
	if err := a.request(ctx, "desired", struct {
		Role string `json:"role"`
	}{role}, &target); err != nil {
		return errors.Join(err, a.revokeManagedNativeRoot(role))
	}
	if err := a.validateDesiredReply(target); err != nil {
		return errors.Join(err, a.revokeManagedNativeRoot(role))
	}
	if target.Desired == nil {
		if err := a.revokeManagedNativeRoot(role); err != nil {
			return err
		}
		if hasPending {
			if err := a.failPendingCycle(ctx, role); err != nil {
				return err
			}
		}
		return nil
	}
	d := *target.Desired
	if d.Cell != a.cfg.Cell || d.Node != a.cfg.Node || d.Environment != a.cfg.Environment || d.Role != role || d.Generation == 0 {
		return errors.Join(errors.New("desired identity mismatch"), a.revokeManagedNativeRoot(role))
	}
	if err := validateDesired(d, a.cfg.Cell, *target.Registration); err != nil {
		return errors.Join(err, a.revokeManagedNativeRoot(role))
	}
	if !d.Withdrawn && d.ManagedMember != nil {
		fingerprint, err := desiredFingerprint(d)
		if err != nil {
			return errors.Join(err, a.revokeManagedNativeRoot(role))
		}
		if err := a.pinManagedNativeRootDesired(role, fingerprint); err != nil {
			return errors.Join(err, a.revokeManagedNativeRoot(role))
		}
		if err := a.stopManagedNativeRootIfChanged(role, fingerprint); err != nil {
			return err
		}
	}
	if hasPending && (d.Withdrawn || d.Generation != pending.query.Generation || d.Digest != pending.query.Digest || d.AuthorityEpoch != pending.query.AuthorityEpoch) {
		if err := a.failPendingCycle(ctx, role); err != nil {
			return err
		}
		hasPending = false
	}
	defer func() {
		if resultErr != nil && !errors.Is(resultErr, errSessionContention) {
			_ = a.publishReport(ctx, a.reportFor(d, "failed", resultErr))
		}
	}()
	if d.Withdrawn {
		if err := a.revokeManagedNativeRoot(role); err != nil {
			return err
		}
		if err := a.runner.Stop(ctx, role); err != nil {
			return err
		}
		return a.publishReport(ctx, a.reportFor(d, "stopped", nil))
	}
	if err := validateDigest(d.Digest); err != nil {
		return err
	}
	if d.ManagedMember != nil {
		if d.ManagedMember.Runtime != nil && a.cfg.ManagedRuntimeRoot != "" {
			command, err := a.fetchManagedDrainCommand(ctx, role)
			if err != nil {
				return err
			}
			if command != nil {
				return a.reconcileManagedDrain(ctx, d, *target.Registration, *command)
			}
		}
		return a.reconcileManaged(ctx, d, target)
	}
	if err := a.revokeManagedNativeRoot(role); err != nil {
		return err
	}
	fingerprint, err := desiredFingerprint(d)
	if err != nil {
		return err
	}
	current, err := a.runner.Observe(ctx, role)
	if err != nil {
		return err
	}
	if current.Running && current.Digest == d.Digest && current.Fingerprint == fingerprint {
		if hasPending {
			pending.query.Succeeded = true
			pending.outcomeReady = true
			a.pending[role] = pending
			if err := a.flushCycle(ctx, role); err != nil {
				return err
			}
		}
		return a.publishReport(ctx, a.reportFor(d, "running", nil))
	}
	var query cycleQuery
	var cycle cycleReply
	if hasPending {
		query = pending.query
		cycle = cycleReply{CycleID: query.CycleID, Fence: query.Fence, State: "active"}
	} else {
		attempt, err := randomID()
		if err != nil {
			return err
		}
		query = cycleQuery{Role: role, Digest: d.Digest, Generation: d.Generation, AuthorityEpoch: d.AuthorityEpoch, Attempt: attempt}
		if err := a.request(ctx, "cycle", query, &cycle); err != nil {
			return err
		}
		if cycle.State != "active" {
			return nil
		}
		query.CycleID = cycle.CycleID
		query.Fence = cycle.Fence
		a.pending[role] = pendingCycle{query: query}
	}
	cycleSucceeded := false
	defer func() {
		if resultErr != nil && !cycleSucceeded && !errors.Is(resultErr, errSessionContention) {
			pending := a.pending[role]
			pending.query.Succeeded = false
			pending.outcomeReady = true
			a.pending[role] = pending
			if ctx.Err() != nil || a.sessionLost.Load() {
				return
			}
			finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = a.flushCycle(finishCtx, role)
		}
	}()
	executable, err := a.fetchArtifact(ctx, role, d.Digest)
	if err != nil {
		return err
	}
	var latest desiredReply
	if err := a.request(ctx, "desired", struct {
		Role string `json:"role"`
	}{role}, &latest); err != nil {
		return err
	}
	if err := a.validateDesiredReply(latest); err != nil {
		return err
	}
	if !sameDesiredReplyBinding(target, latest) {
		return errors.New("desired target changed before native apply")
	}
	var active cycleReply
	if err := a.request(ctx, "cycle", cycleQuery{Role: role, Digest: d.Digest, Generation: d.Generation, AuthorityEpoch: d.AuthorityEpoch, Attempt: query.Attempt}, &active); err != nil {
		return err
	}
	if active.State != "active" || active.CycleID != cycle.CycleID || active.Fence != cycle.Fence {
		return errors.New("cycle fence changed before native apply")
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	if err := a.runner.Apply(ctx, Workload{Role: role, Digest: d.Digest, Fingerprint: fingerprint, Executable: executable, Args: d.Args, Env: d.Env}); err != nil {
		return err
	}
	observed, err := a.runner.Observe(ctx, role)
	if err != nil {
		return err
	}
	if !observed.Running || observed.Digest != d.Digest || observed.Fingerprint != fingerprint {
		return errors.New("native workload did not start")
	}
	cycleSucceeded = true
	pending = a.pending[role]
	pending.query.Succeeded = true
	pending.outcomeReady = true
	a.pending[role] = pending
	if err := a.flushCycle(ctx, role); err != nil {
		return err
	}
	if err := a.publishReport(ctx, a.reportFor(d, "running", nil)); err != nil {
		return err
	}
	return nil
}

func sameDesiredReplyBinding(first, latest desiredReply) bool {
	return first.Desired != nil && latest.Desired != nil && first.Registration != nil && latest.Registration != nil &&
		first.Revision == latest.Revision && first.RegistrationRevision == latest.RegistrationRevision &&
		sameJSON(*first.Registration, *latest.Registration) && sameJSON(*first.Desired, *latest.Desired)
}

func (a *Agent) validateDesiredReply(reply desiredReply) error {
	if len(a.cfg.Identity) != ed25519.PrivateKeySize {
		return errors.New("agent host identity key is invalid")
	}
	a.mu.RLock()
	generation := a.session.RegistrationGeneration
	a.mu.RUnlock()
	if reply.Registration == nil || reply.RegistrationRevision == 0 ||
		reply.Registration.Generation != generation ||
		reply.Registration.Cell != a.cfg.Cell || reply.Registration.Node != a.cfg.Node ||
		reply.Registration.Environment != a.cfg.Environment ||
		reply.Registration.PublicKey != base64.StdEncoding.EncodeToString(a.cfg.Identity.Public().(ed25519.PublicKey)) {
		return errors.New("desired reply registration differs from host session")
	}
	return validateRegistration(*reply.Registration, a.cfg.Cell)
}

func desiredFingerprint(d Desired) (string, error) {
	d.AuthorityEpoch = 0
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func (a *Agent) flushCycle(ctx context.Context, role string) error {
	pending, ok := a.pending[role]
	if !ok || !pending.outcomeReady {
		return nil
	}
	query := pending.query
	var result cycleReply
	if err := a.request(ctx, "cycle", query, &result); err != nil {
		return err
	}
	expected := "failed"
	if query.Succeeded {
		expected = "succeeded"
	}
	if result.CycleID != query.CycleID || result.Fence != query.Fence || result.State != expected {
		return errors.New("cycle outcome receipt mismatch")
	}
	delete(a.pending, role)
	return nil
}

func (a *Agent) failPendingCycle(ctx context.Context, role string) error {
	pending := a.pending[role]
	pending.query.Succeeded = false
	pending.outcomeReady = true
	a.pending[role] = pending
	return a.flushCycle(ctx, role)
}

func (a *Agent) reportFor(d Desired, state string, failure error) Report {
	a.mu.RLock()
	s := a.session
	a.mu.RUnlock()
	r := Report{Cell: a.cfg.Cell, Node: a.cfg.Node, Environment: a.cfg.Environment, Role: d.Role, Digest: d.Digest, Generation: d.Generation, SessionID: s.SessionID, Epoch: s.Epoch, State: state, ObservedAt: time.Now().UTC()}
	if failure != nil {
		r.Error = failure.Error()
	}
	return r
}

func (a *Agent) publishReport(ctx context.Context, r Report) error {
	a.mu.RLock()
	s := a.session
	a.mu.RUnlock()
	r.SessionID = s.SessionID
	r.Epoch = s.Epoch
	if r.Error != "" && len(r.Error) > 1024 {
		r.Error = r.Error[:1024]
	}
	var ack struct {
		Accepted bool `json:"accepted"`
	}
	if err := a.request(ctx, "report", r, &ack); err != nil {
		return err
	}
	if !ack.Accepted {
		return errors.New("report was not accepted")
	}
	return nil
}

func (a *Agent) fetchArtifact(ctx context.Context, role, digest string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	root := filepath.Join(a.cfg.InstallRoot, role, "sha256-"+digest)
	path := filepath.Join(root, role)
	for _, directory := range []string{a.cfg.InstallRoot, filepath.Join(a.cfg.InstallRoot, role), root} {
		if err := ensureInstallDirectory(directory, a.cfg.WorkloadIdentity.GID); err != nil {
			return "", err
		}
	}
	if valid, err := verifyInstalledArtifact(path, digest, a.cfg.WorkloadIdentity.GID); err != nil {
		return "", err
	} else if valid {
		return path, nil
	}
	tmp, err := os.CreateTemp(root, "partial-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	hash := sha256.New()
	var offset, total int64
	for {
		var part artifactReply
		if err := a.request(ctx, "artifact", artifactQuery{Role: role, Digest: digest, Offset: offset, Length: artifactChunkBytes}, &part); err != nil {
			if errors.Is(err, errArtifactPreparing) || errors.Is(err, errSessionContention) {
				select {
				case <-ctx.Done():
					return "", ctx.Err()
				case <-time.After(250 * time.Millisecond):
					continue
				}
			}
			return "", err
		}
		if part.Digest != digest || part.Offset != offset || part.Total <= 0 || part.Total > maxArtifactBytes || len(part.Data) == 0 || len(part.Data) > artifactChunkBytes || offset+int64(len(part.Data)) > part.Total || total != 0 && part.Total != total {
			return "", errors.New("artifact chunk binding mismatch")
		}
		total = part.Total
		if _, err := tmp.Write(part.Data); err != nil {
			return "", err
		}
		if _, err := hash.Write(part.Data); err != nil {
			return "", err
		}
		offset += int64(len(part.Data))
		if offset == total {
			break
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return "", errors.New("artifact SHA-256 mismatch")
	}
	if err := tmp.Chown(-1, int(a.cfg.WorkloadIdentity.GID)); err != nil {
		return "", err
	}
	if err := tmp.Chmod(0550); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	dir, err := os.Open(root)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return "", err
	}
	return path, nil
}

func ensureInstallDirectory(path string, gid uint32) error {
	if err := os.Mkdir(path, 0710); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create install directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Uid != uint32(os.Geteuid()) ||
		info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("install directory %s must be supervisor-owned and not tenant-writable", path)
	}
	if owner.Gid != gid {
		if err := os.Chown(path, -1, int(gid)); err != nil {
			return fmt.Errorf("set install directory group: %w", err)
		}
	}
	if err := os.Chmod(path, 0710); err != nil {
		return fmt.Errorf("set install directory mode: %w", err)
	}
	return nil
}

func verifyInstalledArtifact(path, digest string, gid uint32) (bool, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open installed artifact: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || owner.Uid != uint32(os.Geteuid()) ||
		info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false, errors.New("installed artifact must be a supervisor-owned, non-writable regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxArtifactBytes+1)); err != nil {
		return false, err
	}
	if info.Size() > maxArtifactBytes || hex.EncodeToString(hash.Sum(nil)) != digest {
		return false, nil
	}
	if owner.Gid != gid {
		if err := file.Chown(-1, int(gid)); err != nil {
			return false, err
		}
	}
	if err := file.Chmod(0550); err != nil {
		return false, err
	}
	return true, nil
}
