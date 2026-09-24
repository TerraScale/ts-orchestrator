package host

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type Agent struct {
	cfg       AgentConfig
	runner    Runner
	mu        sync.RWMutex
	session   session
	processID string
	pending   map[string]cycleQuery
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
	if !filepath.IsAbs(cfg.InstallRoot) || !filepath.IsAbs(cfg.StateRoot) {
		return nil, errors.New("agent installation and state roots must be absolute")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.PollInterval < 100*time.Millisecond {
		return nil, errors.New("agent poll interval is too short")
	}
	runner := cfg.Runner
	if runner == nil {
		runner = NewProcessRunner(filepath.Join(cfg.StateRoot, cfg.Cell, cfg.Node))
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, runner: runner, processID: id, pending: make(map[string]cycleQuery)}, nil
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
	if err := a.acquire(work); err != nil {
		return err
	}
	lost := make(chan error, 1)
	go a.maintainSession(work, cancel, lost)
	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()
	for {
		for _, role := range a.cfg.Roles {
			if err := work.Err(); err != nil {
				break
			}
			_ = a.reconcile(work, role)
		}
		select {
		case err := <-lost:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-work.Done():
			select {
			case err := <-lost:
				return err
			default:
				return work.Err()
			}
		case <-ticker.C:
		}
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
	r := request{Version: 1, Node: a.cfg.Node, Operation: operation, SessionID: a.processID, Epoch: s.Epoch, Nonce: nonce, IssuedAt: time.Now().UTC(), Payload: data}
	if err := signRequest(&r, a.cfg.Identity, a.cfg.Cell); err != nil {
		return request{}, err
	}
	return r, nil
}

func (a *Agent) acquire(ctx context.Context) error {
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
	if s.SessionID != a.processID || s.Epoch == 0 || !time.Now().Before(s.ExpiresAt.Add(-5*time.Second)) {
		return errors.New("invalid acquired host session")
	}
	a.mu.Lock()
	a.session = s
	a.mu.Unlock()
	return nil
}

func (a *Agent) maintainSession(ctx context.Context, cancel context.CancelFunc, lost chan<- error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		a.mu.RLock()
		current := a.session
		a.mu.RUnlock()
		if !time.Now().Before(current.ExpiresAt.Add(-5 * time.Second)) {
			cancel()
			lost <- errors.New("host session execution reserve exhausted")
			return
		}
		r, err := a.makeRequest("session", struct {
			Kind string `json:"kind"`
		}{"renew"})
		if err == nil {
			var next session
			err = exchange(ctx, a.cfg.Conn, a.cfg.Cell, a.cfg.ControllerPublicKey, r, &next)
			if err == nil {
				if next.SessionID != current.SessionID || next.Epoch != current.Epoch || !next.ExpiresAt.After(current.ExpiresAt) {
					err = errors.New("renewed session binding mismatch")
				} else {
					a.mu.Lock()
					a.session = next
					a.mu.Unlock()
				}
			}
		}
		if err != nil {
			cancel()
			lost <- fmt.Errorf("host session renewal failed: %w", err)
			return
		}
	}
}

func (a *Agent) request(ctx context.Context, operation string, payload, out any) error {
	r, err := a.makeRequest(operation, payload)
	if err != nil {
		return err
	}
	return exchange(ctx, a.cfg.Conn, a.cfg.Cell, a.cfg.ControllerPublicKey, r, out)
}

func (a *Agent) reconcile(ctx context.Context, role string) (resultErr error) {
	if err := a.flushCycle(ctx, role); err != nil {
		return err
	}
	var target desiredReply
	if err := a.request(ctx, "desired", struct {
		Role string `json:"role"`
	}{role}, &target); err != nil {
		return err
	}
	if target.Desired == nil {
		return nil
	}
	d := *target.Desired
	if d.Cell != a.cfg.Cell || d.Node != a.cfg.Node || d.Environment != a.cfg.Environment || d.Role != role || d.Generation == 0 {
		return errors.New("desired identity mismatch")
	}
	defer func() {
		if resultErr != nil {
			_ = a.publishReport(ctx, a.reportFor(d, "failed", resultErr))
		}
	}()
	if d.Withdrawn {
		if err := a.runner.Stop(ctx, role); err != nil {
			return err
		}
		return a.publishReport(ctx, a.reportFor(d, "stopped", nil))
	}
	if err := validateDigest(d.Digest); err != nil {
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
		return a.publishReport(ctx, a.reportFor(d, "running", nil))
	}
	attempt, err := randomID()
	if err != nil {
		return err
	}
	query := cycleQuery{Role: role, Digest: d.Digest, Generation: d.Generation, AuthorityEpoch: d.AuthorityEpoch, Attempt: attempt}
	var cycle cycleReply
	if err := a.request(ctx, "cycle", query, &cycle); err != nil {
		return err
	}
	if cycle.State != "active" {
		return nil
	}
	query.CycleID = cycle.CycleID
	query.Fence = cycle.Fence
	a.pending[role] = query
	cycleSucceeded := false
	defer func() {
		if resultErr != nil && !cycleSucceeded {
			pending := a.pending[role]
			pending.Succeeded = false
			a.pending[role] = pending
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
	if latest.Desired == nil || !sameJSON(*latest.Desired, d) {
		return errors.New("desired target changed before native apply")
	}
	var active cycleReply
	if err := a.request(ctx, "cycle", cycleQuery{Role: role, Digest: d.Digest, Generation: d.Generation, AuthorityEpoch: d.AuthorityEpoch, Attempt: attempt}, &active); err != nil {
		return err
	}
	if active.State != "active" || active.CycleID != cycle.CycleID || active.Fence != cycle.Fence {
		return errors.New("cycle fence changed before native apply")
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
	pending := a.pending[role]
	pending.Succeeded = true
	a.pending[role] = pending
	if err := a.flushCycle(ctx, role); err != nil {
		return err
	}
	if err := a.publishReport(ctx, a.reportFor(d, "running", nil)); err != nil {
		return err
	}
	return nil
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
	query, ok := a.pending[role]
	if !ok {
		return nil
	}
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
	if existing, err := os.Open(path); err == nil {
		hash := sha256.New()
		_, copyErr := io.Copy(hash, io.LimitReader(existing, maxArtifactBytes+1))
		closeErr := existing.Close()
		if copyErr == nil && closeErr == nil && hex.EncodeToString(hash.Sum(nil)) == digest {
			return path, nil
		}
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
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
			if errors.Is(err, errArtifactPreparing) {
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
	if err := tmp.Chmod(0500); err != nil {
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
