package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Controller holds the durable host authority and serves restricted host RPCs.
// Administrative callers own admission of Register and ApplyDesired operations.
type Controller struct {
	cell             string
	conn             *nats.Conn
	state            jetstream.KeyValue
	controlLog       jetstream.Stream
	readOnly         bool
	mutations        authority.HostMutationStore
	artifacts        ArtifactStore
	responseKey      ed25519.PrivateKey
	ready            chan struct{}
	readyOnce        sync.Once
	cacheMu          sync.Mutex
	cacheFile        *os.File
	cacheDigest      string
	cacheSize        int64
	cacheDownloading bool
	cacheClosed      bool
	cacheCancel      context.CancelFunc
	cacheContext     context.Context
	cacheRetryAfter  time.Time
	authorityEpoch   func() uint64
	authorityGuard   func(context.Context, uint64) error
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
	controlLog := cfg.ControlLog
	if controlLog == nil {
		controlLog, err = cfg.JS.Stream(ctx, "TS_CONTROL_LOG")
		if err != nil {
			return nil, fmt.Errorf("open ordered control log: %w", err)
		}
	}
	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	return &Controller{cell: cfg.Cell, conn: cfg.Conn, state: state, controlLog: controlLog, mutations: cfg.HostMutations, artifacts: cfg.Artifacts, responseKey: cfg.ResponseKey, ready: make(chan struct{}), authorityEpoch: cfg.AuthorityEpoch, authorityGuard: cfg.AuthorityGuard, cacheContext: cacheCtx, cacheCancel: cacheCancel}, nil
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

func registrationKey(cell, node string) string  { return "registration." + cell + "." + node }
func sessionKey(cell, node string) string       { return "session." + cell + "." + node }
func desiredKey(cell, node, role string) string { return "desired." + cell + "." + node + "." + role }
func reportKey(cell, node, role string) string  { return "report." + cell + "." + node + "." + role }
func cycleKey(cell, node, role string) string   { return "cycle." + cell + "." + node + "." + role }

func (c *Controller) get(ctx context.Context, key string, destination any) (uint64, bool, error) {
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

// Register admits a public host key and role scope. A generation is immutable.
func (c *Controller) Register(ctx context.Context, r Registration) (Receipt, error) {
	if err := validateRegistration(r, c.cell); err != nil {
		return Receipt{}, err
	}
	authorityEpoch := c.authorityEpoch()
	if err := c.guard(ctx, authorityEpoch); err != nil {
		return Receipt{}, err
	}
	payload, operationID, err := mutationPayload(r)
	if err != nil {
		return Receipt{}, err
	}
	key := registrationSubjectKey(c.cell, r.Node)
	for range 8 {
		current, revision, exists, err := c.readRegistration(ctx, r.Node)
		if err != nil {
			return Receipt{}, err
		}
		if exists {
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

// ApplyDesired persists one exact node/role target. It never rewrites a generation.
func (c *Controller) ApplyDesired(ctx context.Context, d Desired) (Receipt, error) {
	if err := c.guard(ctx, d.AuthorityEpoch); err != nil {
		return Receipt{}, err
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
	if !d.Withdrawn {
		info, err := c.artifacts.GetInfo(ctx, "sha256-"+d.Digest)
		if err != nil {
			return Receipt{}, err
		}
		if info.Deleted || info.Opts != nil && info.Opts.Link != nil || info.Size == 0 || info.Size > maxArtifactBytes {
			return Receipt{}, errors.New("artifact is absent, linked or outside size limit")
		}
	}
	payload, operationID, err := mutationPayload(d)
	if err != nil {
		return Receipt{}, err
	}
	key := desiredSubjectKey(c.cell, d.Node, d.Role)
	for range 8 {
		current, revision, exists, err := c.readDesired(ctx, d.Node, d.Role)
		if err != nil {
			return Receipt{}, err
		}
		if exists {
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
		if err := c.guard(ctx, d.AuthorityEpoch); err != nil {
			return Receipt{}, err
		}
		written, err := c.mutations.CommitHostMutation(ctx, d.AuthorityEpoch, authority.MutationDesired, key, operationID, revision, payload)
		if err == nil {
			return Receipt{d.Generation, written}, nil
		}
		if !errors.Is(err, authority.ErrConflict) {
			return Receipt{}, err
		}
	}
	return Receipt{}, errors.New("desired contention")
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

func (c *Controller) ListHosts(ctx context.Context) ([]HostStatus, error) {
	if c.controlLog == nil {
		return nil, errors.New("ordered control log is required for host discovery")
	}
	prefix := "ts.control." + c.cell + ".host.registration." + c.cell + "."
	info, err := c.controlLog.Info(ctx, jetstream.WithSubjectFilter(prefix+"*"))
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
		status := HostStatus{Registration: r, Verified: !c.readOnly}
		var s session
		sessionRevision, exists, err := c.get(ctx, sessionKey(c.cell, r.Node), &s)
		if err != nil {
			return nil, err
		}
		if exists && s.RegistrationGeneration == r.Generation && time.Now().Before(s.ExpiresAt) {
			status.SessionExpiresAt = s.ExpiresAt
			for _, role := range r.Roles {
				var report Report
				reportRevision, ok, err := c.get(ctx, reportKey(c.cell, r.Node, role), &report)
				if err != nil {
					return nil, err
				}
				if !ok || report.SessionID != s.SessionID || report.Epoch != s.Epoch || time.Since(report.ObservedAt) >= 30*time.Second || report.ObservedAt.After(time.Now().Add(maxClockSkew)) {
					continue
				}
				desired, desiredRevision, ok, err := c.readDesired(ctx, r.Node, role)
				if err != nil {
					return nil, err
				}
				if !ok || report.Generation != desired.Generation || report.Digest != desired.Digest || desired.Withdrawn && report.State == "running" {
					continue
				}
				confirmed, confirmedRevision, ok, err := c.readDesired(ctx, r.Node, role)
				if err != nil || !ok || confirmedRevision != desiredRevision || !sameJSON(confirmed, desired) {
					return nil, errors.New("desired changed during host status read")
				}
				if c.readOnly {
					var check Report
					checkRevision, ok, err := c.get(ctx, reportKey(c.cell, r.Node, role), &check)
					if err != nil || !ok || checkRevision != reportRevision || !sameJSON(check, report) {
						return nil, errors.New("report changed during host status read")
					}
				} else if _, err := c.cas(ctx, reportKey(c.cell, r.Node, role), report, reportRevision); err != nil {
					return nil, fmt.Errorf("report changed during host status read: %w", err)
				}
				status.Reports = append(status.Reports, report)
			}
			if c.readOnly {
				var check session
				checkRevision, ok, err := c.get(ctx, sessionKey(c.cell, r.Node), &check)
				if err != nil || !ok || checkRevision != sessionRevision || !sameJSON(check, s) {
					return nil, errors.New("session changed during host status read")
				}
			} else if _, err := c.cas(ctx, sessionKey(c.cell, r.Node), s, sessionRevision); err != nil {
				return nil, fmt.Errorf("session changed during host status read: %w", err)
			}
		}
		confirmed, confirmedRevision, ok, err := c.readRegistration(ctx, node)
		if err != nil || !ok || confirmedRevision != registrationRevision || !sameJSON(confirmed, r) {
			return nil, errors.New("registration changed during host status read")
		}
		hosts = append(hosts, status)
	}
	slices.SortFunc(hosts, func(a, b HostStatus) int { return strings.Compare(a.Registration.Node, b.Registration.Node) })
	return hosts, nil
}

// Run serves exact host requests until ctx ends. Safe to run on several controllers;
// durable CAS resolves concurrent admission and report writes.
func (c *Controller) Run(ctx context.Context) error {
	var subscriptions []*nats.Subscription
	for _, operation := range []string{"session", "desired", "artifact", "cycle", "report"} {
		sub, err := c.conn.QueueSubscribe("ts.orch.v1."+c.cell+".agent.*.observation."+operation, "host-controller-"+operation, func(msg *nats.Msg) { c.handle(ctx, msg) })
		if err != nil {
			for _, existing := range subscriptions {
				_ = existing.Unsubscribe()
			}
			return err
		}
		subscriptions = append(subscriptions, sub)
	}
	defer func() {
		for _, sub := range subscriptions {
			_ = sub.Unsubscribe()
		}
		c.closeCache()
	}()
	flushCtx, flushCancel := context.WithTimeout(ctx, 5*time.Second)
	err := c.conn.FlushWithContext(flushCtx)
	flushCancel()
	if err != nil {
		return fmt.Errorf("flush host subscriptions: %w", err)
	}
	c.readyOnce.Do(func() { close(c.ready) })
	<-ctx.Done()
	return ctx.Err()
}

func (c *Controller) handle(parent context.Context, msg *nats.Msg) {
	if msg.Reply == "" || len(msg.Data) > 64<<10 {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
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
	expectedSubject, err := protocol.AgentObservationSubject(c.cell, req.Node, req.Operation)
	if err != nil || expectedSubject != msg.Subject || envelope.Actor != req.Node || envelope.Kind != "host."+req.Operation {
		return
	}
	result := response{Nonce: req.Nonce, Node: req.Node, SessionID: req.SessionID, Epoch: req.Epoch, Operation: req.Operation}
	var payload any
	switch req.Operation {
	case "session":
		payload, err = c.handleSession(ctx, req)
	case "desired", "artifact", "cycle", "report":
		payload, err = c.handleAuthorized(ctx, req)
	default:
		err = errors.New("unknown host operation")
	}
	if err != nil {
		result.Error = err.Error()
		result.Retryable = errors.Is(err, errArtifactPreparing)
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
	r, _, exists, err := c.readRegistration(ctx, node)
	if err != nil {
		return Registration{}, err
	}
	if !exists {
		return Registration{}, errors.New("host is not registered")
	}
	return r, nil
}

func (c *Controller) handleSession(ctx context.Context, req request) (any, error) {
	r, err := c.registration(ctx, req.Node)
	if err != nil {
		return nil, err
	}
	key, err := decodePublicKey(r.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := verifyRequest(req, key, c.cell, time.Now().UTC()); err != nil {
		return nil, err
	}
	var operation struct {
		Kind string `json:"kind"`
	}
	if err := decodeStrict(req.Payload, &operation); err != nil {
		return nil, err
	}
	stateKey := sessionKey(c.cell, req.Node)
	for range 8 {
		now := time.Now().UTC()
		var old session
		revision, exists, err := c.get(ctx, stateKey, &old)
		if err != nil {
			return nil, err
		}
		if exists && old.RegistrationGeneration == r.Generation && req.SessionID == old.SessionID && req.Nonce == old.LastNonce && req.IssuedAt.Equal(old.LastIssuedAt) && now.Before(old.ExpiresAt) {
			if _, err := c.cas(ctx, stateKey, old, revision); err == nil {
				return old, nil
			} else if casConflict(err) {
				continue
			} else {
				return nil, err
			}
		}
		var next session
		switch operation.Kind {
		case "acquire":
			if req.Epoch != 0 {
				return nil, errors.New("acquire requires epoch zero")
			}
			if exists && old.RegistrationGeneration == r.Generation && now.Before(old.ExpiresAt) {
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
			if !exists || old.RegistrationGeneration != r.Generation || old.SessionID != req.SessionID || old.Epoch != req.Epoch || !now.Before(old.ExpiresAt) || !req.IssuedAt.After(old.LastIssuedAt) {
				return nil, errors.New("session is no longer renewable")
			}
			next = old
			next.ExpiresAt = req.IssuedAt.Add(sessionTTL)
			next.LastNonce = req.Nonce
			next.LastIssuedAt = req.IssuedAt
		default:
			return nil, errors.New("unknown session operation")
		}
		written, err := c.cas(ctx, stateKey, next, revision)
		if err == nil && written > 0 {
			return next, nil
		}
		if !casConflict(err) {
			return nil, err
		}
	}
	return nil, errors.New("session contention")
}

func (c *Controller) authorize(ctx context.Context, req request) (Registration, session, error) {
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
	var s session
	stateKey := sessionKey(c.cell, req.Node)
	revision, exists, err := c.get(ctx, stateKey, &s)
	if err != nil {
		return Registration{}, session{}, err
	}
	if !exists || s.RegistrationGeneration != r.Generation || s.SessionID != req.SessionID || s.Epoch != req.Epoch || !time.Now().Before(s.ExpiresAt) || req.IssuedAt.Before(s.LastIssuedAt.Add(-requestTTL)) {
		return Registration{}, session{}, errors.New("host session is not current")
	}
	if _, err := c.cas(ctx, stateKey, s, revision); err != nil {
		return Registration{}, session{}, fmt.Errorf("host session changed: %w", err)
	}
	return r, s, nil
}

func (c *Controller) handleAuthorized(ctx context.Context, req request) (any, error) {
	r, s, err := c.authorize(ctx, req)
	if err != nil {
		return nil, err
	}
	switch req.Operation {
	case "desired":
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
			return desiredReply{}, nil
		}
		return desiredReply{Desired: &desired, Revision: revision}, nil
	case "artifact":
		return c.serveArtifact(ctx, req, r)
	case "cycle":
		return c.serveCycle(ctx, req, r, s)
	case "report":
		return c.storeReport(ctx, req, r, s)
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
