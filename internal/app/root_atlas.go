package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/atlas"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type rootAtlasState struct {
	mu        sync.Mutex
	publisher atlas.Publisher
	peers     rosterPeers
	sequence  uint64
	roster    []byte
}

type rootAtlasObservation struct {
	root     *rootReleaseObservation
	state    *rootAtlasState
	sequence uint64
	roster   []byte
	ref      vaultsecret.Ref
	secrets  vaultsecret.BundleClient
	key      vaultsecret.Current
	keySHA   [32]byte
}

func (b *rootReleaseChannels) ReconcileAtlasTopology(parent context.Context, call rootoci.Call) (rootoci.AtlasTopologyReceipt, error) {
	if b == nil || !b.atlas.mu.TryLock() {
		return rootoci.AtlasTopologyReceipt{}, rootrelease.ErrPending
	}
	defer b.atlas.mu.Unlock()
	ctx, stop := context.WithTimeout(parent, atlas.Interval)
	defer stop()
	ctx, cancel, o, err := b.beginChannel(ctx, call, rootoci.OperationReconcileAtlasTopology)
	defer cancel()
	if err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	deadline, _ := ctx.Deadline()
	o.capDeadline(deadline)
	if o.registry.atlasConfig() == nil {
		if err := o.guard(ctx); err != nil {
			return rootoci.AtlasTopologyReceipt{}, err
		}
		if err := o.call.Seal(ctx); err != nil {
			return rootoci.AtlasTopologyReceipt{}, err
		}
		return rootoci.AtlasTopologyReceipt{State: rootoci.AtlasTopologyUnconfigured, ExpiresAt: o.deadline}, nil
	}

	a := &rootAtlasObservation{root: o, state: &b.atlas}
	if roster, sequence, wire, err := a.readRoster(ctx); err == nil {
		peers := rosterPeersOf(roster, b.cfg.NATS.Cell)
		// Match followRoster: an initial empty peer set keeps the spec fallback.
		if !slices.Equal(peers, b.atlas.peers.current()) {
			b.atlas.peers.apply(peers)
		}
		b.atlas.sequence, b.atlas.roster = sequence, bytes.Clone(wire)
	}
	// An unavailable roster retains root's last admitted prefix, not a claim
	// that the global home is current. Before that prefix, use the signed spec.
	a.sequence, a.roster = b.atlas.sequence, bytes.Clone(b.atlas.roster)
	config := atlasRoster(o.registry.atlasConfig, b.cfg.NATS.Cell, &b.atlas.peers)()
	if err := config.Validate(b.cfg.NATS.Cell); err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	a.ref = config.PublishKey
	if err := o.guard(ctx); err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	secrets, err := vaultsecret.SecretsClient(b.factory)
	if err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	a.secrets = secrets
	a.key, err = vaultsecret.ReadCurrent(ctx, a.secrets, a.ref)
	if err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	if !a.key.ExpiresAt.IsZero() {
		o.capDeadline(a.key.ExpiresAt)
	}
	a.keySHA = sha256.Sum256([]byte(a.key.Value()))
	if err := a.guard(ctx); err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	key, err := atlas.ParseKey(a.key.Value())
	if err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	transport := newRootAtlasHTTP(*config, a.guard, o.guard, a.seal)
	b.atlas.publisher.Key = key
	b.atlas.publisher.HTTP = &http.Client{Transport: transport, Timeout: atlas.Interval,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer func() { b.atlas.publisher.Key, b.atlas.publisher.HTTP = nil, nil }()
	if err := b.atlas.publisher.Publish(ctx, *config, time.Now().UTC(), a.guard); err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	if err := a.guard(ctx); err != nil {
		return rootoci.AtlasTopologyReceipt{}, err
	}
	return rootoci.AtlasTopologyReceipt{State: rootoci.AtlasTopologyPublished, ExpiresAt: o.deadline}, nil
}

// Every successful read verifies the existing stream against root's signed
// topology, then reads the home record or the mirror's authenticated prefix.
func (a *rootAtlasObservation) readRoster(ctx context.Context) (globalcontrol.Roster, uint64, []byte, error) {
	b := a.root.b
	home, err := globalControlHome(b.cfg.Controller.Global, b.cfg.NATS)
	if err != nil {
		return globalcontrol.Roster{}, 0, nil, err
	}
	var reader *globalcontrol.Reader
	if home == b.cfg.NATS.Cell {
		reader, err = globalcontrol.OpenHomeReader(ctx, b.js, b.cfg.NATS.Replicas)
	} else {
		reader, err = globalcontrol.OpenMirrorReader(ctx, b.js, home, b.cfg.NATS.Cell, b.cfg.NATS.Replicas)
	}
	if err != nil {
		return globalcontrol.Roster{}, 0, nil, err
	}
	roster, sequence, err := reader.Roster(ctx)
	if errors.Is(err, globalcontrol.ErrNotFound) {
		return globalcontrol.Roster{}, 0, nil, nil
	}
	if err != nil {
		return globalcontrol.Roster{}, 0, nil, err
	}
	wire, err := json.Marshal(roster, json.Deterministic(true))
	return roster, sequence, wire, err
}

func (a *rootAtlasObservation) guard(ctx context.Context) error {
	if err := a.root.guard(ctx); err != nil {
		return err
	}
	_, sequence, wire, err := a.readRoster(ctx)
	if err == nil && (sequence != a.sequence || !bytes.Equal(wire, a.roster)) {
		return rootrelease.ErrPending
	}
	if err := a.seal(ctx); err != nil {
		return err
	}
	current, err := vaultsecret.ReadCurrent(ctx, a.secrets, a.ref)
	if err != nil {
		return err
	}
	if current.ID != a.key.ID || current.Version != a.key.Version || !current.ExpiresAt.Equal(a.key.ExpiresAt) ||
		sha256.Sum256([]byte(current.Value())) != a.keySHA {
		return rootrelease.ErrPending
	}
	if err := a.root.guard(ctx); err != nil {
		return err
	}
	return a.seal(ctx)
}

// The last seal performs no remote read, so another await cannot extend the
// original Call, runtime lease, source, key or selected roster snapshot.
func (a *rootAtlasObservation) seal(ctx context.Context) error {
	o := a.root
	if err := o.call.Seal(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || o.scopeCtx.Err() != nil || o.b.ctx.Err() != nil ||
		!time.Now().Before(o.deadline) || !time.Now().Before(o.source.ExpiresAt()) ||
		!time.Now().Before(o.lease.Deadline()) ||
		!a.key.ExpiresAt.IsZero() && !time.Now().Before(a.key.ExpiresAt) ||
		a.state.sequence != a.sequence || !bytes.Equal(a.state.roster, a.roster) {
		return rootrelease.ErrPending
	}
	return nil
}

type rootAtlasHTTP struct {
	publish    string
	probes     map[string]bool
	guard      func(context.Context) error
	probeGuard func(context.Context) error
	seal       func(context.Context) error
	dispatched atomic.Bool
}

func newRootAtlasHTTP(config atlas.Config, guard, probeGuard, seal func(context.Context) error) *rootAtlasHTTP {
	transport := &rootAtlasHTTP{publish: strings.TrimSuffix(config.URL, "/") + "/v1/publish",
		probes: map[string]bool{}, guard: guard, probeGuard: probeGuard, seal: seal}
	for _, region := range config.Regions {
		transport.probes[strings.TrimSuffix(region.API, "/")+"/readyz"] = true
	}
	return transport
}

func (t *rootAtlasHTTP) RoundTrip(request *http.Request) (*http.Response, error) {
	guard := t.probeGuard
	if request.Method == http.MethodPost {
		if request.URL.String() != t.publish || !t.dispatched.CompareAndSwap(false, true) {
			return nil, rootoci.ErrUnauthorized
		}
		// A partially written signed POST must never be replayed by Transport.
		request = request.Clone(request.Context())
		request.GetBody = nil
		guard = t.guard
	} else if request.Method != http.MethodGet || !t.probes[request.URL.String()] {
		return nil, rootoci.ErrUnauthorized
	}
	if err := guard(request.Context()); err != nil {
		return nil, err
	}
	if err := t.seal(request.Context()); err != nil {
		return nil, err
	}
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		return response, err
	}
	if err := guard(request.Context()); err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	response.Body = &rootAtlasBody{ReadCloser: response.Body, ctx: request.Context(), seal: t.seal}
	return response, nil
}

type rootAtlasBody struct {
	io.ReadCloser
	ctx  context.Context
	seal func(context.Context) error
}

func (b *rootAtlasBody) Read(value []byte) (int, error) {
	if err := b.seal(b.ctx); err != nil {
		return 0, err
	}
	n, err := b.ReadCloser.Read(value)
	if guardErr := b.seal(b.ctx); guardErr != nil {
		return 0, guardErr
	}
	return n, err
}
