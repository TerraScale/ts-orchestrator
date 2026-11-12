package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

const peerCredentialHeader = "X-TerraBase-Peer-Credential"
const forwardedClientHeader = "X-TerraBase-Forwarded-For"

const (
	maxRegionalSockets           = 512
	maxRegionalSocketsPerAddress = 64
	maxInternalTunnels           = 256
)

type regionalTunnel struct {
	node, client string
	cancel       context.CancelFunc
}

type regionalRouter struct {
	nodes     atomic.Pointer[func() []mesh.WorkerPeer]
	changing  chan struct{}
	ingressMu sync.Mutex
	leases    int
	held      chan struct{}
	drained   chan struct{}
	mu        sync.Mutex
	owner     mesh.WorkerPeer
	checked   time.Time
	transport *http.Transport
	requests  chan struct{}
	waiting   atomic.Int64
	recovery  chan struct{}
	tunnelMu  sync.Mutex
	tunnels   map[*regionalTunnel]struct{}
	clients   map[string]int
	sockets   int
	internal  int
}
type regionalStatus struct {
	Node   string `json:"node"`
	Owner  string `json:"owner"`
	Epoch  int64  `json:"epoch"`
	Writer bool   `json:"writer"`
	Ready  bool   `json:"ready"`
}

// SetRegionalNodes discovers backends from authenticated mesh membership.
func (e *Edge) SetRegionalNodes(nodes func() []mesh.WorkerPeer) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetUnencryptedHTTP2(true)
	transport.ResponseHeaderTimeout = 60 * time.Second
	router := e.regional.Load()
	if router == nil {
		candidate := &regionalRouter{transport: transport, requests: make(chan struct{}, 1024), recovery: make(chan struct{}, 2),
			changing: make(chan struct{}, 1), tunnels: map[*regionalTunnel]struct{}{}, clients: map[string]int{}}
		candidate.nodes.Store(&nodes)
		if e.regional.CompareAndSwap(nil, candidate) {
			return
		}
		router = e.regional.Load()
	}
	transport.CloseIdleConnections()
	router.nodes.Store(&nodes)
}

func (e *Edge) regionalRequest(ctx context.Context, router *regionalRouter, peer mesh.WorkerPeer, method, path string) (*http.Response, error) {
	key := e.requestProofSecret.Load()
	if key == nil {
		return nil, errors.New("TerraBase peer credential unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+net.JoinHostPort(peer.Address, "8081")+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set(peerCredentialHeader, string(*key))
	return router.transport.RoundTrip(request)
}
func (e *Edge) regionalStatus(ctx context.Context, router *regionalRouter, peer mesh.WorkerPeer) (regionalStatus, error) {
	response, err := e.regionalRequest(ctx, router, peer, http.MethodGet, "/v1/rollout/status")
	if err != nil {
		return regionalStatus{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return regionalStatus{}, fmt.Errorf("regional status HTTP %d", response.StatusCode)
	}
	var status regionalStatus
	err = json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&status)
	if err == nil && status.Node != peer.Node {
		err = errors.New("regional node identity mismatch")
	}
	return status, err
}
func (e *Edge) regionalOwner(ctx context.Context, router *regionalRouter, fresh bool) (mesh.WorkerPeer, error) {
	router.mu.Lock()
	defer router.mu.Unlock()
	if !fresh && router.owner.Node != "" && time.Since(router.checked) < 250*time.Millisecond {
		return router.owner, nil
	}
	peers := (*router.nodes.Load())()
	// Try the last writer first; during a replacement the other node can be absent.
	if router.owner.Node != "" {
		peers = append([]mesh.WorkerPeer{router.owner}, peers...)
	}
	for _, peer := range peers {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		status, err := e.regionalStatus(probe, router, peer)
		cancel()
		if err != nil || !status.Writer || !status.Ready || status.Owner != peer.Node {
			continue
		}
		router.owner = peer
		router.checked = time.Now()
		return peer, nil
	}
	return mesh.WorkerPeer{}, errors.New("no fenced regional writer is ready")
}

type regionalBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *regionalBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}
func (b *regionalBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.release); return err }

func (r *regionalRouter) change(ctx context.Context) error {
	select {
	case r.changing <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *regionalRouter) holding() chan struct{} {
	r.ingressMu.Lock()
	defer r.ingressMu.Unlock()
	return r.held
}

func (r *regionalRouter) enter() chan struct{} {
	r.ingressMu.Lock()
	defer r.ingressMu.Unlock()
	if r.held == nil {
		r.leases++
	}
	return r.held
}

func (r *regionalRouter) leave() {
	r.ingressMu.Lock()
	defer r.ingressMu.Unlock()
	if r.leases--; r.leases == 0 && r.drained != nil {
		close(r.drained)
		r.drained = nil
	}
}

func (r *regionalRouter) hold(ctx context.Context) (func(), error) {
	held, drained := make(chan struct{}), make(chan struct{})
	r.ingressMu.Lock()
	r.held = held
	if r.leases == 0 {
		close(drained)
	} else {
		r.drained = drained
	}
	r.ingressMu.Unlock()
	release := func() {
		r.ingressMu.Lock()
		r.held, r.drained = nil, nil
		r.ingressMu.Unlock()
		close(held)
	}
	select {
	case <-drained:
		return release, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

func (r *regionalRouter) openTunnel(t *regionalTunnel) (int, string) {
	r.tunnelMu.Lock()
	defer r.tunnelMu.Unlock()
	switch {
	case t.client == "" && r.internal >= maxInternalTunnels:
		return http.StatusServiceUnavailable, fmt.Sprintf("this edge already relays %d internal tunnels to this region\n", maxInternalTunnels)
	case t.client == "":
		r.internal++
	case r.clients[t.client] >= maxRegionalSocketsPerAddress:
		return http.StatusTooManyRequests, fmt.Sprintf("this address already has %d open WebSockets to this region\n", maxRegionalSocketsPerAddress)
	case r.sockets >= maxRegionalSockets:
		return http.StatusServiceUnavailable, fmt.Sprintf("this region already relays %d WebSockets\n", maxRegionalSockets)
	default:
		r.clients[t.client]++
		r.sockets++
	}
	r.tunnels[t] = struct{}{}
	return 0, ""
}

func (r *regionalRouter) closeTunnel(t *regionalTunnel) {
	r.tunnelMu.Lock()
	defer r.tunnelMu.Unlock()
	if _, open := r.tunnels[t]; !open {
		return
	}
	delete(r.tunnels, t)
	if t.client == "" {
		r.internal--
		return
	}
	r.sockets--
	if r.clients[t.client]--; r.clients[t.client] == 0 {
		delete(r.clients, t.client)
	}
}

func (r *regionalRouter) endTunnels(node string, writer bool) {
	r.tunnelMu.Lock()
	defer r.tunnelMu.Unlock()
	for t := range r.tunnels {
		if writer || t.node == node {
			t.cancel()
		}
	}
}

func socketAddress(client string) string {
	address, err := netip.ParseAddr(client)
	if err != nil {
		return client
	}
	if address = address.Unmap(); address.Is4() {
		return address.String()
	}
	network, _ := address.Prefix(64)
	return network.String()
}

func (e *Edge) regionalRoundTrip(request *http.Request, internal bool) (*http.Response, error) {
	if e.bootstrapErr != nil {
		return nil, e.bootstrapErr
	}
	if e.bootstrap != nil {
		held, err := e.bootstrap.Ingress(request.Context())
		if err != nil {
			return nil, err
		}
		if held != nil && held.Member == held.Owner {
			return nil, errors.New("regional maintenance ingress held")
		}
	}
	router := e.regional.Load()
	if router == nil {
		return nil, nil
	}
	select {
	case router.requests <- struct{}{}:
	default:
		return nil, errors.New("regional ingress is full")
	}
	admitted, waited, paced, handedOff := false, false, false, false
	release := func() {
		if admitted {
			router.leave()
		}
		if paced {
			<-router.recovery
		}
		if waited {
			router.waiting.Add(-1)
		}
		<-router.requests
	}
	defer func() {
		if !handedOff {
			release()
		}
	}()
	for {
		held := router.holding()
		if held == nil {
			if !paced && router.waiting.Load() > 0 {
				select {
				case router.recovery <- struct{}{}:
					paced = true
				case <-request.Context().Done():
					return nil, request.Context().Err()
				}
			}
			if held = router.enter(); held == nil {
				admitted = true
				break
			}
		}
		if !waited {
			waited = true
			router.waiting.Add(1)
		}
		select {
		case <-request.Context().Done():
			return nil, request.Context().Err()
		case <-held:
		}
	}
	peer, err := e.regionalOwner(request.Context(), router, false)
	if err != nil {
		return nil, err
	}
	key := e.requestProofSecret.Load()
	if key == nil {
		return nil, errors.New("TerraBase peer credential unavailable")
	}
	client := ""
	if !internal {
		// X-Forwarded-For was derived by this edge (or its authenticated mesh peer).
		// Never trust a public caller's peer-only client identity header.
		client, _, _ = net.SplitHostPort(request.RemoteAddr)
		if forwarded := request.Header.Get("X-Forwarded-For"); forwarded != "" {
			client = strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
	}
	ctx := request.Context()
	var transport http.RoundTripper = router.transport
	tunnel := &regionalTunnel{node: peer.Node, client: socketAddress(client)}
	established := roundTripper(func(r *http.Request) (*http.Response, error) {
		response, err := tunnelTransport{dial: router.transport.DialContext}.RoundTrip(r)
		if err == nil && response.StatusCode/100 == 2 {
			response.Body = &regionalBody{ReadCloser: response.Body, release: func() { router.closeTunnel(tunnel) }}
		}
		return response, err
	})
	switch {
	case isExtendedConnect(request):
		transport = established
	case websocketHandshake(request):
		transport = upgradeTunnel{established}
	default:
		tunnel = nil
	}
	if tunnel != nil {
		ctx, tunnel.cancel = context.WithCancel(ctx)
		if status, message := router.openTunnel(tunnel); status != 0 {
			tunnel.cancel()
			header := http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "Content-Length": {strconv.Itoa(len(message))}, "Retry-After": {"1"}}
			return &http.Response{Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), StatusCode: status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
				Header: header, Body: io.NopCloser(strings.NewReader(message)), ContentLength: int64(len(message)), Request: request}, nil
		}
		context.AfterFunc(ctx, func() { router.closeTunnel(tunnel) })
	}
	out := request.Clone(ctx)
	out.URL.Host = net.JoinHostPort(peer.Address, "8081")
	out.URL.Scheme = "http"
	out.Header.Set(peerCredentialHeader, string(*key))
	if !internal {
		out.Header.Set(forwardedClientHeader, client)
	}
	if tunnel == nil {
		out.Header.Del("Connection")
		out.Header.Del("Upgrade")
	}
	response, err := transport.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	if tunnel != nil && (response.StatusCode == http.StatusSwitchingProtocols || response.StatusCode/100 == 2) {
		return response, nil
	}
	response.Body = &regionalBody{ReadCloser: response.Body, release: release}
	handedOff = true
	return response, nil
}

// DrainRegionalNode authorizes a stop only after ingress has drained and a
// different ready node owns the region following an applied-position handoff.
func (e *Edge) DrainRegionalNode(ctx context.Context, node string) error {
	router := e.regional.Load()
	if router == nil {
		return errors.New("regional routing unavailable")
	}
	if err := router.change(ctx); err != nil {
		return err
	}
	defer func() { <-router.changing }()
	owner, err := e.regionalOwner(ctx, router, true)
	if err != nil {
		return err
	}
	var target mesh.WorkerPeer
	admitted := false
	for _, peer := range (*router.nodes.Load())() {
		if peer.Node == node {
			admitted = true
		} else {
			target = peer
		}
	}
	if !admitted || target.Node == "" {
		return errors.New("replacement has no admitted regional peer")
	}
	slog.Info("regional replacement requested", "source", node, "target", target.Node, "writer", owner.Node)
	if owner.Node == node {
		// Copy bulk state while clients still use the writer; the final fenced pull
		// under the ingress barrier proves positions and transfers ownership.
		response, err := e.regionalRequest(ctx, router, target, http.MethodPost, "/v1/rollout/prime?source="+url.QueryEscape(node))
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("regional prime HTTP %d", response.StatusCode)
		}
	}
	release, err := router.hold(ctx)
	if err != nil {
		return err
	}
	router.endTunnels(node, owner.Node == node)
	held := true
	releaseIngress := func() {
		if held {
			release()
			held = false
		}
	}
	defer releaseIngress()
	slog.Info("regional edge requests drained", "source", node, "target", target.Node)
	router.transport.CloseIdleConnections()
	source := owner
	for _, peer := range (*router.nodes.Load())() {
		if peer.Node == node {
			source = peer
		}
	}
	drainCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	drained := make(chan error, 1)
	go func() {
		drained <- e.regionalDrain(drainCtx, router, source, target)
	}()
	complete := false
	for {
		// The candidate's writer readiness follows the applied-position proof
		// and CAS. Serve there while the source finishes remote observation and
		// direct-request drain; only a completed drain can authorize SIGTERM.
		probe, stopProbe := context.WithTimeout(ctx, time.Second)
		status, err := e.regionalStatus(probe, router, target)
		stopProbe()
		if err == nil && status.Writer && status.Ready && status.Owner == target.Node {
			router.mu.Lock()
			router.owner = target
			router.checked = time.Now()
			router.mu.Unlock()
			if held {
				releaseIngress()
				slog.Info("regional ingress resumed", "source", node, "target", target.Node, "epoch", status.Epoch)
			}
			if complete {
				slog.Info("regional surviving writer ready", "source", node, "target", target.Node, "epoch", status.Epoch)
				return nil
			}
		}
		select {
		case err := <-drained:
			if err != nil {
				return err
			}
			complete = true
		case <-ctx.Done():
			if !complete {
				if err := <-drained; err != nil {
					return err
				}
			}
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (e *Edge) regionalDrain(ctx context.Context, router *regionalRouter, source, target mesh.WorkerPeer) error {
	var lastErr error
	for {
		response, err := e.regionalRequest(ctx, router, source, http.MethodPost, "/v1/rollout/drain?target="+url.QueryEscape(target.Node))
		if err != nil {
			if lastErr != nil && ctx.Err() != nil {
				return fmt.Errorf("%w: %w", lastErr, ctx.Err())
			}
			return err
		}
		if response.StatusCode == http.StatusNoContent {
			response.Body.Close()
			return nil
		}
		var refusal struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&refusal)
		response.Body.Close()
		if decodeErr != nil && lastErr != nil && ctx.Err() != nil {
			return fmt.Errorf("%w: %w", lastErr, ctx.Err())
		}
		lastErr = fmt.Errorf("regional handoff HTTP %d", response.StatusCode)
		if refusal.Error.Code != "" {
			lastErr = fmt.Errorf("%w: %s", lastErr, refusal.Error.Code)
		}
		delay, ok := regionalDrainDelay(response.Header.Get("Retry-After"))
		if response.StatusCode != http.StatusServiceUnavailable || !ok {
			return lastErr
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
			return fmt.Errorf("%w: %w", lastErr, context.DeadlineExceeded)
		}
		slog.Info("regional handoff waiting", "source", source.Node, "target", target.Node, "code", refusal.Error.Code, "delay", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%w: %w", lastErr, ctx.Err())
		case <-timer.C:
		}
	}
}

func regionalDrainDelay(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		if seconds >= 30 {
			return 30 * time.Second, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return min(max(time.Until(when), 0), 30*time.Second), true
}

// serveRegionalInternal selects a backend for each HTTP/2 request, including
// already pooled auth/dashboard connections, rather than pinning the TCP stream.
func (e *Edge) serveRegionalInternal(ln net.Listener) error {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	relay := roundTripper(func(r *http.Request) (*http.Response, error) {
		if response, err := e.regionalRoundTrip(r, true); response != nil || err != nil {
			return response, err
		}
		address, err := e.terrabase()
		if err != nil {
			closeBody(r)
			return nil, err
		}
		r.URL.Host = address
		if isExtendedConnect(r) {
			return tunnelTransport{dial: dialTerraBase}.RoundTrip(r)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Protocols = protocols
		transport.DialContext = dialTerraBase
		defer transport.CloseIdleConnections()
		return transport.RoundTrip(r)
	})
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(&url.URL{Scheme: "http", Host: terrabaseLoopback})
		pr.Out.Host = pr.In.Host
	}, Transport: relay, FlushInterval: -1}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isExtendedConnect(r) {
			relayTunnel(w, r, relay)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: handler, Protocols: protocols, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10,
		IdleTimeout: clientIdleTimeout, HTTP2: &http.HTTP2Config{WriteByteTimeout: clientIdleTimeout}}
	return server.Serve(ln)
}
