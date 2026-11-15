package edge

import (
	"context"
	"crypto/hmac"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

const edgeHopHeader = "X-TerraScale-Edge-Hop"
const edgeUnavailableHeader = "X-TerraScale-Edge-Unavailable"

var errNoReadyService = errors.New("no ready service backend")

type edgeHopKey struct{}
type edgeTargetKey struct{}

type edgeTarget struct {
	addresses []string
}

type serviceRoutes struct {
	hosts map[string]string
	ready map[string]bool
}

func (e *Edge) SetServiceRoutes(web, postgres map[string]int, hosts map[string]string, ready []string) {
	routes := &serviceRoutes{hosts: make(map[string]string, len(hosts)), ready: map[string]bool{}}
	for host, service := range hosts {
		routes.hosts[strings.ToLower(host)] = service
	}
	for _, service := range ready {
		routes.ready[service] = true
	}
	e.serviceRoutes.Store(routes)
	e.setRoutes(web, postgres)
}

func (e *Edge) ReadyServices() []string {
	routes := e.serviceRoutes.Load()
	if routes == nil || e.draining.Load() {
		return nil
	}
	return slices.Sorted(maps.Keys(routes.ready))
}

func (e *Edge) SetPeerEdges(peers func() []mesh.WorkerPeer) { e.peerEdges.Store(&peers) }

func (e *Edge) peerAdvertised(peer mesh.WorkerPeer) {
	e.peerSeen.Store(peer.Address, time.Now())
	if len(peer.ReadyServices) != 0 {
		e.peerDown.Delete(peer.Address)
	}
}

func (e *Edge) peerAlive(address string) bool {
	seen, ok := e.peerSeen.Load(address)
	return ok && time.Since(seen.(time.Time)) <= time.Duration(e.peerLiveness.Load())
}

func (e *Edge) watchPeer(address string, done <-chan struct{}, cancel context.CancelFunc) {
	liveness := time.Duration(e.peerLiveness.Load())
	if liveness <= 0 {
		return
	}
	tick := time.NewTicker(liveness / 4)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			if !e.peerAlive(address) {
				cancel()
				return
			}
		}
	}
}

func (e *Edge) authorizeEdgeHop(w http.ResponseWriter, r *http.Request) bool {
	values := r.Header.Values(edgeHopHeader)
	if len(values) == 0 {
		r.Header.Del(peerCredentialHeader)
		return true
	}
	key := e.requestProofSecret.Load()
	credentials := r.Header.Values(peerCredentialHeader)
	if len(values) != 1 || values[0] != "1" || key == nil || len(credentials) != 1 || !hmac.Equal([]byte(credentials[0]), *key) {
		secureHeaders(w.Header())
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if port, _ := e.port(r.Host); port == 8080 {
		secureHeaders(w.Header())
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), edgeHopKey{}, true))
	r.Header.Del(edgeHopHeader)
	r.Header.Del(peerCredentialHeader)
	return true
}

func (e *Edge) routePeerEdge(r *http.Request, balance bool) *http.Request {
	port, _ := e.port(r.Host)
	if port == 8080 {
		return r
	}
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	routes := e.serviceRoutes.Load()
	if routes == nil {
		return r
	}
	service := routes.hosts[strings.ToLower(host)]
	if service == "" {
		return r
	}
	held := handoff.Held(uint16(port))
	ready := routes.ready[service] && !e.draining.Load()
	if r.Context().Value(edgeHopKey{}) != nil {
		if ready || held {
			return r
		}
		return r.WithContext(context.WithValue(r.Context(), edgeTargetKey{}, edgeTarget{addresses: []string{""}}))
	}
	if ready && !held {
		return r
	}
	addresses := []string{}
	if peers := e.peerEdges.Load(); peers != nil && e.requestProofSecret.Load() != nil {
		for _, peer := range (*peers)() {
			if _, down := e.peerDown.Load(peer.Address); !down && slices.Contains(peer.ReadyServices, service) {
				addresses = append(addresses, peer.Address)
			}
		}
	}
	if balance && len(addresses) > 1 {
		value, _ := e.edgeNext.LoadOrStore(service, new(atomic.Uint64))
		start := int((value.(*atomic.Uint64).Add(1) - 1) % uint64(len(addresses)))
		addresses = append(slices.Clone(addresses[start:]), addresses[:start]...)
	}
	addresses = append(addresses, "")
	if len(addresses) == 1 && held {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), edgeTargetKey{}, edgeTarget{addresses: addresses}))
}

type edgeAttemptBody struct {
	io.ReadCloser
	consumed *atomic.Bool
}

func (b edgeAttemptBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 || err != nil {
		b.consumed.Store(true)
	}
	return n, err
}

func (b edgeAttemptBody) Close() error {
	if b.consumed.Load() {
		return b.ReadCloser.Close()
	}
	return nil
}

type peerResponseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b peerResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

type peerUpgradeBody struct {
	io.ReadWriteCloser
	cancel context.CancelFunc
}

func (b peerUpgradeBody) Close() error {
	err := b.ReadWriteCloser.Close()
	b.cancel()
	return err
}

func resendable(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions || method == http.MethodTrace
}

func (e *Edge) peerEdgeRoundTrip(r *http.Request, target edgeTarget) (*http.Response, error) {
	key := e.requestProofSecret.Load()
	if key == nil {
		closeBody(r)
		return nil, errors.New("edge peer credential unavailable")
	}
	grpc := isGRPC(r)
	value, ok := e.edgeTransports.Load(grpc)
	if !ok {
		transport := newPeerTransport(e)
		if grpc {
			transport.ResponseHeaderTimeout = 0
		}
		transport.Protocols = new(http.Protocols)
		transport.Protocols.SetHTTP1(true)
		transport.Protocols.SetHTTP2(grpc)
		value, ok = e.edgeTransports.LoadOrStore(grpc, transport)
		if ok {
			transport.CloseIdleConnections()
		}
	}
	hasBody := r.Body != nil && r.Body != http.NoBody
	var lastErr error
	for _, address := range target.addresses {
		if address == "" {
			local := context.WithValue(r.Context(), edgeTargetKey{}, nil)
			if port, err := strconv.ParseUint(r.URL.Port(), 10, 16); err == nil && !handoff.Held(uint16(port)) {
				local = context.WithValue(local, localDialOnceKey{}, true)
			}
			response, err := e.local.RoundTrip(r.WithContext(local))
			if errors.Is(err, syscall.ECONNREFUSED) {
				err = errors.Join(errNoReadyService, err)
			}
			return response, err
		}
		attempt, cancel := context.WithCancel(r.Context())
		connected, consumed := new(atomic.Bool), new(atomic.Bool)
		out := r.Clone(httptrace.WithClientTrace(attempt, &httptrace.ClientTrace{
			GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
		}))
		out.URL.Scheme = "https"
		out.URL.Host = net.JoinHostPort(address, "443")
		out.Header.Set(peerCredentialHeader, string(*key))
		out.Header.Set(edgeHopHeader, "1")
		if hasBody {
			out.Body = edgeAttemptBody{ReadCloser: r.Body, consumed: consumed}
		}
		done := make(chan struct{})
		go e.watchPeer(address, done, cancel)
		response, err := value.(*http.Transport).RoundTrip(out)
		close(done)
		if err == nil && response.Header.Get(edgeUnavailableHeader) != "" {
			response.Header.Del(edgeUnavailableHeader)
			if !consumed.Load() {
				response.Body.Close()
				cancel()
				lastErr = errNoReadyService
				continue
			}
		}
		if err == nil {
			if upgraded, ok := response.Body.(io.ReadWriteCloser); ok && response.StatusCode == http.StatusSwitchingProtocols {
				response.Body = peerUpgradeBody{ReadWriteCloser: upgraded, cancel: cancel}
			} else {
				response.Body = peerResponseBody{ReadCloser: response.Body, cancel: cancel}
			}
			return response, nil
		}
		cancel()
		if r.Context().Err() != nil {
			closeBody(r)
			return nil, err
		}
		e.peerDown.Store(address, time.Now())
		if consumed.Load() || connected.Load() && !resendable(r.Method) {
			closeBody(r)
			return nil, err
		}
		lastErr = err
	}
	closeBody(r)
	return nil, lastErr
}
