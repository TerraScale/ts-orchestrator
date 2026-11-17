package edge

import (
	"context"
	"crypto/hmac"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

const edgeHopHeader = "X-TerraScale-Edge-Hop"
const peerLayerBudget = 30 * time.Second

type edgeHopKey struct{}
type peerUnreachableKey struct{}
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
	before := e.ReadyServices()
	e.serviceRoutes.Store(routes)
	observability.SetServiceRequestRoutes(routes.hosts)
	e.setRoutes(web, postgres)
	if !slices.Equal(before, e.ReadyServices()) {
		e.announceReady()
	}
}

func (e *Edge) announceReady() {
	if changed := e.readyChanged.Load(); changed != nil {
		(*changed)()
	}
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
	if len(peer.ReadyServices) != 0 {
		e.peerDown.Delete(peer.Address)
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
	if r.Context().Value(edgeHopKey{}) != nil {
		return r
	}
	port, _ := e.port(r.Host)
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	service, addresses := e.peerCandidates(host, port)
	if len(addresses) == 0 {
		return r
	}
	if balance && len(addresses) > 1 {
		value, _ := e.edgeNext.LoadOrStore(service, new(atomic.Uint64))
		start := int((value.(*atomic.Uint64).Add(1) - 1) % uint64(len(addresses)))
		addresses = append(slices.Clone(addresses[start:]), addresses[:start]...)
	}
	return r.WithContext(context.WithValue(r.Context(), edgeTargetKey{}, edgeTarget{addresses: append(addresses, "")}))
}

func (e *Edge) peerCandidates(host string, port int) (string, []string) {
	routes := e.serviceRoutes.Load()
	peers := e.peerEdges.Load()
	if port == 8080 || routes == nil || peers == nil || e.requestProofSecret.Load() == nil {
		return "", nil
	}
	service := routes.hosts[strings.ToLower(host)]
	if service == "" || routes.ready[service] && !e.draining.Load() && !handoff.Held(uint16(port)) {
		return "", nil
	}
	addresses := []string{}
	for _, peer := range (*peers)() {
		if _, down := e.peerDown.Load(peer.Address); !down && slices.Contains(peer.ReadyServices, service) {
			addresses = append(addresses, peer.Address)
		}
	}
	return service, addresses
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

func (b peerUpgradeBody) CloseWrite() error {
	if writer, ok := b.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return http.ErrNotSupported
}

func resendable(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions || method == http.MethodTrace
}

func (e *Edge) peerEdgeRoundTrip(r *http.Request, target edgeTarget) (*http.Response, error) {
	grpc := isGRPC(r)
	budget, endBudget := context.WithCancel(r.Context())
	var mu sync.Mutex
	var timer *time.Timer
	answered := false
	budget = httptrace.WithClientTrace(budget, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if grpc || info.Err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if !answered && timer == nil {
				timer = time.AfterFunc(peerLayerBudget, endBudget)
			}
		},
	})
	stopBudget := func() {
		mu.Lock()
		defer mu.Unlock()
		answered = true
		if timer != nil {
			timer.Stop()
		}
	}
	fail := func(err error) (*http.Response, error) {
		stopBudget()
		endBudget()
		closeBody(r)
		return nil, err
	}
	answer := func(response *http.Response, cancel context.CancelFunc) (*http.Response, error) {
		stopBudget()
		end := func() {
			cancel()
			endBudget()
		}
		if upgraded, ok := response.Body.(io.ReadWriteCloser); ok && response.StatusCode == http.StatusSwitchingProtocols {
			response.Body = peerUpgradeBody{ReadWriteCloser: upgraded, cancel: end}
		} else {
			response.Body = peerResponseBody{ReadCloser: response.Body, cancel: end}
		}
		return response, nil
	}
	hasBody := r.Body != nil && r.Body != http.NoBody
	var lastErr error
	for _, address := range target.addresses {
		if address == "" {
			response, err := e.local.RoundTrip(r.WithContext(context.WithValue(budget, edgeTargetKey{}, nil)))
			if err != nil {
				stopBudget()
				endBudget()
				return nil, err
			}
			return answer(response, func() {})
		}
		key := e.requestProofSecret.Load()
		if key == nil {
			continue
		}
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
		attempt, cancel := context.WithCancel(budget)
		connected, consumed, unreachable := new(atomic.Bool), new(atomic.Bool), new(atomic.Bool)
		out := r.Clone(httptrace.WithClientTrace(context.WithValue(attempt, peerUnreachableKey{}, unreachable), &httptrace.ClientTrace{
			GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
		}))
		out.URL.Scheme = "https"
		out.URL.Host = net.JoinHostPort(address, "443")
		out.Header.Set(peerCredentialHeader, string(*key))
		out.Header.Set(edgeHopHeader, "1")
		if hasBody {
			out.Body = edgeAttemptBody{ReadCloser: r.Body, consumed: consumed}
		}
		response, err := value.(*http.Transport).RoundTrip(out)
		if err == nil {
			return answer(response, cancel)
		}
		cancel()
		if r.Context().Err() != nil || budget.Err() != nil {
			return fail(err)
		}
		if unreachable.Load() && !connected.Load() {
			e.peerDown.Store(address, time.Now())
		}
		if consumed.Load() || connected.Load() && !resendable(r.Method) {
			return fail(err)
		}
		lastErr = err
	}
	return fail(lastErr)
}
