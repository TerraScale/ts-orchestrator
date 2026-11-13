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
	"strings"
	"sync/atomic"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

const edgeHopHeader = "X-TerraScale-Edge-Hop"

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
	if routes == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(routes.ready))
}

func (e *Edge) SetPeerEdges(peers func() []mesh.WorkerPeer) { e.peerEdges.Store(&peers) }

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

func (e *Edge) routePeerEdge(r *http.Request) *http.Request {
	port, _ := e.port(r.Host)
	if port == 8080 || r.Context().Value(edgeHopKey{}) != nil {
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
	peers := e.peerEdges.Load()
	if service == "" || routes.ready[service] || peers == nil || e.requestProofSecret.Load() == nil {
		return r
	}
	addresses := []string{}
	for _, peer := range (*peers)() {
		if slices.Contains(peer.ReadyServices, service) {
			addresses = append(addresses, peer.Address)
		}
	}
	if len(addresses) == 0 {
		return r
	}
	value, _ := e.edgeNext.LoadOrStore(service, new(atomic.Uint64))
	start := int((value.(*atomic.Uint64).Add(1) - 1) % uint64(len(addresses)))
	addresses = append(slices.Clone(addresses[start:]), addresses[:start]...)
	return r.WithContext(context.WithValue(r.Context(), edgeTargetKey{}, edgeTarget{addresses: addresses}))
}

type edgeAttemptBody struct {
	io.ReadCloser
	connected *atomic.Bool
}

func (b edgeAttemptBody) Close() error {
	if b.connected.Load() {
		return b.ReadCloser.Close()
	}
	return nil
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
	var lastErr error
	for _, address := range target.addresses {
		connected := new(atomic.Bool)
		out := r.Clone(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
			GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
		}))
		out.URL.Scheme = "https"
		out.URL.Host = net.JoinHostPort(address, "443")
		out.Header.Set(peerCredentialHeader, string(*key))
		out.Header.Set(edgeHopHeader, "1")
		if r.Body != nil {
			out.Body = edgeAttemptBody{ReadCloser: r.Body, connected: connected}
		}
		response, err := value.(*http.Transport).RoundTrip(out)
		var dialErr *net.OpError
		if err == nil || connected.Load() {
			return response, err
		}
		if !errors.As(err, &dialErr) || dialErr.Op != "dial" || r.Context().Err() != nil {
			closeBody(r)
			return response, err
		}
		lastErr = err
	}
	closeBody(r)
	return nil, lastErr
}
