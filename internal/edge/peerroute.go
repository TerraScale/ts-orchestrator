package edge

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"errors"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

const edgeHopHeader = "X-TerraScale-Edge-Hop"

type edgeHopKey struct{}
type edgeTargetKey struct{}

type edgeTransportKey struct {
	serverName string
	grpc       bool
}

type edgeTarget struct {
	address, serverName string
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

func (e *Edge) ClearReadyServices() {
	for {
		routes := e.serviceRoutes.Load()
		if routes == nil || e.serviceRoutes.CompareAndSwap(routes, &serviceRoutes{hosts: routes.hosts, ready: map[string]bool{}}) {
			return
		}
	}
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
		return true
	}
	key := e.requestProofSecret.Load()
	credentials := r.Header.Values(peerCredentialHeader)
	if len(values) != 1 || values[0] != "1" || key == nil || len(credentials) != 1 || !hmac.Equal([]byte(credentials[0]), *key) {
		secureHeaders(w.Header())
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), edgeHopKey{}, true))
	r.Header.Del(edgeHopHeader)
	r.Header.Del(peerCredentialHeader)
	return true
}

func (e *Edge) routePeerEdge(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	routes := e.serviceRoutes.Load()
	service := ""
	if routes != nil {
		service = routes.hosts[strings.ToLower(host)]
		if service != "" && routes.ready[service] {
			return r, true
		}
	}
	if service != "" && r.Context().Value(edgeHopKey{}) == nil {
		if peers := e.peerEdges.Load(); peers != nil {
			candidates := []mesh.WorkerPeer{}
			for _, peer := range (*peers)() {
				if slices.Contains(peer.ReadyServices, service) {
					candidates = append(candidates, peer)
				}
			}
			if len(candidates) != 0 && e.requestProofSecret.Load() != nil {
				value, _ := e.edgeNext.LoadOrStore(service, new(atomic.Uint64))
				peer := candidates[(value.(*atomic.Uint64).Add(1)-1)%uint64(len(candidates))]
				sni := host
				if r.TLS != nil && r.TLS.ServerName != "" {
					sni = r.TLS.ServerName
				}
				target := edgeTarget{address: peer.Address, serverName: sni}
				return r.WithContext(context.WithValue(r.Context(), edgeTargetKey{}, target)), true
			}
		}
	}
	secureHeaders(w.Header())
	w.WriteHeader(http.StatusServiceUnavailable)
	return r, false
}

func (e *Edge) peerEdgeRoundTrip(r *http.Request, target edgeTarget) (*http.Response, error) {
	key := e.requestProofSecret.Load()
	if key == nil {
		return nil, errors.New("edge peer credential unavailable")
	}
	transportKey := edgeTransportKey{serverName: target.serverName, grpc: isGRPC(r)}
	value, ok := e.edgeTransports.Load(transportKey)
	if !ok {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.serverName}
		transport.ResponseHeaderTimeout = 30 * time.Second
		transport.Protocols = new(http.Protocols)
		transport.Protocols.SetHTTP1(true)
		transport.Protocols.SetHTTP2(transportKey.grpc)
		value, ok = e.edgeTransports.LoadOrStore(transportKey, transport)
		if ok {
			transport.CloseIdleConnections()
		}
	}
	out := r.Clone(r.Context())
	out.URL.Scheme = "https"
	out.URL.Host = net.JoinHostPort(target.address, "443")
	out.Header.Set(peerCredentialHeader, string(*key))
	out.Header.Set(edgeHopHeader, "1")
	return value.(*http.Transport).RoundTrip(out)
}
