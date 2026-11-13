package edge

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

const challengePath = "/.well-known/acme-challenge/"

type challengeResult struct {
	code   int
	header http.Header
	body   []byte
}

type challengeFlight struct {
	done   chan struct{}
	result challengeResult
}

type challengeGuard struct {
	mu        sync.Mutex
	flights   map[string]*challengeFlight
	negative  map[string]time.Time
	sources   map[string]int
	active    int
	maxSource int
	changed   chan struct{}
}

func validChallengeToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	for _, char := range token {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func challengeSource(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "unknown"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	ip = ip.Unmap()
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(ip, bits).Masked().String()
}

func (e *Edge) serveChallenge(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, challengePath)
	if !validChallengeToken(token) {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	key := strings.ToLower(r.Host) + "/" + token
	if fromPeer(r) {
		key = "peer/" + key
	}
	source := challengeSource(r.RemoteAddr)
	g := &e.challengeGuard
	for {
		g.mu.Lock()
		if g.flights == nil {
			g.flights = map[string]*challengeFlight{}
			g.negative = map[string]time.Time{}
			g.sources = map[string]int{}
			g.changed = make(chan struct{})
		}
		if until, ok := g.negative[key]; ok && time.Now().Before(until) {
			g.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		if flight := g.flights[key]; flight != nil {
			g.mu.Unlock()
			select {
			case <-flight.done:
				writeChallenge(w, flight.result)
			case <-r.Context().Done():
				http.Error(w, "challenge wait expired", http.StatusServiceUnavailable)
			}
			return
		}
		if g.active < 16 && g.sources[source] < 2 {
			flight := &challengeFlight{done: make(chan struct{})}
			g.flights[key] = flight
			g.active++
			g.sources[source]++
			if g.sources[source] > g.maxSource {
				g.maxSource = g.sources[source]
			}
			g.mu.Unlock()
			result := e.lookupChallenge(r)
			g.mu.Lock()
			flight.result = result
			delete(g.flights, key)
			g.active--
			g.sources[source]--
			if g.sources[source] == 0 {
				delete(g.sources, source)
			}
			now := time.Now()
			for cached, until := range g.negative {
				if !now.Before(until) {
					delete(g.negative, cached)
				}
			}
			if result.code == http.StatusNotFound && len(g.negative) < 4096 {
				g.negative[key] = now.Add(5 * time.Second)
			}
			close(flight.done)
			close(g.changed)
			g.changed = make(chan struct{})
			g.mu.Unlock()
			writeChallenge(w, result)
			return
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			http.Error(w, "challenge wait expired", http.StatusServiceUnavailable)
			return
		case <-changed:
		}
	}
}

func writeChallenge(w http.ResponseWriter, result challengeResult) {
	for key, value := range result.header {
		w.Header()[key] = value
	}
	w.WriteHeader(result.code)
	_, _ = w.Write(result.body)
}

func (e *Edge) lookupChallenge(r *http.Request) challengeResult {
	e.challengeLookups.Add(1)
	local := httptest.NewRecorder()
	e.challenges.ServeHTTP(local, r)
	m := e.meshNode()
	if local.Code != http.StatusOK && !fromPeer(r) && m != nil {
		for _, region := range mesh.Regions() {
			if region == m.Region() {
				continue
			}
			if token, ok := e.peerChallenge(r, region); ok {
				return challengeResult{http.StatusOK, http.Header{"Content-Type": []string{"text/plain"}}, token}
			}
		}
	}
	return challengeResult{local.Code, local.Header(), local.Body.Bytes()}
}
func (e *Edge) peerChallenge(r *http.Request, region string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+e.peerAddr(region)+r.URL.Path, nil)
	if err != nil {
		return nil, false
	}
	req.Host = r.Host
	resp, err := e.peers.RoundTrip(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	token, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return token, err == nil && resp.StatusCode == http.StatusOK
}

func isChallenge(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, challengePath) }
