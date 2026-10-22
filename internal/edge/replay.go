package edge

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

// A backend that cannot answer a request in this region (TerraBase for a
// database placed elsewhere) adds replayHeader to its answer; the edge then
// sends the same request to the nearest region it names, edge to edge over
// mesh mTLS on :443.
const (
	// Response: region=<r1>,<r2>[;instance=<machine>][;fallback=self].
	replayHeader = "Ts-Replay"
	// Request: region=<source>. A replayed request is never replayed again.
	replaySrcHeader = "Ts-Replay-Src"
	// Request: no named region answered, so the source region serves it
	// (sent only for fallback=self).
	replayFailedHeader = "Ts-Replay-Failed"
	// Edge-to-edge response: this region cannot serve the host, try the next.
	replayDownHeader = "Ts-Replay-Down"
	// replaySNI selects the mesh mTLS config on :443; it is never a public route.
	replaySNI = "replay." + mesh.Domain
	// A larger body streams through and is never replayed.
	maxReplayBody = 1 << 20
)

// Mesh is what replay needs from this host's mesh node.
type Mesh interface {
	Region() string
	TLS() *tls.Config
	RTT() map[string]time.Duration
}

// SetMesh enables replays; until then a replay answer reaches the client as is.
func (e *Edge) SetMesh(m Mesh) { e.mesh.Store(&m) }

func (e *Edge) meshNode() Mesh {
	if m := e.mesh.Load(); m != nil {
		return *m
	}
	return nil
}

// meshTLS hands the mesh mTLS config to handshakes that ask for replaySNI.
func (e *Edge) meshTLS(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if m := e.meshNode(); m != nil && hello.ServerName == replaySNI {
		return m.TLS(), nil
	}
	return nil, nil
}

// fromPeer reports a request another region's edge replayed here.
func fromPeer(r *http.Request) bool {
	return r.TLS != nil && r.TLS.ServerName == replaySNI && len(r.TLS.VerifiedChains) > 0
}

func newPeerTransport(e *Edge) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			m := e.meshNode()
			if m == nil {
				return nil, errors.New("edge: mesh not started")
			}
			config := m.TLS().Clone()
			config.ServerName = replaySNI
			// A region that does not answer in 2s counts as down.
			return (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: config}).DialContext(ctx, network, addr)
		},
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
}

// bufferBody keeps a body of up to maxReplayBody in memory so a replay can
// send it again; GetBody marks the request replayable.
func bufferBody(r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		r.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReplayBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxReplayBody {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return nil
}

// replay answers a backend's replay request. It sends the request to the
// named regions nearest first, moving on only while a region is down; with
// none reachable the client gets the backend's own answer, or with
// fallback=self the backend's answer to the request marked replayFailedHeader.
func (e *Edge) replay(resp *http.Response) error {
	ask, out, m := resp.Header.Get(replayHeader), resp.Request, e.meshNode()
	if ask == "" || out.GetBody == nil || m == nil || out.Header.Get(replaySrcHeader) != "" {
		return nil
	}
	regions, fallback := parseReplay(ask)
	for _, region := range nearest(m.RTT(), m.Region(), regions) {
		next, err := e.send(out, region, m.Region())
		if err != nil {
			return err
		}
		if next != nil {
			swap(resp, next)
			return nil
		}
		slog.WarnContext(out.Context(), "edge replay: region down", "host", out.Host, "region", region)
	}
	if !fallback {
		return nil
	}
	again, err := out.GetBody()
	if err != nil {
		return err
	}
	local := out.Clone(out.Context())
	local.Body = again
	local.Header.Set(replayFailedHeader, "1")
	next, err := e.local.RoundTrip(local)
	if err != nil {
		return err
	}
	swap(resp, next)
	return nil
}

// send replays out to region's edge. A nil response with a nil error means
// the region is down and the request did not run there.
func (e *Edge) send(out *http.Request, region, source string) (*http.Response, error) {
	body, err := out.GetBody()
	if err != nil {
		return nil, err
	}
	var wrote atomic.Bool
	ctx := httptrace.WithClientTrace(out.Context(), &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wrote.Store(true) }})
	req := out.Clone(ctx)
	req.Body = body
	req.URL.Scheme = "https"
	req.URL.Host = e.peerAddr(region)
	req.Header.Set(replaySrcHeader, "region="+source)
	resp, err := e.peers.RoundTrip(req)
	if err != nil {
		// Once a write may have reached the region, only a safe method may run twice.
		if !wrote.Load() || slices.Contains([]string{http.MethodGet, http.MethodHead, http.MethodOptions}, req.Method) {
			return nil, nil
		}
		return nil, err
	}
	if resp.Header.Get(replayDownHeader) != "" {
		resp.Body.Close()
		return nil, nil
	}
	return resp, nil
}

// parseReplay reads "region=a,b;instance=m;fallback=self".
func parseReplay(value string) (regions []string, fallback bool) {
	for field := range strings.SplitSeq(value, ";") {
		key, val, _ := strings.Cut(strings.TrimSpace(field), "=")
		switch key {
		case "region":
			for region := range strings.SplitSeq(val, ",") {
				regions = append(regions, strings.TrimSpace(region))
			}
		case "fallback":
			fallback = val == "self"
		}
	}
	return regions, fallback
}

// nearest orders the known regions other than self by measured RTT; a region
// without a live gateway goes last, in the backend's order.
func nearest(rtt map[string]time.Duration, self string, regions []string) []string {
	known := mesh.Regions()
	var picked []string
	for _, region := range regions {
		if region != self && slices.Contains(known, region) && !slices.Contains(picked, region) {
			picked = append(picked, region)
		}
	}
	slices.SortStableFunc(picked, func(a, b string) int {
		ra, okA := rtt[a]
		rb, okB := rtt[b]
		switch {
		case okA && okB:
			return cmp.Compare(ra, rb)
		case okA:
			return -1
		case okB:
			return 1
		}
		return 0
	})
	return picked
}

// swap makes resp the replayed answer; ReverseProxy has already removed the
// hop-by-hop headers of the first answer, so swap removes them from next.
func swap(resp, next *http.Response) {
	resp.Body.Close()
	for _, h := range next.Header.Values("Connection") {
		for name := range strings.SplitSeq(h, ",") {
			next.Header.Del(strings.TrimSpace(name))
		}
	}
	for _, h := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		next.Header.Del(h)
	}
	request := resp.Request
	*resp = *next
	resp.Request = request
}
