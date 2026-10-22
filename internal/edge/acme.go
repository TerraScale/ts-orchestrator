package edge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

const challengePath = "/.well-known/acme-challenge/"

// serveChallenge answers an HTTP-01 challenge. Under GeoDNS the CA's
// vantage points reach different regions, so a token this edge does not
// hold is fetched from the other regions' edges over mesh mTLS.
func (e *Edge) serveChallenge(w http.ResponseWriter, r *http.Request) {
	local := httptest.NewRecorder()
	e.challenges.ServeHTTP(local, r)
	m := e.meshNode()
	if local.Code != http.StatusOK && !fromPeer(r) && m != nil {
		for _, region := range mesh.Regions() {
			if region == m.Region() {
				continue
			}
			if token, ok := e.peerChallenge(r, region); ok {
				w.Header().Set("Content-Type", "text/plain")
				w.Write(token)
				return
			}
		}
	}
	for k, v := range local.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(local.Code)
	w.Write(local.Body.Bytes())
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
	// A key authorization is a token, a dot and a key thumbprint: well under 4 KiB.
	token, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return token, err == nil && resp.StatusCode == http.StatusOK
}

func isChallenge(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, challengePath) }
