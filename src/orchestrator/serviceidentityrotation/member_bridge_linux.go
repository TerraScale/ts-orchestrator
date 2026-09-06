//go:build linux

package serviceidentityrotation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const HandlerPath = "/v1/identity-service-key"

type MemberBridgeConfig struct {
	NodeID, SocketPath string
	ControllerSPKI     []string
	CheckPeerAuthority func(context.Context, string, uint64, string) error
}
type remoteMemberRequest struct {
	NodeID           string `json:"node_id"`
	AuthorityEpoch   uint64 `json:"authority_epoch"`
	AuthorityLeaseID string `json:"authority_lease_id"`
	MemberRequest
}

func validMemberRequest(q MemberRequest) bool {
	if q.Generation == 0 || len(q.Version) == 0 || len(q.Version) > 128 || len(q.Secret) != 43 {
		return false
	}
	for _, c := range q.Version {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(q.Secret)
	defer clear(decoded)
	return err == nil && len(decoded) == 32
}

// NewMemberBridge delivers only to the configured local admission socket. The
// authority callback must bind the presented certificate to the live GRU lease.
func NewMemberBridge(c MemberBridgeConfig) (http.Handler, error) {
	if c.NodeID == "" || !filepath.IsAbs(c.SocketPath) || filepath.Clean(c.SocketPath) != c.SocketPath || c.CheckPeerAuthority == nil || len(c.ControllerSPKI) == 0 {
		return nil, ErrRotation
	}
	pins := map[string]bool{}
	for _, pin := range c.ControllerSPKI {
		decoded, err := hex.DecodeString(pin)
		if err != nil || len(decoded) != sha256.Size {
			return nil, ErrRotation
		}
		pins[strings.ToLower(pin)] = true
	}
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fail := func(code int) { http.Error(w, "identity service rotation rejected", code) }
		if r.Method != http.MethodPost || r.URL.Path != HandlerPath || r.URL.RawQuery != "" {
			fail(404)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			fail(401)
			return
		}
		peer := r.TLS.PeerCertificates[0]
		if now := time.Now(); now.Before(peer.NotBefore) || !now.Before(peer.NotAfter) {
			fail(401)
			return
		}
		digest := sha256.Sum256(peer.RawSubjectPublicKeyInfo)
		pin := hex.EncodeToString(digest[:])
		if !pins[pin] {
			fail(403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(20 * time.Second))
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		defer clear(body)
		var q remoteMemberRequest
		if err != nil || json.Unmarshal(body, &q, json.RejectUnknownMembers(true)) != nil || q.NodeID != c.NodeID || q.AuthorityEpoch == 0 || len(q.AuthorityLeaseID) == 0 || len(q.AuthorityLeaseID) > 256 || !validMemberRequest(q.MemberRequest) {
			fail(400)
			return
		}
		defer func() { q.Secret = "" }()
		mu.Lock()
		defer mu.Unlock()
		if c.CheckPeerAuthority(ctx, pin, q.AuthorityEpoch, q.AuthorityLeaseID) != nil {
			fail(503)
			return
		}
		if DeliverLocal(ctx, c.SocketPath, q.MemberRequest) != nil {
			fail(502)
			return
		}
		if c.CheckPeerAuthority(ctx, pin, q.AuthorityEpoch, q.AuthorityLeaseID) != nil {
			fail(503)
			return
		}
		response, err := json.Marshal(MemberReceipt{Version: q.Version, Generation: q.Generation, State: "adopted"})
		if err != nil {
			fail(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(response)
	}), nil
}
