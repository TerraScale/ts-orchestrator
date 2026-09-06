package keyrotation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type MemberReceiverConfig struct {
	NodeID, SocketPath, TokenFile string
	StateDir                      string
	ControllerSPKI                []string
	CheckPeerAuthority            func(context.Context, string, uint64, string) error
	ControlTLS                    *DynamicTLS
}
type memberReceiver struct {
	config    MemberReceiverConfig
	client    *http.Client
	token     string
	pins      map[string]bool
	mu        sync.Mutex
	stateLock *os.File
}

func privateRootPath(path string, directory bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("credential path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("credential path unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || directory != info.IsDir() {
		return errors.New("credential path must be private and owned by root or the service")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe credential ancestor")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || (info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return errors.New("unsafe credential ancestor")
		}
		if parent == "/" {
			break
		}
	}
	return nil
}
func NewMemberReceiver(c MemberReceiverConfig) (http.Handler, error) {
	if c.NodeID == "" || c.CheckPeerAuthority == nil || len(c.ControllerSPKI) == 0 {
		return nil, errors.New("incomplete member receiver configuration")
	}
	if err := privateRootPath(filepath.Dir(c.SocketPath), true); err != nil {
		return nil, err
	}
	if err := privateRootPath(filepath.Dir(c.TokenFile), true); err != nil {
		return nil, err
	}
	if err := privateRootPath(c.TokenFile, false); err != nil {
		return nil, err
	}
	token, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, errors.New("credential token unavailable")
	}
	token = bytes.TrimSuffix(token, []byte("\n"))
	if len(token) < 32 || len(token) > 4096 || bytes.ContainsAny(token, "\r\n \t") {
		return nil, errors.New("invalid credential token")
	}
	if err := privateRootPath(c.StateDir, true); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(c.StateDir, ".receiver.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("receiver state lock unavailable")
	}
	locked := false
	defer func() {
		if !locked {
			lock.Close()
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.New("receiver state already in use")
	}
	for name, dynamic := range map[string]*DynamicTLS{"control": c.ControlTLS} {
		if dynamic == nil {
			continue
		}
		dir := filepath.Join(c.StateDir, name)
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return nil, errors.New("TLS state directory unavailable")
		}
		if err := dynamic.AttachState(dir); err != nil {
			return nil, err
		}
	}
	pins := map[string]bool{}
	for _, p := range c.ControllerSPKI {
		v, e := hex.DecodeString(p)
		if e != nil || len(v) != sha256.Size {
			return nil, errors.New("invalid controller identity")
		}
		pins[strings.ToLower(p)] = true
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := privateRootPath(filepath.Dir(c.SocketPath), true); err != nil {
			return nil, err
		}
		info, err := os.Lstat(c.SocketPath)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("credential socket unavailable")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return nil, errors.New("credential socket owner invalid")
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", c.SocketPath)
	}, DisableKeepAlives: true}
	locked = true
	return &memberReceiver{stateLock: lock, config: c, token: string(token), pins: pins, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (r *memberReceiver) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	fail := func(status int) { http.Error(w, "credential rotation rejected", status) }
	if request.Method != http.MethodPost || request.URL.Path != "/v1/credential-rotation" {
		fail(http.StatusNotFound)
		return
	}
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		fail(http.StatusUnauthorized)
		return
	}
	peer := request.TLS.PeerCertificates[0]
	if now := time.Now(); now.Before(peer.NotBefore) || !now.Before(peer.NotAfter) {
		fail(http.StatusUnauthorized)
		return
	}
	pin := sha256.Sum256(peer.RawSubjectPublicKeyInfo)
	if !r.pins[hex.EncodeToString(pin[:])] {
		fail(http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 1<<20))
	defer clear(body)
	if err != nil {
		fail(http.StatusBadRequest)
		return
	}
	var q MemberRotationRequest
	defer func() { clearRotationMaterial(&q) }()
	if json.Unmarshal(body, &q, json.RejectUnknownMembers(true)) != nil || q.AuthorityEpoch == 0 || q.AuthorityLeaseID == "" || q.NodeID != r.config.NodeID || q.OperationID == "" || (q.Generation == 0 && q.Action != "fence") || (q.ExpiresAt != 0 && q.ExpiresAt <= time.Now().Unix()) || (q.Consumer != "member" && q.Consumer != "control") {
		fail(http.StatusBadRequest)
		return
	}
	switch q.Action {
	case "stage", "verify", "activate", "retire", "rollback", "fence", "reload":
	default:
		fail(http.StatusBadRequest)
		return
	}
	if q.Consumer == "member" && q.Action == "reload" {
		fail(http.StatusBadRequest)
		return
	}
	var dynamic *DynamicTLS
	if q.Consumer == "control" {
		dynamic = r.config.ControlTLS
	}
	if dynamic == nil && q.Consumer == "control" {
		fail(http.StatusServiceUnavailable)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Validate candidate material before either consumer can change.
	if dynamic != nil && (q.Action == "stage" || q.Action == "reload") {
		pem := q.WorkloadTLS
		if q.Consumer == "control" {
			pem = q.ControlTLS
		}
		snapshot, err := parseTLSSnapshot(pem, q.TrustBundle, q.Generation, q.ExpiresAt)
		if err != nil {
			fail(http.StatusBadRequest)
			return
		}
		clearRotationMaterial(&snapshot.material)
	}
	if err := r.config.CheckPeerAuthority(request.Context(), hex.EncodeToString(pin[:]), q.AuthorityEpoch, q.AuthorityLeaseID); err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	var response MemberRotationResponse
	if q.Consumer == "member" && q.Action != "reload" {
		// Remove the fields that belong solely to the HTTPS/TLS consumer.
		payload := struct {
			OperationID        string `json:"operation_id"`
			Action             string `json:"action"`
			Generation         uint64 `json:"generation"`
			ExpiresAt          int64  `json:"expires_at"`
			CurrentKeyID       string `json:"current_key_id"`
			CurrentKey         []byte `json:"current_key"`
			PreviousKeyID      string `json:"previous_key_id"`
			PreviousKey        []byte `json:"previous_key"`
			PreviousExpiresAt  int64  `json:"previous_expires_at"`
			PreviousGeneration uint64 `json:"previous_generation"`
			WorkloadTLS        []byte `json:"workload_tls"`
			TrustBundle        []byte `json:"trust_bundle"`
		}{q.OperationID, q.Action, q.Generation, q.ExpiresAt, q.CurrentKeyID, q.CurrentKey, q.PreviousKeyID, q.PreviousKey, q.PreviousExpiresAt, q.PreviousGeneration, q.WorkloadTLS, q.TrustBundle}
		data, err := json.Marshal(payload)
		defer clear(data)
		if err != nil {
			fail(http.StatusBadRequest)
			return
		}
		req, err := http.NewRequestWithContext(request.Context(), http.MethodPost, "http://localhost/v1/credential-rotation", bytes.NewReader(data))
		if err != nil {
			fail(http.StatusBadRequest)
			return
		}
		req.Header.Set("Authorization", "Bearer "+r.token)
		req.Header.Set("Content-Type", "application/json")
		if err := r.config.CheckPeerAuthority(request.Context(), hex.EncodeToString(pin[:]), q.AuthorityEpoch, q.AuthorityLeaseID); err != nil {
			fail(http.StatusServiceUnavailable)
			return
		}
		res, err := r.client.Do(req)
		if err != nil {
			fail(http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		data, err = io.ReadAll(io.LimitReader(res.Body, (1<<16)+1))
		defer clear(data)
		if err != nil || len(data) > 1<<16 || res.StatusCode != http.StatusOK || json.Unmarshal(data, &response) != nil || response.OperationID != q.OperationID || (q.Action != "fence" && response.Generation != q.Generation) {
			fail(http.StatusBadGateway)
			return
		}
	}
	if err := r.config.CheckPeerAuthority(request.Context(), hex.EncodeToString(pin[:]), q.AuthorityEpoch, q.AuthorityLeaseID); err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	var tlsResponse MemberRotationResponse
	if dynamic != nil {
		tlsResponse, err = dynamic.apply(q)
	}
	if err != nil {
		fail(http.StatusConflict)
		return
	}
	if q.Consumer == "control" || q.Action == "reload" {
		response = tlsResponse
	} else if tlsResponse.ValidUntil > 0 && (response.ValidUntil == 0 || tlsResponse.ValidUntil < response.ValidUntil) {
		response.ValidUntil = tlsResponse.ValidUntil
	}
	data, err := json.Marshal(response)
	if err != nil {
		fail(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func clearRotationMaterial(q *MemberRotationRequest) {
	clear(q.CurrentKey)
	clear(q.PreviousKey)
	clear(q.WorkloadTLS)
	clear(q.ControlTLS)
	clear(q.TrustBundle)
}

// Close releases exclusive ownership of the receiver state directory.
// Stop serving requests before calling Close.
func (r *memberReceiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.client.CloseIdleConnections()
	if r.stateLock != nil {
		err := r.stateLock.Close()
		r.stateLock = nil
		return err
	}
	return nil
}
