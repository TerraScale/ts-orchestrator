package keyrotation

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type tlsSnapshot struct {
	config     *tls.Config
	generation uint64
	expires    int64
	material   MemberRotationRequest
}

// DynamicTLS supplies immutable configurations to each new TLS handshake.
// Callers must install TLSConfig on the actual consuming listener.
type DynamicTLS struct {
	active            atomic.Pointer[tlsSnapshot]
	mu                sync.Mutex
	staged, previous  *tlsSnapshot
	operation         string
	stateDir          string
	lastDigest        [32]byte
	lastOperation     string
	lastResponse      MemberRotationResponse
	highestGeneration uint64
}

func parseTLSSnapshot(combined, trust []byte, generation uint64, expires int64) (*tlsSnapshot, error) {
	cert, err := tls.X509KeyPair(combined, combined)
	if err != nil {
		return nil, errors.New("invalid TLS identity")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid TLS certificate")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("TLS certificate is not current")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust) {
		return nil, errors.New("invalid TLS trust bundle")
	}
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, errors.New("invalid TLS chain")
		}
		intermediates.AddCert(c)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, errors.New("TLS identity is not trusted")
	}
	if expires == 0 || expires > leaf.NotAfter.Unix() {
		expires = leaf.NotAfter.Unix()
	}
	if expires <= now.Unix() {
		return nil, errors.New("expired TLS generation")
	}
	return &tlsSnapshot{config: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: roots, RootCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, generation: generation, expires: expires, material: MemberRotationRequest{Generation: generation, ExpiresAt: expires, WorkloadTLS: bytes.Clone(combined), TrustBundle: bytes.Clone(trust)}}, nil
}

func NewDynamicTLS(combined, trust []byte) (*DynamicTLS, error) {
	s, e := parseTLSSnapshot(combined, trust, 0, 0)
	if e != nil {
		return nil, e
	}
	d := new(DynamicTLS)
	d.active.Store(s)
	return d, nil
}

// NewDynamicTLSFromState restores an existing durable generation before examining
// bootstrap material. Corrupt or fenced state never falls back to bootstrap.
func NewDynamicTLSFromState(combined, trust []byte, stateDir string) (*DynamicTLS, error) {
	if _, err := os.Lstat(filepath.Join(stateDir, "tls-state.json")); err != nil {
		if os.IsNotExist(err) {
			return NewDynamicTLS(combined, trust)
		}
		return nil, errors.New("TLS state unavailable")
	}
	dynamic := new(DynamicTLS)
	if err := dynamic.AttachState(stateDir); err != nil {
		return nil, err
	}
	return dynamic, nil
}

func (d *DynamicTLS) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		s := d.active.Load()
		if s == nil || s.expires <= time.Now().Unix() {
			return nil, errors.New("TLS consumer unavailable")
		}
		return s.config, nil
	}}
}

// apply serializes generation changes; the receiver serializes this with the key effect.
func (d *DynamicTLS) apply(q MemberRotationRequest) (MemberRotationResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	pendingActive := d.active.Load()
	response := MemberRotationResponse{OperationID: q.OperationID, Generation: q.Generation}
	raw, _ := json.Marshal(q)
	digest := sha256.Sum256(raw)
	clear(raw)
	if q.Action != "verify" && d.lastOperation == q.OperationID {
		if d.lastDigest == digest {
			return d.lastResponse, nil
		}
		return response, errors.New("TLS operation payload conflict")
	}

	if current := pendingActive; q.Action != "fence" && current != nil && q.Generation < current.generation {
		return response, errors.New("stale TLS generation")
	}
	if q.Action != "fence" && d.staged != nil && q.Generation < d.staged.generation {
		return response, errors.New("stale TLS generation")
	}

	switch q.Action {
	case "stage", "reload":
		if q.Generation < d.highestGeneration {
			return response, errors.New("stale TLS generation")
		}
		if q.Generation == d.highestGeneration && d.highestGeneration != 0 {
			retained := false
			for _, snapshot := range []*tlsSnapshot{pendingActive, d.staged} {
				if snapshot != nil && snapshot.generation == q.Generation {
					retained = true
				}
			}
			if !retained {
				return response, errors.New("TLS generation no longer retained")
			}
		}
		pem := q.WorkloadTLS
		if q.Consumer == "control" {
			pem = q.ControlTLS
		}
		s, err := parseTLSSnapshot(pem, q.TrustBundle, q.Generation, q.ExpiresAt)
		if err != nil {
			return response, err
		}
		current := pendingActive
		if q.Action != "fence" && current != nil && q.Generation < current.generation {
			return response, errors.New("stale TLS generation")
		}
		if q.Action != "fence" && d.staged != nil && q.Generation < d.staged.generation {
			return response, errors.New("TLS operation conflict")
		}
		for _, existing := range []*tlsSnapshot{current, d.staged} {
			if existing != nil && existing.generation == q.Generation {
				if !bytes.Equal(existing.material.WorkloadTLS, pem) || !bytes.Equal(existing.material.TrustBundle, q.TrustBundle) {
					return response, errors.New("TLS generation material conflict")
				}
				s = existing
			}
		}
		d.highestGeneration = max(d.highestGeneration, q.Generation)
		d.operation = q.OperationID
		d.staged = s
		if q.Action == "reload" {
			if current != s {
				d.previous = current
				pendingActive = s
			}
		}
		response.ValidUntil = s.expires
		response.State = "staged"
		if q.Action == "reload" {
			response.State = "active"
		}
	case "activate":
		if d.staged == nil || d.staged.generation != q.Generation {
			return response, errors.New("TLS generation not staged")
		}
		if pendingActive != d.staged {
			d.previous = pendingActive
			pendingActive = d.staged
		}
		response.State = "active"
		response.ValidUntil = d.staged.expires
	case "verify":
		s := pendingActive
		if d.staged != nil && d.staged.generation == q.Generation {
			s = d.staged
		}
		if s == nil || s.generation != q.Generation || s.expires <= time.Now().Unix() {
			return response, errors.New("TLS generation not active")
		}
		response.State = "active"
		response.ValidUntil = s.expires
	case "retire":
		if current := pendingActive; (current == nil || current.generation != q.Generation) && (d.staged == nil || d.staged.generation != q.Generation) {
			return response, errors.New("TLS operation conflict")
		}
		d.previous = nil
		d.staged = nil
		d.operation = ""
		response.State = "retired"
		if s := pendingActive; s != nil {
			response.ValidUntil = s.expires
		}
	case "rollback":
		if current := pendingActive; (current == nil || current.generation != q.Generation) && (d.staged == nil || d.staged.generation != q.Generation) {
			return response, errors.New("TLS operation conflict")
		}
		if d.previous != nil {
			pendingActive = d.previous
		}
		d.previous = nil
		d.staged = nil
		d.operation = ""
		response.State = "rolled_back"
	case "fence":
		pendingActive = nil
		d.previous = nil
		d.staged = nil
		d.operation = ""
		response.State = "fenced"
	default:
		return response, errors.New("invalid TLS action")
	}
	if q.Action != "verify" && d.stateDir != "" {
		state := tlsDiskState{HighestGeneration: d.highestGeneration, Operation: d.operation, LastOperation: q.OperationID, LastDigest: digest, LastResponse: response}
		if v := pendingActive; v != nil {
			state.Active = &v.material
		}
		if d.staged != nil {
			state.Staged = &d.staged.material
		}
		if d.previous != nil {
			state.Previous = &d.previous.material
		}
		data, err := json.Marshal(state)
		defer clear(data)
		if err == nil {
			err = writeTLSState(d.stateDir, data)
		}
		if err != nil {
			d.active.Store(nil)
			d.staged = nil
			d.previous = nil
			d.operation = ""
			d.lastOperation = ""
			return response, errors.New("TLS persistence failed")
		}
	}
	if q.Action != "verify" {
		d.active.Store(pendingActive)
		d.lastOperation = q.OperationID
		d.lastDigest = digest
		d.lastResponse = response
	}
	return response, nil
}

// AttachState restores durable TLS effects before the listener starts.
func (d *DynamicTLS) AttachState(dir string) error {
	if err := privateRootPath(dir, true); err != nil {
		return err
	}
	path := filepath.Join(dir, "tls-state.json")
	data, err := os.ReadFile(path)
	defer clear(data)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("TLS state unavailable")
	}
	if err == nil {
		if err := privateRootPath(path, false); err != nil {
			return err
		}
		var state tlsDiskState
		defer func() {
			for _, q := range []*MemberRotationRequest{state.Active, state.Staged, state.Previous} {
				if q != nil {
					clearRotationMaterial(q)
				}
			}
		}()
		if len(data) > 16<<20 || json.Unmarshal(data, &state, json.RejectUnknownMembers(true)) != nil {
			return errors.New("invalid TLS state")
		}
		restore := func(q *MemberRotationRequest) (*tlsSnapshot, error) {
			if q == nil {
				return nil, nil
			}
			return parseTLSSnapshot(q.WorkloadTLS, q.TrustBundle, q.Generation, q.ExpiresAt)
		}
		active, e := restore(state.Active)
		if e != nil {
			return e
		}
		staged, e := restore(state.Staged)
		if e != nil {
			return e
		}
		var previous *tlsSnapshot
		if state.Previous != nil && state.Previous.ExpiresAt > time.Now().Unix() {
			previous, e = restore(state.Previous)
			if e != nil {
				return e
			}
		}
		for _, snapshot := range []*tlsSnapshot{active, staged, previous} {
			if snapshot != nil && snapshot.generation > state.HighestGeneration {
				return errors.New("invalid TLS generation highwater")
			}
		}
		d.highestGeneration = state.HighestGeneration
		d.active.Store(active)
		d.staged = staged
		d.previous = previous
		d.operation = state.Operation
		d.lastOperation = state.LastOperation
		d.lastDigest = state.LastDigest
		d.lastResponse = state.LastResponse
	}
	d.stateDir = dir
	return nil
}
func writeTLSState(dir string, data []byte) error {
	f, err := os.CreateTemp(dir, ".tls-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(dir, "tls-state.json")); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

type tlsDiskState struct {
	HighestGeneration        uint64
	LastOperation            string
	LastDigest               [32]byte
	LastResponse             MemberRotationResponse
	Operation                string
	Active, Staged, Previous *MemberRotationRequest
}
