package natscell

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// ReloadingTLS serves one TLS identity from files that are replaced in place
// while the process runs: a renewed leaf, or a CA bundle that gains or drops a
// CA during a rollover (TS-568). At most every checkEvery, one handshake
// reads the three files; when their bytes changed, the new set is verified
// before it is used. Other handshakes serve the current set without I/O. The key
// must match the leaf. The leaf must be current, carry the usages of its role
// and chain to both the new bundle and the bundle in use, so a bundle can
// only be rolled over in steps. Its subject and addresses must equal the
// startup leaf's, so a renewal can never change which slot this process is.
// A set that fails is logged and the last good one stays in use, so a
// half-written renewal never breaks a handshake; live connections keep the
// material they started with.
type ReloadingTLS struct {
	files    TLSFiles
	role     string
	identity string

	mu      sync.Mutex
	stamp   tlsStamp
	current tlsMaterial
	// rejected is the stamp of the last set that failed, so a broken set is
	// loaded and logged once a minute rather than on every handshake; the
	// retry picks up a set that was rejected only as not yet valid.
	rejected   tlsStamp
	rejectedAt time.Time
	// loading marks a check in flight; other handshakes keep using current
	// instead of waiting for its file reads. checkedAt is when the last check
	// began; checkEvery bounds how often one runs, whatever the handshake
	// rate.
	loading    bool
	checkedAt  time.Time
	checkEvery time.Duration
}

// tlsCheckEvery is how soon a renewed file set is seen.
const tlsCheckEvery = 5 * time.Second

type tlsMaterial struct {
	certificate *tls.Certificate
	roots       *x509.CertPool
}

// tlsFiles is one read of the certificate, key and CA files; stamp is their
// SHA-256 digests, so any change in their bytes is a new set.
type tlsFiles struct {
	certificate, key, bundle []byte
}

type tlsStamp [3][sha256.Size]byte

func (files tlsFiles) stamp() tlsStamp {
	return tlsStamp{sha256.Sum256(files.certificate), sha256.Sum256(files.key), sha256.Sum256(files.bundle)}
}

// NewReloadingTLS loads the startup material for a role, listener or route,
// with the checks a reload makes against its own bundle. A controller whose
// leaf expired while it was down renews it before NATS starts.
func NewReloadingTLS(files TLSFiles, role string) (*ReloadingTLS, error) {
	if role != "listener" && role != "route" {
		return nil, fmt.Errorf("unsupported reloading TLS role %q", role)
	}
	read, err := readTLSFiles(files)
	if err != nil {
		return nil, fmt.Errorf("NATS %s TLS: %w", role, err)
	}
	defer clear(read.key)
	material, err := parseTLSMaterial(read)
	if err == nil {
		err = verifyTLSLeaf(material.certificate.Leaf, material.certificate.Certificate[1:], material.roots, role)
	}
	if err != nil {
		return nil, fmt.Errorf("NATS %s TLS: %w", role, err)
	}
	return &ReloadingTLS{files: files, role: role, identity: leafIdentity(material.certificate.Leaf),
		stamp: read.stamp(), current: material, checkedAt: time.Now(), checkEvery: tlsCheckEvery}, nil
}

// material returns the current set. When a check is due, this handshake
// reads the files outside the lock and, if their bytes changed, parses and
// verifies the new set from those same bytes.
func (r *ReloadingTLS) material() tlsMaterial {
	r.mu.Lock()
	current := r.current
	if r.loading || time.Since(r.checkedAt) < r.checkEvery {
		r.mu.Unlock()
		return current
	}
	r.loading, r.checkedAt = true, time.Now()
	r.mu.Unlock()
	read, err := readTLSFiles(r.files)
	defer clear(read.key)
	stamp := read.stamp()
	r.mu.Lock()
	unchanged := err == nil && stamp == r.stamp || stamp == r.rejected && time.Since(r.rejectedAt) < time.Minute
	r.mu.Unlock()
	var material tlsMaterial
	if !unchanged && err == nil {
		material, err = r.verified(read, current.roots)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loading = false
	if unchanged {
		return r.current
	}
	if err != nil {
		r.rejected, r.rejectedAt = stamp, time.Now()
		slog.Warn("NATS TLS reload rejected; keeping the last good certificate", "tls", r.role, "error", err)
		return r.current
	}
	r.stamp, r.current = stamp, material
	slog.Info("NATS TLS reloaded", "tls", r.role, "not_after", material.certificate.Leaf.NotAfter)
	return material
}

// verified parses one read and checks it against the running set, whose
// bundle is roots.
func (r *ReloadingTLS) verified(read tlsFiles, roots *x509.CertPool) (tlsMaterial, error) {
	material, err := parseTLSMaterial(read)
	if err != nil {
		return tlsMaterial{}, err
	}
	leaf, chain := material.certificate.Leaf, material.certificate.Certificate[1:]
	if err := verifyTLSLeaf(leaf, chain, material.roots, r.role); err != nil {
		return tlsMaterial{}, fmt.Errorf("against the new CA bundle: %w", err)
	}
	if err := verifyTLSLeaf(leaf, chain, roots, r.role); err != nil {
		return tlsMaterial{}, fmt.Errorf("against the CA bundle in use: %w", err)
	}
	if leafIdentity(leaf) != r.identity {
		return tlsMaterial{}, errors.New("certificate names a different subject or address than the running one")
	}
	return material, nil
}

// Certificate is a tls.Config GetCertificate callback.
func (r *ReloadingTLS) Certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.material().certificate, nil
}

// ServerConfig accepts only clients whose certificate chains to the current
// bundle. Session tickets are off: a resumed session would skip that check.
func (r *ReloadingTLS) ServerConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			material := r.material()
			return &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
				Certificates: []tls.Certificate{*material.certificate},
				ClientCAs:    material.roots, ClientAuth: tls.RequireAndVerifyClientCert}, nil
		}}
}

// PeerConfig serves both ends of a NATS route. It accepts like ServerConfig.
// When this server dials, it presents the current certificate and verifies
// the peer with Go's built-in check, address included, against the bundle
// loaded at startup, then again against the current bundle. A tls.Config has
// no reloadable root pool and a custom check cannot see the dialed address,
// so the dialing side trusts only CAs in both bundles: a dropped CA stops
// being trusted at once, but a CA rollover restarts each controller once,
// after its bundle gains the new CA and before any leaf moves to it.
func (r *ReloadingTLS) PeerConfig() *tls.Config {
	config := r.ServerConfig()
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return r.material().certificate, nil
	}
	r.mu.Lock()
	config.RootCAs = r.current.roots
	r.mu.Unlock()
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("NATS route peer presented no certificate")
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: r.material().roots,
			Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return err
	}
	return config
}

// readTLSFiles reads the three files; the key with loadTLS's owner-only
// checks.
func readTLSFiles(files TLSFiles) (tlsFiles, error) {
	key, err := readPrivateFile(files.KeyFile, 64<<10)
	if err != nil {
		return tlsFiles{}, fmt.Errorf("private key: %w", err)
	}
	certificate, err := os.ReadFile(files.CertFile)
	if err != nil {
		clear(key)
		return tlsFiles{}, fmt.Errorf("certificate: %w", err)
	}
	bundle, err := os.ReadFile(files.CAFile)
	if err != nil {
		clear(key)
		return tlsFiles{}, fmt.Errorf("CA bundle: %w", err)
	}
	return tlsFiles{certificate: certificate, key: key, bundle: bundle}, nil
}

// parseTLSMaterial requires a key that matches the leaf and a bundle with at
// least one certificate.
func parseTLSMaterial(read tlsFiles) (tlsMaterial, error) {
	certificate, err := tls.X509KeyPair(read.certificate, read.key)
	if err != nil {
		return tlsMaterial{}, fmt.Errorf("certificate: %w", err)
	}
	// Parse the leaf here, as preflight does, rather than rely on the
	// toolchain filling Leaf.
	if certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0]); err != nil {
		return tlsMaterial{}, fmt.Errorf("certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(read.bundle) {
		return tlsMaterial{}, errors.New("CA bundle has no certificates")
	}
	return tlsMaterial{certificate: &certificate, roots: roots}, nil
}

// leafIdentity is the exact subject and names a renewal must keep.
func leafIdentity(leaf *x509.Certificate) string {
	names := []string{"subject:" + string(leaf.RawSubject)}
	for _, name := range leaf.DNSNames {
		names = append(names, "dns:"+name)
	}
	for _, uri := range leaf.URIs {
		names = append(names, "uri:"+uri.String())
	}
	for _, ip := range leaf.IPAddresses {
		names = append(names, "ip:"+ip.String())
	}
	slices.Sort(names[1:])
	return strings.Join(names, "\x00")
}
