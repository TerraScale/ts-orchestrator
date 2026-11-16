package natscell

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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

type tlsMaterial struct {
	certificate *tls.Certificate
	roots       *x509.CertPool
}

type tlsStamp [3][sha256.Size]byte
