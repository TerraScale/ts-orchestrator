package bootstrapmaterial

import (
	"crypto/ecdsa"
	"crypto/x509"
	"time"

	"github.com/nats-io/nkeys"
)

// issuedBackdate is how far before issue an issued leaf is valid, to absorb
// clock skew between controllers; issued lifetimes allow for it.
const issuedBackdate = time.Minute

const controllerIssuedLifetime = 90 * 24 * time.Hour

// LeafIdentity is the subject and names of one controller slot's TLS leaf.
type LeafIdentity struct {
	CommonName string
	DNSName    string
	IP         string
}

// ControllerIssuer is a generation's online issuing material, which every
// controller holds: the controller TLS issuer and the cell account signer.
type ControllerIssuer struct {
	identity issuerIdentity
	certPEM  []byte
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	signer   nkeys.KeyPair
}

type issuerIdentity struct {
	Cell, Environment, Operator, CellAccount, AccountSigner string
	lifetime                                                time.Duration
	expiresAt                                               time.Time
}
