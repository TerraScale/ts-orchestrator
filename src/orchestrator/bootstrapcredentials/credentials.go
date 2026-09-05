package bootstrapcredentials

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

type Reference struct {
	URL             string `json:"url"`
	CAFile          string `json:"caFile"`
	CertificateFile string `json:"certificateFile"`
	PrivateKeyFile  string `json:"privateKeyFile"`
	NKeySeedFile    string `json:"nkeySeedFile"`
}
type Identity struct {
	URL               string `json:"url"`
	PublicNKey        string `json:"publicNkey"`
	CASHA256          string `json:"caSha256"`
	CertificateSHA256 string `json:"certificateSha256"`
}

// Credentials owns captured authentication material until all consumers have
// closed their connections. Options may be reused for synchronous connections;
// Close must follow those consumers, and permanently disables NKey signatures.
type Credentials struct {
	URL      string
	Options  []nats.Option
	identity Identity
	mu       sync.Mutex
	pair     nkeys.KeyPair
}

func (c *Credentials) PublicIdentity() Identity {
	if c == nil {
		return Identity{}
	}
	return c.identity
}
func (c *Credentials) sign(nonce []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pair == nil {
		return nil, errors.New("bootstrapcredentials: credentials closed")
	}
	return c.pair.Sign(nonce)
}
func (c *Credentials) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pair != nil {
		c.pair.Wipe()
		c.pair = nil
	}
	return nil
}
func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Load validates captured TLS/NKey material. No resulting option reads a file.
// PEM and seed input buffers are cleared after their parsed identity is owned.
func Load(ref Reference) (*Credentials, error) {
	invalid := errors.New("bootstrapcredentials: valid explicit TLS and NKey identity required")
	parsed, err := url.Parse(ref.URL)
	if err != nil || parsed.Scheme != "tls" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || strings.Contains(ref.URL, "#") {
		return nil, invalid
	}
	ca, err := ReadFile(ref.CAFile, false, 1<<20)
	if err != nil {
		return nil, err
	}
	cert, err := ReadFile(ref.CertificateFile, false, 1<<20)
	if err != nil {
		return nil, err
	}
	key, err := ReadFile(ref.PrivateKeyFile, true, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, invalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, invalid
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return nil, invalid
	}
	intermediates := x509.NewCertPool()
	for _, raw := range identity.Certificate[1:] {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, invalid
		}
		intermediates.AddCert(certificate)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, invalid
	}
	seed, err := ReadFile(ref.NKeySeedFile, true, 4096)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	pair, err := nkeys.FromSeed(bytes.TrimSpace(seed))
	if err != nil {
		return nil, invalid
	}
	transferred := false
	defer func() {
		if !transferred {
			pair.Wipe()
		}
	}()
	public, err := pair.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return nil, invalid
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: parsed.Hostname(), RootCAs: roots, Certificates: []tls.Certificate{identity}}
	credentials := &Credentials{URL: ref.URL, identity: Identity{URL: ref.URL, PublicNKey: public, CASHA256: hash(ca), CertificateSHA256: hash(cert)}, pair: pair}
	credentials.Options = []nats.Option{nats.Secure(config), nats.Nkey(public, credentials.sign), nats.NoReconnect(), nats.ReconnectBufSize(-1)}
	transferred = true
	return credentials, nil
}
