package nodeauthority

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/natsconnect"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// ReaderConfig pins an independently provisioned, read-only authority identity.
// Its NKey's account assignment is part of the admitted broker configuration.
type ReaderConfig struct {
	Endpoint          string `json:"endpoint"`
	ServerName        string `json:"serverName"`
	Account           string `json:"account"`
	NKeySeedFile      string `json:"nkeySeedFile"`
	PublicNKey        string `json:"publicNkey"`
	CAFile            string `json:"caFile"`
	CASHA256          string `json:"caSha256"`
	CertificateFile   string `json:"certificateFile"`
	CertificateSHA256 string `json:"certificateSha256"`
	KeyFile           string `json:"keyFile"`
}

func (r ReaderConfig) Validate() error {
	bad := errors.New("nodeauthority: explicit pinned authority reader configuration required")
	u, err := url.Parse(r.Endpoint)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || r.ServerName == "" || len(r.ServerName) > 128 || r.Account == "" || len(r.Account) > 63 || !nkeys.IsValidPublicUserKey(r.PublicNKey) {
		return bad
	}
	paths := map[string]bool{}
	for _, p := range []string{r.NKeySeedFile, r.CAFile, r.CertificateFile, r.KeyFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") || paths[p] {
			return bad
		}
		paths[p] = true
	}
	for _, h := range []string{r.CASHA256, r.CertificateSHA256} {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 || strings.ToLower(h) != h {
			return bad
		}
	}
	return nil
}

// ReaderPermissions grants stream-leader reads, never writes or provisioning.
// MSG.GET selects the key in its payload, so this is a bucket-level read grant.
func ReaderPermissions(bucket string) ([]string, []string, error) {
	if !authorityBucket(bucket) {
		return nil, nil, errors.New("nodeauthority: invalid authority bucket")
	}
	return []string{"$JS.API.STREAM.MSG.GET.KV_" + bucket}, []string{"_INBOX.>"}, nil
}

// LazyRegionalCommandAuthorizer serves no authority from memory. Each command
// is verified by the existing regional verifier against the original live store.
// Construction does not contact the broker, allowing finite owner activation.
type LazyRegionalCommandAuthorizer struct {
	lifetime   context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	reader     ReaderConfig
	config     CommandAuthorityConfig
	connection *nats.Conn
	closed     bool
}

func NewLazyRegionalCommandAuthorizer(reader ReaderConfig, node, bucket string, trust *security.CommandSignatureVerifier, candidates map[string]string) (*LazyRegionalCommandAuthorizer, error) {
	if err := reader.Validate(); err != nil {
		return nil, err
	}
	cfg := CommandAuthorityConfig{NodeID: node, Bucket: bucket, Trust: trust, SignerCandidates: candidates}
	if err := validateCommandAuthorityConfig(cfg); err != nil {
		return nil, err
	}
	cfg.SignerCandidates = copyCandidates(candidates)
	lifetime, cancel := context.WithCancel(context.Background())
	return &LazyRegionalCommandAuthorizer{reader: reader, config: cfg, lifetime: lifetime, cancel: cancel}, nil
}
func copyCandidates(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
func (a *LazyRegionalCommandAuthorizer) Authorize(ctx context.Context, subject string, wire []byte) (CommandAuthorization, error) {
	if ctx == nil {
		return CommandAuthorization{}, errors.New("nodeauthority: context required")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(a.lifetime, cancel)
	defer stop()
	connection, err := a.connect(bounded)
	if err != nil {
		return CommandAuthorization{}, err
	}
	cfg := a.config
	cfg.Connection = connection
	verifier, err := NewRegionalCommandAuthorizer(cfg)
	if err != nil {
		return CommandAuthorization{}, err
	}
	return verifier.Authorize(bounded, subject, wire)
}
func (a *LazyRegionalCommandAuthorizer) connect(ctx context.Context) (*nats.Conn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errors.New("nodeauthority: authority reader closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.connection != nil && a.connection.IsConnected() {
		return a.connection, nil
	}
	if a.connection != nil {
		a.connection.Close()
		a.connection = nil
	}
	options, release, err := a.reader.options()
	if err != nil {
		return nil, err
	}
	defer release()
	connection, err := natsconnect.Connect(ctx, options, net.Dialer{})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		connection.Close()
		return nil, err
	}
	if connection.ConnectedServerName() != a.reader.ServerName {
		connection.Close()
		return nil, errors.New("nodeauthority: authority server differs from admitted identity")
	}
	if err := commandAuthorityTLS(connection); err != nil {
		connection.Close()
		return nil, err
	}
	a.connection = connection
	return connection, nil
}
func (a *LazyRegionalCommandAuthorizer) Close() error {
	a.cancel()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.connection != nil {
		a.connection.Close()
		a.connection = nil
	}
	return nil
}
func readerFile(path string, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("nodeauthority: credential path must be clean and absolute")
	}
	directory, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { unix.Close(directory) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := 0; ; i++ {
		var stat unix.Stat_t
		if err := unix.Fstat(directory, &stat); err != nil {
			return nil, err
		}
		if stat.Uid != 0 || stat.Mode&0022 != 0 {
			return nil, errors.New("nodeauthority: credential ancestors must be root-owned and not writable by others")
		}
		if i == len(parts)-1 {
			break
		}
		next, err := unix.Openat(directory, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		unix.Close(directory)
		directory = next
	}
	fd, err := unix.Openat(directory, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || (info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 && (private || info.Mode().Perm() != 0444)) || info.Size() <= 0 || info.Size() > 64<<10 {
		return nil, errors.New("nodeauthority: authority credential must be bounded root-private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("nodeauthority: authority credential read failed")
	}
	return data, nil
}
func (r ReaderConfig) options() (natsconnect.Config, func(), error) {
	ca, err := readerFile(r.CAFile, false)
	if err != nil {
		return natsconnect.Config{}, nil, err
	}
	cert, err := readerFile(r.CertificateFile, false)
	if err != nil {
		return natsconnect.Config{}, nil, err
	}
	key, err := readerFile(r.KeyFile, true)
	if err != nil {
		return natsconnect.Config{}, nil, err
	}
	defer clear(key)
	for _, entry := range []struct {
		data []byte
		hash string
	}{{ca, r.CASHA256}, {cert, r.CertificateSHA256}} {
		sum := sha256.Sum256(entry.data)
		if hex.EncodeToString(sum[:]) != entry.hash {
			return natsconnect.Config{}, nil, errors.New("nodeauthority: authority TLS pin differs")
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return natsconnect.Config{}, nil, errors.New("nodeauthority: authority CA invalid")
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return natsconnect.Config{}, nil, err
	}
	seed, err := readerFile(r.NKeySeedFile, true)
	if err != nil {
		return natsconnect.Config{}, nil, err
	}
	defer clear(seed)
	pair, err := nkeys.FromSeed(seed)
	if err != nil {
		return natsconnect.Config{}, nil, err
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || public != r.PublicNKey {
		return natsconnect.Config{}, nil, errors.New("nodeauthority: authority NKey pin differs")
	}
	// No reconnects are enabled. Keep only the copied signing seed through the
	// synchronous connect handshake, then let nats release the callback with Conn.
	private := append([]byte(nil), seed...)
	return natsconnect.Config{URL: r.Endpoint, Timeout: 5 * time.Second, PublicNKey: public, Sign: func(nonce []byte) ([]byte, error) {
		p, err := nkeys.FromSeed(private)
		if err != nil {
			return nil, err
		}
		defer p.Wipe()
		return p.Sign(nonce)
	}, TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}}}, func() { clear(private) }, nil
}

func (r *ReaderConfig) UnmarshalJSON(data []byte) error {
	if _, err := decodeObject(data, "endpoint", "serverName", "account", "nkeySeedFile", "publicNkey", "caFile", "caSha256", "certificateFile", "certificateSha256", "keyFile"); err != nil {
		return err
	}
	type wire ReaderConfig
	var value wire
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*r = ReaderConfig(value)
	return nil
}
