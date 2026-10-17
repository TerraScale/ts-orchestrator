package controllercredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"golang.org/x/sys/unix"
)

const controllerReaderConfig = "/etc/terrascale-orchestrator/controller.json"

type controllerReaderSnapshot struct {
	accepted bootstrapstart.AcceptedIdentity
	chain    []byte
	config   []byte
	refs     map[string]bootstrap.SecretReference
	nats     natscell.Config
	expires  time.Time
}

// ConnectControllerReader opens the actual accepted controller's credentials
// only inside root memory. Callers use the connection for concrete root readers.
func ConnectControllerReader(ctx context.Context) (*nats.Conn, error) {
	conn, _, err := ConnectControllerReaderLease(ctx)
	return conn, err
}

// ConnectControllerReaderLease retains the exact original credential lifetime.
// Root composition carries it through every protected operation and receipt.
func ConnectControllerReaderLease(ctx context.Context) (*nats.Conn, context.Context, error) {
	reader, err := OpenControllerReader(ctx)
	if err != nil {
		return nil, nil, err
	}
	return reader.conn, reader.lease, nil
}

// ControllerReader retains the actual connection, original lifetime and signed
// credential snapshot together. Its private fields cannot admit caller sources.
type ControllerReader struct {
	conn           *nats.Conn
	lease          context.Context
	snapshot       controllerReaderSnapshot
	sourceIdentity string
	sourceExpires  time.Time
}

type controllerReaderMaterial struct {
	Reference bootstrap.SecretReference
	SHA256    string
	ExpiresAt time.Time
}

// OpenControllerReader independently opens the fixed accepted credential source.
func OpenControllerReader(ctx context.Context) (*ControllerReader, error) {
	reader, err := openControllerReaderLease(ctx)
	if err != nil {
		return nil, err
	}
	if err := reader.Guard(ctx); err != nil {
		reader.conn.Close()
		return nil, err
	}
	return reader, nil
}

func (reader *ControllerReader) Conn() *nats.Conn         { return reader.conn }
func (reader *ControllerReader) Context() context.Context { return reader.lease }

// SourceIdentity describes the original verified material; it grants no authority.
// Its cap excludes transient caller deadlines and is never refreshed by Guard.
func (reader *ControllerReader) SourceIdentity(ctx context.Context) (string, time.Time, error) {
	if reader.Guard(ctx) != nil || reader.sourceIdentity == "" || reader.sourceExpires.IsZero() ||
		!time.Now().Before(reader.sourceExpires) {
		return "", time.Time{}, ErrDelivery
	}
	identity, expires := reader.sourceIdentity, reader.sourceExpires
	if reader.Guard(ctx) != nil || !time.Now().Before(expires) {
		return "", time.Time{}, ErrDelivery
	}
	return identity, expires, nil
}

func controllerReaderSourceIdentity(snapshot controllerReaderSnapshot, materials []controllerReaderMaterial, expires time.Time) (string, error) {
	wire, err := json.Marshal(struct {
		Domain    string
		Accepted  bootstrapstart.AcceptedIdentity
		Chain     []byte
		Config    []byte
		Materials []controllerReaderMaterial
		ExpiresAt time.Time
	}{"controller-reader-original-material-v1", snapshot.accepted, snapshot.chain, snapshot.config, materials, expires}, json.Deterministic(true))
	if err != nil {
		return "", ErrDelivery
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

// Guard rejects credential drift synchronously before and after protected work.
func (reader *ControllerReader) Guard(ctx context.Context) error {
	if os.Geteuid() != 0 || reader == nil || reader.conn == nil || reader.lease == nil ||
		ctx == nil || ctx.Err() != nil || reader.lease.Err() != nil || reader.conn.IsClosed() {
		return ErrDelivery
	}
	deadline, ok := reader.lease.Deadline()
	if !ok || reader.lease.Done() == nil || !time.Now().Before(deadline) {
		return ErrDelivery
	}
	current, err := loadControllerReaderSnapshot()
	if err != nil || !reflect.DeepEqual(reader.snapshot, current) || ctx.Err() != nil || reader.lease.Err() != nil || reader.conn.IsClosed() ||
		!time.Now().Before(deadline) || !reader.snapshot.expires.IsZero() && !time.Now().Before(reader.snapshot.expires) {
		return ErrDelivery
	}
	return nil
}

func openControllerReaderLease(ctx context.Context) (*ControllerReader, error) {
	snapshot, err := controllerReaderConnectionSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	region, err := snapshot.acceptedRegion()
	if err != nil {
		return nil, ErrDelivery
	}
	readCtx, stopReads := snapshot.readContext(ctx)
	defer stopReads()
	factory, err := ociclient.InstancePrincipalContext(readCtx, region)
	if err != nil {
		return nil, ErrDelivery
	}
	client, err := vaultsecret.SecretsClientContext(readCtx, factory)
	if err != nil {
		return nil, ErrDelivery
	}
	return connectControllerReaderLease(ctx, readCtx, snapshot, client)
}

func controllerReaderConnectionSnapshot(ctx context.Context) (controllerReaderSnapshot, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil {
		return controllerReaderSnapshot{}, ErrDelivery
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return controllerReaderSnapshot{}, ErrDelivery
		}
	}
	snapshot, err := loadControllerReaderSnapshot()
	if err != nil {
		return controllerReaderSnapshot{}, ErrDelivery
	}
	if _, err := snapshot.acceptedRegion(); err != nil || snapshot.guard(ctx) != nil {
		return controllerReaderSnapshot{}, ErrDelivery
	}
	return snapshot, nil
}

func (snapshot controllerReaderSnapshot) guard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || !snapshot.expires.IsZero() && !time.Now().Before(snapshot.expires) {
		return ErrDelivery
	}
	current, err := loadControllerReaderSnapshot()
	if err != nil || !reflect.DeepEqual(snapshot, current) || ctx.Err() != nil ||
		!snapshot.expires.IsZero() && !time.Now().Before(snapshot.expires) {
		return ErrDelivery
	}
	return nil
}

// readContext bounds acquisition without replacing the original connection lifetime.
func (snapshot controllerReaderSnapshot) readContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(30 * time.Second)
	if !snapshot.expires.IsZero() && snapshot.expires.Before(deadline) {
		deadline = snapshot.expires
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	return ociclient.WithCredentialSourceGuard(bounded, snapshot.guard), cancel
}

func connectControllerReaderLease(ctx, readCtx context.Context, snapshot controllerReaderSnapshot, client secrets.SecretsClient) (*ControllerReader, error) {
	guard := func() error { return snapshot.guard(ctx) }
	if guard() != nil {
		return nil, ErrDelivery
	}
	readDeadline, bounded := readCtx.Deadline()
	if !bounded || readCtx.Err() != nil {
		return nil, ErrDelivery
	}
	client.HTTPClient = Dispatcher{Next: client.HTTPClient, Guard: func() error {
		if readCtx.Err() != nil {
			return ErrDelivery
		}
		return guard()
	}}
	paths := []string{snapshot.nats.CredentialsFile, snapshot.nats.TLS.CAFile, snapshot.nats.TLS.CertFile, snapshot.nats.TLS.KeyFile}
	values := make([][]byte, len(paths))
	materials := make([]controllerReaderMaterial, len(paths))
	defer func() {
		for _, value := range values {
			clear(value)
		}
	}()
	expires := snapshot.expires
	for index, path := range paths {
		reference, ok := snapshot.refs[filepath.Base(path)]
		if !ok || path != filepath.Join(bootstrap.MaterialDirectory, reference.TargetFile) || guard() != nil {
			return nil, ErrDelivery
		}
		value, deadline, err := ReadExact(readCtx, &client, reference)
		if err != nil {
			return nil, ErrDelivery
		}
		values[index] = value
		digest := sha256.Sum256(value)
		materials[index] = controllerReaderMaterial{Reference: reference, SHA256: hex.EncodeToString(digest[:]), ExpiresAt: deadline}
		if !deadline.IsZero() && (expires.IsZero() || deadline.Before(expires)) {
			expires = deadline
		}
		if index == 0 {
			if natscell.ValidateBrokerControllerCredentialBytes(value, snapshot.nats.Cell, snapshot.nats.Instance) != nil {
				return nil, ErrDelivery
			}
			raw, err := jwt.ParseDecoratedJWT(value)
			if err != nil {
				return nil, ErrDelivery
			}
			claim, err := jwt.DecodeUserClaims(raw)
			if err != nil || claim.IssuerAccount != snapshot.accepted.Broker.CellAccount &&
				(claim.IssuerAccount != "" || claim.Issuer != snapshot.accepted.Broker.CellAccount) {
				return nil, ErrDelivery
			}
			if claim.Expires > 0 && (expires.IsZero() || time.Unix(claim.Expires, 0).Before(expires)) {
				expires = time.Unix(claim.Expires, 0)
			}
		}
		if index == 2 {
			certificateExpiry, err := controllerReaderCertificateExpiry(value, values[1])
			if err != nil {
				return nil, ErrDelivery
			}
			if expires.IsZero() || certificateExpiry.Before(expires) {
				expires = certificateExpiry
			}
		}
		if !expires.IsZero() && expires.Before(readDeadline) {
			readDeadline = expires
			var stopCap context.CancelFunc
			readCtx, stopCap = context.WithDeadline(readCtx, readDeadline)
			defer stopCap()
		}
		if readCtx.Err() != nil || guard() != nil {
			return nil, ErrDelivery
		}
	}
	certificate, err := tls.X509KeyPair(values[2], values[3])
	if err != nil {
		return nil, ErrDelivery
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(values[1]) || guard() != nil || readCtx.Err() != nil || !expires.IsZero() && !time.Now().Before(expires) {
		return nil, ErrDelivery
	}
	sourceIdentity, err := controllerReaderSourceIdentity(snapshot, materials, expires)
	if err != nil {
		return nil, ErrDelivery
	}
	connectionCtx, cancel := context.WithCancel(ctx)
	if !expires.IsZero() {
		var deadlineCancel context.CancelFunc
		connectionCtx, deadlineCancel = context.WithDeadline(connectionCtx, expires)
		previous := cancel
		cancel = func() { deadlineCancel(); previous() }
	}
	conn, lease, err := natscell.ConnectMemoryLeaseForOperation(connectionCtx, readCtx, snapshot.nats.Cell, snapshot.nats.URL, values[0],
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		cancel()
		return nil, ErrDelivery
	}
	if guard() != nil || readCtx.Err() != nil || !expires.IsZero() && !time.Now().Before(expires) {
		conn.Close()
		cancel()
		return nil, ErrDelivery
	}
	go func() {
		defer cancel()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-connectionCtx.Done():
				conn.Close()
				return
			case <-ticker.C:
				if conn.IsClosed() || guard() != nil {
					conn.Close()
					return
				}
			}
		}
	}()
	return &ControllerReader{conn: conn, lease: lease, snapshot: snapshot, sourceIdentity: sourceIdentity, sourceExpires: expires}, nil
}

func controllerReaderCertificateExpiry(certificatePEM, rootPEM []byte) (time.Time, error) {
	var certificates []*x509.Certificate
	for block, rest := pem.Decode(certificatePEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, ErrDelivery
		}
		certificates = append(certificates, certificate)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if len(certificates) == 0 || !roots.AppendCertsFromPEM(rootPEM) {
		return time.Time{}, ErrDelivery
	}
	for _, intermediate := range certificates[1:] {
		intermediates.AddCert(intermediate)
	}
	chains, err := certificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 {
		return time.Time{}, ErrDelivery
	}
	expires := certificates[0].NotAfter
	for _, certificate := range chains[0] {
		if certificate.NotAfter.Before(expires) {
			expires = certificate.NotAfter
		}
	}
	return expires, nil
}

func (snapshot controllerReaderSnapshot) acceptedRegion() (string, error) {
	target, err := bootstrapstart.GenerationTargetFromAccepted(snapshot.accepted)
	if err != nil {
		return "", err
	}
	return target.Expected.Cell.OCIRegion()
}

func loadControllerReaderSnapshot() (controllerReaderSnapshot, error) {
	var snapshot controllerReaderSnapshot
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return snapshot, ErrDelivery
	}
	target, err := bootstrapstart.GenerationTargetFromAccepted(accepted)
	if err != nil {
		return snapshot, ErrDelivery
	}
	inputs, err := bootstrapstart.LoadTrustInputs(accepted)
	if err != nil {
		return snapshot, ErrDelivery
	}
	chain, err := ReadInstalledChain()
	if err != nil || len(chain) == 0 && accepted.MaterialGenerationSHA256 != "" {
		return snapshot, ErrDelivery
	}
	snapshot.accepted, snapshot.chain = accepted, chain
	snapshot.refs = make(map[string]bootstrap.SecretReference)
	add := func(references []bootstrap.SecretReference) {
		for _, reference := range references {
			if reference.Slot == "" || reference.Slot == accepted.Slot {
				snapshot.refs[reference.TargetFile] = reference
			}
		}
	}
	add(accepted.MaterialReferences)
	configSHA := accepted.ConfigSHA256["controller.json"]
	if len(chain) != 0 {
		decoded, err := bootstrap.DecodeMaterialGenerationChain(chain)
		if err != nil {
			return snapshot, ErrDelivery
		}
		verified, err := target.VerifyAdoptedChain(decoded, inputs.Roots.Current)
		if err != nil || len(verified) == 0 {
			return snapshot, ErrDelivery
		}
		newest := verified[len(verified)-1]
		snapshot.expires = newest.ExpiresAt()
		if !time.Now().Before(snapshot.expires) {
			return snapshot, ErrDelivery
		}
		generation := newest.Generation()
		add(generation.Secrets)
		for _, pin := range generation.ControllerConfigs {
			if pin.Slot == accepted.Slot {
				configSHA = pin.SHA256
			}
		}
	}
	config, err := readControllerReaderConfig()
	digest := sha256.Sum256(config)
	if err != nil || hex.EncodeToString(digest[:]) != configSHA {
		return snapshot, ErrDelivery
	}
	var decoded struct {
		NATS natscell.Config `json:"nats"`
	}
	if json.Unmarshal(config, &decoded) != nil || decoded.NATS.Cell != strings.ToLower(accepted.Cell) || decoded.NATS.Instance != accepted.Slot ||
		decoded.NATS.ClientRole != "" && decoded.NATS.ClientRole != "controller" || decoded.NATS.NKeySeedFile != "" {
		return snapshot, ErrDelivery
	}
	snapshot.nats, snapshot.config = decoded.NATS, config
	return snapshot, nil
}

func readControllerReaderConfig() ([]byte, error) {
	directory, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrDelivery
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(filepath.Dir(controllerReaderConfig), "/"), "/") {
		next, err := unix.Openat(directory, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(directory)
		if err != nil {
			return nil, ErrDelivery
		}
		directory = next
		var stat unix.Stat_t
		if unix.Fstat(directory, &stat) != nil || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			unix.Close(directory)
			return nil, ErrDelivery
		}
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, filepath.Base(controllerReaderConfig), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrDelivery
	}
	file := os.NewFile(uintptr(fd), controllerReaderConfig)
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&0o022 != 0 || stat.Size <= 0 || stat.Size > bootstrap.MaxControllerConfigBytes {
		return nil, ErrDelivery
	}
	wire, err := io.ReadAll(io.LimitReader(file, bootstrap.MaxControllerConfigBytes+1))
	if err != nil || int64(len(wire)) != stat.Size || bytes.IndexByte(wire, 0) >= 0 {
		return nil, ErrDelivery
	}
	return wire, nil
}
