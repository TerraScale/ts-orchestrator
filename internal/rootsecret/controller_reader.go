package rootsecret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
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
	conn     *nats.Conn
	lease    context.Context
	snapshot controllerReaderSnapshot
}

// OpenControllerReader independently opens the fixed accepted credential source.
func OpenControllerReader(ctx context.Context) (*ControllerReader, error) {
	conn, lease, snapshot, err := openControllerReaderLease(ctx)
	if err != nil {
		return nil, err
	}
	reader := &ControllerReader{conn: conn, lease: lease, snapshot: snapshot}
	if err := reader.Guard(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return reader, nil
}

func (reader *ControllerReader) Conn() *nats.Conn         { return reader.conn }
func (reader *ControllerReader) Context() context.Context { return reader.lease }

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

func openControllerReaderLease(ctx context.Context) (*nats.Conn, context.Context, controllerReaderSnapshot, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return nil, nil, controllerReaderSnapshot{}, ErrDelivery
		}
	}
	snapshot, err := loadControllerReaderSnapshot()
	if err != nil {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	guard := func() error {
		if ctx.Err() != nil || !snapshot.expires.IsZero() && !time.Now().Before(snapshot.expires) {
			return ErrDelivery
		}
		current, err := loadControllerReaderSnapshot()
		if err != nil || !reflect.DeepEqual(snapshot, current) || ctx.Err() != nil ||
			!snapshot.expires.IsZero() && !time.Now().Before(snapshot.expires) {
			return ErrDelivery
		}
		return nil
	}
	region, err := snapshot.acceptedRegion()
	if err != nil || guard() != nil {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	factory, err := ociclient.InstancePrincipal(region)
	if err != nil {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	client, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	readCtx, stopReads := context.WithTimeout(ctx, 30*time.Second)
	defer stopReads()
	client.HTTPClient = credentialDispatcher{next: client.HTTPClient, guard: func() error {
		if readCtx.Err() != nil {
			return ErrDelivery
		}
		return guard()
	}}
	paths := []string{snapshot.nats.CredentialsFile, snapshot.nats.TLS.CAFile, snapshot.nats.TLS.CertFile, snapshot.nats.TLS.KeyFile}
	values := make([][]byte, len(paths))
	defer func() {
		for _, value := range values {
			clear(value)
		}
	}()
	expires := snapshot.expires
	for index, path := range paths {
		reference, ok := snapshot.refs[filepath.Base(path)]
		if !ok || path != filepath.Join(bootstrap.MaterialDirectory, reference.TargetFile) || guard() != nil {
			return nil, nil, controllerReaderSnapshot{}, ErrDelivery
		}
		value, deadline, err := readExact(readCtx, &client, reference)
		if err != nil {
			return nil, nil, controllerReaderSnapshot{}, ErrDelivery
		}
		values[index] = value
		if !deadline.IsZero() && (expires.IsZero() || deadline.Before(expires)) {
			expires = deadline
		}
	}
	if natscell.ValidateBrokerControllerCredentialBytes(values[0], snapshot.nats.Cell, snapshot.nats.Instance) != nil {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	raw, err := jwt.ParseDecoratedJWT(values[0])
	if err != nil {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil || claim.IssuerAccount != snapshot.accepted.Broker.CellAccount &&
		(claim.IssuerAccount != "" || claim.Issuer != snapshot.accepted.Broker.CellAccount) {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	certificate, err := tls.X509KeyPair(values[2], values[3])
	if err != nil {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(values[1]) || guard() != nil || readCtx.Err() != nil || !expires.IsZero() && !time.Now().Before(expires) {
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	connectionCtx, cancel := context.WithCancel(ctx)
	if !expires.IsZero() {
		var deadlineCancel context.CancelFunc
		connectionCtx, deadlineCancel = context.WithDeadline(connectionCtx, expires)
		previous := cancel
		cancel = func() { deadlineCancel(); previous() }
	}
	conn, lease, err := natscell.ConnectMemoryLease(connectionCtx, snapshot.nats.Cell, snapshot.nats.URL, values[0],
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		cancel()
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
	}
	if guard() != nil || !expires.IsZero() && !time.Now().Before(expires) {
		conn.Close()
		cancel()
		return nil, nil, controllerReaderSnapshot{}, ErrDelivery
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
	return conn, lease, snapshot, nil
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
	chain, err := readInstalledChain()
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
