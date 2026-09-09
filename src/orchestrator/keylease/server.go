//go:build linux

package keylease

import (
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"io"
	"net"
	"os"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

const maximumFrame = 2048

type Config struct {
	SocketPath       string
	CatalogPath      string
	Environment      string
	Region           string
	AllowedUID       uint32
	SocketGID        uint32
	Customer         *CustomerConfig
	WorkloadIdentity WorkloadIdentityIssuer
}

// CustomerAuthority unwraps ciphertext for an explicitly admitted customer
// binding. Implementations must perform provider authentication and must not
// use ambient credentials.
type CustomerAuthority interface {
	Unwrap(context.Context, Binding, string) (*hostsecrets.DataKey, error)
}

type CustomerConfig struct {
	Authority   CustomerAuthority
	Provider    string
	KeyID       string
	KeyRegion   string
	KeyEndpoint string
}

type WorkloadIdentityScope struct {
	Environment       string  `json:"environment"`
	TenantID          string  `json:"tenant_id"`
	ProjectID         string  `json:"project_id"`
	DatabaseID        string  `json:"database_id"`
	Role              string  `json:"role"`
	ExternalID        *string `json:"external_id,omitempty"`
	Endpoint          string  `json:"endpoint"`
	Bucket            string  `json:"bucket"`
	Region            string  `json:"region"`
	PlacementRevision string  `json:"placement_revision"`
}

type WorkloadIdentityCredentials struct {
	AccessKey            string `json:"access_key"`
	SecretKey            string `json:"secret_key"`
	SessionToken         string `json:"session_token"`
	ExpiresAtUnixSeconds uint64 `json:"expires_at_unix_seconds"`
}

type WorkloadIdentityIssuer interface {
	Issue(context.Context, WorkloadIdentityScope) (WorkloadIdentityCredentials, error)
}

type Server struct {
	config     Config
	listener   *net.UnixListener
	cancel     context.CancelFunc
	workers    sync.WaitGroup
	completion chan error
	stopped    chan struct{}
	once       sync.Once
}

// Start binds a dedicated-group Unix socket with an exact peer UID allowlist.
// OCI IAM authentication happens when a
// key is requested; startup does not fetch or persist any plaintext keys.
func Start(ctx context.Context, config Config) (*Server, error) { return start(ctx, config, unwrapOCI) }
func start(ctx context.Context, config Config, unwrap UnwrapFunc) (*Server, error) {
	if ctx == nil || unwrap == nil || ociRegion(config.Region) == "" || !validEnvironment(config.Environment) || config.Customer != nil && config.Customer.Authority == nil {
		return nil, ErrUnavailable
	}
	_, err := ReadCatalog(config.CatalogPath)
	if err != nil {
		return nil, ErrUnavailable
	}

	root, name, err := socketRoot(config.SocketPath, config.SocketGID)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer root.Close()
	// A stale socket must be removed explicitly by systemd RuntimeDirectory
	// cleanup. Never unlink a live service or a caller-supplied filesystem object.
	if _, err := root.Lstat(name); !os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, ErrUnavailable
	}
	if root.Chown(name, os.Geteuid(), int(config.SocketGID)) != nil || root.Chmod(name, 0660) != nil {
		listener.Close()
		return nil, ErrUnavailable
	}
	local, cancel := context.WithCancel(ctx)
	s := &Server{config: config, listener: listener, cancel: cancel, completion: make(chan error, 1), stopped: make(chan struct{})}
	go s.serve(local, unwrap)
	return s, nil
}
func (s *Server) Completion() <-chan error { return s.completion }
func (s *Server) Close() error {
	s.once.Do(func() { s.cancel(); s.listener.Close(); <-s.stopped; s.workers.Wait() })
	return nil
}
func (s *Server) serve(ctx context.Context, unwrap UnwrapFunc) {
	stop := context.AfterFunc(ctx, func() { s.listener.Close() })
	defer stop()
	defer close(s.completion)
	defer close(s.stopped)
	// Bound queued connections and SDK work. Four requests can wait on the one
	// existing process-wide OCI identity worker; no unbounded goroutine admission.
	slots := make(chan struct{}, 4)
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() == nil {
				s.completion <- ErrUnavailable
			}
			return
		}
		select {
		case slots <- struct{}{}:
			s.workers.Go(func() { defer func() { <-slots }(); defer connection.Close(); s.handle(ctx, connection, unwrap) })
		default:
			connection.Close()
		}
	}
}
func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, ErrUnavailable
	}
	var credential *unix.Ucred
	var inner error
	if raw.Control(func(fd uintptr) { credential, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || inner != nil || credential == nil {
		return 0, ErrUnavailable
	}
	return credential.Uid, nil
}
func (s *Server) handle(ctx context.Context, connection *net.UnixConn, unwrap UnwrapFunc) {
	uid, err := peerUID(connection)
	if err != nil || uid != s.config.AllowedUID {
		return
	}
	if connection.SetDeadline(time.Now().Add(25*time.Second)) != nil {
		return
	}
	local, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(local, func() { connection.Close() })
	defer stop()
	protocol, binding, customer, err := readRequest(connection)
	if protocol == "S3" {
		if customer.Workload == nil {
			return
		}
		s.serveWorkloadIdentity(local, connection, customer.Workload)
		return
	}
	if err != nil || binding.Environment != s.config.Environment || binding.Region != s.config.Region {
		writeUnavailableProtocol(connection, protocol)
		return
	}
	entry, err := s.lookup(binding, time.Now())
	if err != nil {
		writeUnavailableProtocol(connection, protocol)
		return
	}
	unwrapKey := unwrap
	if protocol == "TBCK" {
		if s.config.Customer == nil || customer.Provider != s.config.Customer.Provider || customer.KeyID != s.config.Customer.KeyID || customer.KeyRegion != s.config.Customer.KeyRegion || customer.KeyEndpoint != s.config.Customer.KeyEndpoint || entry.Provider != customer.Provider || entry.KeyID != customer.KeyID || entry.KeyRegion != customer.KeyRegion || entry.KeyEndpoint != customer.KeyEndpoint {
			writeUnavailableProtocol(connection, protocol)
			return
		}
		unwrapKey = func(ctx context.Context, entry Entry) (*hostsecrets.DataKey, error) {
			return s.config.Customer.Authority.Unwrap(ctx, binding, entry.Ciphertext)
		}
	}
	key, err := unwrapKey(local, entry)
	defer hostsecrets.ReleaseDataKey(key)
	if err != nil || len(key.Bytes()) != 32 {
		writeUnavailableProtocol(connection, protocol)
		return
	}
	// Re-check after remote latency: revocation or rotation must not race a
	// pending Vault unwrap. Old versions remain usable only if explicitly kept.
	unlock, err := catalogLock(s.config.CatalogPath)
	if err != nil {
		writeUnavailableProtocol(connection, protocol)
		return
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	current, err := s.lookup(binding, time.Now())
	if err != nil || current != entry {
		writeUnavailableProtocol(connection, protocol)
		return
	}
	seconds := min(entry.LeaseSeconds, uint32(max(0, time.Until(entry.NotAfter)/time.Second)))
	if seconds == 0 {
		writeUnavailableProtocol(connection, protocol)
		return
	}
	// The catalog check is the linearization point for this lease. Release the
	// lock before writing the response so a completed request cannot make a
	// concurrent catalog update spuriously fail on the socket write.
	unlock()
	unlock = nil
	var response [40]byte
	defer clear(response[:])
	binary.BigEndian.PutUint32(response[:4], 68)
	copy(response[4:8], protocol)
	response[8] = 1
	response[9] = 0
	binary.BigEndian.PutUint32(response[10:14], seconds)
	copy(response[14:40], binding.KeyVersion)
	writeAll(connection, response[:])
	writeAll(connection, key.Bytes())
}

func (s *Server) serveWorkloadIdentity(ctx context.Context, connection *net.UnixConn, scope *WorkloadIdentityScope) {
	if s.config.WorkloadIdentity == nil || scope == nil {
		return
	}
	credentials, err := s.config.WorkloadIdentity.Issue(ctx, *scope)
	if err != nil || credentials.AccessKey == "" || credentials.SecretKey == "" || credentials.SessionToken == "" || credentials.ExpiresAtUnixSeconds == 0 {
		return
	}
	body, err := json.Marshal(credentials)
	if err != nil || len(body) > maximumFrame {
		return
	}
	writeAll(connection, binary.BigEndian.AppendUint32(nil, uint32(len(body))))
	writeAll(connection, body)
}
func (s *Server) lookup(binding Binding, now time.Time) (Entry, error) {
	catalog, err := ReadCatalog(s.config.CatalogPath)
	if err != nil {
		return Entry{}, ErrUnavailable
	}
	for _, e := range catalog.Entries {
		if e.Binding == binding {
			if e.Revoked || !e.NotAfter.After(now) {
				return Entry{}, ErrUnavailable
			}
			return e, nil
		}
	}
	return Entry{}, ErrUnavailable
}

type customerRequest struct {
	Provider, KeyID, KeyRegion, KeyEndpoint string
	Workload                                *WorkloadIdentityScope
}

func readRequest(reader io.Reader) (string, Binding, customerRequest, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return "", Binding{}, customerRequest{}, ErrUnavailable
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || size > maximumFrame {
		return "", Binding{}, customerRequest{}, ErrUnavailable
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return "", Binding{}, customerRequest{}, ErrUnavailable
	}
	if body[0] == '{' {
		var envelope struct {
			Version uint8                 `json:"version"`
			Scope   WorkloadIdentityScope `json:"scope"`
		}
		if json.Unmarshal(body, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.Version != 1 {
			return "", Binding{}, customerRequest{}, ErrUnavailable
		}
		return "S3", Binding{}, customerRequest{Workload: &envelope.Scope}, nil
	}
	if len(body) < 5 {
		return "", Binding{}, customerRequest{}, ErrUnavailable
	}
	protocol := string(body[:4])
	if protocol != "TBKL" && protocol != "TBCK" || body[4] != 1 {
		return "", Binding{}, customerRequest{}, ErrUnavailable
	}
	var customer customerRequest
	var b Binding
	fields := []*string{&b.Environment, &b.TenantID, &b.ProjectID, &b.DatabaseID, &b.KeyVersion, &b.Region, &b.Purpose}
	if protocol == "TBCK" {
		fields = append([]*string{&customer.Provider, &customer.KeyID, &customer.KeyRegion, &customer.KeyEndpoint}, fields...)
	}
	cursor := 5
	for _, field := range fields {
		if cursor+2 > len(body) {
			return "", Binding{}, customerRequest{}, ErrUnavailable
		}
		n := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
		cursor += 2
		if n < 1 || n > 128 || cursor+n > len(body) || !utf8.Valid(body[cursor:cursor+n]) {
			return "", Binding{}, customerRequest{}, ErrUnavailable
		}
		*field = string(body[cursor : cursor+n])
		cursor += n
	}
	if cursor != len(body) || !b.valid() {
		return "", Binding{}, customerRequest{}, ErrUnavailable
	}
	return protocol, b, customer, nil
}
func readBinding(reader io.Reader) (Binding, error) {
	_, binding, _, err := readRequest(reader)
	return binding, err
}
func writeUnavailable(writer io.Writer) { writeUnavailableProtocol(writer, "TBKL") }
func writeUnavailableProtocol(writer io.Writer, protocol string) {
	if protocol != "TBCK" {
		protocol = "TBKL"
	}
	writeAll(writer, []byte{0, 0, 0, 6, protocol[0], protocol[1], protocol[2], protocol[3], 1, 1})
}
func writeAll(writer io.Writer, body []byte) {
	for len(body) > 0 {
		n, err := writer.Write(body)
		if err != nil || n == 0 {
			return
		}
		body = body[n:]
	}
}
