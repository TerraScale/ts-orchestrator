package databaseadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission/subjects"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

const RestoreSubject = subjects.Restore
const CreateSubject = subjects.Create
const StatusSubject = subjects.Status
const maxMessage = 256 << 10

type Result struct {
	RestoreReceipt   []byte    `json:"restore_receipt,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	ParentDatabaseID string    `json:"parent_database_id,omitempty"`
	Environment      string    `json:"environment"`
	TenantID         string    `json:"tenant_id"`
	ProjectID        string    `json:"project_id"`
	OperationID      string    `json:"operation_id"`
	DatabaseID       string    `json:"database_id"`
	KeyVersion       string    `json:"key_version"`
	Name             string    `json:"name"`
	Regions          []string  `json:"regions"`
	Residency        string    `json:"residency"`
	State            string    `json:"state"`
}
type response struct {
	Result *Result `json:"result,omitempty"`
	Error  string  `json:"error,omitempty"`
}

func result(r Record) Result {
	state := "pending"
	if r.State == "ready" {
		state = "ready"
	}
	var receipt []byte
	if r.State == "ready" {
		receipt = r.RestoreReceipt
	}
	return Result{RestoreReceipt: receipt, CreatedAt: r.CreatedAt, ParentDatabaseID: r.Request.ParentDatabaseID, Environment: r.Request.Environment, TenantID: r.Request.TenantID, ProjectID: r.Request.ProjectID, OperationID: r.Request.OperationID, DatabaseID: r.DatabaseID, KeyVersion: r.KeyVersion, Name: r.Request.Name, Regions: r.Request.Regions, Residency: r.Request.Residency, State: state}
}

type Service struct {
	close func() error
	once  sync.Once
	done  chan struct{}
	err   error
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() { s.err = s.close(); close(s.done) })
	return s.err
}
func (s *Service) Completion() <-chan struct{} { return s.done }
func secureConnection(nc *nats.Conn) bool {
	if nc == nil || !nc.IsConnected() || !nc.AuthRequired() {
		return false
	}
	options := nc.Opts
	if options.Nkey == "" || options.SignatureCB == nil || options.AllowReconnect || options.ReconnectBufSize >= 0 || options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify || options.TLSConfig.RootCAs == nil || (len(options.TLSConfig.Certificates) == 0 && options.TLSConfig.GetClientCertificate == nil && options.TLSCertCB == nil) {
		return false
	}
	state, err := nc.TLSConnectionState()
	return err == nil && state.HandshakeComplete && state.Version >= tls.VersionTLS13 && len(state.VerifiedChains) > 0
}
func HostSubject(identity string) (string, error) {
	path, ok := strings.CutPrefix(identity, "spiffe://terrascale.tech/")
	parts := strings.Split(path, "/")
	if !ok || len(parts) != 4 || !environmentName.MatchString(parts[0]) || parts[1] != "terrabase-member" || !canonicalID.MatchString(parts[2]) || !canonicalID.MatchString(parts[3]) {
		return "", ErrInvalid
	}
	sum := sha256.Sum256([]byte(identity))
	return strings.Replace(subjects.HostInstallPattern, "*", hex.EncodeToString(sum[:]), 1), nil
}

// HostPermissions are the exact dedicated database service NKey grants.
// Installation can be received only for this engine identity; the host cannot
// publish installation, mutate the journal, or consume another host's intent.
func HostPermissions(identity string) (publish, subscribe []string, err error) {
	subject, err := HostSubject(identity)
	if err != nil {
		return nil, nil, err
	}
	branch, err := BranchRestoreSubject(identity)
	if err != nil {
		return nil, nil, err
	}
	return []string{CreateSubject, RestoreSubject, StatusSubject, subjects.OperationList, DeletionBeginSubject, DeletionStatusSubject, "_INBOX.>"}, []string{subject, branch, "_INBOX.>"}, nil
}

// Broker grants must bind these subjects to the admitted service NKeys. A
// customer-facing credential must never publish the internal control subjects.
func StartAuthority(ctx context.Context, nc *nats.Conn, pipeline *Pipeline) (*Service, error) {
	if ctx == nil || !secureConnection(nc) || pipeline == nil {
		return nil, ErrInvalid
	}
	listSubscription, err := subscribeOperationList(ctx, nc, pipeline)
	if err != nil {
		return nil, err
	}
	_ = listSubscription.SetPendingLimits(128, 8<<20)
	subscriptions := []*nats.Subscription{listSubscription}
	for _, subject := range []string{CreateSubject, RestoreSubject, StatusSubject} {
		sub, err := nc.Subscribe(subject, func(message *nats.Msg) {
			if len(message.Data) > maxMessage || message.Reply == "" {
				return
			}
			opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			var request Request
			reply := response{}
			if message.Subject == RestoreSubject {
				var restore RestoreRequest
				if json.Unmarshal(message.Data, &restore, json.RejectUnknownMembers(true)) != nil {
					reply.Error = "invalid"
				} else {
					record, err := pipeline.AcceptRestore(opctx, restore)
					if err != nil {
						reply.Error = lifecycleError(err)
					} else {
						reply.Result = new(result(record))
					}
				}
			} else if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) != nil {
				reply.Error = "invalid"
			} else {
				var record Record
				var err error
				if message.Subject == CreateSubject {
					record, err = pipeline.Accept(opctx, request)
				} else {
					record, err = pipeline.LookupOperation(opctx, request)
				}
				if err != nil {
					if errors.Is(err, ErrConflict) {
						reply.Error = "conflict"
					} else if errors.Is(err, ErrInvalid) {
						reply.Error = "invalid"
					} else if errors.Is(err, ErrForbidden) {
						reply.Error = "forbidden"
					} else {
						reply.Error = "unavailable"
					}
				} else {
					reply.Result = new(result(record))
					if message.Subject == CreateSubject {
						reply.Result.State = "pending"
					}
				}
			}
			data, _ := json.Marshal(reply)
			_ = message.Respond(data)
		})
		if err != nil {
			for _, s := range subscriptions {
				_ = s.Unsubscribe()
			}
			return nil, err
		}
		_ = sub.SetPendingLimits(128, 8<<20)
		subscriptions = append(subscriptions, sub)
	}
	if err := nc.FlushTimeout(5 * time.Second); err != nil {
		for _, s := range subscriptions {
			_ = s.Unsubscribe()
		}
		return nil, err
	}
	service := &Service{done: make(chan struct{}), close: func() error {
		var e []error
		for _, s := range subscriptions {
			e = append(e, s.Unsubscribe())
		}
		return errors.Join(e...)
	}}
	context.AfterFunc(ctx, func() { _ = service.Close() })
	return service, nil
}

type IngressConfig struct {
	Connection *nats.Conn
	SocketPath string
	AllowedUID uint32
	Lifecycle  *LifecycleIngressConfig
}

func StartIngress(ctx context.Context, c IngressConfig) (*Service, error) {
	if ctx == nil || !secureConnection(c.Connection) {
		return nil, ErrInvalid
	}
	if err := validateLifecycleIngress(c.Lifecycle); err != nil {
		return nil, err
	}
	listener, err := listenPrivate(c.SocketPath)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	registerLifecycleIngress(mux, c.Lifecycle)
	registerDeletionIngress(mux, c)
	registerOperationListIngress(mux, c)
	for path, subject := range map[string]string{"/internal/v1/databases/create": CreateSubject, "/internal/v1/databases/restore": RestoreSubject, "/internal/v1/databases/status": StatusSubject} {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			uid, ok := r.Context().Value(peerUIDKey{}).(uint32)
			if !ok || uid != c.AllowedUID {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
			if err != nil {
				http.Error(w, "invalid", 400)
				return
			}
			var request Request
			decodeError := json.Unmarshal(data, &request, json.RejectUnknownMembers(true))
			validationError := ValidateRequest(request)
			if subject == StatusSubject {
				validationError = validateLookup(request)
			} else if subject == RestoreSubject {
				var restore RestoreRequest
				decodeError = json.Unmarshal(data, &restore, json.RejectUnknownMembers(true))
				validationError = ValidateRestoreRequest(restore)
			}
			if decodeError != nil || validationError != nil {
				http.Error(w, "invalid", 400)
				return
			}
			opctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			message, err := c.Connection.RequestWithContext(opctx, subject, data)
			if err != nil || len(message.Data) > maxMessage {
				http.Error(w, "unavailable", 503)
				return
			}
			var reply response
			if json.Unmarshal(message.Data, &reply) != nil || reply.Result == nil {
				code := 503
				if reply.Error == "conflict" {
					code = 409
				}
				if reply.Error == "invalid" {
					code = 400
				}
				if reply.Error == "forbidden" {
					code = 403
				}
				http.Error(w, "create unavailable", code)
				return
			}
			payload, _ := json.Marshal(reply.Result)
			w.Header().Set("Content-Type", "application/json")
			status := http.StatusAccepted
			if subject == StatusSubject {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			_, _ = w.Write(payload)
		})
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 25 * time.Second, MaxHeaderBytes: 16 << 10, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		uid, err := peerUID(c)
		if err != nil {
			return ctx
		}
		return context.WithValue(ctx, peerUIDKey{}, uid)
	}}
	service := &Service{done: make(chan struct{}), close: func() error { return server.Close() }}
	go func() { _ = server.Serve(listener); _ = service.Close() }()
	context.AfterFunc(ctx, func() { _ = service.Close() })
	return service, nil
}

type peerUIDKey struct{}

func peerUID(connection net.Conn) (uint32, error) {
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, ErrInvalid
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var inner error
	if err = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, err
	}
	if inner != nil || cred == nil {
		return 0, ErrInvalid
	}
	return cred.Uid, nil
}
func listenPrivate(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	dir := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return nil, ErrInvalid
	}
	for current := dir; ; current = filepath.Dir(current) {
		var stat unix.Stat_t
		if unix.Lstat(current, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0022 != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return nil, ErrInvalid
		}
		if current == dir && (stat.Mode&0777 != 0700 || stat.Uid != uint32(os.Geteuid())) {
			return nil, ErrInvalid
		}
		if current == "/" {
			break
		}
	}
	// Never remove an existing endpoint: its owner may still be serving.
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if os.Chmod(path, 0600) != nil {
		_ = listener.Close()
		return nil, ErrInvalid
	}
	return listener, nil
}

type Admission struct {
	Request
	CreatedAt  int64  `json:"created_at"`
	DatabaseID string `json:"database_id"`
	KeyVersion string `json:"key_version"`
	Region     string `json:"region"`
	MemberID   string `json:"member_id"`
}
type installRequest struct {
	Admission Admission        `json:"admission"`
	Entries   []keylease.Entry `json:"entries"`
}
type HostConfig struct {
	Connection     *nats.Conn
	ServerIdentity string
	CatalogPath    string
	EngineSocket   string
	EngineUID      uint32
	Environment    string
	Region         string
	MemberID       string
}

func RemoteInstall(nc *nats.Conn) func(context.Context, Record, Target, []keylease.Entry) error {
	return func(ctx context.Context, r Record, t Target, entries []keylease.Entry) error {
		if !secureConnection(nc) {
			return ErrInvalid
		}
		subject, err := HostSubject(t.ServerIdentity)
		if err != nil {
			return err
		}
		data, err := json.Marshal(installRequest{Admission{Request: r.Request, CreatedAt: r.CreatedAt.UnixMilli(), DatabaseID: r.DatabaseID, KeyVersion: r.KeyVersion, Region: t.Region, MemberID: t.MemberID}, entries})
		if err != nil || len(data) > maxMessage {
			return ErrInvalid
		}
		opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		reply, err := nc.RequestWithContext(opctx, subject, data)
		if err != nil {
			return err
		}
		if string(reply.Data) != "installed" {
			return errors.New("database admission: host install unresolved")
		}
		return nil
	}
}
func StartHost(ctx context.Context, c HostConfig) (*Service, error) {
	if ctx == nil || !secureConnection(c.Connection) || !canonicalID.MatchString(c.MemberID) || !filepath.IsAbs(c.EngineSocket) {
		return nil, ErrInvalid
	}
	subject, err := HostSubject(c.ServerIdentity)
	if err != nil {
		return nil, err
	}
	identityParts := strings.Split(strings.TrimPrefix(c.ServerIdentity, "spiffe://terrascale.tech/"), "/")
	if identityParts[0] != c.Environment || identityParts[3] != c.MemberID {
		return nil, ErrInvalid
	}
	if _, err := keylease.ReadCatalog(c.CatalogPath); err != nil {
		return nil, err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.EngineSocket)
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(conn)
		if err != nil || uid != c.EngineUID {
			_ = conn.Close()
			return nil, ErrInvalid
		}
		return conn, nil
	}}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sub, err := c.Connection.Subscribe(subject, func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) > maxMessage {
			return
		}
		opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if handleHostPreparation(opctx, c, client, message) {
			return
		}
		if handleHostDeletion(opctx, c, client, message) {
			return
		}
		if handleHostBudgetPoolRefill(opctx, c, client, message) {
			return
		}
		if handleHostBudgetAllocation(opctx, c, client, message) {
			return
		}
		if handleHostUsage(opctx, c, client, message) {
			return
		}
		var request installRequest
		if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) != nil || validateInstall(c, request) != nil {
			_ = message.Respond([]byte("invalid"))
			return
		}
		if keylease.MergeEntries(c.CatalogPath, request.Entries) != nil {
			_ = message.Respond([]byte("unavailable"))
			return
		}
		data, _ := json.Marshal(request.Admission)
		req, err := http.NewRequestWithContext(opctx, http.MethodPost, "http://unix/internal/v1/databases/admit", bytes.NewReader(data))
		if err != nil {
			_ = message.Respond([]byte("unavailable"))
			return
		}
		req.Header.Set("Content-Type", "application/json")
		reply, err := client.Do(req)
		if err != nil {
			_ = message.Respond([]byte("unavailable"))
			return
		}
		defer reply.Body.Close()
		body, err := io.ReadAll(io.LimitReader(reply.Body, 16<<10))
		var receipt struct {
			OperationID string `json:"operation_id"`
			DatabaseID  string `json:"database_id"`
			State       string `json:"state"`
		}
		if err != nil || reply.StatusCode != 200 || json.Unmarshal(body, &receipt) != nil || receipt.OperationID != request.Admission.OperationID || receipt.DatabaseID != request.Admission.DatabaseID || receipt.State != "admitted" {
			_ = message.Respond([]byte("unavailable"))
			return
		}
		_ = message.Respond([]byte("installed"))
	})
	if err != nil {
		return nil, err
	}
	_ = sub.SetPendingLimits(128, 8<<20)
	if err := c.Connection.FlushTimeout(5 * time.Second); err != nil {
		_ = sub.Unsubscribe()
		return nil, err
	}
	service := &Service{done: make(chan struct{}), close: func() error { transport.CloseIdleConnections(); return sub.Unsubscribe() }}
	context.AfterFunc(ctx, func() { _ = service.Close() })
	return service, nil
}
func validateInstall(c HostConfig, r installRequest) error {
	a := r.Admission
	if a.CreatedAt <= 0 || ValidateRequest(a.Request) != nil || a.Environment != c.Environment || a.Region != c.Region || a.MemberID != c.MemberID || !canonicalID.MatchString(a.DatabaseID) || !canonicalID.MatchString(a.KeyVersion) || len(r.Entries) != len(databaseKeyPurposes) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, entry := range r.Entries {
		b := entry.Binding
		if b.Environment != a.Environment || b.TenantID != a.TenantID || b.ProjectID != a.ProjectID || b.DatabaseID != a.DatabaseID || b.KeyVersion != a.KeyVersion || b.Region != a.Region || !slices.Contains(databaseKeyPurposes[:], b.Purpose) || seen[b.Purpose] || entry.Revoked {
			return ErrInvalid
		}
		seen[b.Purpose] = true
	}
	found := false
	for _, region := range a.Regions {
		if region == a.Region {
			found = true
		}
	}
	if !found {
		return ErrInvalid
	}
	return nil
}
