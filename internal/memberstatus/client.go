package memberstatus

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxEvidenceBytes = 8192

// ProcessObservation is supplied by the native host runner, which must check
// the process start time and role cgroup. The client checks that this
// observation remains unchanged across every Unix HTTP request.
type ProcessObservation struct {
	PID         int
	UID         uint32
	GID         uint32
	KernelStart string
	Cgroup      string
}

type ObserveProcess func(context.Context) (ProcessObservation, error)

type Client struct {
	socket    string
	scope     Scope
	authority Authority
	observe   ObserveProcess
}

func NewClient(socket string, scope Scope, authority Authority, observe ObserveProcess) (*Client, error) {
	if socket == "" || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket ||
		!scope.valid() || !authority.valid() || observe == nil {
		return nil, errors.New("incomplete signed member control binding")
	}
	return &Client{socket: socket, scope: scope, authority: authority, observe: observe}, nil
}

func nonce() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("member challenge: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	challenge, err := nonce()
	if err != nil {
		return Status{}, err
	}
	code, body, process, err := c.exchange(ctx, http.MethodGet, "/v1/member/status?nonce="+challenge, nil)
	if err != nil {
		return Status{}, err
	}
	if code != http.StatusOK {
		return Status{}, fmt.Errorf("member status HTTP %d", code)
	}
	// The load block is telemetry, never evidence: it is split off before
	// the strict decode, and a malformed, incomplete or out-of-range block
	// is dropped instead of failing the status.
	evidence, load := SplitLoad(body)
	var status Status
	if err := decodeRequired(evidence, &status, statusPaths...); err != nil {
		return Status{}, err
	}
	status.Load = DecodeLoad(load)
	if status.SchemaVersion != 2 || status.Nonce != challenge || status.Process.PID != process.PID ||
		!status.Process.valid() || status.Scope != c.scope || status.Authority != c.authority ||
		!status.Capabilities.ServingProof || !status.Capabilities.DurableDrain {
		return Status{}, ErrStaleBinding
	}
	status.verified = true
	return status, nil
}

// ServingProof requires a fresh status from this exact process and a named,
// signed survivor. The remote ACK and root coverage checks use typed fields;
// caller-provided health booleans cannot satisfy them.
func (c *Client) ServingProof(ctx context.Context, status Status, survivor Survivor) (ServingProof, error) {
	if !survivor.valid() {
		return ServingProof{}, ErrNotServing
	}
	return c.servingProof(ctx, status, survivor.MemberID, survivor.Incarnation)
}

// ServingProofForPeer binds the signed peer member ID at the host. The
// controller must compare the returned incarnation with its signed roster.
func (c *Client) ServingProofForPeer(ctx context.Context, status Status, peerMemberID string) (ServingProof, error) {
	return c.servingProof(ctx, status, peerMemberID, "")
}

func (c *Client) servingProof(ctx context.Context, status Status, peerMemberID, peerIncarnation string) (ServingProof, error) {
	if !status.verified || !canonicalID(peerMemberID) || peerMemberID == c.scope.MemberID ||
		status.Scope != c.scope || status.Authority != c.authority || !status.Process.valid() ||
		status.ReceiverOnly || !status.Serving || !status.Local.Healthy || !status.Local.Ready {
		return ServingProof{}, ErrNotServing
	}
	challenge, err := nonce()
	if err != nil {
		return ServingProof{}, err
	}
	code, body, process, err := c.exchange(ctx, http.MethodGet, "/v1/member/serving-proof?nonce="+challenge, nil)
	if err != nil {
		return ServingProof{}, err
	}
	if code == http.StatusServiceUnavailable {
		return ServingProof{}, ErrNotServing
	}
	if code != http.StatusOK {
		return ServingProof{}, fmt.Errorf("member serving proof HTTP %d", code)
	}
	proof, err := decodeServingProof(body)
	if err != nil {
		return ServingProof{}, err
	}
	if proof.SchemaVersion != 1 || proof.Nonce != challenge || proof.Process != status.Process ||
		proof.Process.PID != process.PID || proof.Scope != c.scope || proof.Authority != c.authority ||
		!proof.Serving || !proof.Listeners.Client || !proof.Listeners.Replication ||
		!lowerHex(proof.Object.RootSHA256, 64) || !lowerHex(proof.Object.TargetSHA256, 64) ||
		!lowerHex(proof.Object.InboxArchiveSHA256AtRecovery, 64) ||
		proof.Object.RemoteAppliedSequence > proof.Object.RemoteInboxDurableSequence ||
		proof.Replication.PeerMemberID != peerMemberID || !lowerHexIdentity(proof.Replication.PeerIncarnation) ||
		peerIncarnation != "" && proof.Replication.PeerIncarnation != peerIncarnation ||
		!proof.Replication.CurrentAuthenticated ||
		proof.Replication.LocalSourceSequence != proof.Object.LocalSourceSequence ||
		proof.Replication.PeerAppliedSequence < proof.Replication.LocalSourceSequence ||
		!proof.Replication.ordered() {
		return ServingProof{}, ErrNotServing
	}
	proof.verified = true
	return proof, nil
}

type socketSnapshot struct {
	parent syscall.Stat_t
	socket syscall.Stat_t
}

func inspectSocket(path string, process ProcessObservation) (socketSnapshot, error) {
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return socketSnapshot{}, err
	}
	socketInfo, err := os.Lstat(path)
	if err != nil {
		return socketSnapshot{}, err
	}
	parent, parentOK := parentInfo.Sys().(*syscall.Stat_t)
	socket, socketOK := socketInfo.Sys().(*syscall.Stat_t)
	if !parentOK || !socketOK || !parentInfo.IsDir() || socketInfo.Mode()&os.ModeSocket == 0 ||
		parent.Uid != 0 || parent.Gid != process.GID || parent.Mode&0o7777 != 0o730 ||
		socket.Uid != process.UID || socket.Gid != process.GID || socket.Mode&0o7777 != 0o602 {
		return socketSnapshot{}, errors.New("unsafe member control socket ownership or mode")
	}
	return socketSnapshot{parent: *parent, socket: *socket}, nil
}

func (s socketSnapshot) same(other socketSnapshot) bool {
	return sameInode(s.parent, other.parent) && sameInode(s.socket, other.socket)
}

func sameInode(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}

func (c *Client) exchange(ctx context.Context, method, path string, requestBody []byte) (int, []byte, ProcessObservation, error) {
	return c.exchangeBounded(ctx, method, path, requestBody, maxEvidenceBytes, 3*time.Second)
}

func (c *Client) exchangeBounded(ctx context.Context, method, path string, requestBody []byte,
	maxResponse int64, timeout time.Duration,
) (int, []byte, ProcessObservation, error) {
	if maxResponse <= 0 || maxResponse > 64<<10 || len(requestBody) > 64<<10 {
		return 0, nil, ProcessObservation{}, errors.New("member control request or response bound is invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	before, err := c.observe(ctx)
	if err != nil {
		return 0, nil, ProcessObservation{}, fmt.Errorf("unverified native member process: %w", err)
	}
	if before.PID < 2 || before.UID == 0 || before.GID == 0 || before.KernelStart == "" || before.Cgroup == "" {
		return 0, nil, ProcessObservation{}, errors.New("unverified native member process")
	}
	pathBefore, err := inspectSocket(c.socket, before)
	if err != nil {
		return 0, nil, ProcessObservation{}, err
	}
	var peerPID atomic.Int64
	transport := &http.Transport{
		DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 4096,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", c.socket)
			if err != nil {
				return nil, err
			}
			credentials, err := peerCredentials(conn)
			if err == nil && (credentials.Pid != int32(before.PID) || credentials.Uid != before.UID || credentials.Gid != before.GID) {
				err = ErrStaleBinding
			}
			if err == nil {
				var current socketSnapshot
				current, err = inspectSocket(c.socket, before)
				if err == nil && !pathBefore.same(current) {
					err = ErrStaleBinding
				}
			}
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			peerPID.Store(int64(credentials.Pid))
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(requestBody))
	if err != nil {
		return 0, nil, ProcessObservation{}, err
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}).Do(request)
	if err != nil {
		return 0, nil, ProcessObservation{}, fmt.Errorf("member control request: %w", err)
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Type") != "application/json" || response.ContentLength < 0 ||
		response.ContentLength > maxResponse || len(response.TransferEncoding) != 0 {
		return 0, nil, ProcessObservation{}, errors.New("invalid member control HTTP response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(body) != int(response.ContentLength) || int64(len(body)) > maxResponse {
		return 0, nil, ProcessObservation{}, errors.New("invalid member control response length")
	}
	if peerPID.Load() != int64(before.PID) {
		return 0, nil, ProcessObservation{}, ErrStaleBinding
	}
	pathAfter, err := inspectSocket(c.socket, before)
	if err != nil || !pathBefore.same(pathAfter) {
		return 0, nil, ProcessObservation{}, ErrStaleBinding
	}
	after, err := c.observe(ctx)
	if err != nil || after != before {
		return 0, nil, ProcessObservation{}, ErrStaleBinding
	}
	return response.StatusCode, body, before, nil
}

func peerCredentials(conn net.Conn) (*unix.Ucred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("member control connection is not Unix")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credentials *unix.Ucred
	var readErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, readErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return credentials, readErr
}

var statusPaths = []string{
	"schema_version", "nonce", "process.pid", "process.start_nonce",
	"scope.cluster_id", "scope.tenant_id", "scope.database_id", "scope.shard_id", "scope.member_id", "scope.incarnation",
	"authority.epoch", "authority.configuration_id", "authority.certificate_sha256", "authority.tls_leaf_sha256",
	"local.storage_recovered", "local.replication_listener_ready", "local.healthy", "local.ready",
	"receiver_only", "serving", "capabilities.serving_proof", "capabilities.durable_drain",
}

var servingPaths = []string{
	"schema_version", "nonce", "process.pid", "process.start_nonce",
	"scope.cluster_id", "scope.tenant_id", "scope.database_id", "scope.shard_id", "scope.member_id", "scope.incarnation",
	"authority.epoch", "authority.configuration_id", "authority.certificate_sha256", "authority.tls_leaf_sha256",
	"serving", "listeners.client", "listeners.replication",
	"object.root_sha256", "object.target_sha256", "object.native_commit_seq_at_recovery", "object.inbox_archive_sha256_at_recovery",
	"object.local_source_sequence", "object.remote_inbox_durable_sequence", "object.remote_applied_sequence",
	"replication.local_source_sequence", "replication.peer_member_id", "replication.peer_incarnation",
	"replication.current_authenticated", "replication.peer_durable_sequence", "replication.peer_applied_sequence",
	"replication.local_inbox_durable_sequence", "replication.local_inbox_applied_sequence",
}

// servingOptionalPaths are absent from TerraBase releases before the received
// prefixes; when present they must be numbers.
var servingOptionalPaths = []string{"replication.peer_received_sequence", "replication.local_inbox_received_sequence"}

func decodeServingProof(body []byte) (ServingProof, error) {
	var proof ServingProof
	if err := decodeRequired(body, &proof, servingPaths...); err != nil {
		return ServingProof{}, err
	}
	if err := rejectNull(body, servingOptionalPaths...); err != nil {
		return ServingProof{}, err
	}
	return proof, nil
}

func encodeRequest(request DrainRequest) ([]byte, error) { return json.Marshal(request) }
