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
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxEvidenceBytes = 8192

// ProcessObservation is supplied by the executor, which must check
// the process start time and role cgroup. The client checks that this
// observation remains unchanged across every Unix HTTP request.
type ProcessObservation struct {
	PID         int
	UID         uint32
	GID         uint32
	KernelStart string
	Cgroup      string
	namespace   processNamespace
}

type processNamespace struct {
	wirePID, initPID       int
	pidNS, mountNS, userNS uint64
	initStart              string
}

// ProtocolPID preserves the PID reported by TerraBase inside its namespace.
// The observation's public PID always remains the host SO_PEERCRED identity.
func (p ProcessObservation) ProtocolPID() int {
	if p.namespace.wirePID != 0 {
		return p.namespace.wirePID
	}
	return p.PID
}

// BindPIDNamespace derives the protocol PID from kernel observations rather
// than accepting a namespace PID asserted by a task or a caller.
func BindPIDNamespace(observation ProcessObservation, containerInitHostPID int) (ProcessObservation, error) {
	if observation.PID < 2 || containerInitHostPID < 2 {
		return ProcessObservation{}, ErrStaleBinding
	}
	current, ids, namespaces, err := readProcessNamespace(observation.PID)
	if err != nil || current.PID != observation.PID || current.UID != observation.UID || current.GID != observation.GID ||
		current.KernelStart != observation.KernelStart || current.Cgroup != observation.Cgroup || len(ids) < 2 {
		return ProcessObservation{}, ErrStaleBinding
	}
	init, initIDs, initNamespaces, err := readProcessNamespace(containerInitHostPID)
	if err != nil || len(initIDs) != len(ids) || initIDs[len(initIDs)-1] != 1 || namespaces != initNamespaces {
		return ProcessObservation{}, ErrStaleBinding
	}
	self, err := namespaceInodes(os.Getpid())
	if err != nil || namespaces[0] == self[0] || namespaces[1] == self[1] || namespaces[2] != self[2] {
		return ProcessObservation{}, ErrStaleBinding
	}
	observation.namespace = processNamespace{wirePID: ids[len(ids)-1], initPID: containerInitHostPID,
		pidNS: namespaces[0], mountNS: namespaces[1], userNS: namespaces[2], initStart: init.KernelStart}
	return observation, nil
}

func namespaceInodes(pid int) ([3]uint64, error) {
	var result [3]uint64
	for i, name := range []string{"pid", "mnt", "user"} {
		var stat unix.Stat_t
		if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, name), &stat); err != nil {
			return result, err
		}
		result[i] = stat.Ino
	}
	return result, nil
}

// ObserveContainerProcess reads a host process and binds its namespace PID to
// the independently selected container init process.
func ObserveContainerProcess(hostPID, containerInitHostPID int) (ProcessObservation, error) {
	observation, _, _, err := readProcessNamespace(hostPID)
	if err != nil {
		return ProcessObservation{}, err
	}
	bound, err := BindPIDNamespace(observation, containerInitHostPID)
	if err != nil {
		return ProcessObservation{}, err
	}
	after, err := BindPIDNamespace(observation, containerInitHostPID)
	if err != nil || bound != after {
		return ProcessObservation{}, ErrStaleBinding
	}
	return bound, nil
}

func readProcessNamespace(pid int) (ProcessObservation, []int, [3]uint64, error) {
	result := ProcessObservation{PID: pid}
	var namespaces [3]uint64
	if pid < 2 {
		return result, nil, namespaces, ErrStaleBinding
	}
	root := fmt.Sprintf("/proc/%d/", pid)
	stat, err := os.ReadFile(root + "stat")
	if err != nil {
		return result, nil, namespaces, err
	}
	_, suffix, ok := strings.CutLast(string(stat), ") ")
	fields := strings.Fields(suffix)
	if !ok || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return result, nil, namespaces, ErrStaleBinding
	}
	result.KernelStart = fields[19]
	status, err := os.ReadFile(root + "status")
	if err != nil {
		return result, nil, namespaces, err
	}
	var ids []int
	uidFound, gidFound := false, false
	for line := range strings.SplitSeq(string(status), "\n") {
		name, values, ok := strings.Cut(line, ":")
		if !ok || (name != "Uid" && name != "Gid" && name != "NSpid") {
			continue
		}
		values = strings.TrimSpace(values)
		for i, value := range strings.Fields(values) {
			number, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return result, nil, namespaces, ErrStaleBinding
			}
			if name == "NSpid" {
				if number == 0 {
					return result, nil, namespaces, ErrStaleBinding
				}
				ids = append(ids, int(number))
			} else if name == "Uid" {
				if i > 0 && result.UID != uint32(number) {
					return result, nil, namespaces, ErrStaleBinding
				}
				result.UID, uidFound = uint32(number), true
			} else {
				if i > 0 && result.GID != uint32(number) {
					return result, nil, namespaces, ErrStaleBinding
				}
				result.GID, gidFound = uint32(number), true
			}
		}
	}
	if !uidFound || !gidFound || len(ids) == 0 || ids[0] != pid {
		return result, nil, namespaces, ErrStaleBinding
	}
	cgroup, err := os.ReadFile(root + "cgroup")
	if err != nil || len(cgroup) == 0 {
		return result, nil, namespaces, ErrStaleBinding
	}
	result.Cgroup = string(cgroup)
	namespaces, err = namespaceInodes(pid)
	return result, ids, namespaces, err
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
	if status.SchemaVersion != 2 || status.Nonce != challenge || status.Process.PID != process.ProtocolPID() ||
		!status.Process.valid() || status.Scope != c.scope || status.Authority != c.authority ||
		!status.Capabilities.ServingProof || !status.Capabilities.DurableDrain {
		return Status{}, ErrStaleBinding
	}
	if status.Serving && (status.ReceiverOnly || !status.Local.StorageRecovered ||
		!status.Local.ReplicationListenerReady || !status.Local.Healthy || !status.Local.Ready) {
		return Status{}, ErrNotServing
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
		status.ReceiverOnly || !status.Serving || !status.Local.StorageRecovered ||
		!status.Local.ReplicationListenerReady || !status.Local.Healthy || !status.Local.Ready {
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
		proof.Process.PID != process.ProtocolPID() || proof.Scope != c.scope || proof.Authority != c.authority ||
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
	if before.namespace.wirePID != 0 {
		bound, err := BindPIDNamespace(before, before.namespace.initPID)
		if err != nil || bound != before {
			return 0, nil, ProcessObservation{}, ErrStaleBinding
		}
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
