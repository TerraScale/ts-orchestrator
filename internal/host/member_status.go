//go:build linux

package host

import (
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

// MemberScope and MemberAuthority are expected from a verified, signed member
// assignment. They must never be learned from the status response itself.
type MemberScope struct {
	ClusterID   string `json:"cluster_id"`
	TenantID    string `json:"tenant_id"`
	DatabaseID  string `json:"database_id"`
	ShardID     uint64 `json:"shard_id"`
	MemberID    string `json:"member_id"`
	Incarnation string `json:"incarnation"`
}

type MemberAuthority struct {
	Epoch             uint64 `json:"epoch"`
	ConfigurationID   string `json:"configuration_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	TLSLeafSHA256     string `json:"tls_leaf_sha256"`
}

type MemberProcess struct {
	PID        int    `json:"pid"`
	StartNonce string `json:"start_nonce"`
}

type MemberLocal struct {
	StorageRecovered         bool `json:"storage_recovered"`
	ReplicationListenerReady bool `json:"replication_listener_ready"`
	Healthy                  bool `json:"healthy"`
	Ready                    bool `json:"ready"`
}

type MemberCapabilities struct {
	ServingProof bool `json:"serving_proof"`
	DurableDrain bool `json:"durable_drain"`
}

// MemberStatus is a bounded v1 member role observation, not serving or drain proof.
type MemberStatus struct {
	SchemaVersion uint64             `json:"schema_version"`
	Nonce         string             `json:"nonce"`
	Process       MemberProcess      `json:"process"`
	Scope         MemberScope        `json:"scope"`
	Authority     MemberAuthority    `json:"authority"`
	Local         MemberLocal        `json:"local"`
	ReceiverOnly  bool               `json:"receiver_only"`
	Serving       bool               `json:"serving"`
	Capabilities  MemberCapabilities `json:"capabilities"`
	ObservedAt    time.Time          `json:"-"`
}

type ExpectedMemberStatus struct {
	SocketPath string
	Role       string
	Scope      MemberScope
	Authority  MemberAuthority
}

type memberStatusWire struct {
	SchemaVersion *uint64 `json:"schema_version"`
	Nonce         *string `json:"nonce"`
	Process       *struct {
		PID        *int    `json:"pid"`
		StartNonce *string `json:"start_nonce"`
	} `json:"process"`
	Scope *struct {
		ClusterID   *string `json:"cluster_id"`
		TenantID    *string `json:"tenant_id"`
		DatabaseID  *string `json:"database_id"`
		ShardID     *uint64 `json:"shard_id"`
		MemberID    *string `json:"member_id"`
		Incarnation *string `json:"incarnation"`
	} `json:"scope"`
	Authority *struct {
		Epoch             *uint64 `json:"epoch"`
		ConfigurationID   *string `json:"configuration_id"`
		CertificateSHA256 *string `json:"certificate_sha256"`
		TLSLeafSHA256     *string `json:"tls_leaf_sha256"`
	} `json:"authority"`
	Local *struct {
		StorageRecovered         *bool `json:"storage_recovered"`
		ReplicationListenerReady *bool `json:"replication_listener_ready"`
		Healthy                  *bool `json:"healthy"`
		Ready                    *bool `json:"ready"`
	} `json:"local"`
	ReceiverOnly *bool `json:"receiver_only"`
	Serving      *bool `json:"serving"`
	Capabilities *struct {
		ServingProof *bool `json:"serving_proof"`
		DurableDrain *bool `json:"durable_drain"`
	} `json:"capabilities"`
}

// ReadMemberStatus authenticates one local TerraBase process and its exact
// signed identity. Only the native process runner can supply process binding.
// The complete operation, including pre/post checks, has a two-second budget.
func ReadMemberStatus(ctx context.Context, runner Runner, expected ExpectedMemberStatus) (MemberStatus, error) {
	p, ok := runner.(*processRunner)
	if !ok || p == nil {
		return MemberStatus{}, errors.New("member status requires a native process runner")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := validateMemberExpectation(expected, p); err != nil {
		return MemberStatus{}, err
	}
	beforePath, err := inspectMemberSocket(expected.SocketPath, p.identity)
	if err != nil {
		return MemberStatus{}, err
	}
	pid, start, cgroup, err := observeMemberProcess(ctx, p, expected.Role)
	if err != nil {
		return MemberStatus{}, err
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return MemberStatus{}, fmt.Errorf("member nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	var peerPID atomic.Int64
	transport := newMemberStatusTransport(func(dialCtx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", expected.SocketPath)
		if err != nil {
			return nil, err
		}
		credentials, err := memberPeerCredentials(conn)
		if err == nil && (credentials.Pid != int32(pid) || credentials.Uid != p.identity.UID || credentials.Gid != p.identity.GID) {
			err = errors.New("member socket peer does not match native workload")
		}
		if err == nil {
			err = verifyMemberSocket(expected.SocketPath, p.identity, beforePath)
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		peerPID.Store(int64(credentials.Pid))
		return conn, nil
	})
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/member/status?nonce="+nonce, nil)
	if err != nil {
		return MemberStatus{}, err
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Do(request)
	if err != nil {
		return MemberStatus{}, fmt.Errorf("read member status: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" ||
		response.ContentLength < 0 || response.ContentLength > 4096 || len(response.TransferEncoding) != 0 {
		return MemberStatus{}, errors.New("invalid member status HTTP response")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return MemberStatus{}, fmt.Errorf("read member status body: %w", err)
	}
	if len(data) != int(response.ContentLength) || len(data) > 4096 {
		return MemberStatus{}, errors.New("invalid member status body length")
	}
	status, err := decodeMemberStatus(data, nonce, pid, expected)
	if err != nil {
		return MemberStatus{}, err
	}
	if peerPID.Load() != int64(pid) {
		return MemberStatus{}, errors.New("member socket peer was not observed")
	}
	if err := verifyMemberSocket(expected.SocketPath, p.identity, beforePath); err != nil {
		return MemberStatus{}, err
	}
	afterPID, afterStart, afterCgroup, err := observeMemberProcess(ctx, p, expected.Role)
	if err != nil {
		return MemberStatus{}, err
	}
	if afterPID != pid || afterStart != start || afterCgroup != cgroup {
		return MemberStatus{}, errors.New("member process changed during status read")
	}
	if err := ctx.Err(); err != nil {
		return MemberStatus{}, err
	}
	status.ObservedAt = time.Now().UTC()
	return status, nil
}

func newMemberStatusTransport(dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 4096,
		DialContext:            dial,
	}
}

func validateMemberExpectation(expected ExpectedMemberStatus, p *processRunner) error {
	if err := validateToken(expected.Role, "member role"); err != nil {
		return err
	}
	if expected.SocketPath == "" || !filepath.IsAbs(expected.SocketPath) || filepath.Clean(expected.SocketPath) != expected.SocketPath {
		return errors.New("member socket path must be absolute and clean")
	}
	if os.Geteuid() != 0 || p.identity.UID == 0 || p.identity.GID == 0 {
		return errors.New("member status requires a root supervisor and non-root tenant")
	}
	if !lowerHex(expected.Scope.ClusterID, 32) || !lowerHex(expected.Scope.Incarnation, 32) ||
		!canonicalMemberID(expected.Scope.TenantID) || !canonicalMemberID(expected.Scope.DatabaseID) || !canonicalMemberID(expected.Scope.MemberID) ||
		!lowerHex(expected.Authority.ConfigurationID, 64) || !lowerHex(expected.Authority.CertificateSHA256, 64) ||
		!lowerHex(expected.Authority.TLSLeafSHA256, 64) || expected.Authority.Epoch == 0 {
		return errors.New("invalid expected signed member identity")
	}
	p.mu.Lock()
	recovered := p.lock != nil
	p.mu.Unlock()
	if !recovered {
		return errors.New("native runner is not recovered")
	}
	root, err := nativeCgroupRoot(p.root)
	if err != nil {
		return err
	}
	if p.cgroups != root {
		return errors.New("native runner cgroup root changed")
	}
	return nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			if value[i] < 'a' || value[i] > 'f' {
				return false
			}
		}
	}
	return true
}

func canonicalMemberID(value string) bool {
	if len(value) != 26 || value[0] > '7' || value[0] < '0' {
		return false
	}
	for i := range len(value) {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", rune(value[i])) {
			return false
		}
	}
	return true
}

type memberPathSnapshot struct {
	parent syscall.Stat_t
	socket syscall.Stat_t
}

func inspectMemberSocket(path string, identity WorkloadIdentity) (memberPathSnapshot, error) {
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return memberPathSnapshot{}, err
	}
	socketInfo, err := os.Lstat(path)
	if err != nil {
		return memberPathSnapshot{}, err
	}
	parent, parentOK := parentInfo.Sys().(*syscall.Stat_t)
	socket, socketOK := socketInfo.Sys().(*syscall.Stat_t)
	if !parentOK || !socketOK || !parentInfo.IsDir() || socketInfo.Mode()&os.ModeSocket == 0 ||
		parent.Uid != 0 || parent.Gid != identity.GID || parent.Mode&07777 != 0730 ||
		socket.Uid != identity.UID || socket.Gid != identity.GID || socket.Mode&07777 != 0602 {
		return memberPathSnapshot{}, errors.New("unsafe member socket ownership or mode")
	}
	return memberPathSnapshot{parent: *parent, socket: *socket}, nil
}

func verifyMemberSocket(path string, identity WorkloadIdentity, before memberPathSnapshot) error {
	after, err := inspectMemberSocket(path, identity)
	if err != nil {
		return err
	}
	if !sameMemberInode(before.parent, after.parent) || !sameMemberInode(before.socket, after.socket) {
		return errors.New("member socket path changed during status read")
	}
	return nil
}

func sameMemberInode(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}

func memberPeerCredentials(conn net.Conn) (*unix.Ucred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("member connection is not a Unix socket")
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

func observeMemberProcess(ctx context.Context, p *processRunner, role string) (int, string, string, error) {
	if err := ctx.Err(); err != nil {
		return 0, "", "", err
	}
	observation, err := p.Observe(ctx, role)
	if err != nil {
		return 0, "", "", err
	}
	if !observation.Running || observation.PID < 2 || observation.Role != role {
		return 0, "", "", errors.New("native member is not running")
	}
	start := currentStartTime(observation.PID)
	p.mu.Lock()
	record, exists := p.records[role]
	p.mu.Unlock()
	if start == "" || !exists || record.PID != observation.PID || record.StartTime != start ||
		!nativeProcessAliveWithStart(observation.PID, start) {
		return 0, "", "", errors.New("cannot verify member process start")
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(observation.PID), "cgroup"))
	if err != nil {
		return 0, "", "", err
	}
	expectedCgroup := strings.TrimPrefix(filepath.Join(p.cgroups, role), "/sys/fs/cgroup")
	if strings.TrimSpace(string(data)) != "0::"+expectedCgroup {
		return 0, "", "", errors.New("member process is outside its native role cgroup")
	}
	return observation.PID, start, expectedCgroup, nil
}

func decodeMemberStatus(data []byte, nonce string, pid int, expected ExpectedMemberStatus) (MemberStatus, error) {
	var wire memberStatusWire
	if err := json.Unmarshal(data, &wire, json.RejectUnknownMembers(true)); err != nil {
		return MemberStatus{}, fmt.Errorf("invalid member status JSON: %w", err)
	}
	if wire.SchemaVersion == nil || wire.Nonce == nil || wire.Process == nil || wire.Scope == nil || wire.Authority == nil ||
		wire.Local == nil || wire.ReceiverOnly == nil || wire.Serving == nil || wire.Capabilities == nil ||
		wire.Process.PID == nil || wire.Process.StartNonce == nil ||
		wire.Scope.ClusterID == nil || wire.Scope.TenantID == nil || wire.Scope.DatabaseID == nil || wire.Scope.ShardID == nil ||
		wire.Scope.MemberID == nil || wire.Scope.Incarnation == nil ||
		wire.Authority.Epoch == nil || wire.Authority.ConfigurationID == nil || wire.Authority.CertificateSHA256 == nil || wire.Authority.TLSLeafSHA256 == nil ||
		wire.Local.StorageRecovered == nil || wire.Local.ReplicationListenerReady == nil || wire.Local.Healthy == nil || wire.Local.Ready == nil ||
		wire.Capabilities.ServingProof == nil || wire.Capabilities.DurableDrain == nil {
		return MemberStatus{}, errors.New("member status omits required fields")
	}
	status := MemberStatus{
		SchemaVersion: *wire.SchemaVersion, Nonce: *wire.Nonce,
		Process: MemberProcess{PID: *wire.Process.PID, StartNonce: *wire.Process.StartNonce},
		Scope: MemberScope{ClusterID: *wire.Scope.ClusterID, TenantID: *wire.Scope.TenantID, DatabaseID: *wire.Scope.DatabaseID,
			ShardID: *wire.Scope.ShardID, MemberID: *wire.Scope.MemberID, Incarnation: *wire.Scope.Incarnation},
		Authority: MemberAuthority{Epoch: *wire.Authority.Epoch, ConfigurationID: *wire.Authority.ConfigurationID,
			CertificateSHA256: *wire.Authority.CertificateSHA256, TLSLeafSHA256: *wire.Authority.TLSLeafSHA256},
		Local: MemberLocal{StorageRecovered: *wire.Local.StorageRecovered, ReplicationListenerReady: *wire.Local.ReplicationListenerReady,
			Healthy: *wire.Local.Healthy, Ready: *wire.Local.Ready},
		ReceiverOnly: *wire.ReceiverOnly, Serving: *wire.Serving,
		Capabilities: MemberCapabilities{ServingProof: *wire.Capabilities.ServingProof, DurableDrain: *wire.Capabilities.DurableDrain},
	}
	if status.SchemaVersion != 1 || status.Nonce != nonce || status.Process.PID != pid || !lowerHex(status.Process.StartNonce, 32) ||
		status.Scope != expected.Scope || status.Authority != expected.Authority ||
		status.Serving || status.Capabilities.ServingProof || status.Capabilities.DurableDrain {
		return MemberStatus{}, errors.New("member status identity or capability mismatch")
	}
	return status, nil
}
