//go:build linux

// memberstatus is a process-level guest probe for the managed TerraBase socket.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
)

type fixture struct {
	ServerBinary         string               `json:"server_binary"`
	TenantUID            uint32               `json:"tenant_uid"`
	TenantGID            uint32               `json:"tenant_gid"`
	AuthorityCertificate string               `json:"authority_certificate"`
	TrustedPublicKey     string               `json:"trusted_public_key"`
	ServerCertificate    string               `json:"server_certificate"`
	ServerPrivateKey     string               `json:"server_private_key"`
	ClientCARoots        string               `json:"client_ca_roots"`
	OutboundPeerMemberID string               `json:"outbound_peer_member_id"`
	MemoryLimitBytes     uint64               `json:"memory_limit_bytes"`
	MemoryHeadroomBytes  uint64               `json:"memory_headroom_bytes"`
	Scope                host.MemberScope     `json:"scope"`
	Authority            host.MemberAuthority `json:"authority"`
}

const roleMemoryMaxBytes = 5 << 30

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "memberstatus probe:", err)
		os.Exit(1)
	}
	fmt.Println("MEMBER_STATUS_GO_OK")
}

func run() (resultErr error) {
	if len(os.Args) != 2 {
		return errors.New("usage: memberstatus <signed-fixture-manifest.json>")
	}
	if os.Geteuid() != 0 {
		return errors.New("managed process probe requires root supervisor")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	if len(data) > 16<<10 {
		return errors.New("fixture manifest is too large")
	}
	var config fixture
	if err := json.Unmarshal(data, &config, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode signed fixture manifest: %w", err)
	}
	if config.TenantUID == 0 || config.TenantGID == 0 || config.OutboundPeerMemberID == "" ||
		config.OutboundPeerMemberID == config.Scope.MemberID || config.MemoryLimitBytes < 4<<30 ||
		config.MemoryHeadroomBytes < 1<<30 {
		return errors.New("invalid managed fixture identity or memory profile")
	}
	reportPhase("manifest_validated")
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("/run", "ts-member-status-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, removeOwnedTree(root)) }()
	identity := host.WorkloadIdentity{UID: config.TenantUID, GID: config.TenantGID}
	if err := os.Chown(root, 0, int(identity.GID)); err != nil {
		return err
	}
	if err := os.Chmod(root, 0710); err != nil {
		return err
	}
	install := filepath.Join(root, "install")
	if err := mkdirOwned(install, 0, identity.GID, 0710); err != nil {
		return err
	}
	executable := filepath.Join(install, "tb-server")
	reportPhase("server_copy_begin")
	if err := copyOwned(config.ServerBinary, executable, 0, identity.GID, 0550); err != nil {
		return fmt.Errorf("stage TerraBase binary: %w", err)
	}
	pki := filepath.Join(root, "pki")
	if err := mkdirOwned(pki, 0, identity.GID, 0710); err != nil {
		return err
	}
	inputs := []struct{ source, name string }{
		{config.AuthorityCertificate, "authority.tbca"},
		{config.TrustedPublicKey, "authority.pub"},
		{config.ServerCertificate, "receiver.pem"},
		{config.ServerPrivateKey, "receiver-key.pem"},
		{config.ClientCARoots, "member-ca.pem"},
	}
	for _, input := range inputs {
		if err := copyOwned(input.source, filepath.Join(pki, input.name), identity.UID, identity.GID, 0600); err != nil {
			return fmt.Errorf("stage %s: %w", input.name, err)
		}
	}
	control := filepath.Join(root, "control")
	if err := mkdirOwned(control, 0, identity.GID, 0730); err != nil {
		return err
	}
	socket := filepath.Join(control, "member.sock")
	dataRoot := filepath.Join(root, "data")
	if err := mkdirOwned(dataRoot, identity.UID, identity.GID, 0700); err != nil {
		return err
	}
	reportPhase("inputs_staged")
	stateRoot := filepath.Join(root, "state")
	runner := host.NewProcessRunner(stateRoot, identity)
	reportPhase("runner_recover_begin")
	if err := runner.Recover(ctx); err != nil {
		return fmt.Errorf("recover native process runner: %w", err)
	}
	reportPhase("runner_recover_ok")
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		resultErr = errors.Join(resultErr, runner.Close(closeCtx))
	}()
	adminPort, err := availablePort()
	if err != nil {
		return err
	}
	replicationPort, err := availablePort()
	if err != nil {
		return err
	}
	args := memberArgs(config, dataRoot, socket, adminPort, replicationPort, pki)
	digest, err := fileDigest(executable)
	if err != nil {
		return err
	}
	reportPhase("runner_apply_begin")
	if err := runner.Apply(ctx, host.Workload{
		Role: "terrabase", Digest: digest, Fingerprint: digest, Executable: executable, Args: args,
		CgroupMemoryMaxBytes: roleMemoryMaxBytes,
	}); err != nil {
		return fmt.Errorf("launch TerraBase through native runner: %w", err)
	}
	reportPhase("runner_apply_ok")
	expected := host.ExpectedMemberStatus{
		SocketPath: socket, Role: "terrabase", Scope: config.Scope, Authority: config.Authority,
	}
	var status host.MemberStatus
	var lastErr error
	readyDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(readyDeadline) {
		status, lastErr = host.ReadMemberStatus(ctx, runner, expected)
		if lastErr == nil && status.Local.Ready && status.Local.ReplicationListenerReady {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	if lastErr != nil || !status.Local.Ready || !status.Local.StorageRecovered || !status.Local.Healthy ||
		!status.ReceiverOnly || status.Serving || status.Capabilities.ServingProof || status.Capabilities.DurableDrain {
		return fmt.Errorf("managed receiver status did not become ready: status=%+v error=%v", status, lastErr)
	}
	reportPhase("status_ready")
	if err := verifyManagedProcessBoundary(ctx, runner, identity); err != nil {
		return err
	}
	fmt.Println("memberstatus: authenticated Go client accepted real receiver-only process")

	wrong := expected
	wrong.Authority.CertificateSHA256 = strings.Repeat("0", 64)
	if _, err := host.ReadMemberStatus(ctx, runner, wrong); err == nil {
		return errors.New("Go client accepted wrong signed authority hash")
	}
	wrong = expected
	wrong.Scope.Incarnation = strings.Repeat("0", 32)
	if _, err := host.ReadMemberStatus(ctx, runner, wrong); err == nil {
		return errors.New("Go client accepted wrong member incarnation")
	}

	nonce := "0123456789abcdef0123456789abcdef"
	for _, probe := range []struct {
		rootWithoutDAC bool
		want           string
	}{
		{true, "200"},
		{false, "403"},
	} {
		var command *exec.Cmd
		url := "http://unix/v1/member/status?nonce=" + nonce
		if probe.rootWithoutDAC {
			command = exec.CommandContext(ctx, "setpriv", "--bounding-set=-dac_override,-dac_read_search", "--",
				"curl", "--silent", "--show-error", "--max-time", "2", "--unix-socket", socket,
				"--output", "/dev/null", "--write-out", "%{http_code}", url)
		} else {
			command = exec.CommandContext(ctx, "setpriv", "--reuid="+strconv.FormatUint(uint64(identity.UID), 10),
				"--regid="+strconv.FormatUint(uint64(identity.GID), 10), "--clear-groups", "--",
				"curl", "--silent", "--show-error", "--max-time", "2", "--unix-socket", socket,
				"--output", "/dev/null", "--write-out", "%{http_code}", url)
		}
		output, err := command.CombinedOutput()
		if err != nil || string(output) != probe.want {
			return fmt.Errorf("Unix peer policy probe: want=%s output=%q error=%v", probe.want, output, err)
		}
	}
	fmt.Println("memberstatus: root without DAC accepted and tenant peer rejected")

	for _, check := range []struct{ request, status string }{
		{"GET /v1/member/status?nonce=invalid HTTP/1.1\r\nHost: unix\r\n\r\n", "400"},
		{"GET /v1/member/status?nonce=" + nonce + " HTTP/1.1\r\nHost: unix\r\nContent-Length: 1\r\n\r\nx", "400"},
		{"GET /v1/member/drain HTTP/1.1\r\nHost: unix\r\n\r\n", "501"},
		{"GET /v1/member/serving-proof HTTP/1.1\r\nHost: unix\r\n\r\n", "501"},
	} {
		response, err := rawMemberRequest(socket, check.request)
		if err != nil || !strings.HasPrefix(response, "HTTP/1.1 "+check.status) {
			return fmt.Errorf("member request validation: want=%s response=%q error=%v", check.status, response, err)
		}
	}
	fmt.Println("memberstatus: malformed requests and reserved operations rejected")

	before, err := os.Lstat(socket)
	if err != nil {
		return err
	}
	duplicateData := filepath.Join(root, "duplicate-data")
	if err := mkdirOwned(duplicateData, identity.UID, identity.GID, 0700); err != nil {
		return err
	}
	duplicateAdmin, err := availablePort()
	if err != nil {
		return err
	}
	duplicateReplication, err := availablePort()
	if err != nil {
		return err
	}
	duplicate := exec.CommandContext(ctx, executable, memberArgs(config, duplicateData, socket, duplicateAdmin, duplicateReplication, pki)...)
	duplicate.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: identity.UID, Gid: identity.GID}}
	duplicateOutput, duplicateErr := duplicate.CombinedOutput()
	if !isRequestedMemberSocketBindFailure(duplicateOutput, duplicateErr, socket) {
		return fmt.Errorf("duplicate socket bind was not rejected: output=%q error=%v", duplicateOutput, duplicateErr)
	}
	after, err := os.Lstat(socket)
	if err != nil || !os.SameFile(before, after) {
		return fmt.Errorf("duplicate bind changed live socket: %w", err)
	}
	if _, err := host.ReadMemberStatus(ctx, runner, expected); err != nil {
		return fmt.Errorf("existing member socket stopped responding after duplicate bind: %w", err)
	}
	fmt.Println("memberstatus: existing socket retained after duplicate bind")

	if err := runner.Stop(ctx, "terrabase"); err != nil {
		return fmt.Errorf("stop receiver-only member: %w", err)
	}
	senderControl := filepath.Join(root, "sender-control")
	if err := mkdirOwned(senderControl, 0, identity.GID, 0730); err != nil {
		return err
	}
	senderSocket := filepath.Join(senderControl, "member.sock")
	peerListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer peerListener.Close()
	senderAdminPort, err := availablePort()
	if err != nil {
		return err
	}
	senderReplicationPort, err := availablePort()
	if err != nil {
		return err
	}
	senderArgs := append(memberArgs(config, dataRoot, senderSocket, senderAdminPort, senderReplicationPort, pki),
		"--replication-peer-member-id", config.OutboundPeerMemberID,
		"--replication-peer-addr", peerListener.Addr().String(),
		"--replication-server-ca-roots", filepath.Join(pki, "member-ca.pem"))
	reportPhase("sender_role_apply_begin")
	if err := runner.Apply(ctx, host.Workload{
		Role: "terrabase", Digest: digest, Fingerprint: digest, Executable: executable, Args: senderArgs,
		CgroupMemoryMaxBytes: roleMemoryMaxBytes,
	}); err != nil {
		return fmt.Errorf("launch sender-enabled TerraBase through native runner: %w", err)
	}
	senderExpected := expected
	senderExpected.SocketPath = senderSocket
	var senderStatus host.MemberStatus
	var senderErr error
	senderDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(senderDeadline) {
		senderStatus, senderErr = host.ReadMemberStatus(ctx, runner, senderExpected)
		if senderErr == nil && senderStatus.Local.Ready && senderStatus.Local.ReplicationListenerReady {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	if senderErr != nil || !senderStatus.Local.Ready || !senderStatus.Local.StorageRecovered ||
		!senderStatus.Local.Healthy || senderStatus.ReceiverOnly || senderStatus.Serving ||
		senderStatus.Capabilities.ServingProof || senderStatus.Capabilities.DurableDrain {
		return fmt.Errorf("managed sender status did not become ready: status=%+v error=%v", senderStatus, senderErr)
	}
	fmt.Println("memberstatus: authenticated Go client accepted real sender-enabled process")
	return nil
}

func isRequestedMemberSocketBindFailure(output []byte, err error, socket string) bool {
	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if !ok || exitErr.ExitCode() != 1 {
		return false
	}
	prefix := "terrabase-server: member-control socket bind " + socket + ": "
	for line := range strings.SplitSeq(string(output), "\n") {
		if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "(os error 98)") {
			continue
		}
		// The OS error wording differs between the pinned guest and host toolchains.
		message := strings.TrimSuffix(strings.TrimPrefix(line, prefix), "(os error 98)")
		if strings.TrimSpace(message) != "" {
			return true
		}
	}
	return false
}

func reportPhase(phase string) {
	fmt.Fprintf(os.Stderr, "MEMBER_PROBE_PHASE=%s pid=%d\n", phase, os.Getpid())
}

func verifyManagedProcessBoundary(ctx context.Context, runner host.Runner, identity host.WorkloadIdentity) error {
	observation, err := runner.Observe(ctx, "terrabase")
	if err != nil || !observation.Running || observation.PID < 2 {
		return fmt.Errorf("observe live managed process: observation=%+v error=%v", observation, err)
	}
	pid := observation.PID
	membership, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return err
	}
	cgroup, ok := strings.CutPrefix(strings.TrimSpace(string(membership)), "0::")
	if !ok || !filepath.IsAbs(cgroup) || filepath.Clean(cgroup) != cgroup || filepath.Base(cgroup) != "terrabase" {
		return fmt.Errorf("invalid managed process cgroup membership: %q", membership)
	}
	rolePath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(cgroup, "/"))
	maxBytes, err := os.ReadFile(filepath.Join(rolePath, "memory.max"))
	if err != nil || strings.TrimSpace(string(maxBytes)) != strconv.FormatUint(roleMemoryMaxBytes, 10) {
		return fmt.Errorf("role memory.max: got=%q error=%v", maxBytes, err)
	}
	parentControl, err := os.ReadFile(filepath.Join(filepath.Dir(rolePath), "cgroup.subtree_control"))
	if err != nil || !slices.Contains(strings.Fields(string(parentControl)), "memory") {
		return fmt.Errorf("role parent memory controller: got=%q error=%v", parentControl, err)
	}
	roleProcesses, err := os.ReadFile(filepath.Join(rolePath, "cgroup.procs"))
	if err != nil || !slices.Contains(strings.Fields(string(roleProcesses)), strconv.Itoa(pid)) {
		return fmt.Errorf("role cgroup process inventory: got=%q error=%v", roleProcesses, err)
	}
	roleMemoryCurrent, err := os.ReadFile(filepath.Join(rolePath, "memory.current"))
	if err != nil {
		return fmt.Errorf("role memory.current: %w", err)
	}
	supervisor, err := processStatusEvidence(os.Getpid())
	if err != nil {
		return err
	}
	workload, err := processStatusEvidence(pid)
	if err != nil {
		return err
	}
	rootIdentity := "0\t0\t0\t0"
	wantTenantUID := strings.Repeat(strconv.FormatUint(uint64(identity.UID), 10)+"\t", 4)
	wantTenantGID := strings.Repeat(strconv.FormatUint(uint64(identity.GID), 10)+"\t", 4)
	if supervisor["Uid"] != rootIdentity || supervisor["Gid"] != rootIdentity ||
		supervisor["CapEff"] != "00000000000001e1" ||
		supervisor["CapBnd"] != "00000000000001e1" {
		return fmt.Errorf("unexpected root supervisor status: uid=%q gid=%q cap_eff=%q cap_bnd=%q",
			supervisor["Uid"], supervisor["Gid"], supervisor["CapEff"], supervisor["CapBnd"])
	}
	if workload["Uid"] != strings.TrimSuffix(wantTenantUID, "\t") ||
		workload["Gid"] != strings.TrimSuffix(wantTenantGID, "\t") ||
		workload["CapEff"] != "0000000000000000" || workload["CapBnd"] != "0000000000000000" {
		return fmt.Errorf("unexpected tenant process status: uid=%q gid=%q cap_eff=%q cap_bnd=%q",
			workload["Uid"], workload["Gid"], workload["CapEff"], workload["CapBnd"])
	}
	fmt.Printf("memberstatus: live supervisor pid=%d uid=%q gid=%q cap_eff=%s cap_bnd=%s\n",
		os.Getpid(), supervisor["Uid"], supervisor["Gid"], supervisor["CapEff"], supervisor["CapBnd"])
	fmt.Printf("memberstatus: live workload pid=%d uid=%q gid=%q cap_eff=%s cap_bnd=%s\n",
		pid, workload["Uid"], workload["Gid"], workload["CapEff"], workload["CapBnd"])
	fmt.Printf("memberstatus: live cgroup=%s role_memory.max=%s parent_subtree_control=%q role_cgroup.procs=%q role_memory.current=%s\n",
		cgroup, strings.TrimSpace(string(maxBytes)), strings.TrimSpace(string(parentControl)),
		strings.TrimSpace(string(roleProcesses)), strings.TrimSpace(string(roleMemoryCurrent)))
	return nil
}

func processStatusEvidence(pid int) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return nil, err
	}
	wanted := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && slices.Contains([]string{"Uid", "Gid", "CapEff", "CapBnd"}, key) {
			wanted[key] = strings.Join(strings.Fields(value), "\t")
		}
	}
	if len(wanted) != 4 {
		return nil, fmt.Errorf("incomplete process status for pid %d: %v", pid, wanted)
	}
	return wanted, nil
}

func memberArgs(config fixture, dataRoot, socket string, adminPort, replicationPort int, pki string) []string {
	return []string{
		"--data-dir", filepath.Join(dataRoot, "local"),
		"--memory-limit-bytes", strconv.FormatUint(config.MemoryLimitBytes, 10),
		"--memory-headroom-bytes", strconv.FormatUint(config.MemoryHeadroomBytes, 10),
		"--port", strconv.Itoa(adminPort),
		"--replication-listen-addr", "127.0.0.1:" + strconv.Itoa(replicationPort),
		"--replication-data-dir", filepath.Join(dataRoot, "replication"),
		"--authority-certificate", filepath.Join(pki, "authority.tbca"),
		"--trusted-public-key", filepath.Join(pki, "authority.pub"),
		"--replication-server-certificate", filepath.Join(pki, "receiver.pem"),
		"--replication-server-private-key", filepath.Join(pki, "receiver-key.pem"),
		"--replication-client-ca-roots", filepath.Join(pki, "member-ca.pem"),
		"--cluster-id", config.Scope.ClusterID,
		"--tenant-id", config.Scope.TenantID,
		"--database-id", config.Scope.DatabaseID,
		"--shard-id", strconv.FormatUint(config.Scope.ShardID, 10),
		"--member-id", config.Scope.MemberID,
		"--member-incarnation", config.Scope.Incarnation,
		"--member-control-socket", socket,
	}
}

func mkdirOwned(path string, uid, gid uint32, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return os.Chown(path, int(uid), int(gid))
}

func copyOwned(source, destination string, uid, gid uint32, mode os.FileMode) (resultErr error) {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, out.Close()) }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Chmod(mode); err != nil {
		return err
	}
	return out.Chown(int(uid), int(gid))
}

func removeOwnedTree(root string) error {
	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return err
		}
		if err := os.Chown(path, 0, 0); err != nil {
			return err
		}
		return os.Chmod(path, 0700)
	})
	return errors.Join(walkErr, os.RemoveAll(root))
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func availablePort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return port, listener.Close()
}

func rawMemberRequest(path, request string) (string, error) {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("unix", path)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, request); err != nil {
		return "", err
	}
	response, err := io.ReadAll(io.LimitReader(conn, 8192))
	return string(response), err
}
