//go:build linux

package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// This test is built into a guest-only test binary. Its controller verifier is
// deliberately local to the test; a pass says nothing about OCI ownership.
type managedMemberFirecrackerConfig struct {
	Version           int                  `json:"version"`
	Node              string               `json:"node"`
	FailureDomain     string               `json:"failure_domain"`
	Member            ManagedMemberBinding `json:"member"`
	Authority         MemberAuthority      `json:"authority"`
	Runtime           ManagedRuntimePins   `json:"runtime"`
	VolumeID          string               `json:"volume_id"`
	AttachmentID      string               `json:"attachment_id"`
	AttachmentETag    string               `json:"attachment_etag"`
	SourceDigest      string               `json:"source_digest"`
	ArtifactPath      string               `json:"artifact_path"`
	ArtifactSHA256    string               `json:"artifact_sha256"`
	ControlAddress    string               `json:"control_address"`
	ControlHostIP     string               `json:"control_host_ip"`
	ControlToken      string               `json:"control_token"`
	ClientRootPath    string               `json:"client_root_path"`
	ClientRootSHA256  string               `json:"client_root_sha256"`
	ClientTokenPath   string               `json:"client_token_path"`
	ClientTokenSHA256 string               `json:"client_token_sha256"`
	CollectionID      string               `json:"collection_id"`
	SchemaGeneration  uint64               `json:"schema_generation"`
	SchemaDigest      string               `json:"schema_digest"`
	DocumentID        string               `json:"document_id"`
}

type managedMemberFirecrackerEvidence struct {
	Version          int                `json:"version"`
	Node             string             `json:"node"`
	MemberID         string             `json:"member_id"`
	ProcessPID       int                `json:"process_pid"`
	ProcessUID       uint32             `json:"process_uid"`
	ProcessGID       uint32             `json:"process_gid"`
	ProcessCgroup    string             `json:"process_cgroup"`
	MemoryMaxBytes   uint64             `json:"memory_max_bytes"`
	FileSystemUUID   string             `json:"filesystem_uuid"`
	MountID          uint64             `json:"mount_id"`
	ClaimSHA256      string             `json:"claim_sha256"`
	StorageRecovered bool               `json:"storage_recovered"`
	ListenerReady    bool               `json:"listener_ready"`
	Metrics          map[string]float64 `json:"metrics"`
}

func TestManagedMemberFirecrackerSignedServing(t *testing.T) {
	configPath := os.Getenv("TS_FC_MANAGED_MEMBER_CONFIG")
	if configPath == "" {
		t.Skip("requires the pinned two-VM Firecracker fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("managed-member Firecracker test requires root supervisor")
	}
	data, err := os.ReadFile(configPath)
	if err != nil || len(data) == 0 || len(data) > 16<<10 {
		t.Fatalf("read bounded guest config: %v", err)
	}
	var cfg managedMemberFirecrackerConfig
	if err := json.Unmarshal(data, &cfg, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 || cfg.Node == "" || cfg.ArtifactPath != "/opt/ts-managed-member/tb-server" ||
		!lowerHex(cfg.ArtifactSHA256, 64) || !lowerHex(cfg.SourceDigest, 64) ||
		len(cfg.ControlToken) != 64 || !lowerHex(cfg.ControlToken, 64) ||
		cfg.ControlHostIP == "" || net.ParseIP(cfg.ControlHostIP) == nil ||
		!lowerHex(cfg.ClientRootSHA256, 64) || !lowerHex(cfg.ClientTokenSHA256, 64) ||
		!canonicalMemberID(cfg.CollectionID) || !canonicalMemberID(cfg.DocumentID) ||
		cfg.SchemaGeneration == 0 || !lowerHex(cfg.SchemaDigest, 64) {
		t.Fatal("guest config identity, artifact or control token is invalid")
	}
	if cfg.ClientRootPath != "/opt/ts-managed-member/client-https-ca.pem" ||
		cfg.ClientTokenPath != "/opt/ts-managed-member/client-api-token" {
		t.Fatal("guest HTTPS client inputs have unexpected paths")
	}
	rootPEM, err := managedMemberReadFixture(cfg.ClientRootPath, cfg.ClientRootSHA256, 1<<20)
	if err != nil {
		t.Fatalf("read pinned HTTPS root: %v", err)
	}
	clientToken, err := managedMemberReadFixture(cfg.ClientTokenPath, cfg.ClientTokenSHA256, 4<<10)
	if err != nil {
		t.Fatalf("read pinned API token: %v", err)
	}
	if strings.TrimSpace(string(clientToken)) != string(clientToken) || len(clientToken) == 0 {
		t.Fatal("pinned API token has unexpected whitespace")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("pinned HTTPS root has no CA certificate")
	}
	httpsClient := &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	controlHost, _, err := net.SplitHostPort(cfg.ControlAddress)
	if err != nil || net.ParseIP(controlHost) == nil || net.ParseIP(controlHost).IsLoopback() ||
		controlHost == cfg.ControlHostIP {
		t.Fatal("test control listener must bind only the member's private guest IP")
	}
	artifact, err := os.ReadFile(cfg.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifact)
	digest := hex.EncodeToString(sum[:])
	if digest != cfg.ArtifactSHA256 {
		t.Fatal("staged TerraBase artifact differs from immutable manifest")
	}
	paths, err := runtimePaths("/srv/ts-managed", ManagedMemberLaunch{Member: cfg.Member})
	if err != nil || cfg.Runtime.MountPath != paths.mount ||
		cfg.Runtime.DevicePath != "/dev/oracleoci/oraclevdb" {
		t.Fatalf("guest runtime paths differ from signed binding: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(paths.mount, managedVolumeClaimName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("volume must start without a claim: %v", err)
	}
	if _, err := os.Lstat(managedShardPath(paths)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replication shard must start absent: %v", err)
	}

	public, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	placement := ManagedPlacementBinding{DatabaseID: "db-fixture", PartitionID: "partition-fixture", SeatID: "seat-" + cfg.Node,
		IntentGeneration: 1, IntentPayloadDigest: cfg.SourceDigest, CanonicalRosterDigest: cfg.SourceDigest,
		ManagedHostProfileDigest: cfg.SourceDigest}
	oci := ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1.." + cfg.Node,
		Owner: "terrascale", FleetGeneration: 1, CreateKey: cfg.Node}
	registration := Registration{Cell: "gru", Node: cfg.Node, Environment: "production",
		FailureDomain: cfg.FailureDomain, Roles: []string{"terrabase"},
		PublicKey: base64.StdEncoding.EncodeToString(public), Generation: 1,
		Capacity: Capacity{MemoryBytes: 7 << 30}, SystemReserveBytes: 1 << 30,
		ManagedPlacement: &placement, ManagedOCI: &oci, ManagedMember: &cfg.Member}
	launch := ManagedMemberLaunch{OCI: oci, Member: cfg.Member, Authority: cfg.Authority,
		SourceDigest: cfg.SourceDigest, VolumeID: cfg.VolumeID, AttachmentID: cfg.AttachmentID,
		AttachmentETag: cfg.AttachmentETag, ProcessMemoryBytes: 4 << 30,
		MemoryHeadroomBytes: 1 << 30, CgroupMemoryMaxBytes: 6 << 30, Runtime: &cfg.Runtime}
	desired := Desired{Cell: "gru", Node: cfg.Node, Environment: "production", Role: "terrabase",
		Digest: digest, Generation: 1, AuthorityEpoch: cfg.Authority.Epoch, ManagedMember: &launch}
	if err := validateDesired(desired, registration.Cell, registration); err != nil {
		t.Fatalf("fixture desired is invalid: %v", err)
	}
	verifier := managedRegistrationVerifierFunc(func(_ context.Context, got Registration) error {
		if !sameJSON(got, registration) {
			return errors.New("test-only registration differs from exact fixture")
		}
		return nil
	})
	controller, conn, store, _, controllerKey := testControllerWithVerifier(t, verifier)
	if _, err := controller.Register(t.Context(), registration); err != nil {
		t.Fatalf("register test-only managed host: %v", err)
	}
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, artifact); err != nil {
		t.Fatalf("publish pinned TerraBase artifact: %v", err)
	}
	clear(artifact)
	if _, err := controller.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatalf("commit signed managed desired: %v", err)
	}
	controllerCtx, stopController := context.WithCancel(t.Context())
	defer stopController()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(controllerCtx) }()
	select {
	case <-controller.Ready():
	case err := <-controllerDone:
		t.Fatalf("controller stopped before ready: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("signed controller was not ready")
	}

	stateRoot, err := os.MkdirTemp("/run", "ts-managed-member-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(stateRoot, 0, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateRoot, 0710); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateRoot) })
	agent, err := NewAgent(AgentConfig{Cell: "gru", Node: cfg.Node, Environment: "production", Roles: []string{"terrabase"},
		Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey),
		InstallRoot: filepath.Join(stateRoot, "install"), StateRoot: filepath.Join(stateRoot, "state"),
		ManagedRuntimeRoot: "/srv/ts-managed", WorkloadIdentity: WorkloadIdentity{UID: 65534, GID: 65534},
		PollInterval: 250 * time.Millisecond, ClockCheck: func() error { return nil }})
	if err != nil {
		t.Fatalf("create native host agent: %v", err)
	}
	agentCtx, stopAgent := context.WithCancel(t.Context())
	defer stopAgent()
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(agentCtx) }()
	deadline := time.Now().Add(120 * time.Second)
	var report Report
	for time.Now().Before(deadline) {
		select {
		case err := <-agentDone:
			t.Fatalf("native agent stopped before running report: %v", err)
		default:
		}
		hosts, err := controller.ListHosts(t.Context())
		if err == nil && len(hosts) == 1 && hosts[0].Verified && len(hosts[0].Reports) == 1 &&
			hosts[0].Reports[0].State == "running" && hosts[0].Reports[0].Managed != nil {
			report = hosts[0].Reports[0]
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if report.Managed == nil {
		t.Fatal("no accepted signed managed running report within deadline")
	}
	fmt.Printf("TS_MANAGED_MEMBER_PHASE=running node=%s pid=%d\n", cfg.Node, report.Managed.ProcessPID)

	listener, err := net.Listen("tcp", cfg.ControlAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan struct{}, 1)
	mux := http.NewServeMux()
	authorize := func(w http.ResponseWriter, r *http.Request) bool {
		remote, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil || remote != cfg.ControlHostIP ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("X-TS-Test-Token")), []byte(cfg.ControlToken)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /evidence", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r) {
			return
		}
		evidence, err := managedMemberCurrentEvidence(r.Context(), controller, desired, paths, report)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, evidence)
	})
	var wrote atomic.Bool
	mux.HandleFunc("POST /write", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r) {
			return
		}
		if r.ContentLength > 0 || !wrote.CompareAndSwap(false, true) {
			http.Error(w, "write may be requested once without a body", http.StatusConflict)
			return
		}
		result, err := managedMemberHTTPSWrite(r.Context(), httpsClient, cfg, string(clientToken))
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, result)
	})
	mux.HandleFunc("GET /read", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r) {
			return
		}
		result, err := managedMemberHTTPSRead(r.Context(), httpsClient, cfg, string(clientToken))
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, result)
	})
	mux.HandleFunc("POST /finish", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r) {
			return
		}
		if r.ContentLength > 0 {
			http.Error(w, "body not accepted", http.StatusBadRequest)
			return
		}
		select {
		case finished <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	select {
	case <-finished:
	case err := <-agentDone:
		t.Fatalf("native agent stopped before driver finished: %v", err)
	case err := <-serverDone:
		t.Fatalf("test control server stopped: %v", err)
	case <-time.After(300 * time.Second):
		t.Fatal("driver did not finish bounded serving check")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = server.Shutdown(shutdownCtx)
	cancel()
	stopAgent()
	select {
	case <-agentDone:
	case <-time.After(15 * time.Second):
		t.Fatal("native agent did not stop")
	}
	fmt.Printf("TS_MANAGED_MEMBER_PHASE=PASS node=%s\n", cfg.Node)
}

func managedMemberReadFixture(path, digest string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || owner.Uid != 0 || info.Mode().Perm() != 0600 ||
		info.Size() == 0 || info.Size() > maximum {
		return nil, errors.New("test fixture file has unsafe owner, mode or size")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("test fixture file differs from immutable input pin")
	}
	return data, nil
}

type managedMemberHTTPSResult struct {
	Status int `json:"status"`
	Body   any `json:"body"`
}

func managedMemberHTTPSWrite(ctx context.Context, client *http.Client, cfg managedMemberFirecrackerConfig, token string) (managedMemberHTTPSResult, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return managedMemberHTTPSResult{}, err
	}
	body, err := json.Marshal(map[string]any{
		"version":        1,
		"transaction_id": map[string]string{"expires_at_unix_ms": strconv.FormatInt(time.Now().Add(time.Hour).UnixMilli(), 10), "nonce": hex.EncodeToString(nonce)},
		"writes": []any{map[string]any{
			"collection": cfg.CollectionID, "document": cfg.DocumentID,
			"schema_generation": strconv.FormatUint(cfg.SchemaGeneration, 10), "schema_digest": cfg.SchemaDigest,
			"observed": []any{}, "value": map[string]any{"kind": "live", "fields": []any{}},
		}},
	})
	if err != nil {
		return managedMemberHTTPSResult{}, err
	}
	url := fmt.Sprintf("https://127.0.0.1:9465/v1/tenants/%s/databases/%s/shards/%d/transactions",
		cfg.Member.Scope.TenantID, cfg.Member.Scope.DatabaseID, cfg.Member.Scope.ShardID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return managedMemberHTTPSResult{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	return managedMemberHTTPSRequest(client, request)
}

func managedMemberHTTPSRead(ctx context.Context, client *http.Client, cfg managedMemberFirecrackerConfig, token string) (managedMemberHTTPSResult, error) {
	url := fmt.Sprintf("https://127.0.0.1:9465/v1/tenants/%s/databases/%s/shards/%d/collections/%s/documents/%s",
		cfg.Member.Scope.TenantID, cfg.Member.Scope.DatabaseID, cfg.Member.Scope.ShardID, cfg.CollectionID, cfg.DocumentID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return managedMemberHTTPSResult{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return managedMemberHTTPSRequest(client, request)
}

func managedMemberHTTPSRequest(client *http.Client, request *http.Request) (managedMemberHTTPSResult, error) {
	response, err := client.Do(request)
	if err != nil {
		return managedMemberHTTPSResult{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		return managedMemberHTTPSResult{}, errors.New("HTTPS response is oversized or not JSON")
	}
	var body any
	if err := json.Unmarshal(data, &body); err != nil {
		return managedMemberHTTPSResult{}, fmt.Errorf("HTTPS response is not JSON: %w", err)
	}
	return managedMemberHTTPSResult{Status: response.StatusCode, Body: body}, nil
}

func managedMemberCurrentEvidence(ctx context.Context, controller *Controller, desired Desired, paths managedRuntimePaths, initial Report) (managedMemberFirecrackerEvidence, error) {
	hosts, err := controller.ListHosts(ctx)
	if err != nil {
		return managedMemberFirecrackerEvidence{}, fmt.Errorf("read accepted host report: %w", err)
	}
	if len(hosts) != 1 || !hosts[0].Verified || len(hosts[0].Reports) != 1 {
		return managedMemberFirecrackerEvidence{}, errors.New("accepted host report is absent")
	}
	report := hosts[0].Reports[0]
	if report.State != "running" || report.Managed == nil || report.Digest != desired.Digest ||
		report.Managed.ProcessPID != initial.Managed.ProcessPID ||
		report.Managed.Member != desired.ManagedMember.Member ||
		report.Managed.Authority != desired.ManagedMember.Authority ||
		report.Managed.FileSystemUUID != desired.ManagedMember.Runtime.FileSystemUUID ||
		report.Managed.MountPath != paths.mount || !report.Managed.StorageRecovered || !report.Managed.ListenerReady {
		return managedMemberFirecrackerEvidence{}, errors.New("accepted managed report changed identity or lost readiness")
	}
	pid := report.Managed.ProcessPID
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return managedMemberFirecrackerEvidence{}, err
	}
	uid, gid, err := managedMemberProcessIdentity(string(status))
	if err != nil {
		return managedMemberFirecrackerEvidence{}, fmt.Errorf("read native UID/GID: %w", err)
	}
	if uid != 65534 || gid != 65534 {
		return managedMemberFirecrackerEvidence{}, fmt.Errorf("native process UID/GID = %d/%d", uid, gid)
	}
	_, mount, socket, err := prepareManagedRuntime(ctx, AgentConfig{
		ManagedRuntimeRoot: "/srv/ts-managed", WorkloadIdentity: WorkloadIdentity{UID: 65534, GID: 65534},
	}, desired, "", "")
	if err != nil {
		return managedMemberFirecrackerEvidence{}, fmt.Errorf("recheck pinned native mount/material: %w", err)
	}
	defer mount.close()
	if mount.id != report.Managed.MountID || socket != paths.socket {
		return managedMemberFirecrackerEvidence{}, errors.New("reported mount or member socket differs from held native witness")
	}
	authority, err := verifyManagedMaterial(filepath.Join(paths.material, "authority.tbca"),
		desired.ManagedMember.Authority.CertificateSHA256, WorkloadIdentity{UID: 65534, GID: 65534}, 1<<20)
	if err != nil {
		return managedMemberFirecrackerEvidence{}, err
	}
	if err := inspectManagedVolumeClaim(paths, *desired.ManagedMember, WorkloadIdentity{UID: 65534, GID: 65534}, mount, authority); err != nil {
		return managedMemberFirecrackerEvidence{}, fmt.Errorf("recheck exact recovered claim: %w", err)
	}
	cgroupPath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(report.Managed.ProcessCgroup, "/"))
	memoryBytes, err := os.ReadFile(filepath.Join(cgroupPath, "memory.max"))
	if err != nil {
		return managedMemberFirecrackerEvidence{}, err
	}
	limit, err := strconv.ParseUint(strings.TrimSpace(string(memoryBytes)), 10, 64)
	if err != nil || limit != desired.ManagedMember.CgroupMemoryMaxBytes {
		return managedMemberFirecrackerEvidence{}, errors.New("native memory.max differs from signed cap")
	}
	procs, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil || !strings.Contains("\n"+string(procs), fmt.Sprintf("\n%d\n", pid)) {
		return managedMemberFirecrackerEvidence{}, errors.New("reported process is absent from native role cgroup")
	}
	claimPath := filepath.Join(paths.mount, managedVolumeClaimName)
	claim, err := os.ReadFile(claimPath)
	if err != nil || string(claim) != string(managedVolumeClaimBytes(*desired.ManagedMember)) {
		return managedMemberFirecrackerEvidence{}, errors.New("durable volume claim differs from signed member")
	}
	claimInfo, err := os.Lstat(claimPath)
	if err != nil {
		return managedMemberFirecrackerEvidence{}, err
	}
	claimOwner, ok := claimInfo.Sys().(*syscall.Stat_t)
	if !ok || !claimInfo.Mode().IsRegular() || claimOwner.Uid != 0 || claimOwner.Gid != 0 || claimInfo.Mode().Perm() != 0600 {
		return managedMemberFirecrackerEvidence{}, errors.New("durable claim ownership or mode is unsafe")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9464/metrics", nil)
	if err != nil {
		return managedMemberFirecrackerEvidence{}, err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return managedMemberFirecrackerEvidence{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return managedMemberFirecrackerEvidence{}, fmt.Errorf("native metrics HTTP %d", response.StatusCode)
	}
	metricsBytes, err := io.ReadAll(io.LimitReader(response.Body, 256<<10+1))
	if err != nil || len(metricsBytes) > 256<<10 {
		return managedMemberFirecrackerEvidence{}, errors.New("native metrics exceeded bound")
	}
	metrics := make(map[string]float64)
	for line := range strings.SplitSeq(string(metricsBytes), "\n") {
		for _, name := range []string{"terrabase_replication_acks_total", "terrabase_replication_sender_connected", "terrabase_replication_sender_durable_lag_events", "terrabase_replication_sender_applied_lag_events"} {
			if !strings.HasPrefix(line, name) || len(line) <= len(name) || line[len(name)] != ' ' && line[len(name)] != '{' {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 2 {
				return managedMemberFirecrackerEvidence{}, errors.New("selected native metric is malformed")
			}
			value, parseErr := strconv.ParseFloat(parts[1], 64)
			if parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				return managedMemberFirecrackerEvidence{}, errors.New("selected native metric is non-finite")
			}
			if _, exists := metrics[parts[0]]; exists {
				return managedMemberFirecrackerEvidence{}, errors.New("selected native metric is duplicated")
			}
			metrics[parts[0]] = value
		}
	}
	claimDigest := sha256.Sum256(claim)
	return managedMemberFirecrackerEvidence{Version: 1, Node: desired.Node,
		MemberID: desired.ManagedMember.Member.Scope.MemberID, ProcessPID: pid, ProcessUID: uid, ProcessGID: gid,
		ProcessCgroup: report.Managed.ProcessCgroup, MemoryMaxBytes: limit,
		FileSystemUUID: report.Managed.FileSystemUUID, MountID: report.Managed.MountID,
		ClaimSHA256: hex.EncodeToString(claimDigest[:]), StorageRecovered: true, ListenerReady: true,
		Metrics: metrics}, nil
}

func managedMemberProcessIdentity(status string) (uint32, uint32, error) {
	var uid, gid uint64
	var sawUID, sawGID bool
	for line := range strings.SplitSeq(status, "\n") {
		if value, ok := strings.CutPrefix(line, "Uid:"); ok {
			if sawUID {
				return 0, 0, errors.New("duplicate process Uid line")
			}
			parsed, err := managedMemberUniformIdentity(value)
			if err != nil {
				return 0, 0, fmt.Errorf("process Uid: %w", err)
			}
			uid, sawUID = uint64(parsed), true
		}
		if value, ok := strings.CutPrefix(line, "Gid:"); ok {
			if sawGID {
				return 0, 0, errors.New("duplicate process Gid line")
			}
			parsed, err := managedMemberUniformIdentity(value)
			if err != nil {
				return 0, 0, fmt.Errorf("process Gid: %w", err)
			}
			gid, sawGID = uint64(parsed), true
		}
	}
	if !sawUID || !sawGID {
		return 0, 0, errors.New("process UID/GID is absent")
	}
	return uint32(uid), uint32(gid), nil
}

func managedMemberUniformIdentity(line string) (uint32, error) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return 0, errors.New("expected real, effective, saved and filesystem IDs")
	}
	var identity uint64
	for index, field := range fields {
		parsed, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return 0, err
		}
		if index != 0 && parsed != identity {
			return 0, errors.New("real, effective, saved and filesystem IDs differ")
		}
		identity = parsed
	}
	return uint32(identity), nil
}

func TestManagedMemberProcessIdentityRejectsRetainedRoot(t *testing.T) {
	valid := "Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n"
	if uid, gid, err := managedMemberProcessIdentity(valid); err != nil || uid != 65534 || gid != 65534 {
		t.Fatalf("uniform dropped IDs: uid=%d gid=%d err=%v", uid, gid, err)
	}
	for _, status := range []string{
		"Uid:\t0\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n",
		"Uid:\t65534\t65534\t0\t65534\nGid:\t65534\t65534\t65534\t65534\n",
		"Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t0\n",
	} {
		if _, _, err := managedMemberProcessIdentity(status); err == nil {
			t.Fatalf("retained root credential accepted: %q", status)
		}
	}
}
