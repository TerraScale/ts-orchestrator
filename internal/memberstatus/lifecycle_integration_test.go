package memberstatus

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The child is a protocol simulator, never a TerraBase build or substitute for
// same-commit database qualification in the monorepo.
func init() {
	if directory := os.Getenv("TS_MEMBER_PROTOCOL_FIXTURE"); directory != "" {
		if err := serveMemberFixture(directory); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

type fixtureConfig struct {
	StatusMutation  string `json:"status_mutation"`
	ProofMutation   string `json:"proof_mutation"`
	ReceiptMutation string `json:"receipt_mutation"`
	LostPOST        bool   `json:"lost_post"`
	HideOperation   bool   `json:"hide_operation"`
	RestartNonce    bool   `json:"restart_nonce"`
}

func fixtureIdentity(pid int) Identity {
	return Identity{Process: Process{PID: pid, StartNonce: strings.Repeat("1", 32)},
		Scope:     Scope{ClusterID: strings.Repeat("b", 32), TenantID: "01HW000000E008000000000001", DatabaseID: "01HW000000E008000000000002", ShardID: 1, MemberID: "01HW000000E008000000000003", Incarnation: strings.Repeat("c", 32)},
		Authority: Authority{Epoch: 7, ConfigurationID: strings.Repeat("d", 64), CertificateSHA256: strings.Repeat("e", 64), TLSLeafSHA256: strings.Repeat("f", 64)}}
}

func fixtureSurvivor() Survivor {
	return Survivor{MemberID: "01HW000000E008000000000004", Incarnation: strings.Repeat("3", 32)}
}

func serveMemberFixture(directory string) error {
	listener, err := net.Listen("unix", filepath.Join(directory, "control", "member.sock"))
	if err != nil {
		return err
	}
	if err := os.Chmod(listener.Addr().String(), 0o602); err != nil {
		return err
	}
	return http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configBytes, err := os.ReadFile(filepath.Join(directory, "config.json"))
		if err != nil {
			panic(err)
		}
		var config fixtureConfig
		if err := json.Unmarshal(configBytes, &config); err != nil {
			panic(err)
		}
		identity := fixtureIdentity(os.Getpid())
		if config.RestartNonce {
			identity.Process.StartNonce = strings.Repeat("9", 32)
		}
		challenge := r.URL.Query().Get("nonce")
		status := Status{SchemaVersion: 2, Nonce: challenge, Process: identity.Process, Scope: identity.Scope, Authority: identity.Authority, Local: Local{true, true, true, true}, Serving: true, Capabilities: Capabilities{true, true}}
		survivor := fixtureSurvivor()
		code := http.StatusOK
		var reply any
		switch r.URL.Path {
		case "/v1/member/status":
			reply = status
		case "/v1/member/serving-proof":
			reply = ServingProof{SchemaVersion: 1, Nonce: challenge, Process: identity.Process, Scope: identity.Scope, Authority: identity.Authority, Serving: true, Listeners: Listeners{true, true},
				Object:      ObjectProof{RootSHA256: strings.Repeat("5", 64), TargetSHA256: strings.Repeat("6", 64), NativeCommitSeqAtRecovery: 30, InboxArchiveSHA256AtRecovery: strings.Repeat("8", 64), LocalSourceSequence: 12, RemoteInboxDurableSequence: 9, RemoteAppliedSequence: 9},
				Replication: ReplicationProof{LocalSourceSequence: 12, PeerMemberID: survivor.MemberID, PeerIncarnation: survivor.Incarnation, CurrentAuthenticated: true, PeerDurableSequence: 12, PeerAppliedSequence: 12, LocalInboxDurableSequence: 9, LocalInboxAppliedSequence: 9}}
		case "/v1/member/drain", "/v1/member/drain-status":
			requestPath := filepath.Join(directory, "request.json")
			var request DrainRequest
			if r.Method == http.MethodPost {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					panic(err)
				}
				if err := json.Unmarshal(body, &request); err != nil {
					panic(err)
				}
				log, err := os.OpenFile(filepath.Join(directory, "posts"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					panic(err)
				}
				_, err = log.Write(append(body, '\n'))
				if err != nil {
					panic(err)
				}
				if err := log.Sync(); err != nil {
					panic(err)
				}
				if err := log.Close(); err != nil {
					panic(err)
				}
				if err := os.WriteFile(requestPath, body, 0o600); err != nil {
					panic(err)
				}
				if config.LostPOST {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						panic(err)
					}
					connection.Close()
					return
				}
				challenge = request.Nonce
			} else {
				body, err := os.ReadFile(requestPath)
				if errors.Is(err, os.ErrNotExist) || config.HideOperation {
					code = http.StatusNotFound
					reply = struct{}{}
					break
				}
				if err != nil {
					panic(err)
				}
				if err := json.Unmarshal(body, &request); err != nil {
					panic(err)
				}
			}
			if config.ReceiptMutation == "pending" {
				code = http.StatusAccepted
				reply = DrainEnvelope{SchemaVersion: 1, Nonce: challenge, Process: identity.Process, OperationID: request.OperationID, State: "pending"}
				break
			}
			receipt := DrainReceipt{SchemaVersion: 1, OperationID: request.OperationID, RequestNonce: request.Nonce, RequestedProcess: request.Expected.Process, DrainedProcess: identity.Process, Scope: request.Expected.Scope, Authority: request.Expected.Authority,
				LocalSourceOrigin: Origin{request.Expected.Scope.MemberID, request.Expected.Scope.Incarnation}, LocalSourceDurableSequence: 15, ArchivedSourceSequence: 15, ObjectRootSHA256: strings.Repeat("5", 64),
				Peer: DrainPeer{Origin: Origin{survivor.MemberID, survivor.Incarnation}, DurableSequence: 15, AppliedSequence: 15, LocalInboxDurableSequence: 9, LocalInboxAppliedSequence: 9}, ReplicationQuiesced: true}
			switch config.ReceiptMutation {
			case "lag":
				receipt.Peer.AppliedSequence = 14
			case "root":
				receipt.ObjectRootSHA256 = ""
			case "nonce":
				receipt.RequestNonce = strings.Repeat("a", 32)
			case "survivor":
				receipt.Peer.Origin.MemberID = request.Expected.Scope.MemberID
			}
			digest, err := receipt.digest()
			if err != nil {
				panic(err)
			}
			if config.ReceiptMutation == "digest" {
				digest = strings.Repeat("0", 64)
			}
			reply = DrainEnvelope{SchemaVersion: 1, Nonce: challenge, Process: identity.Process, OperationID: request.OperationID, State: "complete", ReceiptSHA256: &digest, Receipt: &receipt}
		default:
			code = http.StatusNotFound
			reply = struct{}{}
		}
		body, err := json.Marshal(reply)
		if err != nil {
			panic(err)
		}
		if r.URL.Path == "/v1/member/status" {
			body = mutateStatus(body, config.StatusMutation)
		}
		if r.URL.Path == "/v1/member/serving-proof" {
			body = mutateProof(body, config.ProofMutation)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(code)
		w.Write(body)
	}))
}

func mutateStatus(body []byte, mutation string) []byte {
	text := string(body)
	switch mutation {
	case "storage":
		text = strings.Replace(text, `"storage_recovered":true`, `"storage_recovered":false`, 1)
	case "listener":
		text = strings.Replace(text, `"replication_listener_ready":true`, `"replication_listener_ready":false`, 1)
	case "missing false":
		text = strings.Replace(text, `"receiver_only":false,`, "", 1)
	case "duplicate":
		text = strings.Replace(text, `"schema_version":2`, `"schema_version":2,"schema_version":2`, 1)
		text = strings.TrimSuffix(text, "}") + `,"load":{}}`
	case "unknown":
		text = strings.TrimSuffix(text, "}") + `,"unexpected":true}`
	case "array":
		text = `[1]`
	case "duplicate load":
		text = strings.TrimSuffix(text, "}") + `,"load":1,"load":2}`
	case "duplicate process":
		text = strings.Replace(text, `"pid":`, `"pid":1,"pid":`, 1)
		text = strings.TrimSuffix(text, "}") + `,"load":{}}`
	case "trailing object":
		text = strings.TrimSuffix(text, "}") + `,"load":{}} {}`
	case "valid load":
		text = strings.TrimSuffix(text, "}") + `,"load":{"connections":4,"storage_bytes":5,"replication_lag_seq":6,"write_qps":7.5}}`
	default:
		if strings.HasPrefix(mutation, "load:") {
			text = strings.TrimSuffix(text, "}") + `,"load":` + strings.TrimPrefix(mutation, "load:") + `}`
		}
	}
	return []byte(text)
}

func mutateProof(body []byte, mutation string) []byte {
	text := string(body)
	switch mutation {
	case "ordered":
		text = strings.Replace(text, `"peer_durable_sequence":12`, `"peer_received_sequence":12,"local_inbox_received_sequence":10,"peer_durable_sequence":12`, 1)
	case "peer behind":
		text = strings.Replace(text, `"peer_durable_sequence":12`, `"peer_received_sequence":11,"local_inbox_received_sequence":9,"peer_durable_sequence":12`, 1)
	case "inbox behind":
		text = strings.Replace(text, `"peer_durable_sequence":12`, `"peer_received_sequence":12,"local_inbox_received_sequence":8,"peer_durable_sequence":12`, 1)
	case "peer only":
		text = strings.Replace(text, `"peer_durable_sequence":12`, `"peer_received_sequence":12,"peer_durable_sequence":12`, 1)
	case "inbox only":
		text = strings.Replace(text, `"peer_durable_sequence":12`, `"local_inbox_received_sequence":9,"peer_durable_sequence":12`, 1)
	case "null":
		text = strings.Replace(text, `"peer_durable_sequence":12`, `"peer_received_sequence":null,"local_inbox_received_sequence":null,"peer_durable_sequence":12`, 1)
	case "unknown":
		text = strings.Replace(text, `"peer_durable_sequence":12`, `"peer_forwarded_sequence":12,"peer_durable_sequence":12`, 1)
	case "lag":
		text = strings.Replace(text, `"peer_applied_sequence":12`, `"peer_applied_sequence":11`, 1)
	}
	return []byte(text)
}

type memberFixture struct {
	directory string
	process   *exec.Cmd
	client    *Client
	store     *FileStore
}

func startMemberFixture(t *testing.T) *memberFixture {
	return startMemberFixtureNamespace(t, 0)
}

func startMemberFixtureNamespace(t *testing.T, namespaces uintptr) *memberFixture {
	t.Helper()
	directory, err := os.MkdirTemp("", "ts-member-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Group write/execute permits unlinking the known socket, not listing.
		os.Remove(filepath.Join(directory, "control", "member.sock"))
		os.Remove(filepath.Join(directory, "control"))
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		uid, gid = 65534, 65534
	}
	if err := os.Chown(directory, uid, gid); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(directory, "control")
	if err := os.Mkdir(control, 0o730); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(control, 0o730); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		err = os.Chown(control, 0, gid)
	} else {
		err = exec.Command("sudo", "-n", "chown", "0:"+strconv.Itoa(gid), control).Run()
	}
	if err != nil {
		t.Fatalf("root-owned control fixture requires root or passwordless sudo: %v", err)
	}
	fixture := &memberFixture{directory: directory}
	fixture.configure(t, fixtureConfig{})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Root-owned go-build directories cannot be traversed by the member UID.
	binary := filepath.Join(directory, "fixture.test")
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture.process = exec.Command(binary, "-test.run=^$")
	fixture.process.Env = append(os.Environ(), "TS_MEMBER_PROTOCOL_FIXTURE="+directory)
	if os.Geteuid() == 0 {
		fixture.process.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, Cloneflags: namespaces}
	} else if namespaces != 0 {
		t.Fatal("real PID/mount namespace fixture requires root")
	}
	var logs bytes.Buffer
	fixture.process.Stderr = &logs
	if err := fixture.process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fixture.process.Process.Kill()
		fixture.process.Wait()
		if logs.Len() > 0 {
			t.Log(logs.String())
		}
	})
	socket := filepath.Join(control, "member.sock")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("member socket missing: %s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	identity := fixtureIdentity(fixture.process.Process.Pid)
	observe := func(context.Context) (ProcessObservation, error) {
		if namespaces != 0 {
			return ObserveContainerProcess(fixture.process.Process.Pid, fixture.process.Process.Pid)
		}
		return observeFixtureProcess(fixture.process.Process.Pid)
	}
	fixture.client, err = NewClient(socket, identity.Scope, identity.Authority, observe)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(directory, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.store, err = NewFileStore(filepath.Join(state, "drain.json"))
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestMemberPIDNamespaceIntegration(t *testing.T) {
	f := startMemberFixtureNamespace(t, syscall.CLONE_NEWPID|syscall.CLONE_NEWNS)
	observation, err := f.client.observe(t.Context())
	if err != nil || observation.PID != f.process.Process.Pid || observation.PID < 2 || observation.ProtocolPID() != 1 {
		t.Fatalf("actual host/namespace identity: %+v, %v", observation, err)
	}
	status, err := f.client.Status(t.Context())
	if err != nil || status.Process.PID != 1 {
		t.Fatalf("PID1 status through host SO_PEERCRED: %+v, %v", status, err)
	}
	proof, err := f.client.ServingProof(t.Context(), status, fixtureSurvivor())
	if err != nil || proof.Process.PID != 1 {
		t.Fatalf("PID1 serving proof: %+v, %v", proof, err)
	}
	const operation = "0H248H248H248H248H248H248H"
	envelope, err := f.client.Drain(t.Context(), fixtureSurvivor(), operation, f.store)
	if err != nil || envelope.Receipt == nil {
		t.Fatalf("PID1 drain receipt: %+v, %v", envelope, err)
	}
	record, found, err := f.store.Load()
	if err != nil || !found || record.Request.Expected.Process.PID != 1 || envelope.Receipt.RequestedProcess.PID != 1 || envelope.Receipt.DrainedProcess.PID != 1 {
		t.Fatalf("protocol identities were rewritten: %+v, %v", record, err)
	}
	if err := VerifyReportedDrain(envelope, operation, record.Request.Expected, record.Survivor, record.SourceSequence); err != nil {
		t.Fatal(err)
	}
	actualObserver := f.client.observe
	f.client.observe = func(ctx context.Context) (ProcessObservation, error) {
		current, err := actualObserver(ctx)
		current.namespace = processNamespace{}
		return current, err
	}
	if _, err := f.client.Status(t.Context()); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("namespace PID without kernel witness: %v", err)
	}
	f.client.observe = actualObserver
	native, err := observeFixtureProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindPIDNamespace(native, os.Getpid()); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("host process supplied as container namespace: %v", err)
	}
	observation.PID = os.Getpid()
	if _, err := BindPIDNamespace(observation, f.process.Process.Pid); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("changed host PID with retained namespace witness: %v", err)
	}
}
func observeFixtureProcess(pid int) (ProcessObservation, error) {
	path := "/proc/" + strconv.Itoa(pid)
	info, err := os.Stat(path)
	if err != nil {
		return ProcessObservation{}, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	raw, err := os.ReadFile(path + "/stat")
	if err != nil {
		return ProcessObservation{}, err
	}
	_, suffix, ok := strings.CutLast(string(raw), ") ")
	fields := strings.Fields(suffix)
	if !ok || len(fields) < 20 {
		return ProcessObservation{}, errors.New("invalid process stat")
	}
	cgroup, err := os.ReadFile(path + "/cgroup")
	if err != nil {
		return ProcessObservation{}, err
	}
	return ProcessObservation{PID: pid, UID: stat.Uid, GID: stat.Gid, KernelStart: fields[19], Cgroup: string(cgroup)}, nil
}
func (f *memberFixture) configure(t *testing.T, config fixtureConfig) {
	t.Helper()
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.directory, "config.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *memberFixture) restart(t *testing.T) {
	t.Helper()
	if err := f.process.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	f.process.Wait()
	if err := os.Remove(f.client.socket); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(f.process.Path, "-test.run=^$")
	process.Env, process.SysProcAttr, process.Stderr = f.process.Env, f.process.SysProcAttr, os.Stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	f.process = process
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(f.client.socket); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("restarted member socket missing")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMemberLifecycleIntegration(t *testing.T) {
	f := startMemberFixture(t)
	const operationID = "0H248H248H248H248H248H248H"
	f.configure(t, fixtureConfig{LostPOST: true, HideOperation: true})
	if _, err := f.client.Drain(t.Context(), fixtureSurvivor(), operationID, f.store); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost POST = %v", err)
	}
	record, found, err := f.store.Load()
	if err != nil || !found {
		t.Fatalf("durable intent missing: %v", err)
	}
	reopened, err := NewFileStore(f.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Create(record); err != nil {
		t.Fatalf("exact durable replay rejected: %v", err)
	}
	if _, err := f.client.Drain(t.Context(), fixtureSurvivor(), operationID, reopened); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("replayed lost POST = %v", err)
	}
	posts, err := os.ReadFile(filepath.Join(f.directory, "posts"))
	if err != nil {
		t.Fatal(err)
	}
	requests := bytes.Split(bytes.TrimSpace(posts), []byte{'\n'})
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
		t.Fatalf("POST changed after reopen: %s", posts)
	}
	changed := record
	changed.Request.Nonce = strings.Repeat("9", 32)
	if err := reopened.Create(changed); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("changed durable nonce = %v", err)
	}
	if _, err := f.client.Drain(t.Context(), fixtureSurvivor(), "01HW000000E008000000000009", reopened); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("changed operation = %v", err)
	}
	f.configure(t, fixtureConfig{RestartNonce: true, HideOperation: true})
	f.restart(t)
	if _, err := f.client.Drain(t.Context(), fixtureSurvivor(), operationID, reopened); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("replacement process replay = %v", err)
	}
	after, err := os.ReadFile(filepath.Join(f.directory, "posts"))
	if err != nil || !bytes.Equal(after, posts) {
		t.Fatalf("replacement process received POST: %s, %v", after, err)
	}
	f.configure(t, fixtureConfig{RestartNonce: true, ReceiptMutation: "pending"})
	pending, err := f.client.Drain(t.Context(), fixtureSurvivor(), operationID, reopened)
	if err != nil || pending.State != "pending" || pending.Receipt != nil {
		t.Fatalf("pending operation = %+v, %v", pending, err)
	}
	if err := VerifyReportedDrain(pending, operationID, record.Request.Expected, record.Survivor, record.SourceSequence); err == nil {
		t.Fatal("pending operation authorized replacement")
	}
	for _, mutation := range []string{"digest", "lag", "root", "nonce", "survivor"} {
		t.Run("receipt "+mutation, func(t *testing.T) {
			f.configure(t, fixtureConfig{RestartNonce: true, ReceiptMutation: mutation})
			if _, err := f.client.Drain(t.Context(), fixtureSurvivor(), operationID, reopened); err == nil {
				t.Fatal("unsafe receipt accepted")
			}
		})
	}
	f.configure(t, fixtureConfig{RestartNonce: true})
	envelope, err := f.client.Drain(t.Context(), fixtureSurvivor(), operationID, reopened)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReportedDrain(envelope, operationID, record.Request.Expected, record.Survivor, record.SourceSequence); err != nil {
		t.Fatalf("recovered final receipt: %v", err)
	}
	if err := VerifyReportedDrain(envelope, operationID, record.Request.Expected, record.Survivor, 16); err == nil {
		t.Fatal("receipt below required final frontier accepted")
	}
	if envelope.Receipt.LocalSourceDurableSequence != 15 {
		t.Fatal("final drain frontier did not advance beyond serving proof")
	}
}

func TestMemberServingIntegration(t *testing.T) {
	f := startMemberFixture(t)
	for _, mutation := range []string{"storage", "listener", "missing false", "duplicate", "unknown", "array", "duplicate load", "duplicate process", "trailing object"} {
		t.Run(mutation, func(t *testing.T) {
			f.configure(t, fixtureConfig{StatusMutation: mutation})
			if _, err := f.client.Status(t.Context()); err == nil {
				t.Fatal("unsafe status accepted")
			}
		})
	}
	for _, load := range []string{`{"connections":-1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`, `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1e400}`, `{"connections":"1","storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`, `{"connections":1}`, `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1,"extra":1}`, `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":-1}`, `null`, `[]`, `{"connections":1,"connections":2,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`} {
		f.configure(t, fixtureConfig{StatusMutation: "load:" + load})
		status, err := f.client.Status(t.Context())
		if err != nil || status.Load != nil {
			t.Fatalf("telemetry changed lifecycle evidence: %+v, %v", status.Load, err)
		}
	}
	f.configure(t, fixtureConfig{StatusMutation: "valid load"})
	status, err := f.client.Status(t.Context())
	if err != nil || status.Load == nil || *status.Load != (Load{4, 5, 6, 7.5}) {
		t.Fatalf("valid telemetry = %+v, %v", status.Load, err)
	}
	for _, mutation := range []string{"", "ordered", "peer behind", "inbox behind", "peer only", "inbox only", "null", "unknown", "lag"} {
		t.Run("proof "+mutation, func(t *testing.T) {
			f.configure(t, fixtureConfig{ProofMutation: mutation})
			status, err := f.client.Status(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			proof, err := f.client.ServingProof(t.Context(), status, fixtureSurvivor())
			valid := mutation == "" || mutation == "ordered"
			if valid {
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyReportedServing(proof, fixtureIdentity(f.process.Process.Pid), fixtureSurvivor()); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe replication proof accepted")
			}
		})
	}
}

func TestMemberSocketBindingIntegration(t *testing.T) {
	f := startMemberFixture(t)
	original := f.client.observe
	f.client.observe = func(ctx context.Context) (ProcessObservation, error) {
		observation, err := original(ctx)
		observation.PID++
		return observation, err
	}
	if _, err := f.client.Status(t.Context()); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("foreign peer PID = %v", err)
	}
	calls := 0
	f.client.observe = func(ctx context.Context) (ProcessObservation, error) {
		observation, err := original(ctx)
		calls++
		if calls > 1 {
			observation.KernelStart += "changed"
		}
		return observation, err
	}
	if _, err := f.client.Status(t.Context()); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("process changed during request = %v", err)
	}
	f.client.observe = original
	if err := os.Chmod(f.client.socket, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Status(t.Context()); err == nil {
		t.Fatal("unsafe socket permissions accepted")
	}
}
