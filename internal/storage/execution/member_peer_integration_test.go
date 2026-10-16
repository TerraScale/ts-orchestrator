package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
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

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
)

type peerBinding struct {
	Scope     memberstatus.Scope
	Authority memberstatus.Authority
	Survivor  memberstatus.Survivor
}

// TestDrainProtocolPeer is an external protocol simulator in a child process.
// It is not a TerraBase binary and supplies no production admission evidence.
func TestDrainProtocolPeer(t *testing.T) {
	directory := os.Getenv("TS_EXECUTION_DRAIN_PEER")
	if directory == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(directory, "binding"))
	if err != nil {
		t.Fatal(err)
	}
	var binding peerBinding
	if err := json.Unmarshal(raw, &binding); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(directory, "control", "member.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(listener.Addr().String(), 0o602); err != nil {
		t.Fatal(err)
	}
	process := memberstatus.Process{PID: os.Getpid(), StartNonce: strings.Repeat("1", 32)}
	err = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("nonce")
		code := http.StatusOK
		var reply any
		switch r.URL.Path {
		case "/v1/member/status":
			reply = memberstatus.Status{SchemaVersion: 2, Nonce: challenge, Process: process, Scope: binding.Scope, Authority: binding.Authority, Local: memberstatus.Local{StorageRecovered: true, ReplicationListenerReady: true, Healthy: true, Ready: true}, Serving: true, Capabilities: memberstatus.Capabilities{ServingProof: true, DurableDrain: true}}
		case "/v1/member/serving-proof":
			reply = memberstatus.ServingProof{SchemaVersion: 1, Nonce: challenge, Process: process, Scope: binding.Scope, Authority: binding.Authority, Serving: true, Listeners: memberstatus.Listeners{Client: true, Replication: true}, Object: memberstatus.ObjectProof{RootSHA256: strings.Repeat("5", 64), TargetSHA256: strings.Repeat("6", 64), InboxArchiveSHA256AtRecovery: strings.Repeat("8", 64), LocalSourceSequence: 12, RemoteInboxDurableSequence: 9, RemoteAppliedSequence: 9}, Replication: memberstatus.ReplicationProof{LocalSourceSequence: 12, PeerMemberID: binding.Survivor.MemberID, PeerIncarnation: binding.Survivor.Incarnation, CurrentAuthenticated: true, PeerDurableSequence: 12, PeerAppliedSequence: 12, LocalInboxDurableSequence: 9, LocalInboxAppliedSequence: 9}}
		case "/v1/member/drain", "/v1/member/drain-status":
			path := filepath.Join(directory, "peer-request")
			var request memberstatus.DrainRequest
			if r.Method == http.MethodPost {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					panic(err)
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					panic(err)
				}
			}
			body, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				code = http.StatusNotFound
				reply = map[string]string{"state": "absent"}
				break
			}
			if err != nil {
				panic(err)
			}
			if err := json.Unmarshal(body, &request); err != nil {
				panic(err)
			}
			if r.Method == http.MethodPost {
				challenge = request.Nonce
			}
			mode, err := os.ReadFile(filepath.Join(directory, "mode"))
			if err != nil {
				panic(err)
			}
			envelope := memberstatus.DrainEnvelope{SchemaVersion: 1, Nonce: challenge, Process: process, OperationID: request.OperationID, State: "pending"}
			if string(mode) == "pending" {
				code = http.StatusAccepted
				reply = envelope
				break
			}
			applied := uint64(15)
			if string(mode) == "lag" {
				applied = 14
			}
			receipt := memberstatus.DrainReceipt{SchemaVersion: 1, OperationID: request.OperationID, RequestNonce: request.Nonce, RequestedProcess: request.Expected.Process, DrainedProcess: process, Scope: binding.Scope, Authority: binding.Authority, LocalSourceOrigin: memberstatus.Origin{MemberID: binding.Scope.MemberID, Incarnation: binding.Scope.Incarnation}, LocalSourceDurableSequence: 15, ArchivedSourceSequence: 15, ObjectRootSHA256: strings.Repeat("5", 64), Peer: memberstatus.DrainPeer{Origin: memberstatus.Origin{MemberID: binding.Survivor.MemberID, Incarnation: binding.Survivor.Incarnation}, DurableSequence: 15, AppliedSequence: applied, LocalInboxDurableSequence: 9, LocalInboxAppliedSequence: 9}, ReplicationQuiesced: true}
			canonical, err := json.Marshal(receipt)
			if err != nil {
				panic(err)
			}
			sum := sha256.Sum256(canonical)
			digest := hex.EncodeToString(sum[:])
			envelope.State = "complete"
			envelope.Receipt = &receipt
			envelope.ReceiptSHA256 = &digest
			reply = envelope
		default:
			code = http.StatusNotFound
			reply = map[string]string{"state": "absent"}
		}
		body, err := json.Marshal(reply)
		if err != nil {
			panic(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}))
	if err != nil {
		t.Fatal(err)
	}
}

func startDrainPeer(t *testing.T, binding peerBinding) (*memberstatus.Client, string) {
	t.Helper()
	directory, err := os.MkdirTemp("", "ts-execution-peer-")
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
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
	var ownershipError error
	if os.Getuid() == 0 {
		ownershipError = os.Chown(control, 0, gid)
	} else {
		ownershipError = exec.Command("sudo", "-n", "chown", "0:"+strconv.Itoa(gid), control).Run()
	}
	if err := ownershipError; err != nil {
		t.Fatalf("root-owned control fixture requires passwordless sudo: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(control, "member.sock"))
		_ = os.Remove(control)
		_ = os.RemoveAll(directory)
	})
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "binding"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "mode"), []byte("pending"), 0o644); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "fixture.test")
	if err := os.WriteFile(binary, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(binary, "-test.run=^TestDrainProtocolPeer$")
	if os.Getuid() == 0 {
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	}
	child.Env = append(os.Environ(), "TS_EXECUTION_DRAIN_PEER="+directory)
	child.Stdout = os.Stderr
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	socket := filepath.Join(control, "member.sock")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("member protocol peer socket missing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	observe := func(context.Context) (memberstatus.ProcessObservation, error) {
		proc := "/proc/" + strconv.Itoa(child.Process.Pid)
		raw, err := os.ReadFile(proc + "/stat")
		if err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		_, suffix, ok := strings.CutLast(string(raw), ") ")
		fields := strings.Fields(suffix)
		if !ok || len(fields) < 20 {
			return memberstatus.ProcessObservation{}, errors.New("invalid process stat")
		}
		cgroup, err := os.ReadFile(proc + "/cgroup")
		if err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		return memberstatus.ProcessObservation{PID: child.Process.Pid, UID: uint32(uid), GID: uint32(gid), KernelStart: fields[19], Cgroup: string(cgroup)}, nil
	}
	client, err := memberstatus.NewClient(socket, binding.Scope, binding.Authority, observe)
	if err != nil {
		t.Fatal(err)
	}
	return client, directory
}
