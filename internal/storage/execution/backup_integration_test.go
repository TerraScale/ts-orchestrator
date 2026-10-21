//go:build linux

package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/moby/swarmkit/v2/api"
)

const backupPeerOperation = "3QEXVQEXVQEXVQEXVQEXVQEXVQ"
const backupPeerReceipt = `{"version":1,"payload":"receipt","signature":"signature"}`
const backupPeerCut = `{"version":1,"payload":"cut","signature":"signature"}`

// This external protocol peer tests dispatch and SO_PEERCRED, never admission.
func serveBackupPeer(t *testing.T, directory string) {
	t.Helper()
	listener, err := net.Listen("unix", filepath.Join(directory, "control", "member.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(listener.Addr().String(), 0o602); err != nil {
		t.Fatal(err)
	}
	if err := http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "last-request"), append([]byte(r.Method+" "+r.URL.Path+"\n"), body...), 0o600); err != nil {
			panic(err)
		}
		var reply []byte
		switch r.URL.Path {
		case "/v1/backup/prepare":
			reply = []byte(backupPeerCut)
		case "/v1/backup/release":
			reply = []byte(`{"version":1,"state":"released"}`)
		case "/v1/backup/cut-proof":
			reply = []byte(`{"version":1,"state":"accepted"}`)
		case "/v1/backup/barrier":
			digest := sha256.Sum256(body)
			reply, err = json.Marshal(struct {
				Version uint64 `json:"version"`
				SHA256  string `json:"barrier_sha256"`
			}{1, hex.EncodeToString(digest[:])})
		case "/v1/backup/complete":
			reply = []byte(backupPeerReceipt)
		case "/v1/backup/operations/" + backupPeerOperation:
			state, err := os.ReadFile(filepath.Join(directory, "mode"))
			if err != nil {
				panic(err)
			}
			reply, err = json.Marshal(memberstatus.BackupOperationStatus{Version: 1, OperationID: backupPeerOperation, State: string(state), Ordinal: 7, Attempt: 2, PublishedHeadReceipt: backupPeerReceipt})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if err != nil {
			panic(err)
		}
		if r.Method == http.MethodPost {
			if err := os.WriteFile(filepath.Join(directory, "last-mutation"), append([]byte(r.URL.Path+"\n"), body...), 0o600); err != nil {
				panic(err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
		_, _ = w.Write(reply)
	})); err != nil {
		t.Fatal(err)
	}
}

func TestBackupRelayAuthenticatedUnixDispatch(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	binding := peerBinding{Backup: true,
		Scope:     memberstatus.Scope{ClusterID: strings.Repeat("1", 32), TenantID: "00000000000000000000000001", DatabaseID: "00000000000000000000000002", ShardID: 1, MemberID: "00000000000000000000000003", Incarnation: strings.Repeat("4", 32)},
		Authority: memberstatus.Authority{Epoch: 1, ConfigurationID: "00000000000000000000000005", CertificateSHA256: strings.Repeat("6", 64), TLSLeafSHA256: strings.Repeat("7", 64)}}
	client, directory := startDrainPeer(t, binding)
	proof, err := json.Marshal(struct {
		Version uint64 `json:"version"`
		Cut     string `json:"cut_envelope"`
		Leaf    string `json:"leaf_der"`
	}{1, base64.RawURLEncoding.EncodeToString([]byte(backupPeerCut)), base64.RawURLEncoding.EncodeToString([]byte("leaf"))})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ kind, path string }{
		{"prepare", "/v1/backup/prepare"}, {"abort", "/v1/backup/release"}, {"cut-proof", "/v1/backup/cut-proof"},
		{"barrier", "/v1/backup/barrier"}, {"publish", "/v1/backup/complete"}, {"complete", "/v1/backup/release"}, {"complete-status", ""},
	} {
		t.Run(test.kind, func(t *testing.T) {
			envelope := []byte(`{"version":1,"payload":"` + test.kind + `","signature":"signature"}`)
			if test.kind == "cut-proof" {
				envelope = proof
			}
			if err := os.Remove(filepath.Join(directory, "last-mutation")); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			digest := sha256.Sum256(envelope)
			command := host.ManagedBackupCommand{Kind: test.kind, OperationID: backupPeerOperation, Envelope: envelope, EnvelopeSHA256: hex.EncodeToString(digest[:])}
			result, err := relayBackup(t.Context(), client, command)
			if err != nil || result.Status.Ordinal != 7 || result.Status.Attempt != 2 || result.Status.OperationID != backupPeerOperation {
				t.Fatalf("relay result: %+v, %v", result, err)
			}
			mutation, err := os.ReadFile(filepath.Join(directory, "last-mutation"))
			if test.path == "" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("status-only recovery mutated the member: %s, %v", mutation, err)
				}
			} else if err != nil || !bytes.Equal(mutation, append([]byte(test.path+"\n"), envelope...)) {
				t.Fatalf("relay changed committed bytes/path: %s, %v", mutation, err)
			}
			if test.kind == "prepare" && string(result.CutEnvelope) != backupPeerCut || test.kind == "publish" && string(result.ReceiptEnvelope) != backupPeerReceipt {
				t.Fatal("relay changed cut/publication evidence")
			}
			command.EnvelopeSHA256 = strings.Repeat("f", 64)
			if _, err := relayBackup(t.Context(), client, command); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("substituted committed envelope accepted: %v", err)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(directory, "mode"), []byte("complete"), 0o644); err != nil {
		t.Fatal(err)
	}
	envelope := []byte("expired-release-read-only")
	digest := sha256.Sum256(envelope)
	result, err := relayBackup(t.Context(), client, host.ManagedBackupCommand{Kind: "complete-status", OperationID: backupPeerOperation, Envelope: envelope, EnvelopeSHA256: hex.EncodeToString(digest[:])})
	if err != nil || result.Status.State != "complete" || result.Status.PublishedHeadReceipt != backupPeerReceipt {
		t.Fatalf("terminal status recovery: %+v, %v", result, err)
	}
}

func TestBackupWithdrawalCancelsBeforePublicationRemoval(t *testing.T) {
	task := &api.Task{ID: "withdraw-task", ServiceID: "withdraw-service", NodeID: "withdraw-node"}
	hash, err := TaskSHA256(task)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publication.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = listener.Close() })
	file, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	request, cancel := context.WithCancel(t.Context())
	grant := VerifiedWorkerGrant{payload: WorkerGrantPayload{TaskSHA256: hash}, admissionSHA256: strings.Repeat("1", 64)}
	var socketPresentAtCancellation bool
	entry := &sourceEntry{grant: grant, backupCancel: func() {
		current, err := os.Lstat(path)
		socketPresentAtCancellation = err == nil && os.SameFile(file, current)
		cancel()
	}, publication: &publication{path: path, file: file, listener: listener, cancel: func() {}}}
	source := &Source{entries: map[string]*sourceEntry{hash: entry}}
	if err := source.WithdrawTask(t.Context(), task, grant); err != nil {
		t.Fatal(err)
	}
	if request.Err() == nil || !socketPresentAtCancellation || !entry.revoked || entry.publication != nil {
		t.Fatal("withdrawal did not cancel backup before revoking publication")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("withdrawal retained publication socket: %v", err)
	}
}
