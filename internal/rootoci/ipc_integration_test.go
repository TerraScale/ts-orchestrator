package rootoci

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

func TestRootOCIProcessExitIntegration(t *testing.T) {
	binary, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), binary, "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	witness, err := CaptureProcess(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = witness.Close() })
	if witness.Peer() != (nativerootoci.Peer{PID: child.Process.Pid, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}) ||
		witness.ParentPID() != os.Getpid() || witness.KernelStart() == 0 || witness.Cgroup() == "" || witness.Binding() == "" {
		t.Fatal("witness did not retain the actual child kernel identity")
	}
	watchdog, stopWatchdog := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopWatchdog()
	ctx, cancel := context.WithCancel(watchdog)
	defer cancel()
	done, err := witness.watchExit(ctx, cancel)
	if err != nil {
		t.Fatal(err)
	}
	if err := witness.Verify(); err != nil {
		t.Fatal(err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-watchdog.Done():
		t.Fatal("pidfd watcher failed to join after child exit")
	}
	if !errors.Is(witness.Verify(), ErrUnauthorized) {
		t.Fatal("exited child retained authorization")
	}
}

// These scenarios exercise the kernel socket/process boundary. The controlled
// reader produces no sealed domain authority and performs no provider effects.
func TestRootOCIUnixRevocationIntegration(t *testing.T) {
	for _, scenario := range []string{"session_cancel", "raw_sign", "unknown_member", "wrong_process", "expired", "effect_then_revoke", "backend_unknown"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			session, revoke := context.WithCancel(ctx)
			defer revoke()
			path := filepath.Join(t.TempDir(), "oci.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			reader := &transportReader{started: make(chan struct{}), stopped: make(chan struct{})}
			var successor atomic.Bool
			foundation := &transportFoundation{successor: &successor, unknown: scenario == "backend_unknown"}
			service := &Service{backends: Backends{Readers: reader, Foundations: foundation}}
			started := make(chan struct{})
			var childPID int
			var authorizations atomic.Int32
			var retained *ProcessWitness
			deadline := time.Now().Add(4 * time.Second)
			if scenario == "expired" {
				deadline = time.Now().Add(-time.Second)
			}
			authorize := func(callCtx context.Context, peer nativerootoci.Peer, operation Operation) (Lease, error) {
				select {
				case <-started:
				case <-callCtx.Done():
					return Lease{}, ErrUnauthorized
				}
				expectedOperation := OperationObserveLocalInstance
				if scenario == "effect_then_revoke" || scenario == "backend_unknown" {
					expectedOperation = OperationReconcileFoundation
				}
				if peer.PID != childPID || peer.UID != uint32(os.Geteuid()) || peer.GID != uint32(os.Getegid()) || operation != expectedOperation {
					return Lease{}, ErrUnauthorized
				}
				if retained == nil {
					var err error
					retained, err = CaptureProcess(childPID)
					if err != nil {
						return Lease{}, err
					}
				}
				if retained.Verify() != nil || retained.Peer() != peer || retained.ParentPID() != os.Getpid() || session.Err() != nil {
					return Lease{}, ErrUnauthorized
				}
				authorizations.Add(1)
				binding := retained.Binding()
				if successor.Load() {
					binding += "-successor"
				}
				return Lease{Context: session, Deadline: deadline, Binding: binding}, nil
			}
			done := make(chan struct{})
			go func() { defer close(done); serve(ctx, listener, service, authorize) }()
			t.Cleanup(func() {
				cancel()
				_ = listener.Close()
				<-done
				if retained != nil {
					_ = retained.Close()
				}
			})
			request := wireRequest{Version: 1, Operation: OperationObserveLocalInstance, Payload: []byte(`{}`)}
			if scenario == "raw_sign" {
				request.Operation = "sign"
			}
			if scenario == "unknown_member" {
				request.Payload = []byte(`{"provider_path":"arbitrary"}`)
			}
			if scenario == "effect_then_revoke" || scenario == "backend_unknown" {
				request.Operation = OperationReconcileFoundation
				request.Payload = []byte(`{"cell":"gru"}`)
			}
			wire, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			python, err := exec.LookPath("python3")
			if err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(ctx, python, "-c", unixRequestScript, path, string(wire))
			var output bytes.Buffer
			child.Stdout = &output
			child.Stderr = &output
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			childPID = child.Process.Pid
			if scenario == "wrong_process" {
				childPID = os.Getpid()
			}
			close(started)
			t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
			if scenario == "session_cancel" {
				select {
				case <-reader.started:
				case <-ctx.Done():
					t.Fatal("guarded reader was never reached")
				}
				revoke()
				select {
				case <-reader.stopped:
				case <-ctx.Done():
					t.Fatal("session cancellation did not stop reader")
				}
			}
			if err := child.Wait(); err != nil {
				t.Fatalf("socket child: %v: %s", err, output.Bytes())
			}
			if scenario == "session_cancel" {
				if authorizations.Load() < 2 || reader.calls.Load() != 1 || output.String() != "closed\n" {
					t.Fatalf("unexpected guarded cancellation: auth=%d reads=%d output=%s", authorizations.Load(), reader.calls.Load(), output.Bytes())
				}
			} else if scenario == "effect_then_revoke" || scenario == "backend_unknown" {
				var response wireResponse
				if json.Unmarshal(output.Bytes(), &response) != nil || response.Status != "outcome_unknown" || foundation.effects.Load() != 1 || reader.calls.Load() != 0 {
					t.Fatalf("uncertain committed effect lost outcome: effects=%d response=%s", foundation.effects.Load(), output.Bytes())
				}
			} else {
				var response wireResponse
				expected := "invalid"
				if scenario == "wrong_process" || scenario == "expired" {
					expected = "unauthorized"
				}
				if json.Unmarshal(output.Bytes(), &response) != nil || response.Status != expected || reader.calls.Load() != 0 ||
					(scenario != "expired" && authorizations.Load() != 0) {
					t.Fatalf("invalid operation crossed authority boundary: %s", output.Bytes())
				}
			}
		})
	}
}

const unixRequestScript = `import socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.settimeout(4)
s.connect(sys.argv[1])
b=sys.argv[2].encode()
s.sendall(struct.pack('!I',len(b))+b)
def receive(n):
 b=b''
 while len(b)<n:
  chunk=s.recv(n-len(b))
  if not chunk:return None
  b+=chunk
 return b
prefix=receive(4)
if prefix is None:print('closed')
else:
 body=receive(struct.unpack('!I',prefix)[0])
 print(body.decode() if body is not None else 'closed')
`

type transportReader struct {
	started, stopped chan struct{}
	calls            atomic.Int32
}

func (reader *transportReader) ObserveLocalInstance(ctx context.Context, call Call) (bootstrapstart.InstanceObservation, error) {
	if err := call.Guard(ctx); err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	reader.calls.Add(1)
	close(reader.started)
	<-ctx.Done()
	close(reader.stopped)
	return bootstrapstart.InstanceObservation{}, ctx.Err()
}
func (*transportReader) Inventory(context.Context, Call) (InventoryObservation, error) {
	return InventoryObservation{}, ErrUnauthorized
}
func (*transportReader) ObserveFleet(context.Context, Call) ([]oci.Instance, error) {
	return nil, ErrUnauthorized
}
func (*transportReader) Costs(context.Context, Call) (ocicost.Report, error) {
	return ocicost.Report{}, ErrUnauthorized
}
func (*transportReader) ObserveImage(context.Context, Call, ImageRequest) (ImageObservation, error) {
	return ImageObservation{}, ErrUnauthorized
}
func (*transportReader) ReleaseChannel(context.Context, Call) (ChannelObservation, error) {
	return ChannelObservation{}, ErrUnauthorized
}

type transportFoundation struct {
	successor *atomic.Bool
	unknown   bool
	effects   atomic.Int32
}

func (foundation *transportFoundation) ReconcileFoundation(ctx context.Context, call Call, request ReconcileFoundationRequest) (FoundationReceipt, error) {
	if err := call.Guard(ctx); err != nil {
		return FoundationReceipt{}, err
	}
	foundation.effects.Add(1)
	if foundation.unknown {
		return FoundationReceipt{}, ErrOutcomeUnknown
	}
	foundation.successor.Store(true)
	return FoundationReceipt{Cell: request.Cell, Stage: "applied"}, nil
}
func (*transportFoundation) EnsureSource(context.Context, Call, SourceRequest) (SourceReceipt, error) {
	return SourceReceipt{}, ErrUnauthorized
}
