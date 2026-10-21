//go:build fixturetest

package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// This exercises actual Unix peers, kernel witnesses and retained lease contexts.
// Its test authorizer does not prove installed marker/systemd/signed-source admission.
func TestRootOCICallerContinuity(t *testing.T) {
	if os.Getenv("TS_ROOT_OCI_CONTINUITY_CHILD") == "1" {
		runRootOCIContinuityChild(t)
		return
	}
	if os.Getenv("TS_ROOT_OCI_CONTINUITY_NAMESPACE") != "1" {
		runRootOCIContinuityNamespace(t)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	admission := &continuityAdmission{expires: time.Now().Add(2 * time.Minute)}
	defer admission.close()
	pool := &continuityPool{}
	service := newContinuityService(t, pool)
	listener, err := rootoci.Listen(ctx, service, admission.authorize, 65534)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	child := startRootOCIContinuityChild(t, ctx)
	admission.admit(t, t.Context(), child.command.Process.Pid)
	first := child.invoke(t)
	second := child.invoke(t)
	if first.Error != "" || second.Error != "" || len(first.View.SessionBindingSHA256) != 64 ||
		first.View.SessionBindingSHA256 != second.View.SessionBindingSHA256 ||
		!first.View.ExpiresAt.Equal(admission.expires) || !second.View.ExpiresAt.Equal(admission.expires) ||
		!first.View.OriginalDeadline.Before(first.View.ExpiresAt) || time.Until(first.View.OriginalDeadline) > 31*time.Second {
		t.Fatalf("fresh clients lost original caller/source continuity: first=%+v second=%+v", first, second)
	}
	if pool.count() != 2 {
		t.Fatal("same original caller did not reach the recording boundary twice")
	}
	// A successor lease for the same live peer cannot reuse the saved admission.
	admission.replace(t.Context())
	if result := child.invoke(t); result.Error == "" || pool.count() != 2 {
		t.Fatal("successor source/session reused the original reserved recording", result)
	}
	child.close(t)
	successor := startRootOCIContinuityChild(t, ctx)
	admission.admit(t, t.Context(), successor.command.Process.Pid)
	if result := successor.invoke(t); result.Error == "" || pool.count() != 2 {
		t.Fatal("replacement process reused the original reserved recording", result)
	}
	// Cancellation during the backend's wait must deny its final effect guard.
	pool.mu.Lock()
	pool.original = ""
	pool.entered, pool.release = make(chan struct{}), make(chan struct{})
	entered, release := pool.entered, pool.release
	pool.mu.Unlock()
	if _, err := io.WriteString(successor.input, "advance\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	admission.cancelLease()
	close(release)
	if result := successor.receive(t); result.Error == "" || pool.count() != 2 {
		t.Fatal("canceled original lease reached the recording effect", result)
	}
	successor.close(t)
	root, err := service.RootClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.Inventory(ctx); err != nil {
		t.Fatal("root-only observation was denied", err)
	}
	if _, err := root.AdvancePoolChild(ctx, continuityExpectation()); err == nil || pool.count() != 2 {
		t.Fatal("RootCall provided admitted caller authority", err)
	}
}

func TestRootOCICallerDisconnectCancelsOriginalCall(t *testing.T) {
	if os.Getenv("TS_ROOT_OCI_CONTINUITY_NAMESPACE") != "1" {
		runRootOCIContinuityNamespace(t)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	admission := &continuityAdmission{expires: time.Now().Add(2 * time.Minute)}
	defer admission.close()
	pool := &continuityPool{entered: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{}), finished: make(chan struct{})}
	release := sync.OnceFunc(func() { close(pool.release) })
	service := newContinuityService(t, pool)
	listener, err := rootoci.Listen(ctx, service, admission.authorize, 65534)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer release()
	child := startRootOCIContinuityChild(t, ctx)
	admission.admit(t, t.Context(), child.command.Process.Pid)
	if _, err := io.WriteString(child.input, "cancel\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pool.entered:
	case <-ctx.Done():
		t.Fatal("request did not reach the recording boundary", ctx.Err())
	}
	if _, err := io.WriteString(child.input, "cancel-now\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pool.canceled:
	case <-ctx.Done():
		t.Fatal("peer disconnect did not cancel the original backend context", ctx.Err())
	}
	release()
	select {
	case <-pool.finished:
	case <-ctx.Done():
		t.Fatal("canceled backend did not finish its final guard", ctx.Err())
	}
	if result := child.receive(t); result.Error == "" || !result.OutcomeUnknown || pool.count() != 0 {
		t.Fatal("canceled request reached a recording effect or lost its unknown outcome", result)
	}
	if _, err := io.WriteString(child.input, "observe\n"); err != nil {
		t.Fatal(err)
	}
	if result := child.receive(t); result.Error != "" || pool.count() != 0 {
		t.Fatal("request cancellation revoked its still-live source or replayed an effect", result)
	}
	child.close(t)
}

func newContinuityService(t *testing.T, pool *continuityPool) *rootoci.Service {
	t.Helper()
	service, err := rootoci.NewService(rootoci.Backends{
		Readers: &continuityReader{}, Capacity: pool,
		Foundations: &struct{ rootoci.Foundation }{}, Credentials: &struct{ rootoci.Credentials }{},
		NetBird: &struct{ rootoci.NetBird }{}, Releases: &struct{ rootoci.Releases }{},
		Volumes: &struct{ rootoci.VolumeReader }{}, Workloads: &struct{ rootoci.WorkloadCredentials }{},
		Backups: &struct{ rootoci.VolumeBackups }{}, ContainerMaterial: &struct{ rootoci.ContainerMaterial }{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type continuityAdmission struct {
	mu      sync.Mutex
	witness *rootoci.ProcessWitness
	lease   rootoci.Lease
	cancel  context.CancelFunc
	expires time.Time
}

func (a *continuityAdmission) admit(t *testing.T, ctx context.Context, pid int) {
	t.Helper()
	witness, err := rootoci.CaptureProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if witness.Peer().UID != 65534 || witness.Peer().GID != 65534 {
		_ = witness.Close()
		t.Fatal("fixture did not observe its actual nonroot child")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
		_ = a.witness.Close()
	}
	a.witness = witness
	a.replaceLocked(ctx)
}

func (a *continuityAdmission) replace(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.replaceLocked(ctx)
}

func (a *continuityAdmission) replaceLocked(ctx context.Context) {
	if a.cancel != nil {
		a.cancel()
	}
	session, cancel := context.WithDeadline(ctx, a.expires)
	a.cancel = cancel
	deadline, _ := session.Deadline()
	a.lease = rootoci.Lease{Context: session, Deadline: deadline,
		Binding:   fmt.Sprintf("%s:fixture-session:%p", a.witness.Binding(), session.Done()),
		RuntimeID: entityid.Derive("controller-runtime", a.witness.Binding())}
}

func (a *continuityAdmission) authorize(ctx context.Context, peer nativerootoci.Peer, _ rootoci.Operation) (rootoci.Lease, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.witness == nil || a.witness.Peer() != peer || a.witness.Verify() != nil || a.lease.Context.Err() != nil {
		return rootoci.Lease{}, rootoci.ErrUnauthorized
	}
	return a.lease, nil
}

func (a *continuityAdmission) cancelLease() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
}

func (a *continuityAdmission) close() {
	a.cancelLease()
	if a.witness != nil {
		_ = a.witness.Close()
	}
}

type continuityPool struct {
	rootoci.Pool
	mu               sync.Mutex
	original         string
	effects          int
	entered, release chan struct{}
	canceled         chan struct{}
	finished         chan struct{}
}

func (p *continuityPool) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.effects
}

// The recording effect is test-only; no SDK, accepted birth or saved wire is minted.
func (p *continuityPool) AdvancePoolChild(ctx context.Context, call rootoci.Call, _ rootoci.PoolChildExpectation) (rootoci.PoolChildView, error) {
	if p.finished != nil {
		defer close(p.finished)
	}
	digest, expires, err := call.AuthorityBindingSHA256(ctx)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	p.mu.Lock()
	if p.original == "" {
		p.original = digest
	}
	original, entered, release := p.original, p.entered, p.release
	p.mu.Unlock()
	if original != digest {
		return rootoci.PoolChildView{}, rootoci.ErrUnauthorized
	}
	if entered != nil {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			if p.canceled != nil {
				close(p.canceled)
				<-release
			}
		}
	}
	if err := call.Guard(ctx); err != nil {
		return rootoci.PoolChildView{}, err
	}
	p.mu.Lock()
	p.effects++
	p.mu.Unlock()
	return rootoci.PoolChildView{SessionBindingSHA256: digest, ExpiresAt: expires, OriginalDeadline: call.Deadline()}, nil
}

type continuityReader struct{ rootoci.Reader }

func (*continuityReader) Inventory(ctx context.Context, call rootoci.Call) (rootoci.InventoryObservation, error) {
	return rootoci.InventoryObservation{}, call.Guard(ctx)
}

func continuityExpectation() rootoci.PoolChildExpectation {
	id := entityid.Derive("continuity-boundary")
	return rootoci.PoolChildExpectation{Cell: "GRU", OperationID: id, ReservationID: id,
		RecipeSHA256: strings.Repeat("a", 64), GrantSHA256: strings.Repeat("b", 64), Generation: 1, Epoch: 1}
}

type continuityReply struct {
	View           rootoci.PoolChildView
	Error          string
	OutcomeUnknown bool
}

type continuityChild struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
	errors  bytes.Buffer
}

func startRootOCIContinuityChild(t *testing.T, ctx context.Context) *continuityChild {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := &continuityChild{command: exec.CommandContext(ctx, self, "-test.run=^TestRootOCICallerContinuity$", "-test.timeout=25s")}
	child.command.Env = append(os.Environ(), "TS_ROOT_OCI_CONTINUITY_CHILD=1")
	child.command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}, Pdeathsig: syscall.SIGKILL}
	child.command.Stderr = &child.errors
	child.input, err = child.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.output = bufio.NewScanner(output)
	if err := child.command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.command.Process.Kill(); _ = child.command.Wait() })
	return child
}

func (child *continuityChild) invoke(t *testing.T) continuityReply {
	t.Helper()
	if _, err := io.WriteString(child.input, "advance\n"); err != nil {
		t.Fatal(err)
	}
	return child.receive(t)
}

func (child *continuityChild) receive(t *testing.T) continuityReply {
	t.Helper()
	var result continuityReply
	if !child.output.Scan() || json.Unmarshal(child.output.Bytes(), &result) != nil {
		t.Fatalf("child response unavailable: %v", child.output.Err())
	}
	return result
}

func (child *continuityChild) close(t *testing.T) {
	t.Helper()
	_ = child.input.Close()
	if err := child.command.Wait(); err != nil {
		t.Fatalf("nonroot child failed: %v\n%s", err, child.errors.String())
	}
}

func runRootOCIContinuityChild(t *testing.T) {
	if os.Geteuid() != 65534 {
		t.Fatal("continuity caller is not nonroot")
	}
	commands := bufio.NewScanner(os.Stdin)
	for commands.Scan() {
		operation := commands.Text()
		client := rootoci.NewClient(rootoci.Expectations{Cell: "GRU", Epoch: 1})
		var view rootoci.PoolChildView
		var err error
		switch operation {
		case "advance":
			view, err = client.AdvancePoolChild(t.Context(), continuityExpectation())
		case "observe":
			_, err = client.Inventory(t.Context())
		case "cancel":
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan continuityReply, 1)
			go func() {
				view, err := client.AdvancePoolChild(ctx, continuityExpectation())
				result := continuityReply{View: view, OutcomeUnknown: errors.Is(err, rootoci.ErrOutcomeUnknown)}
				if err != nil {
					result.Error = err.Error()
				}
				done <- result
			}()
			valid := commands.Scan() && commands.Text() == "cancel-now"
			cancel()
			result := <-done
			_ = client.Close()
			if !valid {
				t.Fatal("cancellation command unavailable")
			}
			writeContinuityReply(t, result)
			continue
		default:
			_ = client.Close()
			t.Fatal("invalid fixture command")
		}
		_ = client.Close()
		result := continuityReply{View: view}
		if err != nil {
			result.Error = err.Error()
		}
		writeContinuityReply(t, result)
	}
	if err := commands.Err(); err != nil {
		t.Fatal(err)
	}
}

func writeContinuityReply(t *testing.T, result continuityReply) {
	t.Helper()
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stdout, string(wire)); err != nil {
		t.Fatal(err)
	}
}

func runRootOCIContinuityNamespace(t *testing.T) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const script = `set -eu
mount --make-rprivate /
mount -t tmpfs -o mode=0755 tmpfs /run
install -o 0 -g 0 -m 0755 "$1" /run/continuity.test
TS_ROOT_OCI_CONTINUITY_NAMESPACE=1 exec /run/continuity.test -test.v -test.run="^$2$" -test.timeout=30s
`
	args := []string{"unshare", "--mount", "--fork", "--kill-child=SIGKILL", "--", "/bin/sh", "-c", script, "ts-caller-continuity", self, t.Name()}
	if os.Geteuid() != 0 {
		args = append([]string{"sudo", "-n"}, args...)
	}
	command := exec.CommandContext(t.Context(), args[0], args[1:]...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated caller continuity fixture: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("--- PASS: "+t.Name())) {
		t.Fatal("isolated continuity fixture did not report its root result")
	}
	t.Log(string(output))
}
