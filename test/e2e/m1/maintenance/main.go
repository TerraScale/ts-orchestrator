package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
)

var started = time.Now()

func step(scenario, name string, err error) {
	if err != nil {
		fmt.Printf("FAIL %s: %s after %s: %v\n", scenario, name, time.Since(started).Round(time.Millisecond), err)
		os.Exit(1)
	}
	fmt.Printf("ok %s: %s at %s\n", scenario, name, time.Since(started).Round(time.Millisecond))
}

func check(ok bool, format string, args ...any) error {
	if ok {
		return nil
	}
	return fmt.Errorf(format, args...)
}

func standIn(address, node string, writerAfter time.Duration, exitCode int) {
	secret := os.Getenv("STAND_IN_PEER_CREDENTIAL")
	begun := time.Now()
	listener, err := net.Listen("tcp", net.JoinHostPort(address, "8081"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(70)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TerraBase-Peer-Credential") != secret {
			http.Error(w, "unknown peer credential", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/v1/rollout/status" {
			http.NotFound(w, r)
			return
		}
		writer := time.Since(begun) >= writerAfter
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"node":%q,"owner":%q,"epoch":1,"writer":%t,"ready":true}`, node, node, writer)
	})}
	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGTERM)
	go func() {
		<-terminate
		_ = listener.Close()
		os.Exit(exitCode)
	}()
	_ = server.Serve(listener)
	select {}
}

type process struct {
	cmd  *exec.Cmd
	done chan struct{}
}

type host struct {
	scenario, node, address, secret string
	writerAfter                     time.Duration
	edge                            *edge.Edge
	mu                              sync.Mutex
	processes                       map[string]*process
	target                          rolloutmaintenance.Pin
}

func (h *host) launch(task string, writerAfter time.Duration, exitCode int) (*process, error) {
	cmd := exec.Command(os.Args[0], "terrabase", h.address, h.node, writerAfter.String(), strconv.Itoa(exitCode))
	cmd.Env = append(os.Environ(), "STAND_IN_PEER_CREDENTIAL="+h.secret)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	h.mu.Lock()
	h.processes[task] = p
	h.mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(h.address, "8081"), time.Second)
		if err == nil {
			connection.Close()
			return p, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("stand-in TerraBase %s never listened: %w", task, err)
		}
		select {
		case <-p.done:
			return nil, fmt.Errorf("stand-in TerraBase %s exited before it listened", task)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (h *host) process(task string) *process {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.processes[task]
}

func (h *host) terminate(ctx context.Context, task string) error {
	p := h.process(task)
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return nil
	}
}

func (h *host) Staged(context.Context, rolloutmaintenance.Job) error { return nil }
func (h *host) Resolve(context.Context, rolloutmaintenance.Job) (rolloutmaintenance.Pin, error) {
	return h.target, nil
}
func (h *host) Prepare(context.Context, rolloutmaintenance.Pin) error { return nil }
func (h *host) Quiesce(ctx context.Context, j rolloutmaintenance.Job) error {
	return h.edge.Bootstrap(ctx, "hold", j)
}
func (h *host) Release(ctx context.Context, j rolloutmaintenance.Job) error {
	return h.edge.Bootstrap(ctx, "release", j)
}
func (h *host) Abort(ctx context.Context, j rolloutmaintenance.Job) error {
	return h.edge.Bootstrap(ctx, "abort", j)
}
func (h *host) Stop(ctx context.Context, p rolloutmaintenance.Pin) error {
	return h.terminate(ctx, p.Task)
}
func (h *host) Halt(ctx context.Context, p rolloutmaintenance.Pin) error {
	return h.terminate(ctx, p.Task)
}
func (h *host) Exited(_ context.Context, p rolloutmaintenance.Pin, retained rolloutmaintenance.Process) (rolloutmaintenance.Exit, error) {
	if current, err := identity(int(retained.PID)); err == nil && current == retained {
		return rolloutmaintenance.Exit{}, errors.New("retained source process is still alive")
	}
	proc := h.process(p.Task)
	if proc == nil {
		return rolloutmaintenance.Exit{}, nil
	}
	select {
	case <-proc.done:
	default:
		return rolloutmaintenance.Exit{}, errors.New("source has not been reaped")
	}
	status := proc.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if status.Signaled() {
		return rolloutmaintenance.Exit{Observed: true, Code: 128 + uint32(status.Signal()), Signal: uint32(status.Signal())}, nil
	}
	return rolloutmaintenance.Exit{Observed: true, Code: uint32(status.ExitStatus())}, nil
}
func (h *host) Start(_ context.Context, p rolloutmaintenance.Pin) error {
	if h.process(p.Task) != nil {
		return nil
	}
	_, err := h.launch(p.Task, h.writerAfter, 0)
	return err
}
func (h *host) Verify(ctx context.Context, j rolloutmaintenance.Job) error {
	p := h.process(j.Target.Task)
	if p == nil {
		return errors.New("pinned replacement was never started")
	}
	select {
	case <-p.done:
		return errors.New("pinned replacement is not running")
	default:
	}
	return h.edge.Bootstrap(ctx, "verify", j)
}

func identity(pid int) (rolloutmaintenance.Process, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return rolloutmaintenance.Process{}, err
	}
	end := strings.LastIndex(string(data), ") ")
	if end < 0 {
		return rolloutmaintenance.Process{}, errors.New("invalid process identity")
	}
	fields := strings.Fields(string(data)[end+2:])
	if len(fields) < 20 {
		return rolloutmaintenance.Process{}, errors.New("invalid process identity")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	return rolloutmaintenance.Process{PID: uint32(pid), Start: start}, err
}

func pin(task, image string) rolloutmaintenance.Pin {
	fingerprint := sha256.Sum256([]byte(task))
	digest := sha256.Sum256([]byte(image))
	return rolloutmaintenance.Pin{Node: "swarm-node-1", Service: "terrabase-service", Task: task, Fingerprint: hex.EncodeToString(fingerprint[:]), Image: "ghcr.io/terrascale/terrabase@sha256:" + hex.EncodeToString(digest[:])}
}

type lane struct {
	*host
	store  *rolloutmaintenance.Store
	driver rolloutmaintenance.Driver
	job    rolloutmaintenance.Job
}

func setup(work, scenario, node, address, secret string, writerAfter time.Duration, sourceExit int) *lane {
	state := filepath.Join(work, scenario)
	step(scenario, "state directory", os.MkdirAll(state, 0700))
	h := &host{scenario: scenario, node: node, address: address, secret: secret, writerAfter: writerAfter, processes: map[string]*process{}}
	h.edge = edge.New(state)
	step(scenario, "edge peer credential", h.edge.SetRequestProofSecret(secret))
	peers := []mesh.WorkerPeer{{Node: node, Address: address}}
	h.edge.SetRegionalNodes(func() []mesh.WorkerPeer { return peers })
	store, err := rolloutmaintenance.Open(state)
	step(scenario, "bootstrap journal", err)
	source := pin("old-"+scenario, "old")
	h.target = pin("new-"+scenario, "new")
	old, err := h.launch(source.Task, 0, sourceExit)
	step(scenario, "OLD stand-in TerraBase serves as the regional writer", err)
	retained, err := identity(old.cmd.Process.Pid)
	step(scenario, "OLD process identity", err)
	j := rolloutmaintenance.Job{Member: node, ID: "c44-" + scenario, Source: source, Target: rolloutmaintenance.Pin{Node: source.Node, Service: source.Service, Image: h.target.Image}, Process: retained, Owner: node, Epoch: 1}
	step(scenario, "arm", store.Arm(context.Background(), j))
	return &lane{host: h, store: store, driver: rolloutmaintenance.Driver{Store: store, Runtime: h}, job: j}
}

func (l *lane) journal() rolloutmaintenance.Job {
	j, err := l.store.Status(context.Background())
	if err == nil && j == nil {
		err = errors.New("no journaled transaction")
	}
	if err != nil {
		step(l.scenario, "read journal", err)
	}
	return *j
}

func (l *lane) ingressHeld() bool {
	held, err := l.store.Ingress(context.Background())
	if err != nil {
		step(l.scenario, "read ingress hold", err)
	}
	return held != nil
}

func (l *lane) running(task string) bool {
	p := l.process(task)
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func refused(err error, want ...string) error {
	if err == nil {
		return errors.New("succeeded, want a refusal")
	}
	for _, text := range want {
		if !strings.Contains(err.Error(), text) {
			return fmt.Errorf("refusal %q does not name %q", err, text)
		}
	}
	return nil
}

func (l *lane) clear() {
	step(l.scenario, "clear lifts the fence", l.store.Clear(context.Background(), l.job.ID))
	j, err := l.store.Status(context.Background())
	step(l.scenario, "no transaction remains after clear", errors.Join(err, check(j == nil, "journal still holds %+v", j)))
}

func expiredDeadline(work, secret string) {
	l := setup(work, "expired", "n1", "127.0.0.2", secret, time.Hour, 0)
	ctx := context.Background()
	id := l.job.ID
	err := l.driver.Replace(ctx, id, false)
	j := l.journal()
	step(l.scenario, "a stalled activation fails replace after its writer window, not after one probe", errors.Join(refused(err, "writer window", "next: ts-orch bootstrap-maintenance replace"),
		check(j.Phase == "starting" && strings.Contains(j.Reason, "writer=false ready=true"), "journal %s %q", j.Phase, j.Reason),
		check(j.SourceExit == rolloutmaintenance.Exit{Observed: true}, "source exit %+v", j.SourceExit),
		check(l.ingressHeld() && l.running(l.target.Task), "ingress held %t, NEW running %t", l.ingressHeld(), l.running(l.target.Task))))
	for attempt := 2; time.Now().Before(j.Deadline); attempt++ {
		err = l.driver.Replace(ctx, id, false)
		step(l.scenario, fmt.Sprintf("resumed replace %d still cannot verify the stalled NEW", attempt), refused(err))
	}
	err = l.driver.Replace(ctx, id, false)
	step(l.scenario, "replace past the deadline refuses and names recover", refused(err, "budget expired", "next: ts-orch bootstrap-maintenance recover --id "+id))
	step(l.scenario, "status names recover past the deadline", check(strings.HasPrefix(l.journal().Next(), "ts-orch bootstrap-maintenance recover --id "+id), "next %q", l.journal().Next()))
	step(l.scenario, "recover after the deadline", l.driver.Recover(ctx, id))
	j = l.journal()
	step(l.scenario, "recover ends failed: target stopped, ingress released, fence kept, reason journaled", errors.Join(
		check(j.Phase == "failed" && strings.HasPrefix(j.Reason, "recovered from starting: NEW was not verified"), "journal %s %q", j.Phase, j.Reason),
		check(!l.running(l.target.Task), "NEW still running"),
		check(!l.ingressHeld(), "ingress still held"),
		check(strings.HasPrefix(j.Next(), "ts-orch bootstrap-maintenance clear --id "+id), "next %q", j.Next())))
	step(l.scenario, "recover of a failed job is idempotent", l.driver.Recover(ctx, id))
	step(l.scenario, "replace of a failed job refuses", refused(l.driver.Replace(ctx, id, false), "is failed"))
	l.clear()
	_, err = l.launch("restarted-"+l.scenario, 0, 0)
	step(l.scenario, "a restarted writer serves", err)
	probe := l.job
	probe.ID = "c44-probe"
	probe.Phase = "held"
	err = l.edge.Bootstrap(ctx, "hold", probe)
	step(l.scenario, "the edge barrier was released: a new transaction can hold ingress", errors.Join(err, l.edge.Bootstrap(ctx, "abort", probe), check(!l.ingressHeld(), "probe hold remains")))
	step(l.scenario, "stop the restarted writer", l.terminate(ctx, "restarted-"+l.scenario))
}

func lateWriter(work, secret string) {
	l := setup(work, "late", "n2", "127.0.0.3", secret, rolloutmaintenance.WriterWindow+8*time.Second, 0)
	ctx := context.Background()
	id := l.job.ID
	err := l.driver.Replace(ctx, id, false)
	j := l.journal()
	step(l.scenario, "replace stops at starting while activation stalls past the writer window", errors.Join(refused(err, "writer window"), check(j.Phase == "starting" && l.ingressHeld(), "journal %s, ingress held %t", j.Phase, l.ingressHeld())))
	step(l.scenario, "recover verifies NEW once its activation completes", l.driver.Recover(ctx, id))
	j = l.journal()
	step(l.scenario, "ingress release is journaled after verified", errors.Join(
		check(j.Phase == "released" && j.Reason == "", "journal %s %q", j.Phase, j.Reason),
		check(!l.ingressHeld() && l.running(l.target.Task), "ingress held %t, NEW running %t", l.ingressHeld(), l.running(l.target.Task)),
		check(strings.HasPrefix(j.Next(), "ts-orch bootstrap-maintenance clear --id "+id), "next %q", j.Next())))
	step(l.scenario, "replace of a released job refuses", refused(l.driver.Replace(ctx, id, false), "is released"))
	l.clear()
	step(l.scenario, "stop NEW", l.terminate(ctx, l.target.Task))
}

func uncleanExit(work, secret string) {
	l := setup(work, "unclean", "n3", "127.0.0.4", secret, time.Second, 3)
	ctx := context.Background()
	id := l.job.ID
	step(l.scenario, "clear refuses an unfinished job", refused(l.store.Clear(ctx, id), "is held"))
	step(l.scenario, "the flag needs a journaled unclean exit", refused(l.driver.Replace(ctx, id, true), "applies only to a journaled unclean source exit"))
	err := l.driver.Replace(ctx, id, false)
	j := l.journal()
	step(l.scenario, "an unclean source exit stops before the target starts", errors.Join(refused(err, "exit code 3 signal 0 is not a clean storage shutdown", "--accept-unclean-exit"),
		check(j.Phase == "exited" && j.SourceExit == rolloutmaintenance.Exit{Observed: true, Code: 3}, "journal %s %+v", j.Phase, j.SourceExit),
		check(l.process(l.target.Task) == nil, "NEW was started")))
	step(l.scenario, "a resumed replace without the flag still refuses", refused(l.driver.Replace(ctx, id, false), "not a clean storage shutdown"))
	step(l.scenario, "replace --accept-unclean-exit", l.driver.Replace(ctx, id, true))
	j = l.journal()
	step(l.scenario, "the operator's flag is journaled and NEW is released as writer", errors.Join(
		check(j.Phase == "released" && j.AcceptUnclean && j.SourceExit.Code == 3, "journal %s accept=%t %+v", j.Phase, j.AcceptUnclean, j.SourceExit),
		check(!l.ingressHeld(), "ingress still held")))
	l.clear()
	step(l.scenario, "stop NEW", l.terminate(ctx, l.target.Task))
}

func main() {
	if len(os.Args) == 6 && os.Args[1] == "terrabase" {
		writerAfter, err := time.ParseDuration(os.Args[4])
		code, e := strconv.Atoi(os.Args[5])
		if err = errors.Join(err, e); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(64)
		}
		standIn(os.Args[2], os.Args[3], writerAfter, code)
		return
	}
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: maintenance WORK")
		os.Exit(64)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	secret := hex.EncodeToString(key)
	var scenarios sync.WaitGroup
	for _, run := range []func(string, string){expiredDeadline, lateWriter, uncleanExit} {
		scenarios.Go(func() { run(os.Args[1], secret) })
	}
	scenarios.Wait()
	fmt.Printf("ok bootstrap maintenance recovery at %s\n", time.Since(started).Round(time.Millisecond))
}
