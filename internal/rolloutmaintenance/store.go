// Package rolloutmaintenance holds a finite, node-pinned bootstrap transaction.
// An interrupted transaction never expires into permission for automatic rollout.
package rolloutmaintenance

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/gofrs/flock"
)

var ErrFenced = errors.New("TerraBase bootstrap transaction holds automatic execution")

const (
	Budget           = 60 * time.Second
	WriterLeaseTTL   = 6 * time.Second
	HomeLeaseTTL     = 10 * time.Second
	ActivationBudget = 10 * time.Second
	WriterWindow     = WriterLeaseTTL + HomeLeaseTTL + ActivationBudget
	SourceStopGrace  = 2 * time.Minute
	RecoveryBudget   = SourceStopGrace + WriterWindow + 30*time.Second
	verifyEvery      = 500 * time.Millisecond
	maxReason        = 1024
)

type Pin struct {
	Node        string `json:"node"`
	Service     string `json:"service"`
	Task        string `json:"task"`
	Fingerprint string `json:"fingerprint"`
	Image       string `json:"image"`
}

type Process struct {
	PID   uint32 `json:"pid"`
	Start uint64 `json:"start"`
}

type Exit struct {
	Observed bool   `json:"observed"`
	Code     uint32 `json:"code"`
	Signal   uint32 `json:"signal"`
}

func (e Exit) Clean() bool { return e.Observed && e.Code == 0 && e.Signal == 0 }

func (e Exit) String() string {
	if !e.Observed {
		return "exit status unobserved"
	}
	return fmt.Sprintf("exit code %d signal %d", e.Code, e.Signal)
}

type Job struct {
	Member        string    `json:"member"`
	ID            string    `json:"id"`
	Source        Pin       `json:"source"`
	Target        Pin       `json:"target"`
	Process       Process   `json:"process"`
	Owner         string    `json:"owner"`
	Epoch         int64     `json:"epoch"`
	Phase         string    `json:"phase"`
	Deadline      time.Time `json:"deadline"`
	SourceExit    Exit      `json:"sourceExit,omitzero"`
	AcceptUnclean bool      `json:"acceptUncleanExit,omitzero"`
	Reason        string    `json:"reason,omitzero"`
}

func (j Job) unresolved() bool {
	switch j.Phase {
	case "held", "quiescing", "stopping", "exited", "failing", "failed":
		return true
	}
	return false
}

func (j Job) Next() string {
	command := func(action string) string {
		return "ts-orch bootstrap-maintenance " + action + " --id " + j.ID
	}
	expired := !j.Deadline.IsZero() && !time.Now().Before(j.Deadline)
	switch {
	case j.Phase == "released":
		return command("clear") + ": NEW is the verified writer and ingress is released; this lifts the fence"
	case j.Phase == "failed":
		return command("clear") + ": the target is stopped and ingress is released; read the reason, then this lifts the fence and returns the service to Swarm"
	case j.Phase == "failing", expired:
		return command("recover") + ": verifies NEW as writer, or stops the target, releases ingress and ends failed"
	case j.Phase == "verified":
		return command("recover") + ": releases ingress for the verified writer"
	case j.Phase == "exited" && !j.SourceExit.Clean() && !j.AcceptUnclean:
		return command("replace") + " --accept-unclean-exit starts the target despite the " + j.SourceExit.String() + ", or " + command("recover") + " ends the job failed without starting it"
	case j.Phase == "held" && j.Deadline.IsZero():
		return command("replace") + " starts the 60 s replacement, or " + command("recover") + " ends the job failed with the source untouched"
	default:
		return command("replace") + " resumes before " + j.Deadline.UTC().Format(time.RFC3339) + ", or " + command("recover") + " ends it now"
	}
}

type Store struct{ root string }

func Open(state string) (*Store, error) {
	if !filepath.IsAbs(state) {
		return nil, errors.New("bootstrap state must be absolute")
	}
	root := filepath.Join(state, "terrabase-bootstrap")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func (s *Store) lock(ctx context.Context, shared bool) (func(), error) {
	l := flock.New(filepath.Join(s.root, "execution.lock"))
	var ok bool
	var err error
	if shared {
		ok, err = l.TryRLockContext(ctx, 10*time.Millisecond)
	} else {
		ok, err = l.TryLockContext(ctx, 10*time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ctx.Err()
	}
	return func() { _ = l.Unlock() }, nil
}

func (s *Store) read() (*Job, error) {
	f, err := os.Open(filepath.Join(s.root, "job.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	var job Job
	if err := protocol.DecodeStrict(data, &job, 64<<10); err != nil {
		return nil, err
	}
	if err := job.validate(); err != nil {
		return nil, err
	}
	return &job, nil
}

func validPin(p Pin) bool {
	_, digest, ok := strings.Cut(p.Image, "@sha256:")
	_, fingerprintErr := hex.DecodeString(p.Fingerprint)
	_, imageErr := hex.DecodeString(digest)
	return p.Node != "" && p.Service != "" && p.Task != "" && len(p.Fingerprint) == 64 && fingerprintErr == nil && ok && len(digest) == 64 && imageErr == nil
}
func (j Job) validate() error {
	targetValid := validPin(j.Target)
	if j.Target.Task == "" && j.Target.Fingerprint == "" && j.unresolved() {
		trial := j.Target
		trial.Task = "unassigned"
		trial.Fingerprint = j.Source.Fingerprint
		targetValid = validPin(trial)
	}
	if j.Phase != "held" && j.Deadline.IsZero() {
		return errors.New("bootstrap phase has no persisted deadline")
	}
	if j.Member == "" || j.ID == "" || len(j.ID) > 128 || !validPin(j.Source) || !targetValid || j.Source.Node != j.Target.Node || j.Source.Service != j.Target.Service || j.Source.Task == j.Target.Task || j.Source.Image == j.Target.Image || j.Process.PID == 0 || j.Process.Start == 0 || j.Owner == "" || j.Epoch < 1 {
		return errors.New("invalid pinned TerraBase bootstrap transaction")
	}
	if len(j.Reason) > maxReason || j.Phase == "failed" && j.Reason == "" {
		return errors.New("invalid bootstrap failure reason")
	}
	switch j.Phase {
	case "held", "preparing", "quiescing", "stopping", "exited", "starting", "verified", "released", "failing", "failed":
	default:
		return errors.New("invalid bootstrap phase")
	}
	return nil
}
func (s *Store) write(j Job) error {
	if err := j.validate(); err != nil {
		return err
	}
	data, err := protocol.EncodeJSON(j)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.root, ".job-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(s.root, "job.json")); err != nil {
		return err
	}
	d, err := os.Open(s.root)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// Arm is idempotent only for the exact retained job. It waits for any preexisting
// executor mutation to finish before recording the fence and returning proof.
func (s *Store) Arm(ctx context.Context, j Job) error {
	unlock, err := s.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	previous, err := s.read()
	if err != nil {
		return err
	}
	j.Phase = "held"
	j.Deadline = time.Time{}
	j.SourceExit = Exit{}
	j.Reason = ""
	if previous != nil {
		retained := *previous
		retained.Phase = "held"
		retained.Deadline = time.Time{}
		if j.Target.Task == "" {
			retained.Target.Task = ""
			retained.Target.Fingerprint = ""
		}
		if retained != j {
			return ErrFenced
		}
		return nil
	}
	return s.write(j)
}
func (s *Store) Status(ctx context.Context) (*Job, error) {
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.read()
}

// Enter fences every ordinary lifecycle mutation of the captured service, even
// if a newer intent changes its labels or task ID. The private grant is minted
// only by Driver; copied input JSON cannot authorize an executor mutation.
func (s *Store) Enter(ctx context.Context, pin Pin, terraBase bool, action string) (context.Context, func(), error) {
	if held, ok := ctx.Value(grantKey{}).(*grant); ok && held.store == s.root {
		if held.permits(pin, action) {
			return ctx, func() {}, nil
		}
		return ctx, func() {}, ErrFenced
	}
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return ctx, func() {}, err
	}
	j, err := s.read()
	if err != nil {
		unlock()
		return ctx, func() {}, err
	}
	if j != nil && (terraBase || pin.Service == j.Source.Service) {
		unlock()
		return ctx, func() {}, ErrFenced
	}
	return ctx, unlock, nil
}

func (s *Store) Publication(ctx context.Context, service string) error {
	if service != "terrabase" {
		return nil
	}
	j, err := s.Status(ctx)
	if err != nil {
		return err
	}
	if j != nil {
		return ErrFenced
	}
	return nil
}

type grantKey struct{}
type grant struct {
	store  string
	job    Job
	action string
}

func (g *grant) permits(p Pin, a string) bool {
	switch g.action {
	case "stop":
		return p == g.job.Source && a == "stop"
	case "halt":
		return p == g.job.Target && a == "stop"
	default:
		return p == g.job.Target && a == g.action
	}
}

type Runtime interface {
	Staged(context.Context, Job) error
	Resolve(context.Context, Job) (Pin, error)
	Prepare(context.Context, Pin) error
	Quiesce(context.Context, Job) error
	Release(context.Context, Job) error
	Abort(context.Context, Job) error
	Stop(context.Context, Pin) error
	Halt(context.Context, Pin) error
	Exited(context.Context, Pin, Process) (Exit, error)
	Start(context.Context, Pin) error
	Verify(context.Context, Job) error
}

type Driver struct {
	Store   *Store
	Runtime Runtime
}

func (d Driver) begin(ctx context.Context, id string) (*Job, func(), error) {
	if d.Store == nil || d.Runtime == nil {
		return nil, nil, errors.New("bootstrap driver unavailable")
	}
	operation := flock.New(filepath.Join(d.Store.root, "operator.lock"))
	ok, err := operation.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, ctx.Err()
	}
	j, err := d.Store.Status(ctx)
	if err == nil && (j == nil || j.ID != id) {
		err = ErrFenced
	}
	if err != nil {
		_ = operation.Unlock()
		return nil, nil, err
	}
	return j, func() { _ = operation.Unlock() }, nil
}

func (d Driver) save(ctx context.Context, j *Job) error {
	unlock, err := d.Store.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := d.Store.read()
	if err != nil {
		return err
	}
	if current == nil || current.ID != j.ID || current.Source != j.Source || current.Target.Task != "" && current.Target != j.Target {
		return ErrFenced
	}
	return d.Store.write(*j)
}

func (d Driver) phase(ctx context.Context, j *Job, name string) error {
	j.Phase = name
	return d.save(ctx, j)
}

func limitReason(reason string) string {
	if len(reason) > maxReason {
		return strings.ToValidUTF8(reason[:maxReason], "")
	}
	return reason
}

func (d Driver) note(ctx context.Context, j *Job, cause error) error {
	j.Reason = limitReason(cause.Error())
	journal, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return errors.Join(fmt.Errorf("%w; next: %s", cause, j.Next()), d.save(journal, j))
}

func (d Driver) act(ctx context.Context, j *Job, action string, p Pin, run func(context.Context, Pin) error) error {
	unlock, err := d.Store.lock(ctx, true)
	if err != nil {
		return err
	}
	defer unlock()
	return run(context.WithValue(ctx, grantKey{}, &grant{store: d.Store.root, job: *j, action: action}), p)
}

func (d Driver) verify(ctx context.Context, j *Job) error {
	window, cancel := context.WithTimeout(ctx, WriterWindow)
	defer cancel()
	for {
		err := d.Runtime.Verify(window, *j)
		if err == nil {
			return nil
		}
		select {
		case <-window.Done():
			return fmt.Errorf("NEW was not verified as the regional writer within its %s writer window: %w", WriterWindow, err)
		case <-time.After(verifyEvery):
		}
	}
}

func (d Driver) release(ctx context.Context, j *Job, reacquire bool) error {
	if reacquire {
		if err := d.Runtime.Quiesce(ctx, *j); err != nil {
			return err
		}
	}
	if err := d.Runtime.Release(ctx, *j); err != nil {
		return err
	}
	if err := d.Store.AbandonIngress(ctx, *j); err != nil {
		return err
	}
	return d.phase(ctx, j, "released")
}

func (d Driver) Replace(ctx context.Context, id string, acceptUnclean bool) error {
	j, done, err := d.begin(ctx, id)
	if err != nil {
		return err
	}
	defer done()
	switch j.Phase {
	case "released", "failing", "failed":
		return fmt.Errorf("bootstrap transaction is %s; next: %s: %w", j.Phase, j.Next(), ErrFenced)
	}
	if acceptUnclean && (j.Phase != "exited" || j.SourceExit.Clean()) {
		return errors.New("--accept-unclean-exit applies only to a journaled unclean source exit")
	}
	if j.Deadline.IsZero() {
		j.Deadline = time.Now().Add(Budget)
	}
	if !time.Now().Before(j.Deadline) {
		return fmt.Errorf("bootstrap budget expired at %s; next: %s: %w", j.Deadline.UTC().Format(time.RFC3339), j.Next(), ErrFenced)
	}
	ctx, cancel := context.WithDeadline(ctx, j.Deadline)
	defer cancel()
	j.AcceptUnclean = j.AcceptUnclean || acceptUnclean
	if err = d.save(ctx, j); err != nil {
		return err
	}
	if j.Phase == "verified" {
		return d.release(ctx, j, true)
	}
	if err = d.Runtime.Staged(ctx, *j); err != nil {
		return err
	}
	if err = d.phase(ctx, j, "quiescing"); err != nil {
		return err
	}
	if err = d.Runtime.Quiesce(ctx, *j); err != nil {
		return err
	}
	if err = d.phase(ctx, j, "stopping"); err != nil {
		return err
	}
	if err = d.act(ctx, j, "stop", j.Source, d.Runtime.Stop); err != nil {
		return err
	}
	exit, err := d.Runtime.Exited(ctx, j.Source, j.Process)
	if err != nil {
		return err
	}
	if !j.SourceExit.Observed {
		j.SourceExit = exit
	}
	if err = d.phase(ctx, j, "exited"); err != nil {
		return err
	}
	if !j.SourceExit.Clean() && !j.AcceptUnclean {
		return d.note(ctx, j, fmt.Errorf("source %s is not a clean storage shutdown; the target was not started", j.SourceExit))
	}
	if j.Target.Task == "" {
		var target Pin
		for {
			target, err = d.Runtime.Resolve(ctx, *j)
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return errors.Join(err, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		if !validPin(target) || target.Node != j.Source.Node || target.Service != j.Source.Service || target.Image != j.Target.Image || target.Task == j.Source.Task {
			return ErrFenced
		}
		j.Target = target
		if err = d.save(ctx, j); err != nil {
			return err
		}
	}
	if err = d.phase(ctx, j, "preparing"); err != nil {
		return err
	}
	if err = d.act(ctx, j, "prepare", j.Target, d.Runtime.Prepare); err != nil {
		return err
	}
	if err = d.phase(ctx, j, "starting"); err != nil {
		return err
	}
	if _, err = d.Runtime.Exited(ctx, j.Source, j.Process); err != nil {
		return err
	}
	if err = d.act(ctx, j, "start", j.Target, d.Runtime.Start); err != nil {
		return err
	}
	if err = d.verify(ctx, j); err != nil {
		return d.note(ctx, j, err)
	}
	j.Reason = ""
	if err = d.phase(ctx, j, "verified"); err != nil {
		return err
	}
	return d.release(ctx, j, false)
}

func (d Driver) Recover(ctx context.Context, id string) error {
	j, done, err := d.begin(ctx, id)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, RecoveryBudget)
	defer cancel()
	switch j.Phase {
	case "released", "failed":
		return nil
	case "verified":
		return d.release(ctx, j, true)
	case "starting":
		err = d.verify(ctx, j)
		if err == nil {
			j.Reason = ""
			if err = d.phase(ctx, j, "verified"); err != nil {
				return err
			}
			return d.release(ctx, j, true)
		}
		j.Reason = err.Error()
	}
	if j.Phase != "failing" {
		cause := j.Reason
		if cause == "" {
			cause = "the operator ended the job"
		}
		j.Reason = limitReason("recovered from " + j.Phase + ": " + cause)
		if err = d.phase(ctx, j, "failing"); err != nil {
			return err
		}
	}
	if j.Target.Task != "" {
		if err = d.act(ctx, j, "halt", j.Target, d.Runtime.Halt); err != nil {
			return err
		}
	}
	if err = d.Runtime.Abort(ctx, *j); err != nil {
		return err
	}
	if err = d.Store.AbandonIngress(ctx, *j); err != nil {
		return err
	}
	return d.phase(ctx, j, "failed")
}

// PinnedStop excludes legacy ownership handoff only inside the selected old
// controller's graceful stop, after Driver has acquired the ingress barrier.
func PinnedStop(ctx context.Context, p Pin) bool {
	g, ok := ctx.Value(grantKey{}).(*grant)
	return ok && (g.action == "stop" || g.action == "halt") && g.permits(p, "stop")
}
