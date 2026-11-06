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

const Budget = 60 * time.Second

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

type Job struct {
	Member   string    `json:"member"`
	ID       string    `json:"id"`
	Source   Pin       `json:"source"`
	Target   Pin       `json:"target"`
	Process  Process   `json:"process"`
	Owner    string    `json:"owner"`
	Epoch    int64     `json:"epoch"`
	Phase    string    `json:"phase"`
	Deadline time.Time `json:"deadline"`
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
	if j.Target.Task == "" && j.Target.Fingerprint == "" && (j.Phase == "held" || j.Phase == "quiescing" || j.Phase == "stopping" || j.Phase == "exited") {
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
	switch j.Phase {
	case "held", "preparing", "prepared", "quiescing", "stopping", "exited", "starting", "verified":
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
	if g.action == "stop" {
		return p == g.job.Source && a == "stop"
	}
	return p == g.job.Target && a == g.action
}

// Runtime keeps admitted task/image/secret verification in the normal executor.
// Exited must inspect the captured process identity; a missing API response is
// not evidence that its process has exited. Quiesce retains ingress until done.
type Runtime interface {
	Staged(context.Context, Job) error
	Resolve(context.Context, Job) (Pin, error)
	Prepare(context.Context, Pin) error
	Quiesce(context.Context, Job) (func(context.Context) error, error)
	Stop(context.Context, Pin) error
	Exited(context.Context, Pin, Process) error
	Start(context.Context, Pin) error
	Verify(context.Context, Job) error
}

type Driver struct {
	Store   *Store
	Runtime Runtime
}

// Replace serializes operators across reconnect/restart. Every phase is durable
// before its side effect; retries re-inspect physical state, never assume a lost
// response means exit. Deadline expiry retains the fence and never kills data.
func (d Driver) Replace(ctx context.Context, id string) error {
	if d.Store == nil || d.Runtime == nil {
		return errors.New("bootstrap driver unavailable")
	}
	operation := flock.New(filepath.Join(d.Store.root, "operator.lock"))
	ok, err := operation.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return err
	}
	if !ok {
		return ctx.Err()
	}
	defer operation.Unlock()
	j, err := d.Store.Status(ctx)
	if err != nil {
		return err
	}
	if j == nil || j.ID != id {
		return ErrFenced
	}

	if j.Deadline.IsZero() {
		j.Deadline = time.Now().Add(Budget)
	}
	if !time.Now().Before(j.Deadline) {
		return fmt.Errorf("bootstrap recovery budget exceeded; fence retained: %w", ErrFenced)
	}
	ctx, cancel := context.WithDeadline(ctx, j.Deadline)
	defer cancel()
	// Persist the budget even if assignment resolution or preparation fails.
	unlockBudget, e := d.Store.lock(ctx, false)
	if e != nil {
		return e
	}
	e = d.Store.write(*j)
	unlockBudget()
	if e != nil {
		return e
	}

	phase := func(name string) error {
		unlock, e := d.Store.lock(ctx, false)
		if e != nil {
			return e
		}
		defer unlock()
		current, e := d.Store.read()
		if e != nil {
			return e
		}
		if current == nil || current.ID != j.ID || current.Source != j.Source || current.Target != j.Target {
			return ErrFenced
		}
		j.Phase = name
		return d.Store.write(*j)
	}
	act := func(action string, p Pin, run func(context.Context, Pin) error) error {
		unlock, e := d.Store.lock(ctx, true)
		if e != nil {
			return e
		}
		defer unlock()
		cap := &grant{store: d.Store.root, job: *j, action: action}
		return run(context.WithValue(ctx, grantKey{}, cap), p)
	}
	if err = d.Runtime.Staged(ctx, *j); err != nil {
		return err
	}

	if err = phase("quiescing"); err != nil {
		return err
	}
	release, err := d.Runtime.Quiesce(ctx, *j)
	if err != nil {
		return err
	}
	// On resume, Stop is idempotent, but its exact old process identity must still
	// be inspected before Start. The private stop grant never covers Terminate.
	if err = phase("stopping"); err != nil {
		return err
	}
	if err = act("stop", j.Source, d.Runtime.Stop); err != nil {
		return err
	}
	if err = d.Runtime.Exited(ctx, j.Source, j.Process); err != nil {
		return err
	}
	if err = phase("exited"); err != nil {
		return err
	}
	// Swarm's normal STOP_FIRST updater can assign the candidate only once
	// the selected old task reports its verified physical exit. Every other
	// executor remains held; no task/spec is synthesized by this driver.
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
		unlock, e := d.Store.lock(ctx, false)
		if e != nil {
			return e
		}
		j.Target = target
		e = d.Store.write(*j)
		unlock()
		if e != nil {
			return e
		}
	}
	if err = phase("preparing"); err != nil {
		return err
	}
	if err = act("prepare", j.Target, d.Runtime.Prepare); err != nil {
		return err
	}
	if err = phase("starting"); err != nil {
		return err
	}
	if err = d.Runtime.Exited(ctx, j.Source, j.Process); err != nil {
		return err
	}
	if err = act("start", j.Target, d.Runtime.Start); err != nil {
		return err
	}
	if err = d.Runtime.Verify(ctx, *j); err != nil {
		return err
	}
	if err = phase("verified"); err != nil {
		return err
	}
	return release(ctx)
}

// PinnedStop excludes legacy ownership handoff only inside the selected old
// controller's graceful stop, after Driver has acquired the ingress barrier.
func PinnedStop(ctx context.Context, p Pin) bool {
	g, ok := ctx.Value(grantKey{}).(*grant)
	return ok && g.action == "stop" && g.permits(p, "stop")
}
