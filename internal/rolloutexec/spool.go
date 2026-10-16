package rolloutexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	// DefaultSpoolDir is the relay's directory, inside the controller's
	// state directory: the newest verified step of the unit and the release
	// binary it names when the node has not staged it.
	DefaultSpoolDir = "/var/lib/terrascale-orchestrator-controller/rollout"
	// HostSpoolDir is the host agent's relay directory.
	HostSpoolDir         = "/var/lib/terrascale-orchestrator-host/rollout"
	spoolStep            = "step.json"
	spoolReleasePrefix   = "release-"
	defaultRelayInterval = 2 * time.Second
)

// ReplyFile is the root step agent's newest reply for systemdUnit, in the
// release root a controller and a host on one node share.
func ReplyFile(systemdUnit string) string {
	return "rollout-reply-" + strings.TrimSuffix(systemdUnit, ".service") + ".json"
}

// BinarySource writes the release binary with digest to dst.
type BinarySource func(ctx context.Context, digest string, dst io.Writer) error

// Relay runs in a unit's controller. It hands the unit's newest step to the
// node's root step agent through the spool directory, fetching the release
// binary the agent will stage, and posts the agent's reply back to the
// leader. The agent verifies every byte it is handed; the relay only moves
// them.
type Relay struct {
	// KV is the step board Run and Pass use; a host's relay, which gets its
	// steps over its session, calls Spool and Reply instead.
	KV          jetstream.KeyValue
	Cell        string
	Unit        string
	SystemdUnit string
	Leaders     trust.Keyring
	Dir         string
	// Layout is the node's release root, read only here.
	Layout selfupdate.Layout
	// Sources are tried in order for a release the node has not staged.
	Sources  []BinarySource
	Interval time.Duration
	Now      func() time.Time

	relayed []byte
}

// Run relays until ctx ends.
func (r *Relay) Run(ctx context.Context) error {
	if r.KV == nil || len(r.Leaders) == 0 || r.Dir == "" || !unitRE.MatchString(r.Unit) {
		return fmt.Errorf("%w: rollout step relay configuration", ErrInvalid)
	}
	if err := os.MkdirAll(r.Dir, 0o700); err != nil {
		return err
	}
	interval := r.Interval
	if interval <= 0 {
		interval = defaultRelayInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ctx := observability.StartTrace(ctx)
		if err := r.Pass(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "rollout step relay", "component", "rollout", "unit", r.Unit, "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Pass spools the unit's current step and relays the agent's reply once.
func (r *Relay) Pass(ctx context.Context) error {
	entry, err := r.KV.Get(ctx, StepKey(r.Unit))
	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound):
		err = nil // no step for this unit: the usual state between rollouts
	case err != nil:
		return err
	default:
		err = r.Spool(ctx, entry.Value())
	}
	return errors.Join(err, r.relayReply(ctx))
}

// Spool hands a current step to the agent, after the binary it names, so
// the agent rarely sees a step whose release is still downloading. A failed
// download still spools the step: the agent's retry reply tells the leader
// why nothing moves.
func (r *Relay) Spool(ctx context.Context, wire []byte) error {
	command, _, err := VerifyStepCommand(wire, r.Cell, r.Unit, r.Leaders, r.now())
	if err != nil {
		// Expired, or not this unit's: the leader posts a fresh one.
		return nil
	}
	path := filepath.Join(r.Dir, spoolStep)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, wire) {
		return nil
	}
	fetchErr := r.fetch(ctx, command.Digest)
	return errors.Join(fetchErr, writeFileAtomic(path, wire, 0o600))
}

// fetch spools the binary of digest unless the node already staged it, and
// removes every other spooled binary.
func (r *Relay) fetch(ctx context.Context, digest string) error {
	entries, err := os.ReadDir(r.Dir)
	if err != nil {
		return err
	}
	name := spoolReleasePrefix + digest
	for _, entry := range entries {
		if entry.Name() != name && (strings.HasPrefix(entry.Name(), spoolReleasePrefix) || strings.HasPrefix(entry.Name(), ".")) {
			_ = os.Remove(filepath.Join(r.Dir, entry.Name()))
		}
	}
	if _, err := os.Stat(r.Layout.BinaryPath(digest)); err == nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(r.Dir, name)); err == nil || len(r.Sources) == 0 {
		return nil
	}
	var failures []error
	for _, source := range r.Sources {
		err := writeVerified(ctx, filepath.Join(r.Dir, name), digest, source)
		if err == nil {
			return nil
		}
		failures = append(failures, err)
	}
	return fmt.Errorf("fetch release %s: %w", short(digest), errors.Join(failures...))
}

// Reply returns the agent's newest reply for the unit, nil when it has
// none.
func (r *Relay) Reply() ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(r.Layout.Root, ReplyFile(r.SystemdUnit)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var reply StepReply
	if len(data) > maxReplyBytes || json.Unmarshal(data, &reply) != nil || reply.Unit != r.Unit {
		return nil, fmt.Errorf("%w: rollout step reply", ErrInvalid)
	}
	return data, nil
}

// relayReply posts the agent's newest reply to the unit's reply key.
func (r *Relay) relayReply(ctx context.Context) error {
	data, err := r.Reply()
	if err != nil || data == nil || bytes.Equal(data, r.relayed) {
		return err
	}
	if _, err := r.KV.Put(ctx, ReplyKey(r.Unit), data); err != nil {
		return err
	}
	r.relayed = data
	return nil
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// writeVerified writes the binary of digest from source to path, keeping it
// only when its bytes hash to digest.
func writeVerified(ctx context.Context, path, digest string, source BinarySource) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".download-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	hash := sha256.New()
	if err := source(ctx, digest, &limitWriter{w: io.MultiWriter(file, hash), left: selfupdate.MaxBinaryBytes}); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("%w: fetched bytes differ from release %s", ErrInvalid, short(digest))
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

type limitWriter struct {
	w    io.Writer
	left int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.left {
		return 0, fmt.Errorf("%w: release exceeds %d bytes", ErrInvalid, selfupdate.MaxBinaryBytes)
	}
	l.left -= int64(len(p))
	return l.w.Write(p)
}

// ApplySpooled is the node's root step agent. The self-update watchdog runs
// it on every timer tick: it applies the unit's spooled step and writes the
// reply for the relay, so a step is retried until it is answered or
// expires. A step that does not verify (expired, another unit's, forged)
// is ignored rather than answered, so a stale copy never answers a later
// attempt of the same operation. The spool belongs to the unprivileged
// controller: everything in it is read beneath it (os.Root) and verified
// before use, and agent.Fetch stages from it through verifier.
func ApplySpooled(ctx context.Context, agent *Agent, dir string, verifier selfupdate.Verifier) error {
	spool, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer spool.Close()
	wire, err := readSpooled(spool, spoolStep, trust.MaxEnvelopeBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	command, expires, err := VerifyStepCommand(wire, agent.Cell, agent.Unit, agent.Leaders, agent.now())
	if err != nil {
		return nil
	}
	if verifier != nil {
		agent.Fetch = spoolFetcher{spool: spool, verifier: verifier, now: agent.now}
	}
	data, err := json.Marshal(agent.handle(ctx, command, expires))
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(agent.Layout.Root, ReplyFile(agent.SystemdUnit)), data, 0o644)
}

// spoolFetcher stages a release from the binary the relay spooled. Stage
// verifies the receipt, the exact size and the digest before it keeps a
// byte.
type spoolFetcher struct {
	spool    *os.Root
	verifier selfupdate.Verifier
	now      func() time.Time
}

func (f spoolFetcher) Fetch(_ context.Context, layout selfupdate.Layout, receipt, delegation []byte) (string, error) {
	verified, err := f.verifier.Verify(receipt, delegation, f.now())
	if err != nil {
		return "", fmt.Errorf("verify release receipt: %w", err)
	}
	file, err := openSpooled(f.spool, spoolReleasePrefix+verified.Receipt().SHA256)
	if err != nil {
		return "", err
	}
	defer file.Close()
	unlock, err := layout.Lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	return selfupdate.Stage(layout, file, receipt, delegation, f.verifier, f.now())
}

// openSpooled opens a regular file beneath the spool. O_NONBLOCK keeps a
// FIFO the controller put there from blocking the root agent.
func openSpooled(spool *os.Root, name string) (*os.File, error) {
	file, err := spool.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%w: spooled %s is not a regular file", ErrInvalid, name)
	}
	return file, nil
}

func readSpooled(spool *os.Root, name string, limit int64) ([]byte, error) {
	file, err := openSpooled(spool, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("%w: spooled %s is too large", ErrInvalid, name)
	}
	return data, err
}

// writeFileAtomic replaces path with data through a temporary file in the
// same directory.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
