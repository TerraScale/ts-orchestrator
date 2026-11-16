package rolloutexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

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
