// Package node contains the small, privileged part of ts-node that installs
// signed release binaries and runs them with the native systemd manager.
//
// The package deliberately has no shell, container, NATS, or cloud
// dependency.  All effects other than signature verification are behind
// interfaces so a host install can be tested without a Linux host or a
// network connection.
package node

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// DefaultArtifactRoot is the immutable host-agent artifact directory.
	DefaultArtifactRoot = "/opt/terrascale"
	// DefaultUnitDirectory is the system manager's unit directory.
	DefaultUnitDirectory = "/etc/systemd/system"
	// SystemctlPath is intentionally not configurable in production.
	SystemctlPath = "/usr/bin/systemctl"
	// MaximumArtifactDownloadBytes bounds one HTTP artifact response. The
	// delivery verifier has the same bound for artifacts admitted in-process;
	// keeping the downloader bounded prevents an untrusted response from being
	// allocated without limit.
	MaximumArtifactDownloadBytes = 256 << 20
)

var pathToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var componentToken = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
var digestToken = regexp.MustCompile(`^[0-9a-f]{64}$`)
var memoryLimitToken = regexp.MustCompile(`^[0-9]+(?:[KMGTP]i?B?|B)$`)

// Artifact is a complete, immutable release candidate. Signature is over the
// exact binary bytes. Digest is accepted as a compatibility spelling for
// SHA256; if both are supplied they must be equal.
type Artifact struct {
	Component  string
	Version    string
	BinaryName string
	URL        string
	SHA256     string
	Digest     string
	Signature  []byte
	PublicKey  ed25519.PublicKey
	Arguments  []string

	RunAsUser  string
	RunAsGroup string
	DataDir    string
	CPUWeight  int
	MemoryMax  string
	IOWeight   int
	TasksMax   int
}

// ReleaseArtifact is the descriptive name used by the delivery API.
type ReleaseArtifact = Artifact

// ArtifactDownloader fetches bytes for one already-admitted artifact. It
// must not write to the filesystem; Delivery performs the atomic write.
type ArtifactDownloader interface {
	Download(context.Context, Artifact) ([]byte, error)
}

// DownloadFunc adapts a function to ArtifactDownloader.
type DownloadFunc func(context.Context, Artifact) ([]byte, error)

func (f DownloadFunc) Download(ctx context.Context, artifact Artifact) ([]byte, error) {
	return f(ctx, artifact)
}

// ProcessResult contains only bounded process status. Output is deliberately
// not used for authorization or state transitions.
type ProcessResult struct {
	ExitCode int
}

// ProcessRunner executes one absolute executable with one argument list.
// Implementations must never invoke a shell.
type ProcessRunner interface {
	Run(context.Context, string, []string) (ProcessResult, error)
}

// DrainCoordinator fences customer traffic while a unit is restarted.
type DrainCoordinator interface {
	BeginDrain(context.Context, string) error
	EndDrain(context.Context, string) error
}

// HealthGate is the post-restart readiness gate. A successful restart is not
// evidence of health.
type HealthGate interface {
	WaitHealthy(context.Context, string, string) error
}

// RecoveryState is the fail-closed reason persisted when a delivery cannot
// prove that the unit and activation are healthy. A non-empty value requires
// an explicit recovery operation; callers must not infer safety from a
// process restart alone.
type RecoveryState string

const (
	RecoveryNone              RecoveryState = ""
	RecoveryInterrupted       RecoveryState = "interrupted"
	RecoveryArtifactMissing   RecoveryState = "artifact_missing"
	RecoveryArtifactUntrusted RecoveryState = "artifact_untrusted"
	RecoveryUnitMissing       RecoveryState = "unit_missing"
	RecoveryActivationFailed  RecoveryState = "activation_failed"
	RecoveryRestartFailed     RecoveryState = "restart_failed"
	RecoveryHealthFailed      RecoveryState = "health_failed"
	RecoveryDrainFailed       RecoveryState = "drain_failed"
)

// RecoveryError identifies a fail-closed recovery boundary without exposing
// process output or secret-bearing paths.
type RecoveryError struct {
	State RecoveryState
	Err   error
}

func (e *RecoveryError) Error() string {
	if e == nil || e.Err == nil {
		return "node: delivery requires recovery"
	}
	return fmt.Sprintf("node: delivery requires recovery (%s): %v", e.State, e.Err)
}

func (e *RecoveryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// DrainFuncs adapts drain callbacks while retaining the explicit two-phase
// boundary in production code.
type DrainFuncs struct {
	Begin func(context.Context, string) error
	End   func(context.Context, string) error
}

func (f DrainFuncs) BeginDrain(ctx context.Context, component string) error {
	if f.Begin == nil {
		return errors.New("node: drain begin callback is unavailable")
	}
	return f.Begin(ctx, component)
}

func (f DrainFuncs) EndDrain(ctx context.Context, component string) error {
	if f.End == nil {
		return errors.New("node: drain end callback is unavailable")
	}
	return f.End(ctx, component)
}

// HealthFunc adapts a health callback.
type HealthFunc func(context.Context, string, string) error

func (f HealthFunc) WaitHealthy(ctx context.Context, component, version string) error {
	if f == nil {
		return errors.New("node: health callback is unavailable")
	}
	return f(ctx, component, version)
}

// SystemdHealthGate uses systemctl's read-only active-state query as a basic
// gate. Deployments needing application readiness should inject a HealthGate
// that additionally probes the component's private readiness endpoint.
type SystemdHealthGate struct{ Process ProcessRunner }

func (g SystemdHealthGate) WaitHealthy(ctx context.Context, component, _ string) error {
	if err := validateComponent(component); err != nil {
		return err
	}
	if g.Process == nil {
		return errors.New("node: health process runner is unavailable")
	}
	result, err := g.Process.Run(ctx, SystemctlPath, []string{"is-active", "--quiet", unitName(component)})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("node: %s is not active (exit code %d)", component, result.ExitCode)
	}
	return nil
}

// FileSystem is the complete filesystem seam needed by Delivery. Paths are
// passed individually so test implementations can reject traversal and track
// crash points.
type FileSystem interface {
	MkdirAll(string, os.FileMode) error
	ReadFile(string) ([]byte, error)
	WriteFile(string, []byte, os.FileMode) error
	Rename(string, string) error
	Symlink(string, string) error
	Readlink(string) (string, error)
	Remove(string) error
	Chmod(string, os.FileMode) error
}

// Config composes one node installer. ArtifactRoot and UnitDirectory are
// overridable only as test seams; production uses the two fixed defaults.
type Config struct {
	FileSystem          FileSystem
	Downloader          ArtifactDownloader
	Process             ProcessRunner
	Drain               DrainCoordinator
	Health              HealthGate
	ArtifactRoot        string
	UnitDirectory       string
	RollbackTimeout     time.Duration
	DrainCleanupTimeout time.Duration
}

// NodeConfig is an alias retained for callers composing the ts-node agent.
type NodeConfig = Config

// Delivery installs and activates one component at a time. Operations for
// different components may proceed independently; each component has a
// crash-safe serialized boundary.
type Delivery struct {
	fs                  FileSystem
	downloader          ArtifactDownloader
	process             ProcessRunner
	drain               DrainCoordinator
	health              HealthGate
	artifactRoot        string
	unitDirectory       string
	rollbackTimeout     time.Duration
	drainCleanupTimeout time.Duration
	locks               sync.Map // map[string]chan struct{}
}

// NewDelivery validates dependencies and creates an installer.
func NewDelivery(config Config) (*Delivery, error) {
	if config.FileSystem == nil {
		return nil, errors.New("node: filesystem is required")
	}
	if config.Downloader == nil {
		return nil, errors.New("node: downloader is required")
	}
	if config.Process == nil {
		return nil, errors.New("node: process runner is required")
	}
	if config.Drain == nil {
		return nil, errors.New("node: drain coordinator is required")
	}
	if config.Health == nil {
		return nil, errors.New("node: health gate is required")
	}
	root := config.ArtifactRoot
	if root == "" {
		root = DefaultArtifactRoot
	}
	units := config.UnitDirectory
	if units == "" {
		units = DefaultUnitDirectory
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(units) {
		return nil, errors.New("node: artifact and unit directories must be absolute")
	}
	if config.RollbackTimeout <= 0 {
		config.RollbackTimeout = 30 * time.Second
	}
	if config.DrainCleanupTimeout <= 0 {
		config.DrainCleanupTimeout = 30 * time.Second
	}
	return &Delivery{fs: config.FileSystem, downloader: config.Downloader,
		process: config.Process, drain: config.Drain, health: config.Health,
		artifactRoot: filepath.Clean(root), unitDirectory: filepath.Clean(units),
		rollbackTimeout: config.RollbackTimeout, drainCleanupTimeout: config.DrainCleanupTimeout}, nil
}

// Node is the host-agent delivery core.
type Node = Delivery

// NewNode composes the host-agent delivery core.
func NewNode(config NodeConfig) (*Node, error) { return NewDelivery(config) }

// VerifyArtifact verifies both the SHA-256 digest and Ed25519 signature.
func VerifyArtifact(artifact Artifact, payload []byte) error {
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	expected := artifact.SHA256
	if expected == "" {
		expected = artifact.Digest
	}
	if artifact.SHA256 != "" && artifact.Digest != "" && artifact.SHA256 != artifact.Digest {
		return errors.New("node: artifact digest fields disagree")
	}
	if !digestToken.MatchString(expected) || !strings.EqualFold(expected, digest) || expected != strings.ToLower(expected) {
		return fmt.Errorf("node: artifact SHA-256 mismatch (got %s)", digest)
	}
	if len(artifact.PublicKey) != ed25519.PublicKeySize || len(artifact.Signature) != ed25519.SignatureSize {
		return errors.New("node: artifact Ed25519 key or signature has the wrong length")
	}
	if !ed25519.Verify(artifact.PublicKey, payload, artifact.Signature) {
		return errors.New("node: artifact Ed25519 signature verification failed")
	}
	return nil
}

// ArtifactPath returns the deterministic executable path for an artifact.
func ArtifactPath(root string, artifact Artifact) (string, error) {
	if err := validateArtifactIdentity(artifact); err != nil {
		return "", err
	}
	name := artifact.BinaryName
	if name == "" {
		name = artifact.Component
	}
	return filepath.Join(root, artifact.Component, artifact.Version, name), nil
}

// CurrentPath returns the atomic activation symlink path.
func CurrentPath(root, component string) (string, error) {
	if err := validateComponent(component); err != nil {
		return "", err
	}
	return filepath.Join(root, component, "current"), nil
}

// Deliver downloads, verifies, installs and health-gates one release. A
// failed gate automatically restores the exact previously active artifact and
// its unit configuration.
// Repeating the same call after a crash converges from the durable symlink and
// journal rather than downloading or applying a second mutable release.
func (d *Delivery) Deliver(ctx context.Context, artifact Artifact) (returnErr error) {
	if ctx == nil {
		return errors.New("node: context must not be nil")
	}
	if d == nil {
		return errors.New("node: delivery is unavailable")
	}
	if err := validateArtifact(artifact); err != nil {
		return err
	}
	unlock, err := d.lock(ctx, artifact.Component)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	executable, err := ArtifactPath(d.artifactRoot, artifact)
	if err != nil {
		return err
	}
	componentRoot := filepath.Dir(filepath.Dir(executable))
	if err := d.fs.MkdirAll(componentRoot, 0755); err != nil {
		return fmt.Errorf("node: create artifact directory: %w", err)
	}
	if err := d.fs.MkdirAll(filepath.Dir(executable), 0755); err != nil {
		return fmt.Errorf("node: create artifact version directory: %w", err)
	}
	if err := d.ensureArtifact(ctx, artifact, executable); err != nil {
		return err
	}
	unit, err := d.unitPath(artifact.Component)
	if err != nil {
		return err
	}

	current, err := CurrentPath(d.artifactRoot, artifact.Component)
	if err != nil {
		return err
	}
	previous, hasPrevious, err := d.previousTarget(current)
	if err != nil {
		return err
	}
	currentTarget, hadCurrent := previous, hasPrevious
	journalPath := filepath.Join(componentRoot, ".delivery-state.json")
	pending, err := d.readState(journalPath)
	if err != nil {
		return err
	}
	if pending != nil && pending.Component == artifact.Component && pending.Drained {
		if err := d.finishDrain(ctx, journalPath, *pending); err != nil {
			return err
		}
		pending.Recovery = RecoveryNone
		pending.Drained = false
	}
	if pending != nil && pending.Component == artifact.Component && pending.Phase == "rollback_failed" {
		return fmt.Errorf("node: delivery for %s is pending recovery", pending.Target)
	}
	pendingActivation := pending != nil && pending.Component == artifact.Component &&
		pending.Target == artifact.Version &&
		(pending.Phase == "prepared" || pending.Phase == "switched") &&
		hadCurrent && sameVersionTarget(currentTarget, artifact.Version)
	if pending != nil && pending.Component == artifact.Component && pending.Target != artifact.Version &&
		(pending.Phase == "prepared" || pending.Phase == "switched" || pending.Phase == "rollback_failed") {
		return fmt.Errorf("node: delivery for %s is pending recovery", pending.Target)
	}
	if pendingActivation && pending.Previous != "" {
		if !pathToken.MatchString(pending.Previous) || pending.Previous == ".." {
			return errors.New("node: pending delivery has an invalid rollback target")
		}
		previous, hasPrevious = pending.Previous, true
	}
	if hasPrevious && sameVersionTarget(previous, artifact.Version) && !pendingActivation {
		return d.health.WaitHealthy(ctx, artifact.Component, artifact.Version)
	}

	unitText, err := renderUnit(d.artifactRoot, artifact)
	if err != nil {
		return err
	}
	trusted := cloneTrustRecords(nil)
	units := cloneUnitRecords(nil)
	if pending != nil {
		trusted = cloneTrustRecords(pending.Trusted)
		units = cloneUnitRecords(pending.Units)
	}
	trusted[artifact.Version] = trustRecordFor(artifact)
	units[artifact.Version] = unitText
	state := deliveryState{Component: artifact.Component, Target: artifact.Version, Trusted: trusted, Units: units}
	if hasPrevious {
		state.Previous = previous
	}
	if err := d.writeState(journalPath, state.withPhase("prepared")); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return d.persistRecovery(journalPath, state, RecoveryInterrupted, err)
	}
	if err := d.drain.BeginDrain(ctx, artifact.Component); err != nil {
		return d.persistRecovery(journalPath, state, recoveryStateForDrain(err), err)
	}
	drained := true
	defer func() {
		if drained {
			// A failed operation still has to release customer traffic. If the
			// release itself fails, persist that fact so a later retry can
			// converge instead of silently declaring the node active.
			if drainErr := d.finishDrain(context.WithoutCancel(ctx), journalPath, state); drainErr != nil {
				returnErr = errors.Join(returnErr, drainErr)
			}
		}
	}()
	state.Drained = true
	if err := d.writeState(journalPath, state.withPhase("prepared")); err != nil {
		return err
	}

	if !pendingActivation || !hasPrevious || !sameVersionTarget(previous, artifact.Version) {
		if err := d.writeUnit(unit, artifact); err != nil {
			return d.persistRecovery(journalPath, state, RecoveryActivationFailed, err)
		}
		if err := d.activate(current, artifact.Version); err != nil {
			return d.persistRecovery(journalPath, state, RecoveryActivationFailed, err)
		}
	} else if err := d.writeUnit(unit, artifact); err != nil {
		return d.persistRecovery(journalPath, state, RecoveryActivationFailed, err)
	}
	if err := d.writeState(journalPath, state.withPhase("switched")); err != nil {
		return d.recoverFailedActivation(ctx, artifact, current, previous, hasPrevious, journalPath, err)
	}
	if err := d.restart(ctx, artifact.Component); err != nil {
		return d.recoverFailedActivation(ctx, artifact, current, previous, hasPrevious, journalPath, err)
	}
	if err := d.health.WaitHealthy(ctx, artifact.Component, artifact.Version); err != nil {
		return d.recoverFailedActivation(ctx, artifact, current, previous, hasPrevious, journalPath, err)
	}
	if err := d.writeState(journalPath, state.withPhase("committed")); err != nil {
		return err
	}
	if err := d.finishDrain(ctx, journalPath, state.withPhase("committed")); err != nil {
		// If the recovery write itself failed, retain the in-process cleanup
		// obligation so the deferred attempt can still release the fence.
		drained = !d.drainRecoveryDurable(journalPath)
		return fmt.Errorf("node: release %s is healthy but drain ended with an error: %w", artifact.Version, err)
	}
	drained = false
	return nil
}

// Rollback selects a previously installed, locally trusted version, restores
// its exact systemd unit configuration atomically, restarts under drain, and
// requires that version to pass the same health gate. It is intentionally
// version-only: callers can roll back only to a safe path token already
// present in the durable trust record on this host.
func (d *Delivery) Rollback(ctx context.Context, component, version string) (returnErr error) {
	if ctx == nil {
		return errors.New("node: context must not be nil")
	}
	if d == nil {
		return errors.New("node: delivery is unavailable")
	}
	if err := validateComponent(component); err != nil {
		return err
	}
	if !pathToken.MatchString(version) || version == ".." {
		return errors.New("node: rollback version is not a safe path token")
	}
	unlock, err := d.lock(ctx, component)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := CurrentPath(d.artifactRoot, component)
	if err != nil {
		return err
	}
	componentRoot := filepath.Join(d.artifactRoot, component)
	journalPath := filepath.Join(componentRoot, ".delivery-state.json")
	pending, err := d.readState(journalPath)
	if err != nil {
		return err
	}
	if pending != nil && pending.Component == component && pending.Drained {
		if err := d.finishDrain(ctx, journalPath, *pending); err != nil {
			return err
		}
		pending.Recovery = RecoveryNone
		pending.Drained = false
	}
	if pending != nil && pending.Component == component && isRecoveryPending(pending.Phase) && !rollbackRecoveryRetry(pending, version) {
		return fmt.Errorf("node: delivery for %s is pending recovery", pending.Target)
	}
	targetArtifact, unitText, err := d.trustedRollbackTarget(component, version, pending)
	if err != nil {
		return d.persistRecovery(journalPath, rollbackState(component, version, pending), recoveryStateForError(err), err)
	}
	target, hasCurrent, err := d.previousTarget(current)
	if err != nil {
		return err
	}
	if hasCurrent && sameVersionTarget(target, version) {
		if err := d.health.WaitHealthy(ctx, component, version); err != nil {
			return d.persistRecovery(journalPath, rollbackState(component, version, pending), recoveryStateForHealth(err), err)
		}
		if pending != nil && pending.Phase == "rollback_failed" {
			state := rollbackState(component, version, pending)
			state.Recovery = RecoveryNone
			if err := d.writeState(journalPath, state.withPhase("committed")); err != nil {
				return err
			}
		}
		return nil
	}
	trusted := cloneTrustRecords(nil)
	units := cloneUnitRecords(nil)
	if pending != nil {
		trusted = cloneTrustRecords(pending.Trusted)
		units = cloneUnitRecords(pending.Units)
	}
	trusted[version] = trustRecordFor(targetArtifact)
	units[version] = unitText
	state := deliveryState{Component: component, Target: version, Action: "rollback", Trusted: trusted, Units: units}
	if hasCurrent {
		state.Previous = target
	}
	if err := d.writeState(journalPath, state.withPhase("prepared")); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return d.persistRecovery(journalPath, state, RecoveryInterrupted, err)
	}
	if err := d.drain.BeginDrain(ctx, component); err != nil {
		return d.persistRecovery(journalPath, state, recoveryStateForDrain(err), err)
	}
	drained := true
	defer func() {
		if drained {
			if drainErr := d.finishDrain(context.WithoutCancel(ctx), journalPath, state); drainErr != nil {
				returnErr = errors.Join(returnErr, drainErr)
			}
		}
	}()
	state.Drained = true
	if err := d.writeState(journalPath, state.withPhase("prepared")); err != nil {
		return err
	}
	unitPath, err := d.unitPath(component)
	if err != nil {
		return d.persistRecovery(journalPath, state, RecoveryActivationFailed, err)
	}
	if err := d.writeUnitContents(unitPath, unitText); err != nil {
		return d.persistRecovery(journalPath, state, RecoveryActivationFailed, err)
	}
	if err := d.activate(current, version); err != nil {
		return d.persistRecovery(journalPath, state, RecoveryActivationFailed, err)
	}
	if err := d.writeState(journalPath, state.withPhase("switched")); err != nil {
		return d.persistRecovery(journalPath, state, RecoveryActivationFailed, err)
	}
	if err := d.restart(ctx, component); err != nil {
		return d.persistRecovery(journalPath, state, recoveryStateForRestart(err), err)
	}
	if err := d.health.WaitHealthy(ctx, component, version); err != nil {
		return d.persistRecovery(journalPath, state, recoveryStateForHealth(err), err)
	}
	if err := d.writeState(journalPath, state.withPhase("committed")); err != nil {
		return err
	}
	if err := d.finishDrain(ctx, journalPath, state.withPhase("committed")); err != nil {
		drained = !d.drainRecoveryDurable(journalPath)
		return err
	}
	drained = false
	return nil
}

// RenderUnit exposes the deterministic hardened unit renderer for delivery
// evidence and offline tests.
func RenderUnit(root string, artifact Artifact) (string, error) {
	return renderUnit(root, artifact)
}

func (d *Delivery) ensureArtifact(ctx context.Context, artifact Artifact, executable string) error {
	if existing, err := d.fs.ReadFile(executable); err == nil {
		if verifyErr := VerifyArtifact(artifact, existing); verifyErr == nil {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("node: inspect artifact: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := d.downloader.Download(ctx, artifact)
	if err != nil {
		return fmt.Errorf("node: download %s/%s: %w", artifact.Component, artifact.Version, err)
	}
	if err := VerifyArtifact(artifact, payload); err != nil {
		return err
	}
	temp := executable + ".staging"
	if err := d.fs.WriteFile(temp, payload, 0755); err != nil {
		return fmt.Errorf("node: stage artifact: %w", err)
	}
	if err := d.fs.Chmod(temp, 0755); err != nil {
		return fmt.Errorf("node: chmod artifact: %w", err)
	}
	if err := d.fs.Rename(temp, executable); err != nil {
		return fmt.Errorf("node: commit artifact: %w", err)
	}
	return nil
}

func (d *Delivery) activate(current, version string) error {
	temp := current + ".staging"
	_ = d.fs.Remove(temp)
	if err := d.fs.Symlink(version, temp); err != nil {
		return fmt.Errorf("node: stage current symlink: %w", err)
	}
	if err := d.fs.Rename(temp, current); err != nil {
		return fmt.Errorf("node: activate current symlink: %w", err)
	}
	return nil
}

func (d *Delivery) recoverFailedActivation(ctx context.Context, artifact Artifact, current, previous string, hasPrevious bool, journalPath string, cause error) error {
	if !hasPrevious {
		_ = d.writeState(journalPath, deliveryState{Component: artifact.Component, Target: artifact.Version, Phase: "failed", Recovery: recoveryStateForError(cause)})
		return fmt.Errorf("node: activation failed and no rollback target exists: %w", cause)
	}
	state, stateErr := d.readState(journalPath)
	if stateErr != nil {
		return errors.Join(cause, &RecoveryError{State: RecoveryArtifactUntrusted, Err: stateErr})
	}
	_, unitText, targetErr := d.trustedRollbackTarget(artifact.Component, previous, state)
	if targetErr != nil {
		return d.persistRecovery(journalPath, stateOrDeliveryState(state, artifact, previous), recoveryStateForError(targetErr), errors.Join(cause, targetErr))
	}
	recoveryCtx, cancel := context.WithTimeout(context.Background(), d.rollbackTimeout)
	defer cancel()
	unitPath, unitErr := d.unitPath(artifact.Component)
	if unitErr != nil {
		return d.persistRecovery(journalPath, stateOrDeliveryState(state, artifact, previous), RecoveryActivationFailed, errors.Join(cause, unitErr))
	}
	if unitErr := d.writeUnitContents(unitPath, unitText); unitErr != nil {
		_ = d.writeState(journalPath, deliveryState{Component: artifact.Component, Target: artifact.Version, Previous: previous, Phase: "rollback_failed", Recovery: RecoveryActivationFailed, Trusted: stateTrusted(state), Units: stateUnits(state)})
		return errors.Join(cause, &RecoveryError{State: RecoveryActivationFailed, Err: unitErr})
	}
	if err := d.activate(current, previous); err != nil {
		return d.persistRecovery(journalPath, stateOrDeliveryState(state, artifact, previous), RecoveryActivationFailed, errors.Join(cause, err))
	}
	if err := d.restart(recoveryCtx, artifact.Component); err != nil {
		return d.persistRecovery(journalPath, stateOrDeliveryState(state, artifact, previous), recoveryStateForRestart(err), errors.Join(cause, err))
	}
	if err := d.health.WaitHealthy(recoveryCtx, artifact.Component, previous); err != nil {
		return d.persistRecovery(journalPath, stateOrDeliveryState(state, artifact, previous), recoveryStateForHealth(err), errors.Join(cause, err))
	}
	rolledBack := stateOrDeliveryState(state, artifact, previous)
	rolledBack.Recovery = RecoveryNone
	_ = d.writeState(journalPath, rolledBack.withPhase("rolled_back"))
	return fmt.Errorf("node: release %s was rolled back: %w", artifact.Version, cause)
}

func (d *Delivery) persistRecovery(path string, state deliveryState, recovery RecoveryState, cause error) error {
	state.Phase = "rollback_failed"
	state.Recovery = recovery
	if err := d.writeState(path, state); err != nil {
		return errors.Join(&RecoveryError{State: recovery, Err: cause}, fmt.Errorf("node: persist recovery state: %w", err))
	}
	return &RecoveryError{State: recovery, Err: cause}
}

// finishDrain releases the traffic fence and records the result durably. The
// latest journal is loaded first because an error path may have completed an
// automatic rollback after the caller's in-memory state was created.
func (d *Delivery) finishDrain(ctx context.Context, path string, state deliveryState) error {
	if latest, err := d.readState(path); err == nil && latest != nil {
		state = *latest
	}
	state.Drained = true
	cleanupContext := context.WithoutCancel(ctx)
	cleanupTimeout := d.drainCleanupTimeout
	if cleanupTimeout <= 0 {
		cleanupTimeout = 30 * time.Second
	}
	cleanupContext, cancel := context.WithTimeout(cleanupContext, cleanupTimeout)
	defer cancel()
	endResult := make(chan error, 1)
	go func() { endResult <- d.drain.EndDrain(cleanupContext, state.Component) }()
	var endErr error
	select {
	case endErr = <-endResult:
	case <-cleanupContext.Done():
		endErr = cleanupContext.Err()
	}
	if endErr != nil {
		state.Recovery = RecoveryDrainFailed
		if persistErr := d.writeState(path, state); persistErr != nil {
			return errors.Join(&RecoveryError{State: RecoveryDrainFailed, Err: endErr}, fmt.Errorf("node: persist drain recovery state: %w", persistErr))
		}
		return &RecoveryError{State: RecoveryDrainFailed, Err: endErr}
	}
	state.Drained = false
	if state.Recovery == RecoveryDrainFailed {
		state.Recovery = RecoveryNone
	}
	if err := d.writeState(path, state); err != nil {
		return fmt.Errorf("node: persist drain completion state: %w", err)
	}
	return nil
}

func (d *Delivery) drainRecoveryDurable(path string) bool {
	state, err := d.readState(path)
	return err == nil && state != nil && state.Drained && state.Recovery == RecoveryDrainFailed
}

func recoveryStateForError(err error) RecoveryState {
	if err == nil {
		return RecoveryNone
	}
	var recovery *RecoveryError
	if errors.As(err, &recovery) && recovery != nil && recovery.State != RecoveryNone {
		return recovery.State
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return RecoveryInterrupted
	}
	return RecoveryHealthFailed
}

func recoveryStateForHealth(err error) RecoveryState {
	return recoveryStateForError(err)
}

func recoveryStateForRestart(err error) RecoveryState {
	if state := recoveryStateForError(err); state == RecoveryInterrupted || state != RecoveryHealthFailed {
		return state
	}
	return RecoveryRestartFailed
}

func recoveryStateForDrain(err error) RecoveryState {
	if state := recoveryStateForError(err); state == RecoveryInterrupted || state != RecoveryHealthFailed {
		return state
	}
	return RecoveryDrainFailed
}

func isRecoveryPending(phase string) bool {
	return phase == "prepared" || phase == "switched" || phase == "rollback_failed"
}

func rollbackRecoveryRetry(state *deliveryState, version string) bool {
	if state == nil || state.Phase != "rollback_failed" {
		return false
	}
	return state.Target == version || state.Previous == version
}

func (d *Delivery) restart(ctx context.Context, component string) error {
	if _, err := d.unitPath(component); err != nil {
		return err
	}
	for _, call := range [][2]any{{"daemon-reload", ""}, {"restart", unitName(component)}} {
		args := []string{call[0].(string)}
		if call[1].(string) != "" {
			args = append(args, call[1].(string))
		}
		result, runErr := d.process.Run(ctx, SystemctlPath, args)
		if runErr != nil {
			return runErr
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("node: systemctl %s failed with exit code %d", args[0], result.ExitCode)
		}
	}
	return nil
}

func (d *Delivery) writeUnit(path string, artifact Artifact) error {
	unit, err := renderUnit(d.artifactRoot, artifact)
	if err != nil {
		return err
	}
	return d.writeUnitContents(path, unit)
}

func (d *Delivery) writeUnitContents(path, unit string) error {
	if err := d.fs.MkdirAll(d.unitDirectory, 0755); err != nil {
		return err
	}
	temp := path + ".staging"
	_ = d.fs.Remove(temp)
	if err := d.fs.WriteFile(temp, []byte(unit), 0644); err != nil {
		return fmt.Errorf("node: stage systemd unit: %w", err)
	}
	if err := d.fs.Chmod(temp, 0644); err != nil {
		return err
	}
	if err := d.fs.Rename(temp, path); err != nil {
		return fmt.Errorf("node: commit systemd unit: %w", err)
	}
	return nil
}

func renderUnit(root string, artifact Artifact) (string, error) {
	if err := validateArtifact(artifact); err != nil {
		return "", err
	}
	dataDir := artifact.DataDir
	if dataDir == "" {
		dataDir = filepath.Join("/var/lib/terrascale", artifact.Component)
	}
	if !filepath.IsAbs(dataDir) || strings.ContainsAny(dataDir, "\r\n") {
		return "", errors.New("node: data directory must be an absolute path")
	}
	cleanDataDir := filepath.Clean(dataDir)
	if cleanDataDir != dataDir || (cleanDataDir != "/var/lib/terrascale" &&
		!strings.HasPrefix(cleanDataDir, "/var/lib/terrascale/")) {
		return "", errors.New("node: data directory must be under /var/lib/terrascale")
	}
	user, group := artifact.RunAsUser, artifact.RunAsGroup
	if user == "" {
		user = "terrascale-" + artifact.Component
	}
	if group == "" {
		group = "terrascale-" + artifact.Component
	}
	if !pathToken.MatchString(user) || !pathToken.MatchString(group) {
		return "", errors.New("node: systemd user and group must be safe tokens")
	}
	if artifact.CPUWeight == 0 {
		artifact.CPUWeight = 100
	}
	if artifact.IOWeight == 0 {
		artifact.IOWeight = 100
	}
	if artifact.TasksMax == 0 {
		artifact.TasksMax = 512
	}
	if artifact.CPUWeight < 1 || artifact.CPUWeight > 10000 || artifact.IOWeight < 1 || artifact.IOWeight > 10000 || artifact.TasksMax < 1 {
		return "", errors.New("node: invalid systemd resource limit")
	}
	if artifact.MemoryMax == "" {
		artifact.MemoryMax = "1G"
	}
	if !memoryLimitToken.MatchString(artifact.MemoryMax) {
		return "", errors.New("node: memory limit is not a safe systemd value")
	}
	name := artifact.BinaryName
	if name == "" {
		name = artifact.Component
	}
	args := []string{filepath.Join(root, artifact.Component, "current", name)}
	for _, argument := range artifact.Arguments {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return "", errors.New("node: systemd argument contains a control character")
		}
		args = append(args, argument)
	}
	quoted := make([]string, len(args))
	for i, argument := range args {
		quoted[i] = quoteSystemd(argument)
	}
	return fmt.Sprintf("[Unit]\nDescription=TerraScale %s\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=exec\nUser=%s\nGroup=%s\nExecStart=%s\nRestart=always\nRestartSec=5s\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nCapabilityBoundingSet=\nSystemCallFilter=@system-service\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nReadWritePaths=%s\nCPUWeight=%d\nMemoryMax=%s\nIOWeight=%d\nTasksMax=%d\n\n[Install]\nWantedBy=multi-user.target\n", artifact.Component, user, group, strings.Join(quoted, " "), dataDir, artifact.CPUWeight, artifact.MemoryMax, artifact.IOWeight, artifact.TasksMax), nil
}

func quoteSystemd(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, `$`, `\$`)
	value = strings.ReplaceAll(value, "`", "\\`")
	return `"` + value + `"`
}

func (d *Delivery) previousTarget(current string) (string, bool, error) {
	target, err := d.fs.Readlink(current)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("node: inspect current symlink: %w", err)
	}
	if !pathToken.MatchString(target) || target == ".." {
		return "", false, errors.New("node: current symlink target is invalid")
	}
	return target, true, nil
}

func (d *Delivery) unitPath(component string) (string, error) {
	if err := validateComponent(component); err != nil {
		return "", err
	}
	return filepath.Join(d.unitDirectory, unitName(component)), nil
}

func unitName(component string) string { return "terrascale-" + component + ".service" }

func (d *Delivery) writeState(path string, state deliveryState) error {
	contents, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temp := path + ".staging"
	_ = d.fs.Remove(temp)
	if err := d.fs.WriteFile(temp, contents, 0600); err != nil {
		return err
	}
	if err := d.fs.Chmod(temp, 0600); err != nil {
		return err
	}
	return d.fs.Rename(temp, path)
}

func (d *Delivery) readState(path string) (*deliveryState, error) {
	contents, err := d.fs.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("node: inspect delivery state: %w", err)
	}
	var state deliveryState
	if err := json.Unmarshal(contents, &state); err != nil {
		return nil, fmt.Errorf("node: delivery state is corrupt: %w", err)
	}
	if err := validateComponent(state.Component); err != nil ||
		!pathToken.MatchString(state.Target) || (state.Previous != "" && !pathToken.MatchString(state.Previous)) {
		return nil, errors.New("node: delivery state contains an unsafe path token")
	}
	for version, record := range state.Trusted {
		if !pathToken.MatchString(version) || version == ".." || record.Component != state.Component || record.Version != version || !pathToken.MatchString(record.BinaryName) || record.BinaryName == "." || record.BinaryName == ".." || !digestToken.MatchString(record.SHA256) || len(record.PublicKey) != ed25519.PublicKeySize || len(record.Signature) != ed25519.SignatureSize {
			return nil, errors.New("node: delivery trust record is invalid")
		}
	}
	for version, unit := range state.Units {
		if !pathToken.MatchString(version) || version == ".." || unit == "" {
			return nil, errors.New("node: delivery unit record is invalid")
		}
	}
	return &state, nil
}

type artifactTrustRecord struct {
	Component  string `json:"component"`
	Version    string `json:"version"`
	BinaryName string `json:"binaryName"`
	SHA256     string `json:"sha256"`
	Signature  []byte `json:"signature"`
	PublicKey  []byte `json:"publicKey"`
}

type deliveryState struct {
	Component string                         `json:"component"`
	Target    string                         `json:"target"`
	Previous  string                         `json:"previous,omitempty"`
	Phase     string                         `json:"phase"`
	Action    string                         `json:"action,omitempty"`
	Recovery  RecoveryState                  `json:"recovery,omitempty"`
	Drained   bool                           `json:"drained,omitempty"`
	Trusted   map[string]artifactTrustRecord `json:"trusted,omitempty"`
	Units     map[string]string              `json:"units,omitempty"`
}

func (s deliveryState) withPhase(phase string) deliveryState { s.Phase = phase; return s }

func trustRecordFor(artifact Artifact) artifactTrustRecord {
	digest := artifact.SHA256
	if digest == "" {
		digest = artifact.Digest
	}
	name := artifact.BinaryName
	if name == "" {
		name = artifact.Component
	}
	return artifactTrustRecord{Component: artifact.Component, Version: artifact.Version, BinaryName: name, SHA256: digest, Signature: append([]byte(nil), artifact.Signature...), PublicKey: append([]byte(nil), artifact.PublicKey...)}
}

func cloneTrustRecords(records map[string]artifactTrustRecord) map[string]artifactTrustRecord {
	cloned := make(map[string]artifactTrustRecord, len(records))
	for version, record := range records {
		record.Signature = append([]byte(nil), record.Signature...)
		record.PublicKey = append([]byte(nil), record.PublicKey...)
		cloned[version] = record
	}
	return cloned
}

func cloneUnitRecords(records map[string]string) map[string]string {
	cloned := make(map[string]string, len(records))
	for version, unit := range records {
		cloned[version] = unit
	}
	return cloned
}

func stateTrusted(state *deliveryState) map[string]artifactTrustRecord {
	if state == nil {
		return nil
	}
	return cloneTrustRecords(state.Trusted)
}

func stateUnits(state *deliveryState) map[string]string {
	if state == nil {
		return nil
	}
	return cloneUnitRecords(state.Units)
}

func stateOrDeliveryState(state *deliveryState, artifact Artifact, previous string) deliveryState {
	if state != nil {
		return *state
	}
	return deliveryState{Component: artifact.Component, Target: artifact.Version, Previous: previous}
}

func rollbackState(component, version string, pending *deliveryState) deliveryState {
	state := deliveryState{Component: component, Target: version, Action: "rollback"}
	if pending != nil {
		state.Trusted = cloneTrustRecords(pending.Trusted)
		state.Units = cloneUnitRecords(pending.Units)
	}
	return state
}

func (d *Delivery) trustedRollbackTarget(component, version string, state *deliveryState) (Artifact, string, error) {
	if state == nil {
		return Artifact{}, "", &RecoveryError{State: RecoveryArtifactUntrusted, Err: errors.New("node: rollback target has no signed-manifest trust record")}
	}
	record, ok := state.Trusted[version]
	if !ok {
		return Artifact{}, "", &RecoveryError{State: RecoveryArtifactUntrusted, Err: errors.New("node: rollback target has no signed-manifest trust record")}
	}
	if record.Component != component || record.Version != version {
		return Artifact{}, "", &RecoveryError{State: RecoveryArtifactUntrusted, Err: errors.New("node: rollback trust record does not match target")}
	}
	artifact := Artifact{Component: component, Version: version, BinaryName: record.BinaryName, SHA256: record.SHA256, Signature: record.Signature, PublicKey: record.PublicKey}
	executable, err := ArtifactPath(d.artifactRoot, artifact)
	if err != nil {
		return Artifact{}, "", &RecoveryError{State: RecoveryArtifactUntrusted, Err: err}
	}
	payload, err := d.fs.ReadFile(executable)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Artifact{}, "", &RecoveryError{State: RecoveryArtifactMissing, Err: errors.New("node: rollback target artifact is missing")}
		}
		return Artifact{}, "", &RecoveryError{State: RecoveryArtifactUntrusted, Err: fmt.Errorf("node: inspect rollback artifact: %w", err)}
	}
	if err := VerifyArtifact(artifact, payload); err != nil {
		return Artifact{}, "", &RecoveryError{State: RecoveryArtifactUntrusted, Err: fmt.Errorf("node: rollback target artifact is not trusted: %w", err)}
	}
	unit, ok := state.Units[version]
	if !ok || unit == "" {
		return Artifact{}, "", &RecoveryError{State: RecoveryUnitMissing, Err: errors.New("node: rollback target has no trusted systemd unit configuration")}
	}
	return artifact, unit, nil
}

func (d *Delivery) lock(ctx context.Context, component string) (func(), error) {
	value, _ := d.locks.LoadOrStore(component, make(chan struct{}, 1))
	lock := value.(chan struct{})
	select {
	case lock <- struct{}{}:
		return func() { <-lock }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func sameVersionTarget(target, version string) bool {
	return target == version || target == filepath.Base(version)
}

func validateArtifact(artifact Artifact) error {
	if err := validateArtifactIdentity(artifact); err != nil {
		return err
	}
	if artifact.SHA256 == "" && artifact.Digest == "" {
		return errors.New("node: artifact SHA-256 digest is required")
	}
	if artifact.SHA256 != "" && !digestToken.MatchString(artifact.SHA256) {
		return errors.New("node: artifact SHA-256 must be lowercase hex")
	}
	if artifact.Digest != "" && !digestToken.MatchString(artifact.Digest) {
		return errors.New("node: artifact digest must be lowercase hex")
	}
	for _, argument := range artifact.Arguments {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("node: artifact argument contains a control character")
		}
	}
	return nil
}

func validateArtifactIdentity(artifact Artifact) error {
	if err := validateComponent(artifact.Component); err != nil {
		return err
	}
	if !pathToken.MatchString(artifact.Version) || artifact.Version == ".." {
		return errors.New("node: artifact version is not a safe path token")
	}
	name := artifact.BinaryName
	if name == "" {
		name = artifact.Component
	}
	if !pathToken.MatchString(name) || name == "." || name == ".." {
		return errors.New("node: artifact binary name is not a safe path token")
	}
	return nil
}

func validateComponent(component string) error {
	if !componentToken.MatchString(component) {
		return errors.New("node: component must be a lowercase DNS-style token")
	}
	return nil
}

// OSFileSystem is the production filesystem implementation.
type OSFileSystem struct{}

func (OSFileSystem) MkdirAll(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }
func (OSFileSystem) ReadFile(path string) ([]byte, error)         { return os.ReadFile(path) }
func (OSFileSystem) WriteFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}
func (OSFileSystem) Rename(oldPath, newPath string) error      { return os.Rename(oldPath, newPath) }
func (OSFileSystem) Symlink(oldPath, newPath string) error     { return os.Symlink(oldPath, newPath) }
func (OSFileSystem) Readlink(path string) (string, error)      { return os.Readlink(path) }
func (OSFileSystem) Remove(path string) error                  { return os.Remove(path) }
func (OSFileSystem) Chmod(path string, mode os.FileMode) error { return os.Chmod(path, mode) }

// OSProcessRunner is the production fixed-path process seam. It uses a new
// process group so cancellation cannot leave a child holding the drain.
type OSProcessRunner struct{}

func (OSProcessRunner) Run(ctx context.Context, executable string, arguments []string) (ProcessResult, error) {
	if ctx == nil {
		return ProcessResult{}, errors.New("node: process context must not be nil")
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process != nil {
			return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	command.WaitDelay = 2 * time.Second
	err := command.Run()
	if ctx.Err() != nil {
		return ProcessResult{}, ctx.Err()
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return ProcessResult{}, err
		}
	}
	if command.ProcessState == nil {
		return ProcessResult{}, errors.New("node: process exited without process state")
	}
	return ProcessResult{ExitCode: command.ProcessState.ExitCode()}, nil
}

// HTTPDownloader is an optional production downloader. Signature and digest
// verification remain in Delivery; this type only fetches bytes with the
// request context. AllowedHosts is an optional exact host boundary supplied by
// the caller; an empty boundary leaves host admission to the caller's own
// injected HTTP transport and does not invent a release host. MaxBytes is the
// response bound, defaulting to MaximumArtifactDownloadBytes when zero.
type HTTPDownloader struct {
	Client       *http.Client
	AllowedHosts []string
	MaxBytes     int64
}

func (d HTTPDownloader) Download(ctx context.Context, artifact Artifact) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("node: download context must not be nil")
	}
	parsed, err := url.Parse(artifact.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || strings.ContainsAny(artifact.URL, "\r\n\x00") {
		return nil, errors.New("node: artifact URL is invalid")
	}
	if !artifactHostAllowed(parsed, d.AllowedHosts) {
		return nil, errors.New("node: artifact URL host is not trusted")
	}
	maxBytes := d.MaxBytes
	if maxBytes == 0 {
		maxBytes = MaximumArtifactDownloadBytes
	}
	if maxBytes < 1 {
		return nil, errors.New("node: artifact response limit is invalid")
	}
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, errors.New("node: artifact download request is invalid")
	}
	// Copy the injected client so redirect policy is hardened without changing
	// the caller's client or its offline RoundTripper test seam.
	safeClient := *client
	safeClient.CheckRedirect = rejectArtifactRedirect
	response, err := safeClient.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, errors.New("node: artifact download request failed")
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("node: artifact download returned no response body")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("artifact server returned HTTP %d", response.StatusCode)
	}
	// Reject a declared oversized body before ReadAll can allocate. Chunked or
	// otherwise unknown lengths are still bounded by the limited reader.
	if response.ContentLength > maxBytes {
		return nil, fmt.Errorf("node: artifact response exceeds %d bytes", maxBytes)
	}
	readLimit := maxBytes
	if maxBytes < int64(^uint64(0)>>1) {
		readLimit++
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, readLimit))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, errors.New("node: artifact response could not be read")
	}
	if int64(len(payload)) > maxBytes {
		return nil, fmt.Errorf("node: artifact response exceeds %d bytes", maxBytes)
	}
	return payload, nil
}

func rejectArtifactRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func artifactHostAllowed(artifactURL *url.URL, allowedHosts []string) bool {
	if len(allowedHosts) == 0 {
		return true
	}
	host := strings.ToLower(artifactURL.Host)
	hostname := strings.TrimSuffix(strings.ToLower(artifactURL.Hostname()), ".")
	for _, allowed := range allowedHosts {
		allowed = strings.TrimSpace(strings.ToLower(allowed))
		if allowed == "" {
			continue
		}
		if allowed == host {
			return true
		}
		// A hostname-only boundary intentionally permits the configured
		// hostname's HTTPS ports. A boundary containing a port remains exact.
		configured, err := url.Parse("https://" + allowed)
		if err == nil && configured.User == nil && configured.Path == "" && configured.RawQuery == "" && configured.Fragment == "" && configured.Port() == "" && strings.TrimSuffix(strings.ToLower(configured.Hostname()), ".") == hostname {
			return true
		}
	}
	return false
}
