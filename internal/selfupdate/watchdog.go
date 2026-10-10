package selfupdate

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Outcome is the watchdog's decision for one check.
type Outcome string

const (
	OutcomeIdle       Outcome = "idle"
	OutcomePending    Outcome = "pending"
	OutcomeConfirmed  Outcome = "confirmed"
	OutcomeRolledBack Outcome = "rolled-back"
)

// ProofCheck locates and authenticates the version proof of one unit.
type ProofCheck struct {
	File      string
	PublicKey ed25519.PublicKey
}

// Watch resolves a pending activation: a fresh signed proof confirms it;
// a missed deadline, or a target whose bytes no longer verify, rolls the
// current link back to the previous release and marks the target known bad
// on this node. Callers restart the unit after OutcomeRolledBack.
func Watch(layout Layout, unit string, proof ProofCheck, now time.Time) (Outcome, Activation, error) {
	// A rollout restore interrupted before its link moved is finished
	// first, so neither the watchdog's restart nor the unit's start ever
	// runs the release the restore rejected.
	if err := layout.finishRestores(); err != nil {
		return OutcomeIdle, Activation{}, fmt.Errorf("finish interrupted restore: %w", err)
	}
	activation, pending, err := layout.Pending()
	if errors.Is(err, ErrUnreadableActivation) {
		return layout.resolveUnreadable(err)
	}
	if err != nil || !pending {
		return OutcomeIdle, Activation{}, err
	}
	if activation.Unit != unit {
		// Another unit's watchdog resolves this activation. Once it is long
		// past its deadline no functioning watchdog is left to do so (a
		// mistyped unit, or a unit without the drop-ins): roll it back so it
		// cannot block every later activation on this node.
		if now.Before(activation.Deadline.Add(OrphanedActivationGrace)) {
			return OutcomePending, activation, nil
		}
		slog.Warn("self-update activation of an unwatched unit expired; rolling back",
			"activation", activation.ActivationID, "unit", activation.Unit)
		if err := layout.rollback(activation); err != nil {
			return OutcomeRolledBack, activation, err
		}
		recordResolution(activation, OutcomeRolledBack)
		return OutcomeRolledBack, activation, nil
	}
	// rollback marks the target known bad before it moves the link and
	// removes the record. A known-bad target therefore means a rollback was
	// committed and interrupted: finish it instead of accepting a proof.
	knownBad, err := layout.KnownBad()
	if err != nil {
		return OutcomePending, activation, err
	}
	if knownBad[activation.Target] {
		slog.Warn("self-update rollback was interrupted; finishing it", "activation", activation.ActivationID)
		if err := layout.rollback(activation); err != nil {
			return OutcomeRolledBack, activation, err
		}
		recordResolution(activation, OutcomeRolledBack)
		return OutcomeRolledBack, activation, nil
	}
	// Only a target that is actually selected can be confirmed. Otherwise
	// the activation stays pending until its deadline rolls it back.
	current, err := layout.Current()
	if err != nil {
		return OutcomePending, activation, err
	}
	targetErr := layout.VerifyRelease(activation.Target)
	if targetErr == nil && current == activation.Target && len(proof.PublicKey) == ed25519.PublicKeySize {
		if wire, err := readProof(proof.File); err == nil {
			if verified, err := VerifyVersionProof(wire, proof.PublicKey, activation, now); err == nil && !processRunning(verified.ProcessID) {
				// A proof only confirms while the process that signed it
				// still runs: one that crashed right after proving must not
				// confirm the activation at the next check.
				slog.Warn("self-update version proof process is gone", "activation", activation.ActivationID, "pid", verified.ProcessID)
			} else if err == nil {
				if err := os.Remove(layout.activationPath()); err != nil {
					return OutcomePending, activation, err
				}
				recordResolution(activation, OutcomeConfirmed)
				// The confirmed release runs the image's root steps from
				// now on (Delegate).
				if err := layout.flipLink(knownGoodLink, activation.Target); err != nil {
					return OutcomeConfirmed, activation, err
				}
				return OutcomeConfirmed, activation, syncDir(layout.Root)
			} else {
				slog.Warn("self-update version proof rejected", "activation", activation.ActivationID, "error", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("self-update version proof unreadable", "activation", activation.ActivationID, "error", err)
		}
	}
	if targetErr == nil && now.Before(activation.Deadline) {
		return OutcomePending, activation, nil
	}
	if err := layout.rollback(activation); err != nil {
		return OutcomeRolledBack, activation, err
	}
	recordResolution(activation, OutcomeRolledBack)
	return OutcomeRolledBack, activation, nil
}

// Backstop rolls back a damaged target or a readable activation still pending
// OrphanedActivationGrace past its deadline. The image-baked binary runs it
// after the known-good release ran prepare or the watchdog, so a release
// whose steps succeed without enforcing deadlines cannot keep an unproven
// target current. A record it cannot read belongs to the newer release that
// wrote it and is left alone. The caller holds Lock.
func Backstop(layout Layout, now time.Time) (Outcome, Activation, error) {
	activation, pending, err := layout.Pending()
	if errors.Is(err, ErrUnreadableActivation) {
		return OutcomeIdle, Activation{}, nil
	}
	if err != nil || !pending {
		return OutcomeIdle, Activation{}, err
	}
	bad, err := layout.KnownBad()
	if err != nil {
		return OutcomePending, activation, err
	}
	if !bad[activation.Target] && layout.VerifyRelease(activation.Target) == nil && now.Before(activation.Deadline.Add(OrphanedActivationGrace)) {
		return OutcomePending, activation, nil
	}
	slog.Warn("self-update activation is damaged or outlived its deadline; rolling back",
		"activation", activation.ActivationID, "unit", activation.Unit)
	if err := layout.rollback(activation); err != nil {
		return OutcomeRolledBack, activation, err
	}
	recordResolution(activation, OutcomeRolledBack)
	return OutcomeRolledBack, activation, nil
}

// processRunning reports whether pid names a live process. Tests replace it.
var processRunning = func(pid int64) bool {
	if pid <= 0 || pid > math.MaxInt32 {
		return false
	}
	err := syscall.Kill(int(pid), 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// OrphanedActivationGrace is how long past its deadline an activation of a
// unit no watchdog matches stays pending before any watchdog rolls it back.
// It covers the matching unit's watchdog timer running late.
const OrphanedActivationGrace = 5 * time.Minute

// resolveUnreadable handles an owned activation record that does not decode
// or validate. It cannot be confirmed, so it fails safe: when the record
// still names a verifiable previous release, that release is restored and
// the target is marked known bad like any unproven activation; the record is
// then moved aside so the unit can start. The VerifyRelease gate on the
// current release in Prepare still refuses bytes that do not verify.
func (layout Layout) resolveUnreadable(cause error) (Outcome, Activation, error) {
	_, exists, err := layout.pendingRecord()
	if err != nil || !exists {
		return OutcomeIdle, Activation{}, err
	}
	outcome := OutcomeIdle
	activation, recoveryErr := layout.RecoveryActivation()
	if recoveryErr == nil && layout.VerifyRelease(activation.Previous) == nil {
		current, err := layout.Current()
		if err != nil {
			return OutcomePending, activation, err
		}
		if current != activation.Target && current != activation.Previous {
			return OutcomePending, activation, fmt.Errorf("%w: unreadable activation does not own current selection", ErrInvalid)
		}
		if err := layout.markKnownBad(activation.Target); err != nil {
			return OutcomePending, activation, err
		}
		if current == activation.Target {
			if err := layout.flipCurrent(activation.Previous); err != nil {
				return OutcomePending, activation, err
			}
		}
		if err := layout.markRestartPending(activation.Unit); err != nil {
			return OutcomePending, activation, err
		}
		outcome = OutcomeRolledBack
	}
	quarantine := layout.activationPath() + ".unreadable-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	if err := os.Rename(layout.activationPath(), quarantine); err != nil {
		return OutcomePending, activation, err
	}
	slog.Warn("self-update activation record was unreadable and was moved aside",
		"path", quarantine, "outcome", outcome, "error", cause)
	return outcome, activation, syncDir(layout.Root)
}

// rollback marks the target known bad first, then restores the previous
// release. The previous release is verified before the link moves.
func (layout Layout) rollback(activation Activation) error {
	if err := layout.markKnownBad(activation.Target); err != nil {
		return err
	}
	if err := layout.VerifyRelease(activation.Previous); err != nil {
		return fmt.Errorf("previous release cannot be restored: %w", err)
	}
	if err := layout.flipCurrent(activation.Previous); err != nil {
		return err
	}
	// The rejected process may still run: keep a restart obligation that
	// outlives this invocation before the activation record goes away.
	if err := layout.markRestartPending(activation.Unit); err != nil {
		return err
	}
	if err := os.Remove(layout.activationPath()); err != nil {
		return err
	}
	return syncDir(layout.Root)
}

// Prepare runs as root before every unit start (ExecStartPre=+). It seeds
// the baked release on first use, resolves an expired activation, and
// refuses to start a current release whose bytes no longer verify.
func Prepare(layout Layout, unit, bakedBinary string, proof ProofCheck, now time.Time) (Outcome, error) {
	if _, err := Seed(layout, bakedBinary); err != nil {
		return OutcomeIdle, fmt.Errorf("seed baked release: %w", err)
	}
	// Prepare runs while the unit (re)starts, so the process behind any
	// existing proof is gone: a proof never confirms across a restart. The
	// new process proves itself again for the watchdog; prepare only
	// resolves expired, unwatched or unreadable activations; its proof
	// argument is accepted for the drop-in's flags and not used to confirm.
	outcome, activation, err := Watch(layout, unit, ProofCheck{}, now)
	if err != nil {
		return outcome, err
	}
	// The unit is starting now, so any restart a rollback still owed it is
	// being served by this start.
	if unitRE.MatchString(unit) {
		if err := layout.ClearRestartPending(unit); err != nil {
			return outcome, err
		}
	}
	current, err := layout.Current()
	if err != nil {
		return outcome, err
	}
	// The units on a node share the current link. A unit never starts the
	// unconfirmed target of another unit's activation: it cannot prove it,
	// and that activation's rollback does not restart it. Its restart policy
	// retries once the activation is resolved.
	if outcome == OutcomePending && activation.Unit != unit && current == activation.Target {
		return outcome, fmt.Errorf("%w: %s waits for the pending activation of %s", ErrInvalid, unit, activation.Unit)
	}
	if err := layout.VerifyRelease(current); err != nil {
		return outcome, fmt.Errorf("current release does not verify: %w", err)
	}
	if removed, err := layout.PruneReleases(now); err != nil {
		slog.Warn("self-update release pruning failed", "error", err)
	} else if len(removed) > 0 {
		slog.Info("self-update pruned settled releases", "releases", removed)
	}
	return outcome, nil
}

// StagedReleaseRetention keeps a release that is neither current nor part
// of a pending activation for this long after it was staged, so a release
// staged for an upcoming activation is not pruned before it is activated.
const StagedReleaseRetention = 24 * time.Hour

// PruneReleases removes settled release directories: everything except the
// current and known-good releases, both sides of a pending activation, the
// image-baked release, and non-known-bad releases staged within
// StagedReleaseRetention.
// The caller holds Lock. It returns the removed digests.
func (layout Layout) PruneReleases(now time.Time) ([]string, error) {
	current, err := layout.Current()
	if err != nil {
		return nil, err
	}
	if current == "" {
		return nil, nil
	}
	keep := map[string]bool{current: true}
	if known, err := layout.KnownGood(); err == nil && known != "" {
		keep[known] = true
	}
	activation, pending, err := layout.Pending()
	if err != nil {
		return nil, err
	}
	if pending {
		keep[activation.Target], keep[activation.Previous] = true, true
	}
	knownBad, err := layout.KnownBad()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(layout.releasesPath())
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, entry := range entries {
		digest := entry.Name()
		if !digestRE.MatchString(digest) || keep[digest] {
			continue
		}
		directory := layout.ReleaseDir(digest)
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, err := os.Lstat(filepath.Join(directory, bakedMarkerFile)); err == nil {
			continue
		}
		if !knownBad[digest] && now.Sub(info.ModTime()) < StagedReleaseRetention {
			continue
		}
		if err := layout.checkOwned(directory, true); err != nil {
			return removed, err
		}
		if err := os.RemoveAll(directory); err != nil {
			return removed, err
		}
		removed = append(removed, digest)
	}
	if len(removed) > 0 {
		return removed, syncDir(layout.releasesPath())
	}
	return removed, nil
}
