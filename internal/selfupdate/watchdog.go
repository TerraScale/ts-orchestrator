package selfupdate

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
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
	activation, pending, err := layout.Pending()
	if err != nil || !pending {
		return OutcomeIdle, Activation{}, err
	}
	if activation.Unit != unit {
		return OutcomePending, activation, nil
	}
	targetErr := layout.VerifyRelease(activation.Target)
	if targetErr == nil && len(proof.PublicKey) == ed25519.PublicKeySize {
		if wire, err := readProof(proof.File); err == nil {
			if _, err := VerifyVersionProof(wire, proof.PublicKey, activation, now); err == nil {
				if err := os.Remove(layout.activationPath()); err != nil {
					return OutcomePending, activation, err
				}
				recordResolution(activation, OutcomeConfirmed)
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
	outcome, _, err := Watch(layout, unit, proof, now)
	if err != nil {
		return outcome, err
	}
	current, err := layout.Current()
	if err != nil {
		return outcome, err
	}
	if err := layout.VerifyRelease(current); err != nil {
		return outcome, fmt.Errorf("current release does not verify: %w", err)
	}
	return outcome, nil
}
