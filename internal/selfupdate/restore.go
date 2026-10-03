package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	restoreIntentPrefix = "restore-"
	restoreIntentSchema = "terrascale.orchestrator.restore-intent.v1"
)

// restoreIntent is written before Restore changes anything and removed once
// the link has moved, so an interrupted restore is finished from it by the
// next Watch (the watchdog timer or the unit's prepare step).
type restoreIntent struct {
	Schema   string `json:"schema"`
	Unit     string `json:"unit"`
	Target   string `json:"target"`
	Rejected string `json:"rejected"`
}

func (layout Layout) restoreIntentPath(unit string) string {
	return filepath.Join(layout.Root, restoreIntentPrefix+unit+".json")
}

// Restore returns unit to digest, a release it ran before, on a rollout's
// order to roll back the rejected release. Unlike Activate it creates no
// pending activation, so a restore whose restart or proof fails never lets
// the watchdog flip the node back to the rejected release: the node stays on
// digest and the rollout's own deadline decides what happens next.
//
// rejected is marked known bad on this node and a restart obligation for
// unit is recorded before Restore returns, so a failed or interrupted
// restart is retried by the watchdog. A pending activation of rejected over
// digest is rolled back exactly as the watchdog would. Restore reports
// whether it changed anything; it refuses a known-bad or unverifiable
// digest, and a node that runs neither release. The caller holds Lock.
func Restore(layout Layout, digest, rejected, unit string) (bool, error) {
	if !digestRE.MatchString(digest) || !digestRE.MatchString(rejected) || digest == rejected || !unitRE.MatchString(unit) {
		return false, fmt.Errorf("%w: restore target", ErrInvalid)
	}
	if err := layout.finishRestores(); err != nil {
		return false, err
	}
	if knownBad, err := layout.KnownBad(); err != nil {
		return false, err
	} else if knownBad[digest] {
		return false, ErrKnownBad
	}
	if err := layout.VerifyRelease(digest); err != nil {
		return false, err
	}
	activation, pending, err := layout.Pending()
	if err != nil {
		return false, err
	}
	if pending {
		if activation.Unit != unit || activation.Target != rejected || activation.Previous != digest {
			return false, fmt.Errorf("%w: activation %s is pending for another release", ErrInvalid, activation.ActivationID)
		}
		if err := layout.rollback(activation); err != nil {
			return true, err
		}
		recordResolution(activation, OutcomeRolledBack)
		return true, nil
	}
	current, err := layout.Current()
	if err != nil {
		return false, err
	}
	switch current {
	case digest:
		return false, nil
	case rejected:
	default:
		return false, fmt.Errorf("%w: the current release is neither the restore target nor the rejected release", ErrInvalid)
	}
	// There is no activation record to recover an interrupted restore
	// from, so a durable intent names the target first; finishRestore
	// completes the switch from it at any later point.
	intent, err := protocol.EncodeJSON(restoreIntent{Schema: restoreIntentSchema, Unit: unit, Target: digest, Rejected: rejected})
	if err != nil {
		return false, err
	}
	if err := writeFileAtomic(layout.restoreIntentPath(unit), intent, 0o644); err != nil {
		return false, err
	}
	if err := layout.finishRestore(unit); err != nil {
		return true, err
	}
	decisionlog.Record(context.Background(), decisionlog.Decision{
		Actor:   decisionlog.Actor{Slice: "selfupdate"},
		Kind:    decisionlog.KindRollback,
		Subject: memberSubject(unit),
		Summary: "Restored release " + shortDigest(digest) + " on " + unit,
		Reason:  "A rollout rolled back the release this unit ran; that release is now known bad on this node.",
		Rule:    "selfupdate.restore",
		Status:  decisionlog.StatusRolledBack,
		Attrs:   map[string]string{"version": digest, "rejected": rejected},
	})
	return true, nil
}

// finishRestores completes every interrupted restore on this node before
// anything else changes the release selection: Activate, Restore and Watch
// call it first, so a recovered restore can never overwrite a newer
// selection. An intent next to a pending activation cannot be produced by
// these paths; it is refused rather than guessed at. The caller holds Lock.
func (layout Layout) finishRestores() error {
	entries, err := os.ReadDir(layout.Root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		unit, ok := strings.CutPrefix(name, restoreIntentPrefix)
		if !ok {
			continue
		}
		unit, ok = strings.CutSuffix(unit, ".json")
		if !ok || !unitRE.MatchString(unit) {
			return fmt.Errorf("%w: restore intent %q", ErrUnsafe, name)
		}
		if _, pending, err := layout.Pending(); err != nil {
			return err
		} else if pending {
			return fmt.Errorf("%w: restore intent of %s next to a pending activation", ErrUnsafe, unit)
		}
		if err := layout.finishRestore(unit); err != nil {
			return err
		}
	}
	return nil
}

// finishRestore completes a restore of unit whose intent is recorded: the
// rejected release is known bad, the restart obligation is durable, and
// only then does the link move to the target and the intent go away. Every
// step is idempotent, so it finishes a restore interrupted at any point.
// The caller holds Lock.
func (layout Layout) finishRestore(unit string) error {
	path := layout.restoreIntentPath(unit)
	if err := layout.checkOwned(path, false); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	data, err := readBounded(path, maxStateBytes)
	if err != nil {
		return err
	}
	var intent restoreIntent
	if err := protocol.DecodeStrict(data, &intent, maxStateBytes); err != nil {
		return err
	}
	if intent.Schema != restoreIntentSchema || intent.Unit != unit || !digestRE.MatchString(intent.Target) ||
		!digestRE.MatchString(intent.Rejected) || intent.Target == intent.Rejected {
		return fmt.Errorf("%w: restore intent", ErrInvalid)
	}
	if err := layout.VerifyRelease(intent.Target); err != nil {
		return fmt.Errorf("restore target cannot be restored: %w", err)
	}
	if err := layout.markKnownBad(intent.Rejected); err != nil {
		return err
	}
	if err := layout.markRestartPending(unit); err != nil {
		return err
	}
	if current, err := layout.Current(); err != nil {
		return err
	} else if current != intent.Target {
		if err := layout.flipCurrent(intent.Target); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(layout.Root)
}

// MarkRestartPending records that unit still owes a restart, so the
// watchdog retries it until the unit starts. The caller holds Lock.
func (layout Layout) MarkRestartPending(unit string) error {
	return layout.markRestartPending(unit)
}
