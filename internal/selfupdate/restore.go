package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	restoreIntentPrefix = "restore-"
	restoreIntentSchema = "terrascale.orchestrator.restore-intent.v1"
)

// RestoreIntent is written before Restore changes anything and removed once
// the link has moved, so an interrupted restore is finished from it by the
// next Watch (the watchdog timer or the unit's prepare step).
type RestoreIntent struct {
	Schema   string `json:"schema"`
	Unit     string `json:"unit"`
	Target   string `json:"target"`
	Rejected string `json:"rejected"`
}

func (layout Layout) restoreIntentPath(unit string) string {
	return filepath.Join(layout.Root, restoreIntentPrefix+unit+".json")
}

// PendingRestores reads owned, strictly validated restore intents without effects.
func (layout Layout) PendingRestores() ([]RestoreIntent, error) {
	if err := layout.validate(); err != nil {
		return nil, err
	}
	if err := layout.checkOwned(layout.Root, true); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(layout.Root)
	if err != nil {
		return nil, err
	}
	var intents []RestoreIntent
	for _, entry := range entries {
		unit, ok := strings.CutPrefix(entry.Name(), restoreIntentPrefix)
		if !ok {
			continue
		}
		unit, ok = strings.CutSuffix(unit, ".json")
		if !ok || !unitRE.MatchString(unit) {
			return nil, fmt.Errorf("%w: restore intent %q", ErrUnsafe, entry.Name())
		}
		if _, pending, err := layout.Pending(); err != nil {
			return nil, err
		} else if pending {
			return nil, fmt.Errorf("%w: restore intent of %s next to a pending activation", ErrUnsafe, unit)
		}
		intent, err := layout.readRestoreIntent(unit)
		if err != nil {
			return nil, err
		}
		intents = append(intents, intent)
	}
	return intents, nil
}

func (layout Layout) readRestoreIntent(unit string) (RestoreIntent, error) {
	path := layout.restoreIntentPath(unit)
	if err := layout.checkOwned(path, false); err != nil {
		return RestoreIntent{}, err
	}
	data, err := readBounded(path, maxStateBytes)
	if err != nil {
		return RestoreIntent{}, err
	}
	var intent RestoreIntent
	if err := protocol.DecodeStrict(data, &intent, maxStateBytes); err != nil {
		return RestoreIntent{}, err
	}
	if intent.Schema != restoreIntentSchema || intent.Unit != unit || !digestRE.MatchString(intent.Target) ||
		!digestRE.MatchString(intent.Rejected) || intent.Target == intent.Rejected {
		return RestoreIntent{}, fmt.Errorf("%w: restore intent", ErrInvalid)
	}
	current, err := layout.Current()
	if err != nil {
		return RestoreIntent{}, err
	}
	if current != intent.Target && current != intent.Rejected {
		return RestoreIntent{}, fmt.Errorf("%w: current differs from recorded restore", ErrUnsafe)
	}
	bad, err := layout.KnownBad()
	if err != nil {
		return RestoreIntent{}, err
	}
	if bad[intent.Target] {
		return RestoreIntent{}, ErrKnownBad
	}
	if err := layout.VerifyRelease(intent.Target); err != nil {
		return RestoreIntent{}, fmt.Errorf("restore target cannot be restored: %w", err)
	}
	return intent, nil
}

// MarkRestartPending records that unit still owes a restart, so the
// watchdog retries it until the unit starts. The caller holds Lock.
func (layout Layout) MarkRestartPending(unit string) error {
	return layout.markRestartPending(unit)
}
