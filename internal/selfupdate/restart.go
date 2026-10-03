package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// restartMarkerPrefix names the per-unit marker a rollback leaves until the
// rolled-back unit has actually restarted. Moving the current link alone does
// not stop the rejected process, so the marker outlives a failed or
// interrupted restart and later watchdog runs retry it.
const restartMarkerPrefix = "restart-pending-"

func (layout Layout) restartMarkerPath(unit string) string {
	return filepath.Join(layout.Root, restartMarkerPrefix+unit)
}

// markRestartPending records that unit must restart onto the restored
// release. It is written before the activation record is removed, so no
// interruption can lose both.
func (layout Layout) markRestartPending(unit string) error {
	if !unitRE.MatchString(unit) {
		return fmt.Errorf("%w: unit", ErrInvalid)
	}
	return writeFileAtomic(layout.restartMarkerPath(unit), []byte(unit+"\n"), 0o644)
}

// RestartPending reports whether a rollback of unit has not been followed by
// a restart yet. The caller holds Lock.
func (layout Layout) RestartPending(unit string) (bool, error) {
	if !unitRE.MatchString(unit) {
		return false, fmt.Errorf("%w: unit", ErrInvalid)
	}
	err := layout.checkOwned(layout.restartMarkerPath(unit), false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// ClearRestartPending removes the marker once unit restarted. Prepare calls
// it at every unit start; the watchdog after a successful restart. The caller
// holds Lock.
func (layout Layout) ClearRestartPending(unit string) error {
	if !unitRE.MatchString(unit) {
		return fmt.Errorf("%w: unit", ErrInvalid)
	}
	if err := os.Remove(layout.restartMarkerPath(unit)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
