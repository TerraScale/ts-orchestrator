package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// epochFile holds the newest authority epoch whose rollout order this node
// accepted. It survives agent restarts, so a deposed leader's still-valid
// signed order can never move the node after a newer leader's did.
const epochFile = "authority-epoch"

// ErrStaleEpoch refuses an order from an older authority epoch.
var ErrStaleEpoch = errors.New("order is from an older authority epoch than one this node accepted")

func (layout Layout) epochPath() string { return filepath.Join(layout.Root, epochFile) }

// AcceptedEpoch returns the newest accepted authority epoch, zero when none.
// The caller holds Lock.
func (layout Layout) AcceptedEpoch() (uint64, error) {
	if err := layout.checkOwned(layout.epochPath(), false); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	data, err := readBounded(layout.epochPath(), 64)
	if err != nil {
		return 0, err
	}
	epoch, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || epoch == 0 {
		return 0, fmt.Errorf("%w: accepted authority epoch", ErrInvalid)
	}
	return epoch, nil
}

// AdmitEpoch durably records epoch as accepted before the caller acts on
// an order from it, and refuses an epoch older than one already accepted.
// The caller holds Lock across AdmitEpoch and the effects it fences.
func (layout Layout) AdmitEpoch(epoch uint64) error {
	if epoch == 0 {
		return fmt.Errorf("%w: authority epoch", ErrInvalid)
	}
	accepted, err := layout.AcceptedEpoch()
	if err != nil {
		return err
	}
	switch {
	case epoch < accepted:
		return ErrStaleEpoch
	case epoch == accepted:
		return nil
	}
	if err := layout.ensureDirs(); err != nil {
		return err
	}
	return writeFileAtomic(layout.epochPath(), fmt.Appendf(nil, "%d\n", epoch), 0o644)
}
