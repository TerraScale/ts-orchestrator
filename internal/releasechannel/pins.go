package releasechannel

import (
	"fmt"
	"time"
)

// PinRefreshInterval keeps inventories current; MaxPinAge bounds how long
// pruning can use one when collection or publication stops succeeding.
const (
	PinRefreshInterval = 30 * time.Second
	MaxPinAge          = 2 * time.Minute
)

// ValidateFresh requires recent, complete inventories before pruning.
func (pins *ReleasePins) ValidateFresh(updatedAt, now time.Time) error {
	if err := pins.Validate(); err != nil {
		return err
	}
	age := now.Sub(updatedAt)
	if updatedAt.IsZero() || age > MaxPinAge || age < -PinRefreshInterval {
		return fmt.Errorf("%w: release pin inventory timestamp %s is missing, stale, or ahead of the clock", ErrInvalid, updatedAt)
	}
	return nil
}
