package vmqual

import "time"

// HostTimeObservation is one atomic read of the qualification host clock.
// MaximumError is the kernel uncertainty estimate, not measured guest offset.
type HostTimeObservation struct {
	MaximumError  time.Duration
	LeapIndicator uint8
}
