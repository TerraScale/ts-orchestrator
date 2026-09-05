//go:build !linux

package vmqual

import "errors"

func SynchronizedHostTime() (HostTimeObservation, error) {
	return HostTimeObservation{}, errors.New("vmqual: host clock qualification requires Linux adjtimex")
}
