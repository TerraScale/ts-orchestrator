//go:build !linux

package vmqual

import (
	"errors"
	"time"
)

func synchronizedHostTime() (time.Duration, error) {
	return 0, errors.New("vmqual: host clock qualification requires Linux adjtimex")
}
