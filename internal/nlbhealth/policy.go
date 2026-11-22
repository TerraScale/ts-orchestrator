package nlbhealth

import "time"

const (
	Interval           = 2 * time.Second
	Timeout            = time.Second
	UnhealthyThreshold = 2
	Retries            = UnhealthyThreshold - 1
	PropagationMargin  = time.Second
	DrainWindow        = Interval*UnhealthyThreshold + Timeout + PropagationMargin
)
