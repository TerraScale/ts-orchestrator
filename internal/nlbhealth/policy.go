package nlbhealth

import "time"

const (
	Interval          = 2 * time.Second
	Timeout           = time.Second
	Retries           = 1
	PropagationMargin = time.Second
	DrainWindow       = Interval*(Retries+1) + Timeout + PropagationMargin
)
