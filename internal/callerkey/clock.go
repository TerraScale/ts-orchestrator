package callerkey

import "time"

func operatorNow() time.Time  { return time.Now() }
func monotonicNow() time.Time { return time.Now() }
