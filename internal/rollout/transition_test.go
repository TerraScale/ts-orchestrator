package rollout

import (
	"strings"

	"time"
)

var (
	fromDigest = strings.Repeat("a", 64)
	toDigest   = strings.Repeat("b", 64)
	otherBad   = strings.Repeat("c", 64)
	testStart  = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
)

func controllers() []Unit {
	return []Unit{{ID: "ctrl-a", Group: "controllers", Seed: true}, {ID: "ctrl-b", Group: "controllers"}, {ID: "ctrl-c", Group: "controllers"}}
}

func testPolicy() Policy {
	policy := DefaultPolicy()
	policy.MinHealthyReports = 2
	return policy
}
