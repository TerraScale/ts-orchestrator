package delivery

import (
	"sync"
	"time"
)

// PlannerRefusedHold starts the error of a receipt held because placement
// never planned the intent: no host desired was written.
const PlannerRefusedHold = "placement planner refused the intent"

type consumerRecovery struct{ initial, max time.Duration }

type plannerRefusalCounter struct {
	mu     sync.Mutex
	counts map[string]int
	order  []string
}
