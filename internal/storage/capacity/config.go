package capacity

import (
	"errors"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
)

// Config enables measurement on a node. It is off by default.
type Config struct {
	Enabled         bool   `json:"enabled,omitzero"`
	IntervalSeconds int    `json:"interval_seconds,omitzero"`
	TTLSeconds      int    `json:"ttl_seconds,omitzero"`
	Policy          Policy `json:"policy,omitzero"`
}

// Interval returns the collection interval, defaulting to 30s.
func (config Config) Interval() time.Duration {
	if config.IntervalSeconds == 0 {
		return storage.DefaultCollectInterval
	}
	return time.Duration(config.IntervalSeconds) * time.Second
}

// TTL returns the usage record TTL, defaulting to two minutes.
func (config Config) TTL() time.Duration {
	if config.TTLSeconds == 0 {
		return storage.DefaultUsageTTL
	}
	return time.Duration(config.TTLSeconds) * time.Second
}

// Validate requires a TTL of at least two collection intervals so one missed
// tick does not expire a healthy node.
func (config Config) Validate() error {
	if config.IntervalSeconds < 0 || config.TTLSeconds < 0 || config.Interval() < time.Second ||
		config.TTL() > time.Hour || config.TTL() < 2*config.Interval() {
		return errors.New("storage capacity interval must be at least 1s and the TTL between two intervals and 1h")
	}
	return config.Policy.Validate()
}
