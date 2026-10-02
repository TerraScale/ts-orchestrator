// Package backup schedules crash-consistent OCI block volume backups of
// retained TerraBase volumes and applies count-based retention. It is a
// second, infrastructure-level recovery path next to TerraBase's logical S3
// backups, which stay the authoritative point-in-time path.
//
// Ownership of a backup is proven by its source volume plus the exact
// controller tags this package writes; a backup that fails either check is
// never deleted. Every OCI mutation is preceded by an authority epoch guard.
package backup

import (
	"errors"
	"time"
)

// Backup types accepted by OCI CreateVolumeBackup.
const (
	TypeFull        = "FULL"
	TypeIncremental = "INCREMENTAL"
)

// Policy is the per-region backup policy. It is off by default; retention
// deletion (Prune) is a separate opt-in.
type Policy struct {
	Enabled bool `json:"enabled,omitzero"`
	// IntervalHours between backups of one volume (default 24).
	IntervalHours int `json:"interval_hours,omitzero"`
	// Retain is how many AVAILABLE backups per volume survive pruning
	// (default 7).
	Retain int `json:"retain,omitzero"`
	// FullEvery makes every Nth backup FULL and the rest INCREMENTAL
	// (default 7; 1 means always FULL).
	FullEvery int `json:"full_every,omitzero"`
	// Prune enables retention deletes of owned backups beyond Retain.
	Prune bool `json:"prune,omitzero"`
	// RunIntervalSeconds is how often the leader evaluates the policy
	// (default 900).
	RunIntervalSeconds int `json:"run_interval_seconds,omitzero"`
}

// WithDefaults fills zero fields.
func (policy Policy) WithDefaults() Policy {
	if policy.IntervalHours == 0 {
		policy.IntervalHours = 24
	}
	if policy.Retain == 0 {
		policy.Retain = 7
	}
	if policy.FullEvery == 0 {
		policy.FullEvery = 7
	}
	if policy.RunIntervalSeconds == 0 {
		policy.RunIntervalSeconds = 900
	}
	return policy
}

// Validate bounds every field.
func (policy Policy) Validate() error {
	policy = policy.WithDefaults()
	if policy.IntervalHours < 1 || policy.IntervalHours > 24*31 || policy.Retain < 1 || policy.Retain > 365 ||
		policy.FullEvery < 1 || policy.FullEvery > 365 || policy.RunIntervalSeconds < 60 || policy.RunIntervalSeconds > 86400 {
		return errors.New("volume backup policy is outside its bounds")
	}
	return nil
}

// Interval returns the backup interval.
func (policy Policy) Interval() time.Duration {
	return time.Duration(policy.WithDefaults().IntervalHours) * time.Hour
}

// RunInterval returns the evaluation interval.
func (policy Policy) RunInterval() time.Duration {
	return time.Duration(policy.WithDefaults().RunIntervalSeconds) * time.Second
}
