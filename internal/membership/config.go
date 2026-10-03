// Package membership supervises the regional controller set after founding.
//
// The authority leader compares each controller slot's ledger-pinned OCI
// instance with the embedded JetStream metadata peers. A slot whose instance
// is TERMINATED, or whose peer has been offline longer than a grace period, is
// reported as lost. Only with offline root-signed retirement evidence for the
// exact prior instance, an intact metadata quorum and an explicit config flag
// does it ask the seed's founder to relaunch the slot as the next ledger
// attempt at the same private IP and NATS server name, so raft catches the
// empty-store replacement up by snapshot without a peer remove.
package membership

import (
	"errors"
	"time"
)

const (
	DefaultInterval     = 10 * time.Second
	DefaultOfflineGrace = 10 * time.Minute
	DefaultRetryBackoff = 5 * time.Minute
	// MinOfflineGrace keeps a rolling restart or a short partition from ever
	// looking like a lost controller.
	MinOfflineGrace = 2 * time.Minute
	// DefaultRetirementEvidenceDir holds operator-supplied, root-signed slot
	// retirement envelopes named <slot>.retirement, and the leader's unsigned
	// <slot>.retirement-request.json files. It lives under the controller
	// unit's StateDirectory, the only tree the service account may write
	// under ProtectSystem=strict. systemd creates the StateDirectory itself;
	// the controller creates this subdirectory (0700) when it first writes a
	// retirement request.
	DefaultRetirementEvidenceDir = "/var/lib/terrascale-orchestrator-controller/membership/retirement"
)

// Config is part of the signed controller config. The zero value disables
// supervision, which is the behavior before this slice existed.
type Config struct {
	// Enabled starts the observer on every controller; only the authority
	// leader evaluates and reports slot health.
	Enabled bool `json:"enabled,omitzero"`
	// Replace lets the leader act on a lost slot. Without it the reconciler
	// only reports what it would do.
	Replace               bool   `json:"replace,omitzero"`
	IntervalSeconds       int    `json:"interval_seconds,omitzero"`
	OfflineGraceSeconds   int    `json:"offline_grace_seconds,omitzero"`
	RetryBackoffSeconds   int    `json:"retry_backoff_seconds,omitzero"`
	RetirementEvidenceDir string `json:"retirement_evidence_dir,omitempty"`
}

func (c Config) Validate() error {
	if c.IntervalSeconds < 0 || c.OfflineGraceSeconds < 0 || c.RetryBackoffSeconds < 0 {
		return errors.New("membership durations must not be negative")
	}
	if c.IntervalSeconds != 0 && (c.IntervalSeconds < 1 || c.IntervalSeconds > 300) {
		return errors.New("membership interval_seconds must be between 1 and 300")
	}
	if c.OfflineGraceSeconds != 0 && time.Duration(c.OfflineGraceSeconds)*time.Second < MinOfflineGrace {
		return errors.New("membership offline_grace_seconds is shorter than the minimum grace")
	}
	if c.RetryBackoffSeconds > 24*60*60 || c.OfflineGraceSeconds > 7*24*60*60 {
		return errors.New("membership durations are unbounded")
	}
	if c.Replace && !c.Enabled {
		return errors.New("membership replace requires enabled")
	}
	if c.RetirementEvidenceDir != "" && c.RetirementEvidenceDir[0] != '/' {
		return errors.New("membership retirement_evidence_dir must be absolute")
	}
	return nil
}

func (c Config) Interval() time.Duration {
	if c.IntervalSeconds == 0 {
		return DefaultInterval
	}
	return time.Duration(c.IntervalSeconds) * time.Second
}

func (c Config) OfflineGrace() time.Duration {
	if c.OfflineGraceSeconds == 0 {
		return DefaultOfflineGrace
	}
	return time.Duration(c.OfflineGraceSeconds) * time.Second
}

func (c Config) RetryBackoff() time.Duration {
	if c.RetryBackoffSeconds == 0 {
		return DefaultRetryBackoff
	}
	return time.Duration(c.RetryBackoffSeconds) * time.Second
}

func (c Config) EvidenceDir() string {
	if c.RetirementEvidenceDir == "" {
		return DefaultRetirementEvidenceDir
	}
	return c.RetirementEvidenceDir
}
