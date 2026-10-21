// Package membership supervises the regional controller set after founding.
//
// The authority leader compares each controller slot's ledger-pinned OCI
// instance with the embedded JetStream metadata peers. A slot whose instance
// is TERMINATED, or whose peer has been offline longer than a grace period, is
// reported as lost. Only with offline root-signed retirement evidence for the
// exact prior instance and an intact metadata quorum does it ask the seed's
// founder to relaunch the slot as the next ledger
// attempt at the same private IP and NATS server name, so raft catches the
// empty-store replacement up by snapshot without a peer remove.
package membership

import "time"

const (
	DefaultInterval     = 10 * time.Second
	DefaultOfflineGrace = 10 * time.Minute
	DefaultRetryBackoff = 5 * time.Minute
	// DefaultRetirementEvidenceDir holds operator-supplied, root-signed slot
	// retirement envelopes named <slot>.retirement, and the leader's unsigned
	// <slot>.retirement-request.json files. It lives under the controller
	// unit's StateDirectory, the only tree the service account may write
	// under ProtectSystem=strict. systemd creates the StateDirectory itself;
	// the controller creates this subdirectory (0700) when it first writes a
	// retirement request.
	DefaultRetirementEvidenceDir = "/var/lib/terrascale-orchestrator-controller/membership/retirement"
)
