package rollout

import (
	"errors"
	"time"
)

// The cell's desired orchestrator release lives in the rollout bucket: one
// record holding the newest generation, written by CAS, plus a retained copy
// of every generation for rollback. The leader's executor derives its program
// from the record; nothing about the release is baked.
//
// ponytail: the minimum the executor needs until the cell spec (TS-556) and
// the KV store (TS-559) own the schema; move it there keeping these rules.
const (
	desiredKey           = "release.desired"
	DesiredSchemaVersion = 2
	// ReleaseHistory is how many generations stay readable for rollback.
	ReleaseHistory = 64
	maxReleaseWire = 64 << 10
	// ControllerReleaseDomain and HostReleaseDomain bind release stage IDs across planning, admission and status.
	ControllerReleaseDomain = "release-controllers"
	HostReleaseDomain       = "release-hosts"
)

var (
	ErrReleaseUnchanged = errors.New("the desired release already names this binary")
	ErrNoRelease        = errors.New("the cell has no such release generation")
)

// Release is one generation of the cell's desired orchestrator binary.
// Receipt and Delegation are the release receipt the steps carry, so a node
// can restage the binary; nodes verify them against their own roots.
// SourceRevision and RunNumber are what the verified receipt names (the run
// only for an update receipt signed after CI qualified it), so a release
// channel can refuse a run older than the cell's newest. RollbackOf names
// the earlier generation a rollback repeats.
type Release struct {
	ReleaseSequence         uint64    `json:"release_sequence,omitzero"`
	SequenceMigration       []byte    `json:"sequence_migration,omitempty"`
	SequenceMigrationSHA256 string    `json:"sequence_migration_sha256,omitempty"`
	ID                      string    `json:"id"`
	Generation              uint64    `json:"generation"`
	Digest                  string    `json:"digest"`
	SourceRevision          string    `json:"source_revision,omitempty"`
	RunNumber               int64     `json:"run_number,omitzero"`
	Receipt                 []byte    `json:"receipt,omitempty"`
	Delegation              []byte    `json:"delegation,omitempty"`
	RollbackOf              uint64    `json:"rollback_of,omitzero"`
	Actor                   string    `json:"actor"`
	CreatedAt               time.Time `json:"created_at"`
}

// Desired is the cell's newest release generation. Paused stops the executor
// from starting another rollout; a rollout already running still finishes.
type Desired struct {
	OrderingFloor       Release `json:"ordering_floor,omitzero"`
	LegacyFloor         Release `json:"legacy_floor,omitzero"`
	LegacyIssuanceFloor Release `json:"legacy_issuance_floor,omitzero"`
	SchemaVersion       int     `json:"schema_version"`
	Cell                string  `json:"cell"`
	Release             Release `json:"release,omitzero"`
	Paused              bool    `json:"paused,omitzero"`
}
