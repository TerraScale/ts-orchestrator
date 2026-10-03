package rollout

import (
	"errors"
	"fmt"
	"strings"
)

// CompatibilitySchema names the release compatibility declaration a TerraBase
// qualification publishes. It is part of the qualified, hash-bound release.
const CompatibilitySchema = "terrascale.terrabase.compatibility.v1"

// ErrNoCompatibilityData reports a release without a compatibility
// declaration. Callers must fail closed on it.
var ErrNoCompatibilityData = errors.New("release publishes no compatibility declaration")

// VersionRange is an inclusive range of protocol or format versions.
type VersionRange struct {
	Min uint64 `json:"min"`
	Max uint64 `json:"max"`
}

func (r VersionRange) valid() bool { return r.Min != 0 && r.Min <= r.Max }

// Contains reports whether version lies inside the range.
func (r VersionRange) Contains(version uint64) bool {
	return r.valid() && version >= r.Min && version <= r.Max
}

// VersionedCapability is one versioned interface a release speaks and the
// range of peer versions it was tested to accept.
type VersionedCapability struct {
	Version uint64       `json:"version"`
	Accepts VersionRange `json:"accepts"`
}

func (c VersionedCapability) valid() bool { return c.Version != 0 && c.Accepts.Contains(c.Version) }

// CompatibilityDeclaration is what one release states about its own
// persistent format, replication protocol and client data contract.
type CompatibilityDeclaration struct {
	Schema string `json:"schema"`
	// PersistentFormat.Version is the format the release writes; Accepts is
	// every format it can open.
	PersistentFormat VersionedCapability `json:"persistent_format"`
	// Replication.Version is the replication protocol the release speaks;
	// Accepts is every peer protocol it interoperates with.
	Replication VersionedCapability `json:"replication"`
	// ClientData.Version is the client-visible data contract; Accepts is every
	// contract whose stored client data the release serves unchanged.
	ClientData VersionedCapability `json:"client_data"`
}

// Validate checks the closed structure of a declaration.
func (d CompatibilityDeclaration) Validate() error {
	if d.Schema != CompatibilitySchema {
		return fmt.Errorf("compatibility declaration schema %q is not %s", d.Schema, CompatibilitySchema)
	}
	if !d.PersistentFormat.valid() || !d.Replication.valid() || !d.ClientData.valid() {
		return errors.New("compatibility declaration needs nonzero versions inside their accepted ranges")
	}
	return nil
}

// CompatibilityVerdict is the evidence a compatibility signer may certify for
// replacing a seat running old with candidate, including rolling back.
type CompatibilityVerdict struct {
	// MixedVersionReplication: each release accepts the other's protocol, so
	// the pair keeps replicating while its seats run different releases.
	MixedVersionReplication bool
	// ClientData: each release serves the other's client data contract.
	ClientData bool
	// PersistentFormatRead: the candidate opens what old wrote.
	PersistentFormatRead bool
	// PersistentFormatWrite: old opens what the candidate writes, so a
	// rollback to old can read the volume after the candidate ran.
	PersistentFormatWrite bool
}

// Compatible reports whether every statement holds.
func (v CompatibilityVerdict) Compatible() bool {
	return v.MixedVersionReplication && v.ClientData && v.PersistentFormatRead && v.PersistentFormatWrite
}

// Failures names each statement that does not hold.
func (v CompatibilityVerdict) Failures() []string {
	var failures []string
	if !v.MixedVersionReplication {
		failures = append(failures, "mixed-version replication")
	}
	if !v.ClientData {
		failures = append(failures, "client data")
	}
	if !v.PersistentFormatRead {
		failures = append(failures, "candidate reads predecessor format")
	}
	if !v.PersistentFormatWrite {
		failures = append(failures, "predecessor reads candidate format")
	}
	return failures
}

// Assess derives the compatibility evidence for replacing old with candidate
// from both releases' declarations. It never assumes a statement.
func Assess(old, candidate CompatibilityDeclaration) (CompatibilityVerdict, error) {
	if err := old.Validate(); err != nil {
		return CompatibilityVerdict{}, fmt.Errorf("predecessor %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return CompatibilityVerdict{}, fmt.Errorf("candidate %w", err)
	}
	mutual := func(left, right VersionedCapability) bool {
		return left.Accepts.Contains(right.Version) && right.Accepts.Contains(left.Version)
	}
	return CompatibilityVerdict{
		MixedVersionReplication: mutual(old.Replication, candidate.Replication),
		ClientData:              mutual(old.ClientData, candidate.ClientData),
		PersistentFormatRead:    candidate.PersistentFormat.Accepts.Contains(old.PersistentFormat.Version),
		PersistentFormatWrite:   old.PersistentFormat.Accepts.Contains(candidate.PersistentFormat.Version),
	}, nil
}

// RequireCompatible returns a terminal error unless every statement holds.
func RequireCompatible(old, candidate CompatibilityDeclaration) (CompatibilityVerdict, error) {
	verdict, err := Assess(old, candidate)
	if err != nil {
		return verdict, Terminal(err)
	}
	if !verdict.Compatible() {
		return verdict, Terminal(fmt.Errorf("releases are not compatible: %s", strings.Join(verdict.Failures(), ", ")))
	}
	return verdict, nil
}
