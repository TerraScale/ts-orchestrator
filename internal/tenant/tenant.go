// Package tenant is a dedicated tenant's desired state: one ts-auth
// organization's project that owns its own TerraBase cluster of one or three
// members and, optionally, its own ts-auth instance, sized by a plan and
// placed apart from platform workloads. See docs/dedicated-tenants.md.
//
// A tenant changes only through its lifecycle methods. Each one returns the
// next generation, and CheckSuccessor, which the store runs against the
// stored record before every write, refuses a record that skips or repeats a
// generation, changes the tenant's identity, leaves the deleted state early
// or mixes a release with a topology change. Records are never removed, so
// a tenant ID is never reused.
package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// Schema names the record format; a reader refuses any other.
const Schema = "terrascale.tenant.v1"

var (
	ErrInvalid   = errors.New("tenant is invalid")
	ErrUnchanged = errors.New("tenant change changes nothing")
	planRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
)

// Retention bounds how long a deleted tenant's volumes and backups stay.
const (
	DefaultRetention = 7 * 24 * time.Hour
	MinRetention     = 24 * time.Hour
	MaxRetention     = 90 * 24 * time.Hour
)

// Plan is a size a tenant buys: what one TerraBase member reserves. A tenant
// keeps the resources of the plan it chose, so a new catalog never resizes a
// running tenant. OCI block volumes grow but never shrink, so a tenant moves
// only to a plan with at least its disk.
type Plan struct {
	Name   string
	Member placement.Resources
}

const gib = int64(1) << 30

// plans are the sizes on sale; Member matches whole Ampere cores. The
// catalog is private so no importer can change what a plan name means.
var plans = [...]Plan{
	{Name: "starter", Member: placement.Resources{CPU: 1, MemoryBytes: 4 * gib, DiskBytes: 20 * gib}},
	{Name: "standard", Member: placement.Resources{CPU: 2, MemoryBytes: 8 * gib, DiskBytes: 100 * gib}},
	{Name: "pro", Member: placement.Resources{CPU: 4, MemoryBytes: 16 * gib, DiskBytes: 250 * gib}},
	{Name: "scale", Member: placement.Resources{CPU: 8, MemoryBytes: 32 * gib, DiskBytes: 500 * gib}},
}

// Plans returns a copy of the plans on sale.
func Plans() []Plan { return slices.Clone(plans[:]) }

// AuthResources is one dedicated ts-auth replica's reservation, the platform
// ts-auth profile's.
var AuthResources = placement.Resources{CPU: 1, MemoryBytes: 1 * gib, DiskBytes: 2 * gib}

// LookupPlan returns the plan named name.
func LookupPlan(name string) (Plan, bool) {
	index := slices.IndexFunc(plans[:], func(plan Plan) bool { return plan.Name == name })
	if index < 0 {
		return Plan{}, false
	}
	return plans[index], true
}

// State is where a tenant is in its lifecycle. Suspended keeps the data and
// stops the machines. Deleted keeps the data until RetainUntil; purged means
// it is gone and only the record stays, so the ID is never reused.
type State string

const (
	StateActive    State = "active"
	StateSuspended State = "suspended"
	StateDeleted   State = "deleted"
	StatePurged    State = "purged"
)

// Spec is what the tenant runs. Member is filled from Plan by New and Change;
// CheckNew and CheckSuccessor hold it to the plan the tenant chooses.
// TerraBase and Auth are admitted artifact digests (lower-case SHA-256 hex);
// an empty Auth means no dedicated ts-auth.
type Spec struct {
	Plan      string              `json:"plan"`
	Member    placement.Resources `json:"member"`
	Members   int                 `json:"members"`
	TerraBase string              `json:"terrabase"`
	Auth      string              `json:"auth,omitempty"`
}

// Tenant is one dedicated tenant in one cell. ID, Organization, Project,
// Cell and CreatedAt never change.
type Tenant struct {
	Schema string `json:"schema"`
	ID     string `json:"id"`
	// Organization and Project are the ts-auth IDs that own the tenant.
	Organization string `json:"organization"`
	Project      string `json:"project"`
	// Cell is the catalog cell that runs the tenant, e.g. gru.
	Cell       string    `json:"cell"`
	Spec       Spec      `json:"spec"`
	State      State     `json:"state"`
	Generation uint64    `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	// RetainUntil is set once the tenant is deleted.
	RetainUntil time.Time `json:"retain_until,omitzero"`
}

// Validate checks the spec's structure. Plan sizes are checked only when a
// tenant chooses a plan, so a stored tenant stays readable when plans change.
func (s Spec) Validate() error {
	if !planRE.MatchString(s.Plan) || s.Member.CPU <= 0 || s.Member.MemoryBytes <= 0 || s.Member.DiskBytes <= 0 {
		return fmt.Errorf("%w: plan %q or its member resources", ErrInvalid, s.Plan)
	}
	if s.Members != 1 && s.Members != 3 {
		return fmt.Errorf("%w: a TerraBase cluster has 1 or 3 members", ErrInvalid)
	}
	if !validDigest(s.TerraBase) || s.Auth != "" && !validDigest(s.Auth) {
		return fmt.Errorf("%w: release digests must be lower-case SHA-256 hex", ErrInvalid)
	}
	return nil
}

// Validate checks the tenant's structure.
func (t Tenant) Validate() error {
	if t.Schema != Schema {
		return fmt.Errorf("%w: schema %q", ErrInvalid, t.Schema)
	}
	if !entityid.Valid(t.ID) {
		return fmt.Errorf("%w: id %q", ErrInvalid, t.ID)
	}
	if _, ok := catalog.LookupName(t.Cell); !ok || !entityid.Valid(t.Organization) || !entityid.Valid(t.Project) {
		return fmt.Errorf("%w: organization, project or cell", ErrInvalid)
	}
	if err := t.Spec.Validate(); err != nil {
		return err
	}
	if t.Generation == 0 || t.CreatedAt.IsZero() || t.UpdatedAt.Before(t.CreatedAt) {
		return fmt.Errorf("%w: generation or timestamps", ErrInvalid)
	}
	switch t.State {
	case StateActive, StateSuspended:
		if !t.RetainUntil.IsZero() {
			return fmt.Errorf("%w: only a deleted tenant has a retention deadline", ErrInvalid)
		}
	case StateDeleted:
		if !t.RetainUntil.After(t.UpdatedAt) {
			return fmt.Errorf("%w: a deleted tenant is retained after its deletion", ErrInvalid)
		}
	case StatePurged:
		if t.RetainUntil.IsZero() || t.UpdatedAt.Before(t.RetainUntil) {
			return fmt.Errorf("%w: a tenant is purged only after its retention", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: state %q", ErrInvalid, t.State)
	}
	return nil
}

// CheckNew reports whether t may be created: a valid active generation 1
// under a free ID, on a plan on sale at exactly its resources.
func CheckNew(t Tenant) error {
	if !ValidID(t.ID) {
		return fmt.Errorf("%w: id %q is taken or malformed", ErrInvalid, t.ID)
	}
	if err := t.Validate(); err != nil {
		return err
	}
	if t.Generation != 1 || t.State != StateActive || !t.UpdatedAt.Equal(t.CreatedAt) {
		return fmt.Errorf("%w: a new tenant is active generation 1", ErrInvalid)
	}
	if plan, ok := LookupPlan(t.Spec.Plan); !ok || plan.Member != t.Spec.Member {
		return fmt.Errorf("%w: plan %q is not on sale at those resources", ErrInvalid, t.Spec.Plan)
	}
	return nil
}

// ValidID reports whether a new tenant may take id.
func ValidID(id string) bool { return entityid.Valid(id) }

// New is generation 1 of an active tenant; it fills spec.Member from the plan.
func New(id, organization, project, cell string, spec Spec, now time.Time) (Tenant, error) {
	plan, ok := LookupPlan(spec.Plan)
	if !ok {
		return Tenant{}, fmt.Errorf("%w: unknown plan %q", ErrInvalid, spec.Plan)
	}
	spec.Member = plan.Member
	now = now.UTC().Round(0)
	t := Tenant{Schema: Schema, ID: id, Organization: organization, Project: project, Cell: cell, Spec: spec,
		State: StateActive, Generation: 1, CreatedAt: now, UpdatedAt: now}
	return t, CheckNew(t)
}

// Change replaces an active tenant's spec: a resize, a scale, adding or
// removing ts-auth, or a release upgrade or rollback. A new plan brings its
// resources; an unchanged one keeps the tenant's.
func (t Tenant) Change(spec Spec, now time.Time) (Tenant, error) {
	spec.Member = t.Spec.Member
	if spec.Plan != t.Spec.Plan {
		plan, ok := LookupPlan(spec.Plan)
		if !ok {
			return Tenant{}, fmt.Errorf("%w: unknown plan %q", ErrInvalid, spec.Plan)
		}
		spec.Member = plan.Member
	}
	return t.successor(StateActive, spec, time.Time{}, now)
}

// Suspend stops an active tenant's machines and keeps its data.
func (t Tenant) Suspend(now time.Time) (Tenant, error) {
	return t.successor(StateSuspended, t.Spec, time.Time{}, now)
}

// Resume restarts a suspended tenant.
func (t Tenant) Resume(now time.Time) (Tenant, error) {
	return t.successor(StateActive, t.Spec, time.Time{}, now)
}

// Delete stops the tenant for good and keeps its volumes and backups for
// retention.
func (t Tenant) Delete(retention time.Duration, now time.Time) (Tenant, error) {
	return t.successor(StateDeleted, t.Spec, t.stamp(now).Add(retention), now)
}

// Purge records that a deleted tenant's data is gone, once its retention
// has passed.
func (t Tenant) Purge(now time.Time) (Tenant, error) {
	return t.successor(StatePurged, t.Spec, t.RetainUntil, now)
}

// stamp is now, but never before the last change, so a controller with a
// slower clock than the previous writer still moves the tenant forward.
func (t Tenant) stamp(now time.Time) time.Time {
	now = now.UTC().Round(0)
	if now.Before(t.UpdatedAt) {
		return t.UpdatedAt
	}
	return now
}

func (t Tenant) successor(state State, spec Spec, retainUntil, now time.Time) (Tenant, error) {
	next := t
	next.State, next.Spec, next.RetainUntil = state, spec, retainUntil
	next.Generation++
	next.UpdatedAt = t.stamp(now)
	if err := CheckSuccessor(t, next); err != nil {
		return Tenant{}, err
	}
	return next, nil
}

// CheckSuccessor reports whether next may replace prev: the next generation
// of the same tenant, through an allowed transition. A generation changes
// either the release or the topology, never both, so a health rollback
// returns exactly the previous release.
func CheckSuccessor(prev, next Tenant) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if prev.ID != next.ID || prev.Organization != next.Organization || prev.Project != next.Project ||
		prev.Cell != next.Cell || !prev.CreatedAt.Equal(next.CreatedAt) {
		return fmt.Errorf("%w: a tenant's identity never changes", ErrInvalid)
	}
	if next.Generation != prev.Generation+1 || next.UpdatedAt.Before(prev.UpdatedAt) {
		return fmt.Errorf("%w: generation %d may only be followed by %d, no earlier than %s",
			ErrInvalid, prev.Generation, prev.Generation+1, prev.UpdatedAt.Format(time.RFC3339))
	}
	sameSpec := next.Spec == prev.Spec
	switch {
	case prev.State == StatePurged:
		return fmt.Errorf("%w: tenant %s is purged", ErrInvalid, prev.ID)
	case prev.State == StateDeleted:
		if next.State != StatePurged || !sameSpec || !next.RetainUntil.Equal(prev.RetainUntil) {
			return fmt.Errorf("%w: tenant %s is deleted and can only be purged", ErrInvalid, prev.ID)
		}
		return nil // Validate holds the purge until RetainUntil.
	case next.State == StatePurged:
		return fmt.Errorf("%w: only a deleted tenant is purged", ErrInvalid)
	case next.State == StateDeleted:
		if retention := next.RetainUntil.Sub(next.UpdatedAt); retention < MinRetention || retention > MaxRetention {
			return fmt.Errorf("%w: retention must be %v to %v", ErrInvalid, MinRetention, MaxRetention)
		}
		if !sameSpec {
			return fmt.Errorf("%w: a deletion changes no spec", ErrInvalid)
		}
		return nil
	case next.State != StateActive || prev.State != StateActive:
		if !sameSpec {
			return fmt.Errorf("%w: only an active tenant changes its spec", ErrInvalid)
		}
		if next.State == prev.State {
			return fmt.Errorf("%w: tenant %s is already %s", ErrUnchanged, prev.ID, prev.State)
		}
		return nil
	case sameSpec:
		return ErrUnchanged
	}
	before, after := prev.Spec, next.Spec
	if after.Plan != before.Plan {
		plan, ok := LookupPlan(after.Plan)
		if !ok || plan.Member != after.Member {
			return fmt.Errorf("%w: plan %q is not on sale at those resources", ErrInvalid, after.Plan)
		}
	} else if after.Member != before.Member {
		return fmt.Errorf("%w: member resources change only with the plan", ErrInvalid)
	}
	if after.Member.DiskBytes < before.Member.DiskBytes {
		return fmt.Errorf("%w: plan %s has less disk than %s, and volumes never shrink", ErrInvalid, after.Plan, before.Plan)
	}
	release := before.TerraBase != after.TerraBase || before.Auth != "" && after.Auth != "" && before.Auth != after.Auth
	topology := before.Plan != after.Plan || before.Members != after.Members || (before.Auth == "") != (after.Auth == "")
	if release && topology {
		return fmt.Errorf("%w: change the release and the topology in separate generations", ErrInvalid)
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	digest, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(digest) == value
}
