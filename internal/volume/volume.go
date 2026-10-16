// Package volume owns managed persistent volumes: Fly-style OCI block volumes
// that keep a machine's data off its boot disk. A volume belongs to an app,
// lives in one availability domain and is mounted by at most one machine.
// See docs/managed-volumes.md.
package volume

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// SchemaVersion is the version of a stored volume record.
const SchemaVersion = 1

// OCI block volume limits and the Fly-style defaults an API applies.
const (
	MinSizeGB                    = 50
	MaxSizeGB                    = 32768
	DefaultVPUsPerGB             = 10
	DefaultSnapshotRetentionDays = 5
	maxSnapshotRetentionDays     = 60
	maxVPUsPerGB                 = 120
	maxMessageBytes              = 1024
)

var (
	ErrInvalid  = errors.New("invalid managed volume")
	ErrNotFound = errors.New("managed volume does not exist")
	// ErrConflict marks a lost compare-and-set race; re-read and retry.
	ErrConflict = errors.New("managed volume changed concurrently")
	// ErrTransition marks a change the volume's current record forbids.
	ErrTransition = errors.New("managed volume change is not allowed")
)

var (
	// appRE and machineRE are internal/machines' app name and machine ID
	// rules.
	appRE  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	nameRE = regexp.MustCompile(`^[a-z0-9_]{1,30}$`)
	zoneRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$`)
)

// State is the reconciler's view of a volume. Growing, restoring and
// attaching show in the spec and status fields and need no state of their
// own.
type State string

const (
	// StateCreating: the record exists and OCI has not confirmed the volume.
	StateCreating State = "creating"
	// StateCreated: the OCI volume is available.
	StateCreated State = "created"
	// StatePendingDestroy: destroy was requested; the OCI volume still exists.
	StatePendingDestroy State = "pending_destroy"
	// StateDestroyed: the OCI volume is deleted. Nothing changes afterwards.
	StateDestroyed State = "destroyed"
	// StateFailed: the OCI volume is lost or unusable and needs an operator.
	StateFailed State = "failed"
)

// transitions lists the states each state may move to.
var transitions = map[State][]State{
	StateCreating:       {StateCreated, StateFailed},
	StateCreated:        {StateFailed, StatePendingDestroy},
	StateFailed:         {StateCreated, StatePendingDestroy},
	StatePendingDestroy: {StateDestroyed},
	StateDestroyed:      nil,
}

// Volume is one record of the TS_VOLUMES bucket. The creator sets the
// identity, the API the size, tier, retention and destroy request, the
// scheduler MachineID and the reconciler Status.
type Volume struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"id"`
	App           string `json:"app"`
	// Name is not unique: an app scales by giving several machines a volume
	// of the same name.
	Name string `json:"name"`
	// Region is the lower-case catalog name, for example gru, as in
	// internal/machines.
	Region string `json:"region"`
	// Zone is the OCI availability domain, fixed at create.
	Zone string `json:"zone"`
	// SizeGB is the desired size. It only grows.
	SizeGB int64 `json:"size_gb"`
	// VPUsPerGB is the OCI performance tier: 0 (Lower Cost), 10 (Balanced)
	// or 20 to 120 in steps of 10.
	VPUsPerGB int `json:"vpus_per_gb"`
	// SnapshotRetentionDays is Fly's snapshot_retention: days of daily
	// snapshots.
	SnapshotRetentionDays int `json:"snapshot_retention"`
	// MachineID is the machine that may mount the volume.
	MachineID          string    `json:"machine_id,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	DestroyRequestedAt time.Time `json:"destroy_requested_at,omitzero"`
	Status             Status    `json:"status"`
	// Revision is the KV revision the record was read at; it is not stored.
	Revision uint64 `json:"-"`
}

// Status is written by the reconciler.
type Status struct {
	State State `json:"state"`
	// Epoch is the authority epoch of the reconciler that wrote the status.
	// It never goes back, so a deposed leader cannot overwrite a newer
	// observation.
	Epoch uint64 `json:"epoch,omitzero"`
	// OCID is the OCI volume. Once recorded it never changes.
	OCID string `json:"ocid,omitempty"`
	// SizeGB is the size OCI confirmed. It may exceed the desired size: an
	// adopted volume or one grown outside the orchestrator stays larger,
	// because OCI never shrinks a volume.
	SizeGB int64 `json:"size_gb,omitzero"`
	// AttachedMachineID is the machine whose host OCI attaches the volume
	// to. It differs from the desired MachineID while the volume moves: the
	// reconciler detaches it from this machine, after proof that it stopped,
	// before it attaches the volume to MachineID.
	AttachedMachineID string `json:"attached_machine_id,omitempty"`
	Message           string `json:"message,omitempty"`
}

// NewID returns a fresh canonical ULID for a volume.
func NewID() string { return entityid.New() }

// Destroying reports whether destroy was requested.
func (v Volume) Destroying() bool { return !v.DestroyRequestedAt.IsZero() }

// Validate checks the shape of one record.
func (v Volume) Validate() error {
	switch {
	case v.SchemaVersion != SchemaVersion:
		return fmt.Errorf("%w: schema version %d", ErrInvalid, v.SchemaVersion)
	case !entityid.Valid(v.ID):
		return fmt.Errorf("%w: id %q", ErrInvalid, v.ID)
	case !appRE.MatchString(v.App):
		return fmt.Errorf("%w: app %q", ErrInvalid, v.App)
	case !nameRE.MatchString(v.Name):
		return fmt.Errorf("%w: name %q must be 1 to 30 of a-z, 0-9 and _", ErrInvalid, v.Name)
	case !validRegion(v.Region):
		return fmt.Errorf("%w: region %q", ErrInvalid, v.Region)
	case !zoneRE.MatchString(v.Zone):
		return fmt.Errorf("%w: zone %q", ErrInvalid, v.Zone)
	case v.SizeGB < MinSizeGB || v.SizeGB > MaxSizeGB:
		return fmt.Errorf("%w: size must be %d to %d GB", ErrInvalid, MinSizeGB, MaxSizeGB)
	case v.VPUsPerGB < 0 || v.VPUsPerGB > maxVPUsPerGB || v.VPUsPerGB%10 != 0:
		return fmt.Errorf("%w: vpus_per_gb must be 0 to %d in steps of 10", ErrInvalid, maxVPUsPerGB)
	case v.SnapshotRetentionDays < 1 || v.SnapshotRetentionDays > maxSnapshotRetentionDays:
		return fmt.Errorf("%w: snapshot retention must be 1 to %d days", ErrInvalid, maxSnapshotRetentionDays)
	case v.MachineID != "" && !entityid.Valid(v.MachineID):
		return fmt.Errorf("%w: machine %q", ErrInvalid, v.MachineID)
	case v.CreatedAt.IsZero():
		return fmt.Errorf("%w: no creation time", ErrInvalid)
	}
	if v.Destroying() && v.MachineID != "" {
		return fmt.Errorf("%w: a destroying volume has no machine", ErrInvalid)
	}
	return v.Status.validate(v.Destroying())
}

func (s Status) validate(destroying bool) error {
	if _, ok := transitions[s.State]; !ok {
		return fmt.Errorf("%w: state %q", ErrInvalid, s.State)
	}
	switch {
	case s.OCID != "" && !isOCID(s.OCID, "volume"):
		return fmt.Errorf("%w: status ocid %q", ErrInvalid, s.OCID)
	case s.State == StateCreated && s.OCID == "":
		return fmt.Errorf("%w: a created volume has an OCID", ErrInvalid)
	case s.SizeGB != 0 && (s.SizeGB < MinSizeGB || s.SizeGB > MaxSizeGB):
		return fmt.Errorf("%w: status size", ErrInvalid)
	case s.AttachedMachineID != "" && (!entityid.Valid(s.AttachedMachineID) || s.OCID == ""):
		return fmt.Errorf("%w: attached machine %q", ErrInvalid, s.AttachedMachineID)
	case len(s.Message) > maxMessageBytes:
		return fmt.Errorf("%w: status message is too long", ErrInvalid)
	case (s.State == StatePendingDestroy || s.State == StateDestroyed) && !destroying:
		return fmt.Errorf("%w: %s without a destroy request", ErrInvalid, s.State)
	case s.State == StateDestroyed && s.AttachedMachineID != "":
		return fmt.Errorf("%w: a destroyed volume is attached", ErrInvalid)
	}
	return nil
}

func validRegion(region string) bool {
	_, ok := catalog.LookupName(region)
	return ok
}

// isOCID is internal/oci's OCID rule.
func isOCID(value, kind string) bool {
	return strings.HasPrefix(value, "ocid1."+kind+".") && len(value) <= 255 && !strings.ContainsAny(value, " \t\r\n")
}

// checkUpdate refuses a change the stored record prev forbids.
func checkUpdate(prev, next Volume) error {
	if err := next.Validate(); err != nil {
		return err
	}
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: volume %s: %s", ErrTransition, prev.ID, fmt.Sprintf(format, args...))
	}
	switch {
	case prev.Status.State == StateDestroyed:
		return fail("it is destroyed")
	case next.ID != prev.ID || next.App != prev.App || next.Name != prev.Name || next.Region != prev.Region ||
		next.Zone != prev.Zone || !next.CreatedAt.Equal(prev.CreatedAt):
		return fail("its identity and zone never change")
	case next.SizeGB < prev.SizeGB || next.Status.SizeGB < prev.Status.SizeGB:
		return fail("it only grows")
	case prev.Destroying() && !next.DestroyRequestedAt.Equal(prev.DestroyRequestedAt):
		return fail("a destroy request is final")
	case prev.MachineID != "" && (next.MachineID != "" && next.MachineID != prev.MachineID || next.Destroying()):
		return fail("it is held by machine %s; release it first", prev.MachineID)
	case next.Status != prev.Status && (next.Status.Epoch == 0 || next.Status.Epoch < prev.Status.Epoch):
		return fail("its status was written at epoch %d; a status write needs that epoch or later", prev.Status.Epoch)
	case prev.Status.OCID != "" && next.Status.OCID != prev.Status.OCID:
		return fail("its OCI volume never changes")
	case next.Status.State != prev.Status.State && !slices.Contains(transitions[prev.Status.State], next.Status.State):
		return fail("state %s cannot become %s", prev.Status.State, next.Status.State)
	}
	return nil
}

// Mount is the volume a machine mounts, in the Fly machine config shape.
type Mount struct {
	Volume string `json:"volume"`
	Path   string `json:"path"`
}

// systemPaths are pseudo-filesystems a volume never covers.
var systemPaths = []string{"/dev", "/proc", "/run", "/sys"}

func (m Mount) validate() error {
	clean := path.Clean(m.Path)
	if !entityid.Valid(m.Volume) || !path.IsAbs(m.Path) || clean != m.Path || clean == "/" || len(m.Path) > 255 ||
		strings.ContainsFunc(m.Path, func(r rune) bool { return r <= ' ' || r == ':' || r == 0x7f }) {
		return fmt.Errorf("%w: mount %q at %q needs a volume ID and a clean absolute path", ErrInvalid, m.Volume, m.Path)
	}
	for _, system := range systemPaths {
		if clean == system || strings.HasPrefix(clean, system+"/") {
			return fmt.Errorf("%w: mount path %q is under %s", ErrInvalid, m.Path, system)
		}
	}
	return nil
}
