package volume

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const testZone = "Uocm:SA-SAOPAULO-1-AD-1"

// m1 and m2 are machine IDs.
const m1, m2 = "0000000000NDAHWBAS9TWA2688", "0000000000010GG0W1SYDN4G5Z"

var created = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func testVolume(id string) Volume {
	return Volume{SchemaVersion: SchemaVersion, ID: id, App: "terrabase", Name: "data", Region: "gru", Zone: testZone,
		SizeGB: 50, VPUsPerGB: DefaultVPUsPerGB, SnapshotRetentionDays: DefaultSnapshotRetentionDays,
		CreatedAt: created, Status: Status{State: StateCreating}}
}

func TestNewIDIsValidAndUnique(t *testing.T) {
	a, b := NewID(), NewID()
	if !entityid.Valid(a) || a == b {
		t.Fatalf("NewID gave %q and %q", a, b)
	}
}

func TestValidateRejectsMalformedRecords(t *testing.T) {
	ocid := "ocid1.volume.oc1.sa-saopaulo-1.abcdef"
	for name, mutate := range map[string]func(*Volume){
		"schema":                func(v *Volume) { v.SchemaVersion = 2 },
		"id":                    func(v *Volume) { v.ID = "vol_UPPER" },
		"app":                   func(v *Volume) { v.App = "bad-" },
		"name":                  func(v *Volume) { v.Name = "has-dash" },
		"region":                func(v *Volume) { v.Region = "GRU" },
		"zone":                  func(v *Volume) { v.Zone = "AD 1" },
		"too small":             func(v *Volume) { v.SizeGB = 49 },
		"too large":             func(v *Volume) { v.SizeGB = MaxSizeGB + 1 },
		"vpus step":             func(v *Volume) { v.VPUsPerGB = 15 },
		"vpus max":              func(v *Volume) { v.VPUsPerGB = 130 },
		"retention":             func(v *Volume) { v.SnapshotRetentionDays = 0 },
		"machine":               func(v *Volume) { v.MachineID = "invalid" },
		"no created_at":         func(v *Volume) { v.CreatedAt = time.Time{} },
		"destroying claimed":    func(v *Volume) { v.DestroyRequestedAt = created; v.MachineID = m1 },
		"state":                 func(v *Volume) { v.Status.State = "extending" },
		"created without ocid":  func(v *Volume) { v.Status.State = StateCreated },
		"ocid kind":             func(v *Volume) { v.Status.OCID = "ocid1.instance.oc1.x.y" },
		"attached without ocid": func(v *Volume) { v.Status.AttachedMachineID = m1 },
		"long message":          func(v *Volume) { v.Status.Message = strings.Repeat("x", maxMessageBytes+1) },
		"pending without request": func(v *Volume) {
			v.Status = Status{State: StatePendingDestroy, OCID: ocid}
		},
		"destroyed but attached": func(v *Volume) {
			v.DestroyRequestedAt = created
			v.Status = Status{State: StateDestroyed, OCID: ocid, AttachedMachineID: m1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := testVolume(NewID())
			mutate(&v)
			if err := v.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() = %v, want ErrInvalid", err)
			}
		})
	}
	v := testVolume(NewID())
	v.VPUsPerGB = 0
	if err := v.Validate(); err != nil {
		t.Fatalf("lower-cost volume: %v", err)
	}
	// OCI test and preview OCIDs carry hyphens in their unique part.
	v.Status = Status{State: StateCreated, Epoch: 1, OCID: "ocid1.volume.oc1.sa-saopaulo-1.managed-a"}
	if err := v.Validate(); err != nil {
		t.Fatalf("hyphenated OCID: %v", err)
	}
}

func TestCheckUpdateGuardsIdentityGrowthAndOwnership(t *testing.T) {
	ocid := "ocid1.volume.oc1.sa-saopaulo-1.abcdef"
	prev := testVolume(NewID())
	prev.MachineID = m1
	prev.Status = Status{State: StateCreated, Epoch: 4, OCID: ocid, SizeGB: 100}
	prev.SizeGB = 100
	for name, mutate := range map[string]func(*Volume){
		"zone":             func(v *Volume) { v.Zone = "Uocm:SA-SAOPAULO-1-AD-2" },
		"app":              func(v *Volume) { v.App = "other" },
		"name":             func(v *Volume) { v.Name = "logs" },
		"created_at":       func(v *Volume) { v.CreatedAt = created.Add(time.Second) },
		"shrink":           func(v *Volume) { v.SizeGB = 50 },
		"status shrink":    func(v *Volume) { v.Status.SizeGB = 50 },
		"steal":            func(v *Volume) { v.MachineID = m2 },
		"rebind ocid":      func(v *Volume) { v.Status.OCID = "ocid1.volume.oc1.sa-saopaulo-1.other" },
		"back to creating": func(v *Volume) { v.Status.State = StateCreating },
		"release and destroy at once": func(v *Volume) {
			v.MachineID = ""
			v.DestroyRequestedAt = created
		},
		// A deposed leader read the record and writes an old observation.
		"older epoch": func(v *Volume) {
			v.Status.Epoch = 3
			v.Status.State = StateFailed
		},
		"status without epoch": func(v *Volume) {
			v.Status.Epoch = 0
			v.Status.Message = "observed"
		},
		"destroyed without pending": func(v *Volume) {
			v.MachineID = ""
			v.DestroyRequestedAt = created
			v.Status.State = StateDestroyed
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := prev
			mutate(&next)
			if err := checkUpdate(prev, next); !errors.Is(err, ErrTransition) {
				t.Fatalf("checkUpdate() = %v, want ErrTransition", err)
			}
		})
	}

	grown := prev
	grown.SizeGB, grown.VPUsPerGB, grown.SnapshotRetentionDays = 200, 0, 30
	if err := checkUpdate(prev, grown); err != nil {
		t.Fatalf("grow and retier: %v", err)
	}
	// OCI never shrinks, so an adopted or console-grown volume is larger
	// than desired and the reconciler records that.
	larger := prev
	larger.Status.SizeGB, larger.Status.Epoch = 500, 5
	if err := checkUpdate(prev, larger); err != nil {
		t.Fatalf("observed size above the desired size: %v", err)
	}

	attached := prev
	attached.Status.AttachedMachineID, attached.Status.Epoch = m1, 5
	if err := checkUpdate(prev, attached); err != nil {
		t.Fatalf("attached: %v", err)
	}
	released := attached
	released.MachineID = ""
	if err := checkUpdate(attached, released); err != nil {
		t.Fatalf("release: %v", err)
	}
	// While the volume moves, OCI still attaches it to the old machine and
	// the new one already holds it; the reconciler acts on the difference.
	moving := released
	moving.MachineID = m2
	if err := checkUpdate(released, moving); err != nil {
		t.Fatalf("claim by another machine while still attached: %v", err)
	}
	destroying := released
	destroying.Status.AttachedMachineID = ""
	destroying.DestroyRequestedAt = created
	if err := checkUpdate(released, destroying); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	pending := destroying
	pending.Status.State, pending.Status.Epoch = StatePendingDestroy, 6
	if err := checkUpdate(destroying, pending); err != nil {
		t.Fatalf("pending destroy at a newer epoch: %v", err)
	}
	undo := pending
	undo.DestroyRequestedAt = time.Time{}
	undo.Status.State = StateCreated
	if err := checkUpdate(pending, undo); !errors.Is(err, ErrTransition) {
		t.Fatalf("undo destroy = %v, want ErrTransition", err)
	}
	gone := pending
	gone.Status.State = StateDestroyed
	if err := checkUpdate(pending, gone); err != nil {
		t.Fatalf("destroyed: %v", err)
	}
	if err := checkUpdate(gone, gone); !errors.Is(err, ErrTransition) {
		t.Fatalf("change after destroyed = %v, want ErrTransition", err)
	}
}
