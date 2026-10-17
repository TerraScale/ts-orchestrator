// Package rootvolumeclient exposes only authenticated retained-volume reads.
package rootvolumeclient

import (
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	InspectOperation    = "inspect_volume_mount"
	TerminatedOperation = "observe_terminated_instance"
)

type Expectations struct {
	Cell        string `json:"cell,omitempty"`
	GrantSHA256 string `json:"grant_sha256,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	Epoch       uint64 `json:"epoch,omitzero"`
}

// Pins narrow an independently verified SDK attachment; they grant no access.
type Pins struct {
	DatabaseID, PartitionID                        string
	InstanceID, HostCreateKey                      string
	VolumeID, AttachmentID, AttachmentETag, Device string
	FileSystemUUID, FileSystemType                 string
}

// Authority is descriptive on the wire. Only Client can mint a usable proof.
type Authority struct {
	SourceSHA256, GrantSHA256, SessionSHA256 string
	Deadline                                 time.Time
}

type InspectRequest struct {
	Pins          Pins
	PredecessorID string
	Original      *Authority `json:",omitempty"`
}

type TerminatedRequest struct {
	InstanceID string
	Original   *Authority `json:",omitempty"`
}

type MountObservation struct {
	Pins                 Pins
	BootDescriptorSHA256 string
	PredecessorID        string
	ObservedAt           time.Time
	Authority            Authority
}

type TerminatedObservation struct {
	InstanceID, Region, Owner string
	Generation                uint64
	ObservedAt                time.Time
	Authority                 Authority
}

func (p Pins) Valid() bool {
	return entityid.Valid(p.DatabaseID) && entityid.Valid(p.PartitionID) && entityid.Valid(p.HostCreateKey) &&
		resourceID(p.InstanceID, "instance") && resourceID(p.VolumeID, "volume") && resourceID(p.AttachmentID, "volumeattachment") &&
		bounded(p.AttachmentETag, 1024) && strings.HasPrefix(p.Device, "/dev/") && bounded(p.Device, 255) &&
		!strings.Contains(p.Device, "..") && bounded(p.FileSystemUUID, 128) &&
		(p.FileSystemType == "ext4" || p.FileSystemType == "xfs")
}

func (r InspectRequest) Valid() bool {
	return r.Pins.Valid() && r.PredecessorID != r.Pins.InstanceID &&
		(r.PredecessorID == "" || resourceID(r.PredecessorID, "instance")) && (r.Original == nil || r.Original.Valid(time.Now()))
}

func (r TerminatedRequest) Valid() bool {
	return resourceID(r.InstanceID, "instance") && (r.Original == nil || r.Original.Valid(time.Now()))
}

func (a Authority) Valid(now time.Time) bool {
	return digest(a.SourceSHA256) && digest(a.GrantSHA256) && digest(a.SessionSHA256) &&
		now.Before(a.Deadline) && !a.Deadline.After(now.Add(30*time.Second))
}

func (o MountObservation) valid(now time.Time) bool {
	return o.Pins.Valid() && digest(o.BootDescriptorSHA256) && o.PredecessorID != o.Pins.InstanceID &&
		(o.PredecessorID == "" || resourceID(o.PredecessorID, "instance")) &&
		!o.ObservedAt.IsZero() && !o.ObservedAt.After(now) && o.Authority.Valid(now) && o.ObservedAt.Before(o.Authority.Deadline)
}

func (o TerminatedObservation) valid(now time.Time) bool {
	entry, ok := catalog.Lookup(o.Region)
	return ok && strings.HasPrefix(o.InstanceID, "ocid1.instance.oc1."+entry.OCIRegion+".") && resourceID(o.InstanceID, "instance") &&
		o.Generation > 0 && bounded(o.Owner, 256) && !o.ObservedAt.IsZero() && !o.ObservedAt.After(now) &&
		o.Authority.Valid(now) && o.ObservedAt.Before(o.Authority.Deadline)
}

func resourceID(value, kind string) bool {
	return strings.HasPrefix(value, "ocid1."+kind+".oc1.") && bounded(value, 255)
}

func bounded(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
