// Package databaselifecycle records resource existence and closes immutable
// billing inventory in the same authority transaction as database admission.
package databaselifecycle

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"math"
	"reflect"
	"regexp"
	"slices"
	"time"
)

var (
	ErrInvalid    = errors.New("database lifecycle: invalid event")
	ErrConflict   = errors.New("database lifecycle: immutable conflict")
	ErrClosed     = errors.New("database lifecycle: inventory window closed")
	ErrIncomplete = errors.New("database lifecycle: stream inventory incomplete")
)
var idPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

type Identity struct {
	Environment    string `json:"environment"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	DatabaseID     string `json:"database_id"`
	// Branches have their own database ID; parent is linkage, never a usage scope.
	ParentDatabaseID string `json:"parent_database_id,omitempty"`
}
type Stream struct {
	Region    string    `json:"region"`
	Partition string    `json:"partition"`
	Epoch     uint64    `json:"epoch"`
	StartedAt time.Time `json:"started_at"`
	StoppedAt time.Time `json:"stopped_at,omitzero"`
}
type Resource struct {
	Identity
	Regions        []string  `json:"regions"`
	CreatedAt      time.Time `json:"created_at"`
	DeletedAt      time.Time `json:"deleted_at,omitzero"`
	UsageStoppedAt time.Time `json:"usage_stopped_at,omitzero"`
	AccessRevoked  bool      `json:"access_revoked"`
	// Physical deletion is separately acknowledged. Retained backup bytes never
	// extend the billable existence interval.
	EffectsCompletedAt time.Time `json:"effects_completed_at,omitzero"`
	RetainUntil        time.Time `json:"retain_until,omitzero"`
	Streams            []Stream  `json:"streams"`
}
type Event struct {
	OperationID string `json:"operation_id"`
	Kind        string `json:"kind"`
	Identity
	At          time.Time `json:"at"`
	Regions     []string  `json:"regions,omitempty"`
	Streams     []Stream  `json:"streams,omitempty"`
	RetainUntil time.Time `json:"retain_until,omitzero"`
}
type Snapshot struct {
	OrganizationID string     `json:"organization_id"`
	Start          time.Time  `json:"start"`
	End            time.Time  `json:"end"`
	Revision       uint64     `json:"revision"`
	Resources      []Resource `json:"resources"`
	Digest         string     `json:"digest"`
}
type State struct {
	Revision  uint64
	Resources map[string]Resource
	Events    map[string]Event
	Closed    map[string]Snapshot
}

func NewState() State {
	return State{Resources: map[string]Resource{}, Events: map[string]Event{}, Closed: map[string]Snapshot{}}
}
func Key(identity Identity) string {
	return identity.Environment + "/" + identity.OrganizationID + "/" + identity.DatabaseID
}
func validIdentity(i Identity) bool {
	return i.Environment != "" && len(i.Environment) <= 128 && idPattern.MatchString(i.OrganizationID) && idPattern.MatchString(i.ProjectID) && idPattern.MatchString(i.DatabaseID) && (i.ParentDatabaseID == "" || idPattern.MatchString(i.ParentDatabaseID) && i.ParentDatabaseID != i.DatabaseID)
}
func validRegions(regions []string) bool {
	if len(regions) < 1 || len(regions) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, r := range regions {
		if seen[r] || !slices.Contains([]string{"GRU", "SFO", "FRA"}, r) {
			return false
		}
		seen[r] = true
	}
	return true
}
func Validate(state State) error {
	if state.Resources == nil || state.Events == nil || state.Closed == nil {
		return ErrInvalid
	}
	for k, r := range state.Resources {
		if k != Key(r.Identity) || !validIdentity(r.Identity) || !validRegions(r.Regions) || r.CreatedAt.IsZero() {
			return ErrInvalid
		}
		if !r.DeletedAt.IsZero() && (r.DeletedAt.Before(r.CreatedAt) || !r.AccessRevoked || !r.UsageStoppedAt.Equal(r.DeletedAt)) {
			return ErrInvalid
		}
		if r.DeletedAt.IsZero() && (r.AccessRevoked || !r.UsageStoppedAt.IsZero() || !r.EffectsCompletedAt.IsZero()) {
			return ErrInvalid
		}
		if !r.EffectsCompletedAt.IsZero() && r.EffectsCompletedAt.Before(r.DeletedAt) {
			return ErrInvalid
		}
		if err := validateStreams(r, r.Streams); err != nil {
			return err
		}
	}
	for key, event := range state.Events {
		if key != eventKey(event) || !validIdentity(event.Identity) || event.At.IsZero() {
			return ErrInvalid
		}
	}
	for key, snapshot := range state.Closed {
		if key != snapshotKey(snapshot.OrganizationID, snapshot.Start, snapshot.End) || snapshot.Digest != digest(snapshot) || snapshot.Revision > state.Revision {
			return ErrInvalid
		}
	}
	return nil
}
func validateStreams(r Resource, streams []Stream) error {
	seen := map[string]bool{}
	for _, s := range streams {
		key := s.Region + "/" + s.Partition + "/" + time.Unix(int64(s.Epoch), 0).String()
		if !slices.Contains(r.Regions, s.Region) || len(s.Partition) == 0 || len(s.Partition) > 255 || s.Epoch == 0 || s.StartedAt.Before(r.CreatedAt) || seen[key] || (!s.StoppedAt.IsZero() && !s.StoppedAt.After(s.StartedAt)) {
			return ErrInvalid
		}
		seen[key] = true
	}
	return nil
}
func eventKey(e Event) string { return e.Environment + "/" + e.OrganizationID + "/" + e.OperationID }
func snapshotKey(org string, start, end time.Time) string {
	return org + "/" + start.UTC().Format(time.RFC3339Nano) + "/" + end.UTC().Format(time.RFC3339Nano)
}
func digest(s Snapshot) string {
	s.Digest = ""
	data, _ := json.Marshal(s)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Apply must run within the caller's durable, epoch-fenced transaction. Retries
// preserve the original event time. Closed intervals reject backdated events.
func Apply(state *State, e Event) error {
	if state == nil || Validate(*state) != nil || !validIdentity(e.Identity) || e.OperationID == "" || len(e.OperationID) > 255 || e.At.IsZero() || state.Revision == math.MaxUint64 {
		return ErrInvalid
	}
	e.At = e.At.UTC()
	e.RetainUntil = e.RetainUntil.UTC()
	e.Regions = slices.Clone(e.Regions)
	slices.Sort(e.Regions)
	if old, ok := state.Events[eventKey(e)]; ok {
		if reflect.DeepEqual(old, e) {
			return nil
		}
		return ErrConflict
	}
	for _, closed := range state.Closed {
		if closed.OrganizationID == e.OrganizationID && e.At.Before(closed.End) && e.Kind != "effects_completed" {
			return ErrClosed
		}
	}
	key := Key(e.Identity)
	r, found := state.Resources[key]
	switch e.Kind {
	case "create", "branch_create":
		if found || !validRegions(e.Regions) || (e.Kind == "create" && e.ParentDatabaseID != "") || (e.Kind == "branch_create" && e.ParentDatabaseID == "") {
			return ErrConflict
		}
		if e.Kind == "branch_create" {
			parentID := e.Identity
			parentID.DatabaseID = e.ParentDatabaseID
			parent, ok := state.Resources[Key(parentID)]
			if !ok || parent.ProjectID != e.ProjectID || !parent.DeletedAt.IsZero() || e.At.Before(parent.CreatedAt) || !slices.Equal(parent.Regions, e.Regions) {
				return ErrConflict
			}
		}
		r = Resource{Identity: e.Identity, Regions: e.Regions, CreatedAt: e.At, Streams: slices.Clone(e.Streams)}
	case "streams":
		if !found || r.Identity != e.Identity || !r.DeletedAt.IsZero() || len(e.Streams) == 0 {
			return ErrConflict
		}
		// A routing revision provides the complete append-only stream history.
		// Existing identities and intervals cannot be silently removed or rewritten.
		for _, old := range r.Streams {
			if !slices.Contains(e.Streams, old) {
				return ErrConflict
			}
		}
		r.Streams = slices.Clone(e.Streams)
	case "delete":
		if !found || r.Identity != e.Identity || !r.DeletedAt.IsZero() || e.At.Before(r.CreatedAt) || (!e.RetainUntil.IsZero() && e.RetainUntil.Before(e.At)) {
			return ErrConflict
		}
		r.DeletedAt = e.At
		r.UsageStoppedAt = e.At
		r.AccessRevoked = true
		r.RetainUntil = e.RetainUntil
		// Parent deletion closes every still-live branch in this same transaction.
		for childKey, child := range state.Resources {
			if child.Environment == r.Environment && child.OrganizationID == r.OrganizationID && child.ParentDatabaseID == r.DatabaseID && child.DeletedAt.IsZero() {
				child.DeletedAt = e.At
				child.UsageStoppedAt = e.At
				child.AccessRevoked = true
				child.RetainUntil = e.RetainUntil
				state.Resources[childKey] = child
			}
		}
	case "effects_completed":
		if !found || r.Identity != e.Identity || r.DeletedAt.IsZero() || e.At.Before(r.DeletedAt) || !r.EffectsCompletedAt.IsZero() {
			return ErrConflict
		}
		r.EffectsCompletedAt = e.At
	default:
		return ErrInvalid
	}
	if err := validateStreams(r, r.Streams); err != nil {
		return err
	}
	state.Resources[key] = r
	state.Events[eventKey(e)] = e
	state.Revision++
	return nil
}

// Freeze establishes the inventory close barrier atomically with its exact
// resource/stream set. Lack of routing evidence is an error, never completeness.
func Freeze(state *State, org string, start, end time.Time) (Snapshot, error) {
	if state == nil || Validate(*state) != nil || !idPattern.MatchString(org) || start.IsZero() || !end.After(start) || state.Revision == math.MaxUint64 {
		return Snapshot{}, ErrInvalid
	}
	key := snapshotKey(org, start, end)
	if old, ok := state.Closed[key]; ok {
		return old, nil
	}
	for _, old := range state.Closed {
		if old.OrganizationID == org && start.Before(old.End) && end.After(old.Start) {
			return Snapshot{}, ErrConflict
		}
	}
	out := Snapshot{OrganizationID: org, Start: start.UTC(), End: end.UTC(), Revision: state.Revision + 1, Resources: []Resource{}}
	for _, r := range state.Resources {
		if r.OrganizationID != org || !r.CreatedAt.Before(end) || (!r.UsageStoppedAt.IsZero() && !r.UsageStoppedAt.After(start)) {
			continue
		}
		from := start
		if r.CreatedAt.After(from) {
			from = r.CreatedAt
		}
		until := end
		if !r.UsageStoppedAt.IsZero() && r.UsageStoppedAt.Before(until) {
			until = r.UsageStoppedAt
		}
		for _, region := range r.Regions {
			covered := false
			for _, stream := range r.Streams {
				if stream.Region == region && !stream.StartedAt.After(from) && (stream.StoppedAt.IsZero() || !stream.StoppedAt.Before(until)) {
					covered = true
				}
			}
			if !covered {
				return Snapshot{}, ErrIncomplete
			}
		}
		// Clone through serialization to prevent callers mutating closed receipts.
		data, _ := json.Marshal(r)
		var cloned Resource
		if err := json.Unmarshal(data, &cloned); err != nil {
			return Snapshot{}, err
		}
		out.Resources = append(out.Resources, cloned)
	}
	slices.SortFunc(out.Resources, func(a, b Resource) int { return cmp.Compare(Key(a.Identity), Key(b.Identity)) })
	out.Digest = digest(out)
	state.Revision++
	state.Closed[key] = out
	return out, nil
}
