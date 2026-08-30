// Port of src/TerraScale.Orchestrator/Messaging/GlobalCellDirectory.cs.
package control

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GlobalCellAdvertisement mirrors the C# record. JSON tags mirror the C#
// source-generated context (default options: PascalCase names, null semantics
// through pointers).
type GlobalCellAdvertisement struct {
	SchemaVersion     int                             `json:"SchemaVersion"`
	Cell              string                          `json:"Cell"`
	Cluster           string                          `json:"Cluster"`
	AuthorityId       string                          `json:"AuthorityId"`
	AuthorityEpoch    int64                           `json:"AuthorityEpoch"`
	AuthorityRevision int64                           `json:"AuthorityRevision"`
	Sequence          int64                           `json:"Sequence"`
	Capabilities      []string                        `json:"Capabilities"`
	Membership        RegionalRuntimeMembershipHealth `json:"Membership"`
	ObservedAt        time.Time                       `json:"ObservedAt"`
	LeaseExpiresAt    time.Time                       `json:"LeaseExpiresAt"`
	Endpoints         []string                        `json:"Endpoints,omitempty"`
}

// GlobalCellAdvertisementSemanticLease mirrors the C# SemanticLease.
const GlobalCellAdvertisementSemanticLease = 20 * time.Second

// IsValid mirrors the C# IsValid.
func (a GlobalCellAdvertisement) IsValid(now time.Time) bool {
	valid := a.SchemaVersion == 1 &&
		GlobalNatsTopologyIsCellToken(a.Cell) &&
		a.Cluster == "orchestrator-control-"+a.Cell &&
		a.AuthorityId == a.Cell+"-regional" &&
		a.AuthorityEpoch > 0 && a.AuthorityRevision > 0 && a.Sequence > 0 &&
		len(a.Capabilities) > 0 && len(a.Capabilities) <= 64 &&
		allCapabilitiesBounded63(a.Capabilities) &&
		isOrdinallySortedAndDistinct(a.Capabilities) &&
		a.Membership.ObservedAt.Equal(a.ObservedAt) &&
		a.Membership.ActiveControllers > 0 && a.Membership.AuthorityLeaders == 1 &&
		!a.ObservedAt.After(now.Add(time.Minute)) &&
		a.LeaseExpiresAt.Equal(a.ObservedAt.Add(GlobalCellAdvertisementSemanticLease)) &&
		len(a.Endpoints) >= 1 && len(a.Endpoints) <= 8

	if !valid {
		return false
	}

	for _, endpoint := range a.Endpoints {
		if !GlobalCellAdvertisementIsControlEndpoint(endpoint) {
			return false
		}
	}

	return isOrdinallySortedAndDistinct(a.Endpoints)
}

func allCapabilitiesBounded63(values []string) bool {
	for _, value := range values {
		if len(value) < 1 || len(value) > 63 {
			return false
		}

		if value[0] == '-' || value[len(value)-1] == '-' {
			return false
		}

		for index := 0; index < len(value); index++ {
			character := value[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
				character == '-' {
				continue
			}

			return false
		}
	}

	return true
}

// GlobalCellAdvertisementIsControlEndpoint mirrors the C# IsControlEndpoint: a
// cell advertisement endpoint is an absolute lowercase URI with an explicit
// port, no path, query, fragment, or user information.
func GlobalCellAdvertisementIsControlEndpoint(endpoint string) bool {
	if len(endpoint) < 8 || len(endpoint) > 253 {
		return false
	}

	parsed, err := url.Parse(endpoint)
	if err != nil || !parsed.IsAbs() {
		return false
	}

	scheme := parsed.Scheme
	if len(scheme) < 3 || len(scheme) > 16 {
		return false
	}

	for index := 0; index < len(scheme); index++ {
		character := scheme[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '+' {
			continue
		}

		return false
	}

	if strings.ToLower(scheme) != scheme {
		return false
	}

	if parsed.Host == "" || strings.ToLower(parsed.Hostname()) != parsed.Hostname() {
		return false
	}

	port := parsed.Port()
	if port == "" {
		return false
	}

	portNumber := 0
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return false
		}

		portNumber = portNumber*10 + int(digit-'0')
	}

	if portNumber <= 0 || portNumber >= 65536 {
		return false
	}

	if parsed.Path != "" && parsed.Path != "/" {
		return false
	}

	return parsed.RawQuery == "" && parsed.Fragment == "" && parsed.User == nil
}

// GlobalCellAdvertisementDisposition mirrors the C# enum.
type GlobalCellAdvertisementDisposition int

const (
	GlobalCellAdvertisementDispositionAccepted  GlobalCellAdvertisementDisposition = 0
	GlobalCellAdvertisementDispositionDuplicate GlobalCellAdvertisementDisposition = 1
	GlobalCellAdvertisementDispositionStale     GlobalCellAdvertisementDisposition = 2
	GlobalCellAdvertisementDispositionRejected  GlobalCellAdvertisementDisposition = 3
)

// GlobalCellDirectoryCondition mirrors the C# enum (serialized as strings by
// the C# JsonStringEnumConverter).
type GlobalCellDirectoryCondition int

const (
	GlobalCellDirectoryConditionUnavailable GlobalCellDirectoryCondition = 0
	GlobalCellDirectoryConditionDegraded    GlobalCellDirectoryCondition = 1
	GlobalCellDirectoryConditionHealthy     GlobalCellDirectoryCondition = 2
)

func (c GlobalCellDirectoryCondition) String() string {
	switch c {
	case GlobalCellDirectoryConditionUnavailable:
		return "Unavailable"
	case GlobalCellDirectoryConditionDegraded:
		return "Degraded"
	case GlobalCellDirectoryConditionHealthy:
		return "Healthy"
	default:
		return ""
	}
}

// GlobalCellDirectoryEntry mirrors the C# record.
type GlobalCellDirectoryEntry struct {
	Cell              string
	Cluster           string
	AuthorityId       string
	AuthorityEpoch    int64
	AuthorityRevision int64
	Sequence          int64
	Capabilities      []string
	Membership        RegionalRuntimeMembershipHealth
	ObservedAt        time.Time
	LeaseExpiresAt    time.Time
	IsStale           bool
	Endpoints         []string
}

// GlobalCellDirectorySnapshot mirrors the C# record. JSON tags mirror the C#
// source-generated context (default options: PascalCase names).
type GlobalCellDirectorySnapshot struct {
	SchemaVersion          int                          `json:"SchemaVersion"`
	ObservedAt             time.Time                    `json:"ObservedAt"`
	ActiveCells            int                          `json:"ActiveCells"`
	StaleCells             int                          `json:"StaleCells"`
	RejectedAdvertisements int64                        `json:"RejectedAdvertisements"`
	Condition              GlobalCellDirectoryCondition `json:"Condition"`
	Cells                  []GlobalCellDirectoryEntry   `json:"Cells"`
}

// Validate mirrors the C# Validate.
func (s *GlobalCellDirectorySnapshot) Validate() error {
	active := 0
	for _, cell := range s.Cells {
		if !cell.IsStale {
			active++
		}
	}

	stale := len(s.Cells) - active
	condition := GlobalCellDirectoryConditionDegraded
	if active == 0 {
		condition = GlobalCellDirectoryConditionUnavailable
	} else if stale == 0 && allCellsHealthy(s.Cells) {
		condition = GlobalCellDirectoryConditionHealthy
	}

	valid := s.SchemaVersion == 1 &&
		!s.ObservedAt.IsZero() &&
		!s.ObservedAt.After(time.Now().UTC().Add(time.Minute)) &&
		s.ActiveCells == active && s.StaleCells == stale && s.RejectedAdvertisements >= 0 &&
		s.Condition == condition

	if valid {
		for _, cell := range s.Cells {
			if cell.IsStale != !cell.LeaseExpiresAt.After(s.ObservedAt) {
				valid = false
				break
			}

			advertisement := GlobalCellAdvertisement{
				SchemaVersion:     1,
				Cell:              cell.Cell,
				Cluster:           cell.Cluster,
				AuthorityId:       cell.AuthorityId,
				AuthorityEpoch:    cell.AuthorityEpoch,
				AuthorityRevision: cell.AuthorityRevision,
				Sequence:          cell.Sequence,
				Capabilities:      cell.Capabilities,
				Membership:        cell.Membership,
				ObservedAt:        cell.ObservedAt,
				LeaseExpiresAt:    cell.LeaseExpiresAt,
				Endpoints:         cell.Endpoints,
			}

			if !advertisement.IsValid(s.ObservedAt) {
				valid = false
				break
			}
		}
	}

	if valid {
		seen := map[string]struct{}{}
		for _, cell := range s.Cells {
			if _, duplicate := seen[cell.Cell]; duplicate {
				valid = false
				break
			}

			seen[cell.Cell] = struct{}{}
		}

		if valid {
			for index := 1; index < len(s.Cells); index++ {
				if s.Cells[index-1].Cell >= s.Cells[index].Cell {
					valid = false
					break
				}
			}
		}
	}

	if !valid {
		return errGlobalCellDirectoryProjectionInvalid
	}

	return nil
}

var errGlobalCellDirectoryProjectionInvalid = &globalCellDirectoryError{}

type globalCellDirectoryError struct{}

func (*globalCellDirectoryError) Error() string {
	return "The global cell directory projection is invalid."
}

func allCellsHealthy(cells []GlobalCellDirectoryEntry) bool {
	for _, cell := range cells {
		if cell.Membership.Condition != RegionalRuntimeMembershipConditionHealthy {
			return false
		}
	}

	return true
}

// GlobalCellDirectory mirrors the C# class: converges durable regional
// advertisements into a read-only global projection. Regional state remains
// authoritative; expiry only marks a projection stale.
type GlobalCellDirectory struct {
	mu                     sync.Mutex
	advertisements         map[string]GlobalCellAdvertisement
	rejectedAdvertisements int64
}

// NewGlobalCellDirectory mirrors the C# constructor.
func NewGlobalCellDirectory() *GlobalCellDirectory {
	return &GlobalCellDirectory{advertisements: map[string]GlobalCellAdvertisement{}}
}

// Apply mirrors the source-key Apply overload.
func (d *GlobalCellDirectory) Apply(
	sourceKey string,
	advertisement GlobalCellAdvertisement,
	appliedAt *time.Time,
) GlobalCellAdvertisementDisposition {
	if strings.TrimSpace(sourceKey) == "" {
		panic("The value cannot be an empty string or composed entirely of whitespace. (Parameter 'sourceKey')")
	}

	expectedKey, err := GlobalNatsTopologyCellAdvertisementKey(advertisement.Cell)
	if err != nil || expectedKey != sourceKey {
		atomic.AddInt64(&d.rejectedAdvertisements, 1)
		return GlobalCellAdvertisementDispositionRejected
	}

	return d.ApplyAdvertisement(advertisement, appliedAt)
}

// ApplyAdvertisement mirrors the plain Apply overload.
func (d *GlobalCellDirectory) ApplyAdvertisement(
	advertisement GlobalCellAdvertisement,
	appliedAt *time.Time,
) GlobalCellAdvertisementDisposition {
	now := time.Now().UTC()
	if appliedAt != nil {
		now = *appliedAt
	}

	if !advertisement.IsValid(now) {
		atomic.AddInt64(&d.rejectedAdvertisements, 1)
		return GlobalCellAdvertisementDispositionRejected
	}

	for {
		d.mu.Lock()
		current, exists := d.advertisements[advertisement.Cell]
		if !exists {
			d.advertisements[advertisement.Cell] = advertisement
			d.mu.Unlock()
			return GlobalCellAdvertisementDispositionAccepted
		}
		d.mu.Unlock()

		order := globalCellDirectoryCompare(advertisement, current)
		if !advertisement.LeaseExpiresAt.After(now) && current.LeaseExpiresAt.After(now) {
			atomic.AddInt64(&d.rejectedAdvertisements, 1)
			return GlobalCellAdvertisementDispositionStale
		}

		if order < 0 {
			atomic.AddInt64(&d.rejectedAdvertisements, 1)
			return GlobalCellAdvertisementDispositionStale
		}

		if order == 0 {
			if globalCellDirectorySame(advertisement, current) {
				return GlobalCellAdvertisementDispositionDuplicate
			}

			atomic.AddInt64(&d.rejectedAdvertisements, 1)
			return GlobalCellDirectoryDispositionRejectedValue
		}

		d.mu.Lock()
		existing, stillExists := d.advertisements[advertisement.Cell]
		if stillExists && globalCellDirectoryIdentity(existing, current) {
			d.advertisements[advertisement.Cell] = advertisement
			d.mu.Unlock()
			return GlobalCellDirectoryDispositionAcceptedValue
		}
		d.mu.Unlock()
	}
}

// GlobalCellDirectoryDispositionRejectedValue mirrors the C# Rejected value.
const (
	GlobalCellDirectoryDispositionRejectedValue = GlobalCellAdvertisementDispositionRejected
	GlobalCellDirectoryDispositionAcceptedValue = GlobalCellAdvertisementDispositionAccepted
)

// Snapshot mirrors the C# Snapshot.
func (d *GlobalCellDirectory) Snapshot(observedAt *time.Time) GlobalCellDirectorySnapshot {
	now := time.Now().UTC()
	if observedAt != nil {
		now = *observedAt
	}

	d.mu.Lock()
	advertisements := make([]GlobalCellAdvertisement, 0, len(d.advertisements))
	for _, advertisement := range d.advertisements {
		advertisements = append(advertisements, advertisement)
	}
	rejected := atomic.LoadInt64(&d.rejectedAdvertisements)
	d.mu.Unlock()

	sort.Slice(advertisements, func(i, j int) bool {
		return advertisements[i].Cell < advertisements[j].Cell
	})

	cells := make([]GlobalCellDirectoryEntry, 0, len(advertisements))
	for _, advertisement := range advertisements {
		endpoints := advertisement.Endpoints
		if endpoints == nil {
			endpoints = []string{}
		}

		cells = append(cells, GlobalCellDirectoryEntry{
			Cell:              advertisement.Cell,
			Cluster:           advertisement.Cluster,
			AuthorityId:       advertisement.AuthorityId,
			AuthorityEpoch:    advertisement.AuthorityEpoch,
			AuthorityRevision: advertisement.AuthorityRevision,
			Sequence:          advertisement.Sequence,
			Capabilities:      advertisement.Capabilities,
			Membership:        advertisement.Membership,
			ObservedAt:        advertisement.ObservedAt,
			LeaseExpiresAt:    advertisement.LeaseExpiresAt,
			IsStale:           !advertisement.LeaseExpiresAt.After(now),
			Endpoints:         endpoints,
		})
	}

	active := 0
	for _, cell := range cells {
		if !cell.IsStale {
			active++
		}
	}

	stale := len(cells) - active
	condition := GlobalCellDirectoryConditionDegraded
	if active == 0 {
		condition = GlobalCellDirectoryConditionUnavailable
	} else if stale == 0 && allCellsHealthy(cells) {
		condition = GlobalCellDirectoryConditionHealthy
	}

	return GlobalCellDirectorySnapshot{
		SchemaVersion:          1,
		ObservedAt:             now,
		ActiveCells:            active,
		StaleCells:             stale,
		RejectedAdvertisements: rejected,
		Condition:              condition,
		Cells:                  cells,
	}
}

// Remove mirrors the C# Remove.
func (d *GlobalCellDirectory) Remove(cell string) {
	d.mu.Lock()
	delete(d.advertisements, cell)
	d.mu.Unlock()
}

// Reject mirrors the C# Reject.
func (d *GlobalCellDirectory) Reject() {
	atomic.AddInt64(&d.rejectedAdvertisements, 1)
}

// globalCellDirectoryIdentity reports whether two advertisements are the same
// observed record (the compare-and-swap guard of the update loop).
func globalCellDirectoryIdentity(left, right GlobalCellAdvertisement) bool {
	return left.Cell == right.Cell &&
		left.AuthorityEpoch == right.AuthorityEpoch &&
		left.AuthorityRevision == right.AuthorityRevision &&
		left.Sequence == right.Sequence &&
		left.ObservedAt.Equal(right.ObservedAt)
}

func globalCellDirectoryCompare(left, right GlobalCellAdvertisement) int {
	if left.AuthorityEpoch != right.AuthorityEpoch {
		if left.AuthorityEpoch < right.AuthorityEpoch {
			return -1
		}

		return 1
	}

	if left.AuthorityRevision != right.AuthorityRevision {
		if left.AuthorityRevision < right.AuthorityRevision {
			return -1
		}

		return 1
	}

	if left.Sequence != right.Sequence {
		if left.Sequence < right.Sequence {
			return -1
		}

		return 1
	}

	return 0
}

func globalCellDirectorySame(left, right GlobalCellAdvertisement) bool {
	if left.SchemaVersion != right.SchemaVersion ||
		left.Cell != right.Cell ||
		left.Cluster != right.Cluster ||
		left.AuthorityId != right.AuthorityId ||
		left.AuthorityEpoch != right.AuthorityEpoch ||
		left.AuthorityRevision != right.AuthorityRevision ||
		left.Sequence != right.Sequence ||
		!left.Membership.Equal(right.Membership) ||
		!left.ObservedAt.Equal(right.ObservedAt) ||
		!left.LeaseExpiresAt.Equal(right.LeaseExpiresAt) {
		return false
	}

	if len(left.Capabilities) != len(right.Capabilities) {
		return false
	}

	for index := range left.Capabilities {
		if left.Capabilities[index] != right.Capabilities[index] {
			return false
		}
	}

	leftEndpoints := left.Endpoints
	if leftEndpoints == nil {
		leftEndpoints = []string{}
	}

	rightEndpoints := right.Endpoints
	if rightEndpoints == nil {
		rightEndpoints = []string{}
	}

	if len(leftEndpoints) != len(rightEndpoints) {
		return false
	}

	for index := range leftEndpoints {
		if leftEndpoints[index] != rightEndpoints[index] {
			return false
		}
	}

	return true
}
