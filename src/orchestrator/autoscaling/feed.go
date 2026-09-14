package autoscaling

// This file defines the bounded scheduler/placement observation consumed by
// the production autoscaler role.  Host heartbeats are deliberately limited
// to node capacity and usage; demand and replica placement are control-plane
// observations and travel on this separate, versioned feed.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

// AutoscalerObservationSubject is the exact regional subject on which the
// scheduler publishes one complete observation feed.  The subject is not a
// command path: consumers treat a missing or stale publication as unavailable
// evidence and never synthesize demand or replica health.
const AutoscalerObservationSubject = "terrascale.scheduler.v1.autoscaler"

const (
	AutoscalerFeedSchemaVersion     = 1
	autoscalerMaximumPlacementNodes = 1024
)

// AutoscalerNodePlacement is the scheduler's placement view of one node.
// Every replica is validated at this boundary; an absent placement entry is
// never equivalent to a node with no replicas when PlacementComplete is true.
type AutoscalerNodePlacement struct {
	NodeId   string
	Replicas []stateful.ReplicaHealth
}

// NewAutoscalerNodePlacement validates and snapshots one node placement.
func NewAutoscalerNodePlacement(nodeId string, replicas []stateful.ReplicaHealth) (AutoscalerNodePlacement, error) {
	validatedNode, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return AutoscalerNodePlacement{}, err
	}
	if len(replicas) > autoscalingMaximumReplicaCount {
		return AutoscalerNodePlacement{}, &errs.Argument{Param: "replicas",
			Message: fmt.Sprintf("Replica input exceeds the bound of %d entries.", autoscalingMaximumReplicaCount)}
	}
	snapshot := make([]stateful.ReplicaHealth, 0, len(replicas))
	seen := make(map[string]struct{}, len(replicas))
	for _, replica := range replicas {
		validated, err := stateful.NewReplicaHealth(replica.RoleKind, replica.AllocationId,
			replica.Up, replica.PeerAckCount, replica.MinReplicas, replica.LagBytes)
		if err != nil {
			return AutoscalerNodePlacement{}, err
		}
		key := validated.RoleKind + "/" + validated.AllocationId
		if _, duplicate := seen[key]; duplicate {
			return AutoscalerNodePlacement{}, &errs.Argument{Param: "replicas",
				Message: "A role allocation may appear only once per node."}
		}
		seen[key] = struct{}{}
		snapshot = append(snapshot, validated)
	}
	return AutoscalerNodePlacement{NodeId: validatedNode, Replicas: snapshot}, nil
}

// AutoscalerObservationFeed is one scheduler/placement observation.  The
// producer must set DemandComplete and PlacementComplete only after it has
// observed the corresponding complete regional state.  A valid feed with an
// empty demand list is authoritative no-demand evidence; no feed at all is
// unavailable evidence.
type AutoscalerObservationFeed struct {
	SchemaVersion     int
	UnixSeconds       int64
	Demand            []AllocationDemand
	DemandComplete    bool
	Placements        []AutoscalerNodePlacement
	PlacementComplete bool
}

// NewAutoscalerObservationFeed validates and snapshots one scheduler feed.
func NewAutoscalerObservationFeed(
	schemaVersion int,
	unixSeconds int64,
	demand []AllocationDemand,
	demandComplete bool,
	placements []AutoscalerNodePlacement,
	placementComplete bool,
) (AutoscalerObservationFeed, error) {
	if schemaVersion != AutoscalerFeedSchemaVersion {
		return AutoscalerObservationFeed{}, &errs.Argument{Param: "schemaVersion",
			Message: fmt.Sprintf("Unsupported autoscaler feed schema version %d.", schemaVersion)}
	}
	if unixSeconds <= 0 {
		return AutoscalerObservationFeed{}, &errs.ArgumentOutOfRangeError{Param: "unixSeconds",
			Message: "Autoscaler feed timestamp must be positive."}
	}
	if len(placements) > autoscalerMaximumPlacementNodes {
		return AutoscalerObservationFeed{}, &errs.Argument{Param: "placements",
			Message: fmt.Sprintf("Placement input exceeds the bound of %d entries.", autoscalerMaximumPlacementNodes)}
	}
	validatedSnapshot, err := NewAutoscalerSnapshot(nil, demand)
	if err != nil {
		return AutoscalerObservationFeed{}, err
	}
	validatedPlacements := make([]AutoscalerNodePlacement, 0, len(placements))
	seenNodes := make(map[string]struct{}, len(placements))
	for _, placement := range placements {
		validated, err := NewAutoscalerNodePlacement(placement.NodeId, placement.Replicas)
		if err != nil {
			return AutoscalerObservationFeed{}, err
		}
		if _, duplicate := seenNodes[validated.NodeId]; duplicate {
			return AutoscalerObservationFeed{}, &errs.Argument{Param: "placements",
				Message: "A node may appear only once per feed."}
		}
		seenNodes[validated.NodeId] = struct{}{}
		validatedPlacements = append(validatedPlacements, validated)
	}
	return AutoscalerObservationFeed{
		SchemaVersion:     AutoscalerFeedSchemaVersion,
		UnixSeconds:       unixSeconds,
		Demand:            validatedSnapshot.Demand,
		DemandComplete:    demandComplete,
		Placements:        validatedPlacements,
		PlacementComplete: placementComplete,
	}, nil
}

type autoscalerFeedWire struct {
	SchemaVersion     int                       `json:"schemaVersion"`
	UnixSeconds       int64                     `json:"unixSeconds"`
	Demand            []autoscalerDemandWire    `json:"demand"`
	DemandComplete    bool                      `json:"demandComplete"`
	Placements        []autoscalerPlacementWire `json:"placements"`
	PlacementComplete bool                      `json:"placementComplete"`
}

type autoscalerDemandWire struct {
	RoleId    string                  `json:"roleId"`
	RoleKind  string                  `json:"roleKind"`
	Stateful  bool                    `json:"stateful"`
	Resources autoscalerResourcesWire `json:"resources"`
}

type autoscalerResourcesWire struct {
	MemoryBytes int64 `json:"memoryBytes"`
	CpuPercent  int   `json:"cpuPercent"`
	Tasks       int   `json:"tasks"`
}

type autoscalerPlacementWire struct {
	NodeId   string                  `json:"nodeId"`
	Replicas []autoscalerReplicaWire `json:"replicas"`
}

type autoscalerReplicaWire struct {
	RoleKind     string `json:"roleKind"`
	AllocationId string `json:"allocationId"`
	Up           bool   `json:"up"`
	PeerAckCount int    `json:"peerAckCount"`
	MinReplicas  int    `json:"minReplicas"`
	LagBytes     int64  `json:"lagBytes"`
}

// MarshalJSON emits the canonical camelCase feed shape after revalidation.
func (f AutoscalerObservationFeed) MarshalJSON() ([]byte, error) {
	validated, err := NewAutoscalerObservationFeed(f.SchemaVersion, f.UnixSeconds,
		f.Demand, f.DemandComplete, f.Placements, f.PlacementComplete)
	if err != nil {
		return nil, err
	}
	wire := autoscalerFeedWire{
		SchemaVersion:     validated.SchemaVersion,
		UnixSeconds:       validated.UnixSeconds,
		DemandComplete:    validated.DemandComplete,
		PlacementComplete: validated.PlacementComplete,
		Demand:            make([]autoscalerDemandWire, 0, len(validated.Demand)),
		Placements:        make([]autoscalerPlacementWire, 0, len(validated.Placements)),
	}
	for _, demand := range validated.Demand {
		wire.Demand = append(wire.Demand, autoscalerDemandWire{
			RoleId: demand.RoleId, RoleKind: demand.RoleKind, Stateful: demand.Stateful,
			Resources: autoscalerResourcesWire{MemoryBytes: demand.Resources.MemoryBytes,
				CpuPercent: demand.Resources.CpuPercent, Tasks: demand.Resources.Tasks},
		})
	}
	for _, placement := range validated.Placements {
		entry := autoscalerPlacementWire{NodeId: placement.NodeId,
			Replicas: make([]autoscalerReplicaWire, 0, len(placement.Replicas))}
		for _, replica := range placement.Replicas {
			entry.Replicas = append(entry.Replicas, autoscalerReplicaWire{
				RoleKind: replica.RoleKind, AllocationId: replica.AllocationId, Up: replica.Up,
				PeerAckCount: replica.PeerAckCount, MinReplicas: replica.MinReplicas,
				LagBytes: replica.LagBytes})
		}
		wire.Placements = append(wire.Placements, entry)
	}
	return json.Marshal(wire)
}

// UnmarshalJSON decodes a strict canonical feed and validates every nested
// demand and replica at the trust boundary.
func (f *AutoscalerObservationFeed) UnmarshalJSON(data []byte) error {
	if autoscalerJSONHasDuplicateProperties(data) {
		return fmt.Errorf("autoscaler feed contains duplicate JSON fields")
	}
	var wire autoscalerFeedWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("autoscaler feed contains trailing JSON")
		}
		return err
	}
	demand := make([]AllocationDemand, 0, len(wire.Demand))
	for _, entry := range wire.Demand {
		value, err := NewAllocationDemand(entry.RoleId, entry.RoleKind, entry.Stateful,
			NodeResources{MemoryBytes: entry.Resources.MemoryBytes, CpuPercent: entry.Resources.CpuPercent,
				Tasks: entry.Resources.Tasks})
		if err != nil {
			return err
		}
		demand = append(demand, value)
	}
	placements := make([]AutoscalerNodePlacement, 0, len(wire.Placements))
	for _, entry := range wire.Placements {
		replicas := make([]stateful.ReplicaHealth, 0, len(entry.Replicas))
		for _, replica := range entry.Replicas {
			replicas = append(replicas, stateful.ReplicaHealth{RoleKind: replica.RoleKind,
				AllocationId: replica.AllocationId, Up: replica.Up, PeerAckCount: replica.PeerAckCount,
				MinReplicas: replica.MinReplicas, LagBytes: replica.LagBytes})
		}
		value, err := NewAutoscalerNodePlacement(entry.NodeId, replicas)
		if err != nil {
			return err
		}
		placements = append(placements, value)
	}
	validated, err := NewAutoscalerObservationFeed(wire.SchemaVersion, wire.UnixSeconds,
		demand, wire.DemandComplete, placements, wire.PlacementComplete)
	if err != nil {
		return err
	}
	*f = validated
	return nil
}

// autoscalerJSONHasDuplicateProperties detects duplicate keys recursively.
// encoding/json otherwise applies last-key-wins semantics, which would make
// an authenticated scheduler publication ambiguous at this trust boundary.
func autoscalerJSONHasDuplicateProperties(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	duplicate, err := scanAutoscalerJSONValue(decoder)
	return err == nil && duplicate
}

func scanAutoscalerJSONValue(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return false, nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return false, err
			}
			name, ok := key.(string)
			if !ok {
				return false, fmt.Errorf("invalid JSON object key")
			}
			// encoding/json matches struct fields case-insensitively. Treat
			// differently-cased spellings as the same key here so a payload
			// cannot smuggle an ambiguous last-key-wins duplicate.
			canonicalName := strings.ToLower(name)
			if _, exists := seen[canonicalName]; exists {
				return true, nil
			}
			seen[canonicalName] = struct{}{}
			duplicate, err := scanAutoscalerJSONValue(decoder)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
		_, err = decoder.Token()
		return false, err
	case '[':
		for decoder.More() {
			duplicate, err := scanAutoscalerJSONValue(decoder)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
		_, err = decoder.Token()
		return false, err
	default:
		return false, fmt.Errorf("unexpected JSON delimiter")
	}
}
