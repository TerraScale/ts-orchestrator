package region

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

// FoundationObservation is durable provisioning progress, not serving health.
// Only this projection may cross the read API; the record contains authority.
type FoundationObservation struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Cell          string                 `json:"cell"`
	OCIRegion     string                 `json:"ociRegion"`
	OperationID   string                 `json:"operationId"`
	Generation    uint64                 `json:"generation"`
	Epoch         uint64                 `json:"epoch"`
	Stage         string                 `json:"stage"`
	Reason        string                 `json:"reason,omitempty"`
	StartedAt     time.Time              `json:"startedAt"`
	UpdatedAt     time.Time              `json:"updatedAt"`
	CompletedAt   time.Time              `json:"completedAt,omitzero"`
	Checkpoints   []FoundationCheckpoint `json:"checkpoints"`
}

// FirstAttemptAt is retained only when the journal has an actual source time.
// Retry tokens, request bodies, signed grants and manager payloads stay private.
type FoundationCheckpoint struct {
	Kind           string    `json:"kind"`
	Key            string    `json:"key"`
	ResourceID     string    `json:"resourceId,omitempty"`
	OperationID    string    `json:"operationId,omitempty"`
	Generation     uint64    `json:"generation,omitzero"`
	FirstAttemptAt time.Time `json:"firstAttemptAt,omitzero"`
}

// FoundationObservationHandler must be mounted behind runtime authentication.
func FoundationObservationHandler(foundations FoundationResolver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		view, err := foundations.ObserveFoundation(ctx, strings.ToUpper(r.PathValue("region")))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			reason := "foundation-observation-unavailable"
			if errors.Is(err, ErrFoundationMissing) {
				reason = "foundation-record-missing"
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.MarshalWrite(w, struct {
				SchemaVersion int    `json:"schemaVersion"`
				State         string `json:"state"`
				Reason        string `json:"reason"`
			}{1, "unavailable", reason})
			return
		}
		_ = json.MarshalWrite(w, view)
	})
}

func (r FoundationResolver) ObserveFoundation(ctx context.Context, cell string) (FoundationObservation, error) {
	if r.Footprint == nil || r.Store == nil {
		return FoundationObservation{}, errors.New("foundation observation requires authenticated footprint and durable store")
	}
	footprint, err := r.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return FoundationObservation{}, err
	}
	if err := validateFootprint(footprint); err != nil {
		return FoundationObservation{}, err
	}
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != cell {
			continue
		}
		record, _, err := r.Store.Load(ctx, cell)
		if err != nil {
			return FoundationObservation{}, err
		}
		digest, err := FoundationIntentDigest(intent)
		if err != nil {
			return FoundationObservation{}, err
		}
		if err := record.validate(); err != nil {
			return FoundationObservation{}, err
		}
		if record.Cell != cell || record.OCIRegion != intent.Plan["region"] || record.IntentDigest != digest ||
			record.Generation != intent.Generation || record.TenancyID != footprint.TenancyID ||
			record.ParentCompartmentID != footprint.ParentCompartmentID || record.SharedCompartmentID != footprint.SharedCompartmentID {
			return FoundationObservation{}, errors.New("foundation observation is outside current authenticated full intent")
		}
		observation := FoundationObservation{SchemaVersion: 1, Cell: record.Cell, OCIRegion: record.OCIRegion,
			OperationID: record.OperationID, Generation: record.Generation, Epoch: record.Epoch,
			Stage: record.Stage, Reason: record.BlockedReason, StartedAt: record.StartedAt,
			UpdatedAt: record.UpdatedAt, CompletedAt: record.CompletedAt, Checkpoints: []FoundationCheckpoint{}}
		for _, source := range []struct {
			kind string
			ids  map[string]string
		}{{"resource", record.ResourceIDs}, {"auxiliary", record.AuxiliaryIDs}} {
			for key, id := range source.ids {
				checkpoint := FoundationCheckpoint{Kind: source.kind, Key: key, ResourceID: id}
				if provenance, ok := record.ResourceProvenance[key]; ok && provenance.ResourceID == id {
					checkpoint.OperationID = provenance.Create.OperationID
					checkpoint.Generation = provenance.Generation
					checkpoint.FirstAttemptAt = provenance.Create.FirstAttemptAt
				}
				observation.Checkpoints = append(observation.Checkpoints, checkpoint)
			}
		}
		for key, pending := range record.PendingCreates {
			observation.Checkpoints = append(observation.Checkpoints, FoundationCheckpoint{Kind: "pending-create", Key: key,
				OperationID: pending.OperationID, Generation: record.Generation, FirstAttemptAt: pending.FirstAttemptAt})
		}
		slices.SortFunc(observation.Checkpoints, func(a, b FoundationCheckpoint) int {
			if a.Kind != b.Kind {
				return cmp.Compare(a.Kind, b.Kind)
			}
			return cmp.Compare(a.Key, b.Key)
		})
		return observation, nil
	}
	return FoundationObservation{}, errors.New("region is outside authenticated foundation footprint")
}
