package databaseadmission

import (
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

// reserveLifecycleCapacity estimates terminal stop/deletion history before
// accepting additional state. These placeholders are marshaled only for the
// capacity check; they can never become accepted authority state.
func reserveLifecycleCapacity(reserved *journalState) {
	reserved.Deletions = maps.Clone(reserved.Deletions)
	reserved.Lifecycle.Resources = maps.Clone(reserved.Lifecycle.Resources)
	reserved.Lifecycle.Events = maps.Clone(reserved.Lifecycle.Events)
	terminal := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	for key, resource := range reserved.Lifecycle.Resources {
		if !resource.EffectsCompletedAt.IsZero() {
			continue
		}
		resource.Streams = slices.Clone(resource.Streams)
		// A resource pending installation still needs space for its first routing
		// identity and terminal stop. Larger routing histories reserve their actual
		// complete length on every registration before serving that new epoch.
		if len(resource.Streams) == 0 {
			for _, region := range resource.Regions {
				resource.Streams = append(resource.Streams, databaselifecycle.Stream{Region: region, Partition: strings.Repeat("p", 255), Epoch: math.MaxUint64, StartedAt: resource.CreatedAt})
			}
		}
		for i := range resource.Streams {
			if resource.Streams[i].StoppedAt.IsZero() {
				resource.Streams[i].StoppedAt = terminal
			}
		}
		if resource.DeletedAt.IsZero() {
			resource.DeletedAt = terminal
			resource.UsageStoppedAt = terminal
			resource.RetainUntil = terminal
			resource.AccessRevoked = true
		}
		resource.EffectsCompletedAt = terminal
		reserved.Lifecycle.Resources[key] = resource
		kinds := []string{"delete", "effects_completed"}
		for range resource.Regions {
			kinds = append(kinds, "streams")
		}
		for index, kind := range kinds {
			// Maximal idempotency text and full stream payload bound retry history.
			op := strings.Repeat("x", 220) + strconv.Itoa(index) + resource.DatabaseID
			event := databaselifecycle.Event{Identity: resource.Identity, OperationID: op, Kind: kind, At: terminal, RetainUntil: terminal}
			if kind == "streams" {
				event.Streams = resource.Streams
			}
			reserved.Lifecycle.Events[resource.Environment+"/"+resource.OrganizationID+"/"+op] = event
		}
		request := DeleteRequest{Environment: resource.Environment, TenantID: resource.OrganizationID, ProjectID: resource.ProjectID, DatabaseID: resource.DatabaseID, OperationID: strings.Repeat("x", 128)}
		deletion := Deletion{Request: request, Cutoff: terminal, State: "cleanup_pending"}
		for _, region := range resource.Regions {
			stop := DeletionStop{Identity: resource.Identity, OperationID: request.OperationID, Region: region, Cutoff: terminal, RetainUntil: terminal}
			deletion.Targets = append(deletion.Targets, DeletionTarget{Stop: stop, Receipt: new(DeletionReceipt{DeletionStop: stop, AccessRevoked: true, UsageStopped: true})})
		}
		// Include the database identity because distinct deletions may share a
		// customer's retry spelling in this capacity-only upper bound.
		reserved.Deletions[deletionKey(request)+"/"+resource.DatabaseID] = deletion
	}
	// Existing accepted deletion targets may be awaiting their terminal receipts.
	for key, deletion := range reserved.Deletions {
		deletion.Targets = slices.Clone(deletion.Targets)
		for i := range deletion.Targets {
			if deletion.Targets[i].Receipt == nil {
				stop := deletion.Targets[i].Stop
				deletion.Targets[i].Receipt = new(DeletionReceipt{DeletionStop: stop, AccessRevoked: true, UsageStopped: true})
			}
		}
		reserved.Deletions[key] = deletion
	}
}
