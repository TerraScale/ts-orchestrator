package capacityinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/resourcesearch"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

// SHA256 identifies the original quote, including its observed prices and
// validity interval. A later equal-cost quote has a different identity.
func (q Quote) SHA256() string {
	if q.scopeSHA256 == "" || q.issuedAt.IsZero() || q.expiresAt.IsZero() || len(q.prices) != 4 {
		return ""
	}
	wire, err := json.Marshal(struct {
		ScopeSHA256, Cell, CompartmentID, Shape, Currency string
		OCPUs, MemoryGB, BootGB                           float64
		MonthlyCents                                      uint64
		IssuedAt, ExpiresAt                               time.Time
		Prices                                            []ocicost.Price
	}{q.scopeSHA256, q.cell, q.compartment, q.shape, q.currency, q.ocpus, q.memoryGB, q.bootGB, q.monthlyCents, q.issuedAt, q.expiresAt, q.prices}, json.Deterministic(true))
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

// ReadJournal adds retained lifecycle evidence, including resources which have
// left provider lists. A voluntary journal is not exhaustive mutation coverage.
func (r *Reader) ReadJournal(ctx context.Context, scope Scope, journal *oci.KVJournal) (Snapshot, error) {
	if err := scope.validate(time.Now()); err != nil {
		return Snapshot{}, err
	}
	result, err := r.ReadOwnedJournal(ctx, scope, journal)
	if err != nil {
		return Snapshot{}, err
	}
	result.ExpiresAt = minTime(result.ExpiresAt, scope.ExpiresAt)
	result.seal = result.digest()
	return result, nil
}

// ReadOwnedJournal reconciles historical ownership without renewing spend
// authority. Neither a missing ID nor a 404 becomes a terminal observation.
func (r *Reader) ReadOwnedJournal(ctx context.Context, scope Scope, journal *oci.KVJournal) (Snapshot, error) {
	if journal == nil {
		return Snapshot{}, errors.New("retained OCI lifecycle journal is absent")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	result, err := r.ReadOwned(ctx, scope)
	if err != nil {
		return Snapshot{}, err
	}
	records, err := journal.ListOperations(ctx)
	if err != nil {
		result.Pending = append(result.Pending, "retained OCI lifecycle history unavailable: "+err.Error())
		result.seal = result.digest()
		return result, nil
	}
	prices := catalogReader{client: r.http, endpoint: r.pricesEndpoint, currency: scope.Currency, cache: map[string]tariff{}}
	seen := map[string]bool{}
	for _, resource := range result.Resources {
		seen[resource.ID] = true
	}
	month := time.Date(result.ObservedAt.UTC().Year(), result.ObservedAt.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	for _, record := range records {
		index := slices.IndexFunc(scope.Regions, func(region RegionScope) bool { return region.Cell == string(record.Intent.Region) })
		if index < 0 {
			continue
		}
		region := scope.Regions[index]
		if record.Intent.CreatedAt.IsZero() || record.Intent.CreatedAt.After(result.ObservedAt) {
			result.Pending = append(result.Pending, "lifecycle operation lacks valid original time: "+record.Intent.Key)
		}
		if record.Result.RecordedAt.IsZero() || record.Result.Unknown {
			result.Pending = append(result.Pending, "accepted lifecycle operation outcome remains charged and unresolved: "+record.Intent.Key)
		}
		if !record.Intent.CreatedAt.Before(month) {
			result.Pending = append(result.Pending, "current-month lifecycle operation lacks a retained historical tariff ceiling: "+record.Intent.Key)
		}
		id := record.Result.ResourceID
		if id == "" {
			id = record.Intent.ResourceID
		}
		if id == "" {
			continue
		}
		if err := r.observeJournalResource(ctx, region, id, &prices, &result, seen); err != nil {
			result.Pending = append(result.Pending, id+": "+err.Error())
		}
		if !strings.HasPrefix(id, "ocid1.instance.") || record.Intent.Action != "launch" {
			continue
		}
		binding, found, err := journal.GetBootBinding(ctx, id)
		if err != nil || !found {
			result.Pending = append(result.Pending, "launch lacks a retained exact boot-volume binding: "+id)
			continue
		}
		if binding.Region != record.Intent.Region || binding.Owner != record.Intent.Owner || binding.Generation != record.Intent.Generation || binding.CreateKey != record.Intent.CreateKey ||
			!slices.Contains(region.CompartmentIDs, binding.CompartmentID) {
			result.Pending = append(result.Pending, "retained boot binding differs from original scoped launch: "+id)
			continue
		}
		if err := r.observeJournalResource(ctx, region, binding.BootVolumeID, &prices, &result, seen); err != nil {
			result.Pending = append(result.Pending, binding.BootVolumeID+": "+err.Error())
		}
		// Existing bindings predate recipe/cost journaling. They recover exact
		// resource membership, but cannot manufacture the original price bound.
		result.Pending = append(result.Pending, "retained boot binding lacks an immutable launch recipe and historical cost ceiling: "+id)
	}
	slices.SortFunc(result.Resources, func(a, b Resource) int { return strings.Compare(a.ID, b.ID) })
	slices.Sort(result.Pending)
	result.Pending = slices.Compact(result.Pending)
	result.seal = result.digest()
	return result, nil
}

func (r *Reader) observeJournalResource(ctx context.Context, region RegionScope, id string, prices *catalogReader, result *Snapshot, seen map[string]bool) error {
	if seen[id] {
		return nil
	}
	kind := ""
	switch {
	case strings.HasPrefix(id, "ocid1.instance."):
		kind = "Instance"
	case strings.HasPrefix(id, "ocid1.volume."):
		kind = "Volume"
	case strings.HasPrefix(id, "ocid1.bootvolume."):
		kind = "BootVolume"
	default:
		return nil
	}
	factory, err := r.factory.ForRegion(region.OCIRegion)
	if err != nil {
		return err
	}
	compute, err := factory.Compute()
	if err != nil {
		return err
	}
	block, err := factory.Blockstorage()
	if err != nil {
		return err
	}
	ociclient.PinHost(&compute.BaseClient, r.endpoint)
	ociclient.PinHost(&block.BaseClient, r.endpoint)
	var actualID, compartment *string
	switch kind {
	case "Instance":
		response, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(id)})
		if err != nil {
			return fmt.Errorf("read retained instance: %w", err)
		}
		actualID, compartment = response.Id, response.CompartmentId
	case "Volume":
		response, err := block.GetVolume(ociclient.RequestContext(ctx), core.GetVolumeRequest{VolumeId: new(id)})
		if err != nil {
			return fmt.Errorf("read retained volume: %w", err)
		}
		actualID, compartment = response.Id, response.CompartmentId
	case "BootVolume":
		response, err := block.GetBootVolume(ociclient.RequestContext(ctx), core.GetBootVolumeRequest{BootVolumeId: new(id)})
		if err != nil {
			return fmt.Errorf("read retained boot volume: %w", err)
		}
		actualID, compartment = response.Id, response.CompartmentId
	}
	if actualID == nil || *actualID != id || compartment == nil || !slices.Contains(region.CompartmentIDs, *compartment) {
		return errors.New("retained resource differs from authenticated owned compartment scope")
	}
	resource := Resource{ID: id, Cell: region.Cell, CompartmentID: *compartment}
	amount, observationErr := observedCost(ctx, compute, block, resourcesearch.ResourceSummary{Identifier: actualID, CompartmentId: compartment, ResourceType: new(kind)}, prices, &resource)
	if ^uint64(0)-result.MonthlyCents < amount {
		return errors.New("retained infrastructure cost overflow")
	}
	resource.MonthlyCents = amount
	result.MonthlyCents += amount
	result.Resources = append(result.Resources, resource)
	seen[id] = true
	return observationErr
}
