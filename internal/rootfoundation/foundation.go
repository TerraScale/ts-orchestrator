package rootfoundation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func (b *Backend) ReconcileFoundation(ctx context.Context, call rootoci.Call, request rootoci.ReconcileFoundationRequest) (rootoci.FoundationReceipt, error) {
	if b == nil || request.Cell != b.cell {
		return rootoci.FoundationReceipt{}, ErrScope
	}
	if selected := call.Operation(); selected != "" && selected != rootoci.OperationReconcileFoundation {
		return rootoci.FoundationReceipt{}, ErrScope
	}
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	resolver, err := b.current(ctx, call)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	footprint, err := resolver.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	var intent region.FoundationIntent
	for _, candidate := range footprint.Regions {
		if candidate.Plan["cell"] == b.cell {
			intent = candidate
			break
		}
	}
	if intent.Generation == 0 || request.CurrentGrantDigest != "" && footprint.GrantSHA256 != request.CurrentGrantDigest {
		return rootoci.FoundationReceipt{}, ErrScope
	}
	operation := entityid.Derive("regional-foundation", footprint.TenancyID, b.cell, fmt.Sprint(intent.Generation))
	record, _, err := resolver.Store.Load(ctx, b.cell)
	if err != nil && !errors.Is(err, region.ErrFoundationMissing) {
		return rootoci.FoundationReceipt{}, err
	}
	if record.LeaseID != "" && time.Now().Before(record.ExpiresAt) {
		return rootoci.FoundationReceipt{}, region.ErrFoundationBusy
	}
	epoch := max(record.Epoch, 1)
	if request.ExpectedOperationID != "" && request.ExpectedOperationID != operation || request.ExpectedEpoch != 0 && request.ExpectedEpoch != epoch {
		return rootoci.FoundationReceipt{}, ErrScope
	}
	if err := checkCall(ctx, call, rootoci.OperationReconcileFoundation, rootoci.Expectations{
		Cell: b.cell, GrantSHA256: footprint.GrantSHA256, OperationID: operation, Epoch: epoch,
	}); err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	digest, err := region.FoundationIntentDigest(intent)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	guard := func(ctx context.Context) error {
		if err := b.guard(ctx, call); err != nil {
			return err
		}
		current, err := resolver.Footprint.AuthorizedRegions(ctx)
		if err != nil {
			return err
		}
		if current.GrantSHA256 != footprint.GrantSHA256 {
			return ErrScope
		}
		for _, candidate := range current.Regions {
			if candidate.Plan["cell"] != b.cell {
				continue
			}
			actual, err := region.FoundationIntentDigest(candidate)
			if err != nil || actual != digest || candidate.Generation != intent.Generation {
				return errors.Join(ErrScope, err)
			}
			return nil
		}
		return ErrScope
	}
	controller := region.FoundationController{Footprint: resolver.Footprint,
		Authority:   guardedAuthority{home: b.home, guard: guard},
		Store:       guardedStore{FoundationStore: resolver.Store, guard: guard},
		Foundations: region.SDKFoundations{Factory: b.factory}}
	record, err = controller.ReconcileCell(effectContext(ctx, guard), b.cell, epoch)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	if err := guard(ctx); err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	return rootoci.FoundationReceipt{Cell: record.Cell, GrantDigest: record.GrantSHA256, OperationID: record.OperationID,
		Generation: record.Generation, Epoch: record.Epoch, Stage: record.Stage}, nil
}

type guardedStore struct {
	region.FoundationStore
	guard func(context.Context) error
}

func (s guardedStore) CompareAndSwap(ctx context.Context, record region.FoundationRecord, etag string) (string, error) {
	if err := s.guard(ctx); err != nil {
		return "", err
	}
	return s.FoundationStore.CompareAndSwap(ctx, record, etag)
}

type guardedAuthority struct {
	home  *region.HomeIAMAuthority
	guard func(context.Context) error
}

func (a guardedAuthority) Guard(ctx context.Context, epoch uint64) error {
	if err := a.guard(ctx); err != nil {
		return err
	}
	return a.home.Guard(ctx, epoch)
}

func (a guardedAuthority) HomeWrite(ctx context.Context, epoch uint64) (context.Context, func(), error) {
	if err := a.Guard(ctx, epoch); err != nil {
		return ctx, nil, err
	}
	return a.home.HomeWrite(ctx, epoch)
}
