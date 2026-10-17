package rootfoundation

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	ocir "github.com/TerraScale/ts-orchestrator/internal/ociregion/registry"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// ReconcileOCIR is root's startup/recovery/rotation caller. Its context and
// guard retain the original accepted runtime sources through the last effect.
// Workers only consume existing Vault bindings and cannot call this lifecycle.
func (b *Backend) ReconcileOCIR(ctx context.Context, sourceGuard func(context.Context) error) error {
	if ctx == nil || b == nil || b.factory == nil || b.home == nil || os.Geteuid() != 0 || sourceGuard == nil {
		return ErrScope
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return ErrScope
	}
	live := func(ctx context.Context) (time.Time, error) {
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return time.Time{}, errors.Join(ErrScope, ctx.Err())
		}
		if err := sourceGuard(ctx); err != nil {
			return time.Time{}, err
		}
		if err := b.home.Guard(ctx, 0); err != nil {
			return time.Time{}, err
		}
		until, err := b.home.FoundationWriterDeadline(ctx)
		if err != nil {
			return time.Time{}, err
		}
		ctx, cancel := context.WithDeadline(ctx, until)
		defer cancel()
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return time.Time{}, errors.Join(ErrScope, ctx.Err())
		}
		if err := sourceGuard(ctx); err != nil {
			return time.Time{}, err
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return time.Time{}, errors.Join(ErrScope, ctx.Err())
		}
		until, _ = ctx.Deadline()
		return until, nil
	}
	until, err := live(ctx)
	if err != nil {
		return err
	}
	ctx, cancelWriter := context.WithDeadline(ctx, until)
	defer cancelWriter()
	deadline, _ = ctx.Deadline()
	ctx = ociclient.WithRequestGuard(ctx, sourceGuard)
	resolver, err := region.DiscoverCurrentFoundation(ctx, b.factory)
	if err != nil {
		return err
	}
	scopes, err := resolver.OCIRIssuers(ctx)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		if scope.Intent().OCIRegion != b.factory.Region() {
			continue
		}
		expires := minTime(deadline, scope.ExpiresAt()).UTC()
		attempt, cancel := context.WithDeadline(ctx, expires)
		record, err := resolver.Resolve(attempt, b.cell)
		if err != nil {
			cancel()
			return err
		}
		guard := func(ctx context.Context) error {
			until, err := live(ctx)
			if err != nil {
				return err
			}
			ctx, cancelWriter := context.WithDeadline(ctx, until)
			defer cancelWriter()
			if !time.Now().Before(expires) {
				return ErrScope
			}
			current, err := region.DiscoverCurrentFoundation(ctx, b.factory)
			if err != nil {
				return err
			}
			if err := current.GuardOCIRIssuer(ctx, scope); err != nil {
				return err
			}
			until, err = b.home.OCIRAuthorityDeadline(ctx, scope)
			if err != nil {
				return err
			}
			ctx, cancelAuthority := context.WithDeadline(ctx, until)
			defer cancelAuthority()
			actual, _, err := current.Store.Load(ctx, b.cell)
			if err != nil {
				return err
			}
			if err := ocirRecordCurrent(actual, record, scope); err != nil {
				return err
			}
			if !time.Now().Before(expires) {
				return ErrScope
			}
			_, err = live(ctx)
			return err
		}
		journal := &ocirJournal{store: resolver.Store, cell: b.cell, original: record, scope: scope, deadline: expires, guard: guard}
		principal, err := b.home.InstancePrincipal(attempt)
		if err != nil {
			cancel()
			return err
		}
		repositoryJournal := &ocirRepositoryJournal{ocirJournal: journal, principal: principal}
		controller, err := ocir.NewWithJournal(b.factory, repositoryJournal, guard)
		if err == nil {
			repositoryContext := ociclient.WithAuthority(attempt, guard)
			repositoryContext = ociclient.WithWireAttempt(repositoryContext, journal.BeginEffect)
			intent := scope.Intent()
			_, err = controller.Ensure(repositoryContext, ocir.Repository{CompartmentID: intent.RepositoryCompartmentID, Namespace: intent.RegistryNamespace, Name: intent.RepositoryName, PrincipalID: principal, Owner: scope.InstallationID()})
		}
		if err != nil {
			cancel()
			return err
		}
		issuer, err := ocir.NewIssuer(attempt, b.factory, journal, scope, guard, func(ctx context.Context) (context.Context, func(), error) {
			if err := guard(ctx); err != nil {
				return ctx, nil, err
			}
			return b.home.HomeWrite(ctx, record.Epoch)
		})
		if err == nil {
			_, err = issuer.Ensure(attempt)
		}
		if err == nil {
			err = guard(attempt)
		}
		cancel()
		if err != nil {
			return err
		}
	}
	_, err = live(ctx)
	return err
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func ocirRecordCurrent(actual, original region.FoundationRecord, scope region.VerifiedOCIRIssuer) error {
	if actual.Cell != original.Cell || actual.OCIRegion != scope.Intent().OCIRegion || actual.TenancyID != scope.TenancyID() ||
		actual.Stage != "reconciled" || actual.LeaseID != "" || actual.Epoch != original.Epoch || actual.OperationID != original.OperationID ||
		actual.Generation != scope.Generation() || actual.Generation != original.Generation || actual.GrantSHA256 != scope.GrantDigest() ||
		actual.GrantSHA256 != original.GrantSHA256 || actual.IntentDigest != original.IntentDigest {
		return ErrScope
	}
	return nil
}
