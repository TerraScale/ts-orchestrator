package rootcapacity

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/nats-io/nats.go/jetstream"
)

// Controller retains only concrete root SDK discovery. NATS is opened lazily
// after operation admission, so the root listener can precede broker startup.
type Controller struct {
	factory       *ociclient.Factory
	resolver      region.FoundationResolver
	store         *region.ObjectFoundationStore
	homeAuthority *region.HomeIAMAuthority
}

func New(ctx context.Context, factory *ociclient.Factory, resolver region.FoundationResolver, homeAuthority *region.HomeIAMAuthority) (*Controller, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || homeAuthority == nil {
		return nil, rootoci.ErrUnauthorized
	}
	store, err := resolver.ProtectedCapacityReaderStore(factory)
	if err != nil {
		return nil, err
	}
	return &Controller{factory: factory, resolver: resolver, store: store, homeAuthority: homeAuthority}, nil
}

func (c *Controller) open(ctx context.Context, call rootoci.Call, cell, operation string) (*attempt, func(), error) {
	if c == nil || c.factory == nil || c.store == nil || ctx == nil || call.Guard(ctx) != nil ||
		cell != strings.ToUpper(cell) || !entityid.Valid(operation) {
		return nil, nil, rootoci.ErrUnauthorized
	}
	if _, err := c.resolver.ProtectedCapacityStore(c.factory); err != nil {
		return nil, nil, err
	}
	expected := call.Expected()
	if expected.Cell != "" && !strings.EqualFold(expected.Cell, cell) || expected.OperationID != "" && expected.OperationID != operation {
		return nil, nil, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	credentials, err := rootsecret.OpenControllerReader(ctx)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	close := func() { credentials.Conn().Close(); cancel() }
	ctx = credentials.Context()
	fail := func(err error) (*attempt, func(), error) { close(); return nil, nil, err }
	if err := errors.Join(call.Guard(ctx), credentials.Guard(ctx)); err != nil {
		return fail(err)
	}
	js, err := jetstream.New(credentials.Conn())
	if err != nil {
		return fail(err)
	}
	home, err := globalcontrol.OpenHomeReader(ctx, js, 3)
	if err != nil {
		return fail(err)
	}
	leader, err := authority.OpenReader(ctx, js, protocol.GlobalScope)
	if err != nil {
		return fail(err)
	}
	lease, err := leader.CurrentLease(ctx)
	if err != nil || expected.Epoch != 0 && lease.Epoch != expected.Epoch {
		return fail(errors.Join(err, authority.ErrFenced))
	}
	deadline, bounded := credentials.Context().Deadline()
	if !bounded {
		return fail(rootoci.ErrUnauthorized)
	}
	if lease.ExpiresAt.Before(deadline) {
		deadline = lease.ExpiresAt
	}
	a := &attempt{call: call, resolver: c.resolver, store: c.store, home: home, leader: leader, credentials: credentials,
		original: lease, deadline: deadline, operation: operation}
	if err := a.guard(ctx); err != nil {
		return fail(err)
	}
	writerCtx, cancelWriter := context.WithDeadline(a.proofContext(ctx), a.deadline)
	originalClose := close
	close = func() { cancelWriter(); originalClose() }
	a.writer, err = c.resolver.CapacityJournalWriter(writerCtx, c.homeAuthority)
	if err != nil {
		return fail(err)
	}
	if expiry := a.writer.ExpiresAt(); expiry.Before(a.deadline) {
		a.deadline = expiry
	}
	authorized, err := c.resolver.Resolve(a.readContext(ctx), cell)
	if err != nil {
		return fail(err)
	}
	a.record, a.etag, err = a.writer.Load(a.readContext(ctx), cell)
	if err != nil {
		return fail(err)
	}
	if a.record.Generation != authorized.Generation || a.record.IntentDigest != authorized.IntentDigest || a.record.TenancyID != authorized.TenancyID ||
		a.record.Cell != cell || a.record.OCIRegion != authorized.OCIRegion || a.record.GrantSHA256 != authorized.GrantSHA256 ||
		a.record.ParentCompartmentID != authorized.ParentCompartmentID || a.record.SharedCompartmentID != authorized.SharedCompartmentID || a.record.Stage != "reconciled" {
		return fail(errors.New("protected foundation changed during capacity authority resolution"))
	}
	a.factory, err = c.factory.ForRegion(a.record.OCIRegion)
	if err != nil {
		return fail(err)
	}
	if err := a.guard(ctx); err != nil {
		return fail(err)
	}
	return a, close, nil
}

func (c *Controller) beginChild(ctx context.Context, call rootoci.Call, request rootoci.PoolChildExpectation) (*attempt, func(), error) {
	if request.Epoch == 0 || request.ReservationID != request.OperationID || len(request.PublicCAPEM) == 0 || len(request.PublicCAPEM) > 32<<10 ||
		len(request.AvailabilityDomains) == 0 || len(request.AvailabilityDomains) > 3 {
		return nil, nil, rootoci.ErrInvalid
	}
	a, close, err := c.open(ctx, call, request.Cell, request.OperationID)
	if err != nil {
		return nil, nil, err
	}
	return c.resolveChild(ctx, call, request, a, close)
}

func (c *Controller) resolveChild(ctx context.Context, call rootoci.Call, request rootoci.PoolChildExpectation, a *attempt, close func()) (*attempt, func(), error) {
	fail := func(err error) (*attempt, func(), error) { close(); return nil, nil, err }
	capacity, exists, err := budget.ReadCapacity(ctx, a.home)
	if err != nil || !exists {
		return fail(errors.Join(err, errors.New("home capacity reservation ledger is unavailable")))
	}
	index := slices.IndexFunc(capacity.Reservations, func(r budget.Reservation) bool { return r.OperationID == request.ReservationID })
	if index < 0 {
		return fail(errors.New("pool operation has no original durable home reservation"))
	}
	a.receipt = capacity.Reservations[index]
	if a.record.Generation != request.Generation || a.record.GrantSHA256 != request.GrantSHA256 ||
		!strings.EqualFold(a.receipt.Cell, request.Cell) || a.receipt.RecipeSHA256 != request.RecipeSHA256 ||
		a.receipt.GrantGeneration > request.Generation ||
		call.Expected().GrantSHA256 != "" && call.Expected().GrantSHA256 != request.GrantSHA256 {
		return fail(errors.New("pool expectation differs from original authenticated reservation"))
	}
	original, err := a.receipt.FinancialReceipt()
	if err != nil {
		return fail(err)
	}
	if err := a.resolveWorker(ctx, request, original); err != nil {
		return fail(err)
	}
	if child, exists := a.record.PoolChildren[request.OperationID]; exists {
		if request.PoolID != "" && request.PoolID != child.PoolID || request.ConfigurationID != "" && request.ConfigurationID != child.ConfigurationID ||
			!slices.Equal(child.PublicCAPEM, request.PublicCAPEM) || !slices.Equal(child.AvailabilityDomains, request.AvailabilityDomains) {
			return fail(errors.New("pool expectation differs from original protected child selectors"))
		}
	}
	if err := a.guard(ctx); err != nil {
		return fail(err)
	}
	return a, close, nil
}

func scaleRecipe(worker region.WorkerRecipe) nodescale.Recipe {
	return nodescale.Recipe{Cell: strings.ToLower(worker.Cell), Capacity: nodescale.Capacity{Role: worker.Role, Architecture: worker.Architecture, Shape: worker.Shape},
		SubnetID: worker.SubnetID, NSGIDs: worker.NSGIDs, AvailabilityDomains: worker.AvailabilityDomains, ImageID: worker.ImageID,
		OCPUs: float32(worker.OCPUs), MemoryGB: float32(worker.MemoryGB), Metadata: worker.Metadata}
}

func (a *attempt) resolveWorker(ctx context.Context, request rootoci.PoolChildExpectation, original capacityledger.Receipt) error {
	var selectionErrors error
	for _, role := range []string{nodescale.RoleContainer, nodescale.RoleWasm} {
		workers, err := a.resolver.WorkerRecipes(a.readContext(ctx), request.Cell, role, request.PublicCAPEM)
		if err != nil {
			selectionErrors = errors.Join(selectionErrors, err)
			continue
		}
		for _, worker := range workers {
			candidate := worker.Recipe()
			candidate.AvailabilityDomains = slices.Clone(request.AvailabilityDomains)
			if err := worker.Match(candidate); err != nil {
				continue
			}
			recipe := scaleRecipe(candidate)
			if recipe.Validate() != nil || recipe.SHA256() != request.RecipeSHA256 || candidate.CompartmentID != original.Quote.CompartmentID ||
				candidate.Shape != original.Quote.Shape || float64(recipe.OCPUs) != original.Quote.OCPUs || float64(recipe.MemoryGB) != original.Quote.MemoryGB ||
				float64(candidate.BootGB) != original.Quote.BootGB || worker.Profile().GrantDigest() != request.GrantSHA256 || worker.Profile().Generation() != request.Generation {
				continue
			}
			if a.worker.IsVerified() {
				return errors.New("pool recipe matches ambiguous independently signed worker profiles")
			}
			a.worker, a.recipe = worker, recipe
		}
	}
	if !a.worker.IsVerified() {
		return errors.Join(selectionErrors, errors.New("original pool recipe has no exact current signed worker authority"))
	}
	return a.guard(ctx)
}
