package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootcapacity"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/nats-io/jwt/v2"
)

// The existing authenticated home reservation route carries finite selectors.
// Its replies are descriptive; regional roots independently observe child birth.
type capacityPoolRequest struct {
	Operation  rootoci.Operation                  `json:"operation"`
	Deadline   time.Time                          `json:"deadline"`
	Child      *rootoci.PoolChildExpectation      `json:"child,omitempty"`
	Retirement *rootoci.PoolRetirementExpectation `json:"retirement,omitempty"`
	Quarantine *rootoci.PoolQuarantineExpectation `json:"quarantine,omitempty"`
}

type capacityPoolResponse struct {
	Operation  rootoci.Operation           `json:"operation"`
	Child      *rootoci.PoolChildView      `json:"child,omitempty"`
	Retirement *rootoci.PoolRetirementView `json:"retirement,omitempty"`
	Quarantine *rootoci.PoolQuarantineView `json:"quarantine,omitempty"`
}

func (r *capacityReservations) applyPool(ctx context.Context, source string, request capacityPoolRequest, epoch uint64) (*capacityPoolResponse, error) {
	if epoch == 0 || request.Deadline.IsZero() || !time.Now().Before(request.Deadline) {
		return nil, rootoci.ErrInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, request.Deadline)
	defer cancel()
	if err := r.global.authority.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	// The regional epoch is a distinct scope. The home root independently
	// checks this actual home leader and derives all signed provider authority.
	client := rootoci.NewClient(rootoci.Expectations{Cell: strings.ToUpper(source), Epoch: epoch})
	defer client.Close()
	response := &capacityPoolResponse{Operation: request.Operation}
	switch request.Operation {
	case rootoci.OperationAdvancePoolChild:
		if request.Child == nil || request.Retirement != nil || request.Quarantine != nil || !strings.EqualFold(request.Child.Cell, source) {
			return nil, rootoci.ErrInvalid
		}
		child := *request.Child
		child.Epoch = epoch
		view, err := client.AdvancePoolChild(ctx, child)
		if err != nil {
			return nil, err
		}
		response.Child = &view
	case rootoci.OperationRetirePoolChild:
		if request.Retirement == nil || request.Child != nil || request.Quarantine != nil || !strings.EqualFold(request.Retirement.Child.Cell, source) {
			return nil, rootoci.ErrInvalid
		}
		retirement := *request.Retirement
		retirement.Child.Epoch = epoch
		view, err := client.RetirePoolChild(ctx, retirement)
		if err != nil {
			return nil, err
		}
		response.Retirement = &view
	case rootoci.OperationQuarantinePoolChild:
		if request.Quarantine == nil || request.Child != nil || request.Retirement != nil || !strings.EqualFold(request.Quarantine.Cell, source) {
			return nil, rootoci.ErrInvalid
		}
		quarantine := *request.Quarantine
		quarantine.Epoch = epoch
		view, err := client.QuarantinePoolChild(ctx, quarantine)
		if err != nil {
			return nil, err
		}
		response.Quarantine = &view
	default:
		return nil, rootoci.ErrInvalid
	}
	if err := r.global.authority.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	return response, nil
}

type rootPoolBackend struct {
	cell  string
	local *rootcapacity.Controller
}

// newRootCapacityBackend always constructs the real regional observer. Home
// alone mutates the protected capacity ledger; spokes use the existing home RPC.
func newRootCapacityBackend(ctx context.Context, factory *ociclient.Factory, resolver region.FoundationResolver, homeAuthority *region.HomeIAMAuthority) (*rootPoolBackend, error) {
	if factory == nil || homeAuthority == nil {
		return nil, rootoci.ErrInvalid
	}
	cell, found := catalog.CellForOCIRegion(factory.Region())
	if !found {
		return nil, rootoci.ErrInvalid
	}
	local, err := rootcapacity.New(ctx, factory, resolver, homeAuthority)
	if err != nil {
		return nil, err
	}
	return &rootPoolBackend{cell: cell.Cell, local: local}, nil
}

func (b *rootPoolBackend) ObservePoolChild(ctx context.Context, call rootoci.Call, request rootoci.PoolChildObservation) (rootoci.PoolChildView, error) {
	return b.local.ObservePoolChild(ctx, call, request)
}

func (b *rootPoolBackend) AdvancePoolChild(ctx context.Context, call rootoci.Call, request rootoci.PoolChildExpectation) (rootoci.PoolChildView, error) {
	if b.cell == catalog.Bootstrap {
		return b.local.AdvancePoolChild(ctx, call, request)
	}
	response, err := b.forward(ctx, call, request.Cell, capacityPoolRequest{Operation: rootoci.OperationAdvancePoolChild, Child: &request})
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	if response.Child == nil || response.Retirement != nil || response.Quarantine != nil {
		return rootoci.PoolChildView{}, rootoci.ErrInvalid
	}
	if response.Child.Cell != request.Cell || response.Child.OperationID != request.OperationID || response.Child.ReservationID != request.ReservationID ||
		response.Child.RecipeSHA256 != request.RecipeSHA256 || response.Child.GrantSHA256 != request.GrantSHA256 || response.Child.Generation != request.Generation {
		return rootoci.PoolChildView{}, rootoci.ErrInvalid
	}
	return *response.Child, nil
}

func (b *rootPoolBackend) RetirePoolChild(ctx context.Context, call rootoci.Call, request rootoci.PoolRetirementExpectation) (rootoci.PoolRetirementView, error) {
	if b.cell == catalog.Bootstrap {
		return b.local.RetirePoolChild(ctx, call, request)
	}
	response, err := b.forward(ctx, call, request.Child.Cell, capacityPoolRequest{Operation: rootoci.OperationRetirePoolChild, Retirement: &request})
	if err != nil {
		return rootoci.PoolRetirementView{}, err
	}
	if response.Retirement == nil || response.Child != nil || response.Quarantine != nil {
		return rootoci.PoolRetirementView{}, rootoci.ErrInvalid
	}
	if response.Retirement.Cell != request.Child.Cell || response.Retirement.InstanceID != request.InstanceID || response.Retirement.RemovalOperationID != request.RemovalOperationID {
		return rootoci.PoolRetirementView{}, rootoci.ErrInvalid
	}
	return *response.Retirement, nil
}

func (b *rootPoolBackend) QuarantinePoolChild(ctx context.Context, call rootoci.Call, request rootoci.PoolQuarantineExpectation) (rootoci.PoolQuarantineView, error) {
	if b.cell == catalog.Bootstrap {
		return b.local.QuarantinePoolChild(ctx, call, request)
	}
	response, err := b.forward(ctx, call, request.Cell, capacityPoolRequest{Operation: rootoci.OperationQuarantinePoolChild, Quarantine: &request})
	if err != nil {
		return rootoci.PoolQuarantineView{}, err
	}
	if response.Quarantine == nil || response.Child != nil || response.Retirement != nil {
		return rootoci.PoolQuarantineView{}, rootoci.ErrInvalid
	}
	if response.Quarantine.Cell != request.Cell || response.Quarantine.PoolID != request.PoolID || response.Quarantine.InstanceID != request.InstanceID || response.Quarantine.OperationID != request.OperationID {
		return rootoci.PoolQuarantineView{}, rootoci.ErrInvalid
	}
	return *response.Quarantine, nil
}

func (b *rootPoolBackend) forward(ctx context.Context, call rootoci.Call, cell string, request capacityPoolRequest) (capacityPoolResponse, error) {
	if b == nil || b.local == nil || b.cell != cell || call.Guard(ctx) != nil ||
		call.Expected().Cell != "" && !strings.EqualFold(call.Expected().Cell, cell) || call.Operation() != request.Operation {
		return capacityPoolResponse{}, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer cancel()
	reader, err := rootsecret.OpenControllerReader(ctx)
	if err != nil {
		return capacityPoolResponse{}, err
	}
	connection := reader.Conn()
	defer connection.Close()
	ctx, stopReader := context.WithDeadline(reader.Context(), call.Deadline())
	defer stopReader()
	guard := func(ctx context.Context) error {
		if err := call.Guard(ctx); err != nil {
			return err
		}
		return reader.Guard(ctx)
	}
	ctx = ociclient.WithRequestGuard(ctx, guard)
	if err := guard(ctx); err != nil {
		return capacityPoolResponse{}, err
	}
	if connection.Opts.UserJWT == nil {
		return capacityPoolResponse{}, rootoci.ErrUnauthorized
	}
	raw, err := connection.Opts.UserJWT()
	if err != nil {
		return capacityPoolResponse{}, err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil || guard(ctx) != nil {
		return capacityPoolResponse{}, rootoci.ErrUnauthorized
	}
	original, err := loadHomeCapacityResponseAuthority(ctx)
	if err != nil || guard(ctx) != nil {
		return capacityPoolResponse{}, errors.Join(rootoci.ErrUnauthorized, err)
	}
	ctx, stopSource := context.WithDeadline(ctx, original.expires)
	defer stopSource()
	homeKey := func(ctx context.Context) (ed25519.PublicKey, error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		current, err := loadHomeCapacityResponseAuthority(ctx)
		if err != nil || guard(ctx) != nil || current.localDigest != original.localDigest || current.homeDigest != original.homeDigest ||
			!current.key.Equal(original.key) || current.expires.Before(original.expires) {
			return nil, errors.Join(rootoci.ErrUnauthorized, err)
		}
		return original.key, nil
	}
	r := &capacityReservations{cell: strings.ToLower(cell), user: claim.Subject, conn: connection, homeKey: homeKey}
	request.Deadline, _ = ctx.Deadline()
	if err := guard(ctx); err != nil {
		return capacityPoolResponse{}, err
	}
	response, err := r.exchange(ctx, "observe", capacityReservationRequest{Pool: &request})
	if err != nil {
		return capacityPoolResponse{}, err
	}
	if guard(ctx) != nil {
		return capacityPoolResponse{}, rootoci.ErrUnauthorized
	}
	if response.Receipt != nil || response.Pool == nil || response.Pool.Operation != request.Operation {
		return capacityPoolResponse{}, rootoci.ErrInvalid
	}
	return *response.Pool, nil
}

type homeCapacityResponseAuthority struct {
	key                     ed25519.PublicKey
	localDigest, homeDigest string
	expires                 time.Time
}

func loadHomeCapacityResponseAuthority(ctx context.Context) (homeCapacityResponseAuthority, error) {
	fail := func(err error) (homeCapacityResponseAuthority, error) { return homeCapacityResponseAuthority{}, err }
	local, derived, present, err := installedAutomaticStartup(ctx)
	if err != nil || !present {
		return fail(errors.Join(errors.New("capacity requires authenticated automatic startup"), err))
	}
	ctx, stopLocal := context.WithDeadline(ctx, derived.ExpiresAt())
	defer stopLocal()
	template, err := bootstrap.VerifyBoundRegionalStartupTemplate(ctx, local.factory, derived.GrantWire(), local.baked.Roots, local.anchor, oci.RegionGRU, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	ctx, stopTemplate := context.WithDeadline(ctx, template.ExpiresAt())
	defer stopTemplate()
	home, err := local.anchor.FoundationScope()
	if err != nil {
		return fail(err)
	}
	factory, err := local.factory.ForRegion(home.OCIRegion)
	if err != nil {
		return fail(err)
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		return fail(err)
	}
	authority, err := bootstrap.LoadDerivedStartupAuthority(ctx, template, &objects, template.Template().SeedSlot, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	key, err := authority.ControllerResponsePublicKey()
	if err != nil || ctx.Err() != nil {
		return fail(errors.Join(rootoci.ErrUnauthorized, err, ctx.Err()))
	}
	expires, _ := ctx.Deadline()
	if authority.ExpiresAt().Before(expires) {
		expires = authority.ExpiresAt()
	}
	if !time.Now().Before(expires) {
		return fail(rootoci.ErrUnauthorized)
	}
	return homeCapacityResponseAuthority{key: key, localDigest: derived.Digest(), homeDigest: authority.Digest(), expires: expires}, nil
}
