// Package rootfoundation owns foundation and source OCI effects in the root
// process. Ordinary callers receive only the rootoci typed IPC operations.
package rootfoundation

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const sourceDirectory = "/var/lib/terrascale-orchestrator-bootstrap/automatic"

var ErrScope = errors.New("root foundation request differs from current protected authority")

type Backend struct {
	factory  *ociclient.Factory
	home     *region.HomeIAMAuthority
	baked    bootstrapstart.BakedInputs
	anchor   bootstrap.VerifiedBootstrapAnchor
	template bootstrap.VerifiedStartupTemplate
	cell     string
}

// NewFounder is also the initial bootstrap's direct backend. No SDK credential
// or source authority is accepted from a socket request.
func NewFounder(ctx context.Context) (*Backend, error) {
	b, resolver, err := local(ctx)
	if err != nil {
		return nil, err
	}
	proof, err := bootstrapstart.VerifySourceFounder(ctx, b.factory, b.template)
	if err != nil {
		return nil, err
	}
	b.home, err = region.NewHomeIAMAuthority(ctx, proof, resolver)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// NewController reopens the installed controller's current signed selection
// and independently observes the local instance principal.
func NewController(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (*Backend, error) {
	b, resolver, err := local(ctx)
	if err != nil {
		return nil, err
	}
	b.home, err = region.NewRuntimeHomeIAMAuthority(ctx, reader, accepted, resolver)
	if err != nil {
		return nil, err
	}
	b.factory, _, err = b.home.GuardedFactory(ctx)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GuardedHomeIAM shares the original admitted authority with required root domains.
func (b *Backend) GuardedHomeIAM(ctx context.Context) (*region.HomeIAMAuthority, error) {
	if os.Geteuid() != 0 || ctx == nil || b == nil || b.home == nil {
		return nil, ErrScope
	}
	if err := b.home.Guard(ctx, 0); err != nil {
		return nil, err
	}
	return b.home, nil
}

func local(ctx context.Context) (*Backend, region.FoundationResolver, error) {
	if os.Geteuid() != 0 || ctx.Err() != nil {
		return nil, region.FoundationResolver{}, errors.Join(ErrScope, ctx.Err())
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return nil, region.FoundationResolver{}, err
	}
	instance, err := bootstrapstart.NewIMDSClient().FetchInstanceID(ctx)
	if err != nil {
		return nil, region.FoundationResolver{}, err
	}
	parts := strings.Split(instance, ".")
	if len(parts) != 5 {
		return nil, region.FoundationResolver{}, ErrScope
	}
	entry, ok := catalog.CellForOCIRegion(parts[3])
	if !ok || string(baked.Identity.Cell) != entry.Cell {
		return nil, region.FoundationResolver{}, ErrScope
	}
	factory, err := ociclient.InstancePrincipal(entry.OCIRegion)
	if err != nil {
		return nil, region.FoundationResolver{}, err
	}
	envelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return nil, region.FoundationResolver{}, err
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(envelope, baked.Roots, baked.Identity.AnchorExpectation(), time.Now().UTC(), bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Anchor().OCIRegion != entry.OCIRegion {
		return nil, region.FoundationResolver{}, errors.Join(ErrScope, err)
	}
	resolver, err := region.DiscoverCurrentFoundation(ctx, factory)
	if err != nil {
		return nil, region.FoundationResolver{}, err
	}
	grant, err := resolver.BootstrapMaterial(ctx, entry.Cell)
	if err != nil {
		return nil, region.FoundationResolver{}, err
	}
	template, err := bootstrap.VerifyBoundStartupTemplate(ctx, factory, grant.FoundationGrantWire(), baked.Roots, anchor, time.Now().UTC())
	if err != nil {
		return nil, region.FoundationResolver{}, err
	}
	return &Backend{factory: factory, baked: baked, anchor: anchor, template: template, cell: entry.Cell}, resolver, nil
}

func (b *Backend) guard(ctx context.Context, call rootoci.Call) error {
	if os.Geteuid() != 0 || b == nil || b.factory == nil || b.home == nil {
		return ErrScope
	}
	if err := call.Guard(ctx); err != nil {
		return err
	}
	// Each domain checks its own HomeIAM lease; source uses a separate sealed
	// founder authority whose lease must not be checked against b.home.
	return b.home.VerifyFoundationWriter(ctx)
}

func (b *Backend) current(ctx context.Context, call rootoci.Call) (region.FoundationResolver, error) {
	if err := b.guard(ctx, call); err != nil {
		return region.FoundationResolver{}, err
	}
	return region.DiscoverCurrentFoundation(ctx, b.factory)
}

func checkCall(ctx context.Context, call rootoci.Call, operation rootoci.Operation, actual rootoci.Expectations) error {
	if err := call.Guard(ctx); err != nil {
		return err
	}
	if selected := call.Operation(); selected != "" && selected != operation {
		return ErrScope
	}
	expected := call.Expected()
	if expected.Cell != "" && expected.Cell != actual.Cell ||
		expected.GrantSHA256 != "" && expected.GrantSHA256 != actual.GrantSHA256 ||
		expected.OperationID != "" && expected.OperationID != actual.OperationID ||
		expected.Epoch != 0 && expected.Epoch != actual.Epoch {
		return ErrScope
	}
	return nil
}

// Admission is independent of the domain's WithAuthority guard, so nested
// source/foundation operations cannot replace the live root caller check.
func effectContext(ctx context.Context, guard func(context.Context) error) context.Context {
	ctx = bootstrapmaterial.WithPublicationGuard(ctx, guard)
	return ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
}

var _ rootoci.Foundation = (*Backend)(nil)
