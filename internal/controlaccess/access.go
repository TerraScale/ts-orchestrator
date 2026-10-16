// Package controlaccess discovers read-only regional API access through OCI.
package controlaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

var ErrPending = errors.New("authenticated regional read access is pending")

type Access struct {
	URLs  []string
	Token string `json:"-"`
}

func (a Access) String() string   { return fmt.Sprintf("regional read access (%d origins)", len(a.URLs)) }
func (a Access) GoString() string { return a.String() }

// Resolve uses the operator's authenticated OCI identity and independent public
// roots. An empty selector chooses the signed home region. No resources change.
func Resolve(ctx context.Context, selector string) (Access, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Access{}, err
	}
	factory, err := ociclient.OperatorConfig(catalog.OCIRegion(catalog.Bootstrap))
	if err != nil {
		return Access{}, fmt.Errorf("%w: authenticated OCI operator credentials are unavailable", ErrPending)
	}
	resolver, err := region.DiscoverCurrentFoundation(ctx, factory)
	if err != nil {
		if ctx.Err() != nil {
			return Access{}, ctx.Err()
		}
		if errors.Is(err, region.ErrFoundationDiscoveryPending) || errors.Is(err, region.ErrFoundationGrantPending) {
			return Access{}, errors.Join(ErrPending, err)
		}
		return Access{}, err
	}
	return resolveCurrent(ctx, resolver, selector, func(ociRegion string) (vaultsecret.BundleClient, error) {
		regional, err := factory.ForRegion(ociRegion)
		if err != nil {
			return nil, err
		}
		return vaultsecret.SecretsClient(regional)
	})
}

func resolveCurrent(ctx context.Context, resolver region.FoundationResolver, selector string,
	bundles func(string) (vaultsecret.BundleClient, error),
) (Access, error) {
	if selector != "" {
		entry, ok := catalog.CellForOCIRegion(selector)
		if !ok {
			entry, ok = catalog.Lookup(strings.ToUpper(selector))
		}
		if !ok {
			return Access{}, errors.New("read access region is outside the catalog")
		}
		selector = entry.Cell
	}
	access, err := resolver.ReadAccess(ctx, selector)
	if err != nil {
		if ctx.Err() != nil {
			return Access{}, ctx.Err()
		}
		if errors.Is(err, region.ErrReadAccessPending) || errors.Is(err, region.ErrFoundationGrantPending) {
			return Access{}, errors.Join(ErrPending, err)
		}
		return Access{}, err
	}
	client, err := bundles(access.OCIRegion())
	if err != nil {
		return Access{}, errors.New("authenticated regional Vault client is unavailable")
	}
	current, err := vaultsecret.ReadCurrent(ociclient.RequestContext(ctx), client, access.UsageToken())
	if err != nil {
		if ctx.Err() != nil {
			return Access{}, ctx.Err()
		}
		if vaultsecret.Absent(err) {
			return Access{}, fmt.Errorf("%w: signed regional usage token is absent", ErrPending)
		}
		return Access{}, err
	}
	if err := ctx.Err(); err != nil {
		return Access{}, err
	}
	if !access.IsVerified() {
		return Access{}, errors.New("signed read access expired during discovery")
	}
	token := current.Value()
	if len(token) < 32 || len(token) > 4096 {
		return Access{}, errors.New("regional usage token has an invalid bearer length")
	}
	for i := range len(token) {
		if token[i] <= ' ' || token[i] >= 127 {
			return Access{}, errors.New("regional usage token has invalid bearer bytes")
		}
	}
	return Access{URLs: access.URLs(), Token: token}, nil
}
