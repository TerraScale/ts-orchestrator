package controlaccess

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type Access struct {
	URLs  []string
	Token string `json:"-"`
}

func Regions() []string {
	return mesh.Regions("")
}

func Resolve(ctx context.Context, selector string) (Access, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if selector == "" {
		selector = catalog.Bootstrap
	}
	entry, ok := catalog.Lookup(strings.ToUpper(selector))
	if !ok {
		entry, ok = catalog.CellForOCIRegion(selector)
	}
	if !ok {
		return Access{}, errors.New("dashboard region is outside the catalog")
	}
	cell := entry.Name()
	environment := mesh.EnvironmentOf(cell)
	if !slices.Contains(environment.Regions, cell) {
		return Access{}, errors.New("dashboard region is outside the runtime roster")
	}
	host := "ts-" + cell + "-1.nb.ts.internal"
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addresses) != 1 || !netip.MustParsePrefix("10.200.0.0/16").Contains(addresses[0]) {
		return Access{}, fmt.Errorf("%s: manager needs one encrypted NetBird address", cell)
	}
	factory, err := ociclient.OperatorConfig(environment.VaultRegion)
	if err != nil {
		return Access{}, errors.New("dashboard OCI operator credentials are unavailable")
	}
	client, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return Access{}, errors.New("dashboard Vault client is unavailable")
	}
	token, err := vaultsecret.Read(ociclient.RequestContext(ctx), client, environment.Vault.VaultID,
		vaultsecret.Name(cell+"-1", cellspec.DashboardRole+"-"+cellspec.DashboardKey))
	if err != nil {
		return Access{}, err
	}
	if len(token) < 32 || len(token) > 4096 {
		return Access{}, errors.New("dashboard token has an invalid bearer length")
	}
	for i := range len(token) {
		if token[i] <= ' ' || token[i] >= 127 {
			return Access{}, errors.New("dashboard token has invalid bearer bytes")
		}
	}
	return Access{URLs: []string{fmt.Sprintf("http://%s:%d", addresses[0], cellspec.DashboardPort)}, Token: token}, nil
}

func Origin(base string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("dashboard endpoint must be an HTTP(S) origin without credentials, path, query or fragment")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip, _ := netip.ParseAddr(host)
		if host != "localhost" && !ip.IsLoopback() && !netip.MustParsePrefix("10.200.0.0/16").Contains(ip) && !strings.HasSuffix(host, ".nb.ts.internal") {
			return nil, errors.New("HTTP dashboard endpoints require loopback or the encrypted NetBird overlay")
		}
	}
	return u, nil
}
