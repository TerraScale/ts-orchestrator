package atlas

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	DiscoveryURL      = "https://atlas.terrascale.tech"
	discoveryTimeout  = 10 * time.Second
	maxDiscoveryBytes = 256 << 10
)

// Discovery is Atlas' GET /v1/discovery answer (ts-atlas
// docs/discovery-v1.md): the published regions ranked for the caller.
type Discovery struct {
	V       int    `json:"v"`
	Updated int64  `json:"updated"`
	Stale   bool   `json:"stale"`
	Closest string `json:"closest"`
	// Regions carry their last health: ok, unknown or down.
	Regions  []DiscoveredRegion `json:"regions"`
	Services []Service          `json:"services"`
}

// ServingCells is the orch-published, signed-spec topology's membership.
// Routing health does not remove an admitted cell from deployment.
func (d Discovery) ServingCells(now time.Time) ([]string, error) {
	if d.V != 1 || len(d.Regions) == 0 || len(d.Regions) > catalog.Len || d.Stale || d.Updated <= 0 ||
		now.Sub(time.Unix(d.Updated, 0)) > StaleAfter || time.Unix(d.Updated, 0).Sub(now) > Interval {
		return nil, errors.New("serving-region discovery is empty, stale or invalid")
	}
	cells := make([]string, 0, len(d.Regions))
	for _, region := range d.Regions {
		name, _, _ := strings.Cut(region.ID, "-")
		entry, known := catalog.LookupName(name)
		if !known {
			return nil, fmt.Errorf("serving-region discovery includes unsupported cell %q", region.ID)
		}
		id, err := naming.RegionCell(entry.Cell).Name()
		if err != nil || id != region.ID || slices.Contains(cells, entry.Cell) {
			return nil, fmt.Errorf("serving-region discovery includes duplicate or unsupported cell %q", region.ID)
		}
		cells = append(cells, entry.Cell)
	}
	slices.Sort(cells)
	return cells, nil
}

// DiscoverServingCells reads membership from ts-orch's published Atlas topology.
func DiscoverServingCells(ctx context.Context, client *http.Client) ([]string, error) {
	discovery, err := Discover(ctx, client, DiscoveryURL)
	if err != nil {
		return nil, err
	}
	return discovery.ServingCells(time.Now().UTC())
}

// DiscoveredRegion is a published region with its health.
type DiscoveredRegion struct {
	Region
	Health string `json:"health"`
}

// Region returns the listed region id.
func (d Discovery) Region(id string) (DiscoveredRegion, bool) {
	for _, region := range d.Regions {
		if region.ID == id {
			return region, true
		}
	}
	return DiscoveredRegion{}, false
}

// Discover reads GET <baseURL>/v1/discovery with client, following no
// redirect, within discoveryTimeout and maxDiscoveryBytes.
func Discover(ctx context.Context, client *http.Client, baseURL string) (Discovery, error) {
	if !httpsURL(baseURL) {
		return Discovery{}, errors.New("atlas url must be https")
	}
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(baseURL, "/")+"/v1/discovery", nil)
	if err != nil {
		return Discovery{}, err
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := noRedirect.Do(request)
	if err != nil {
		return Discovery{}, fmt.Errorf("atlas discovery: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryBytes+1))
	if err != nil {
		return Discovery{}, fmt.Errorf("atlas discovery: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return Discovery{}, fmt.Errorf("atlas discovery answered %s", response.Status)
	}
	if len(body) > maxDiscoveryBytes {
		return Discovery{}, fmt.Errorf("atlas discovery exceeds %d bytes", maxDiscoveryBytes)
	}
	var discovery Discovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return Discovery{}, fmt.Errorf("decode atlas discovery: %w", err)
	}
	if discovery.V != 1 {
		return Discovery{}, fmt.Errorf("atlas discovery version %d is not 1", discovery.V)
	}
	return discovery, nil
}
