package atlas

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
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
