package capacityinventory

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

const priceCatalog = "https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/"

type tariff struct {
	value  float64
	metric string
}

type catalogReader struct {
	client   *http.Client
	endpoint string
	currency string
	cache    map[string]tariff
}

func (c *catalogReader) price(ctx context.Context, sku, metric string) (float64, error) {
	if price, ok := c.cache[sku]; ok {
		if price.metric != metric {
			return 0, errors.New("OCI tariff unit mismatch")
		}
		return price.value, nil
	}
	endpoint, err := url.Parse(c.endpoint)
	if err != nil {
		return 0, err
	}
	query := endpoint.Query()
	query.Set("partNumber", sku)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Cache-Control", "no-cache")
	response, err := c.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("OCI price catalog HTTP %d", response.StatusCode)
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(wire) > 1<<20 {
		return 0, errors.New("OCI price catalog unreadable or oversized")
	}
	var document struct {
		LastUpdated time.Time `json:"lastUpdated"`
		Items       []struct {
			PartNumber string `json:"partNumber"`
			Metric     string `json:"metricName"`
			Currencies []struct {
				Currency string `json:"currencyCode"`
				Prices   []struct {
					Model string   `json:"model"`
					Value *float64 `json:"value"`
				} `json:"prices"`
			} `json:"currencyCodeLocalizations"`
		} `json:"items"`
	}
	if err := json.Unmarshal(wire, &document); err != nil {
		return 0, err
	}
	if document.LastUpdated.IsZero() || document.LastUpdated.After(time.Now().Add(time.Minute)) || len(document.Items) != 1 || document.Items[0].PartNumber != sku || document.Items[0].Metric != metric {
		return 0, errors.New("OCI catalog lacks exact SKU, unit or publication date")
	}
	found, amount := false, 0.0
	for _, currency := range document.Items[0].Currencies {
		if currency.Currency != c.currency {
			continue
		}
		if found {
			return 0, errors.New("OCI catalog repeats currency")
		}
		for _, tier := range currency.Prices {
			if tier.Model != "PAY_AS_YOU_GO" {
				continue
			}
			if tier.Value == nil || math.IsNaN(*tier.Value) || math.IsInf(*tier.Value, 0) || *tier.Value < 0 || *tier.Value > 1e7 {
				return 0, errors.New("OCI tariff invalid")
			}
			// Price at the highest published tier; free allowances are not spending authority.
			amount, found = max(amount, *tier.Value), true
		}
	}
	if !found {
		return 0, errors.New("OCI catalog has no payable tariff in authorized currency")
	}
	c.cache[sku] = tariff{amount, metric}
	return amount, nil
}

// Prices reads current tariffs for observed compatible shapes. Shapes without
// reviewed SKU identities stay unpriced; known candidates can still be compared.
func (r *Reader) Prices(ctx context.Context, scope Scope, shapes []string) ([]ocicost.Price, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := scope.validate(time.Now()); err != nil {
		return nil, err
	}
	if len(shapes) > 256 {
		return nil, errors.New("OCI candidate shape set exceeds inventory bound")
	}
	units := map[string]string{"B91961": "Gigabyte Storage Capacity Per Month", "B91962": "Performance Units Per Gigabyte Per Month"}
	knownShape := false
	for _, shape := range shapes {
		cpu, memory, known := ocicost.ComputeSKUs(shape)
		if !known {
			continue
		}
		knownShape = true
		units[cpu], units[memory] = "OCPU Per Hour", "Gigabyte Per Hour"
	}
	if !knownShape {
		return nil, errors.New("observed OCI shapes have no reviewed tariff identities")
	}
	catalog := catalogReader{client: r.http, endpoint: r.pricesEndpoint, currency: scope.Currency, cache: map[string]tariff{}}
	var prices []ocicost.Price
	var failures []error
	for _, sku := range slices.Sorted(maps.Keys(units)) {
		value, err := catalog.price(ctx, sku, units[sku])
		if err != nil {
			failures = append(failures, fmt.Errorf("SKU %s: %w", sku, err))
			continue
		}
		prices = append(prices, ocicost.Price{SKU: sku, PerUnit: value})
	}
	return prices, errors.Join(failures...)
}
