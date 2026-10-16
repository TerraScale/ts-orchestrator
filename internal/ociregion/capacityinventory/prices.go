package capacityinventory

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"
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
	servedAt, err := http.ParseTime(response.Header.Get("Date"))
	if err != nil || servedAt.After(time.Now().Add(time.Minute)) || time.Since(servedAt) > 2*time.Minute {
		return 0, errors.New("OCI tariff response freshness is absent or stale")
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
