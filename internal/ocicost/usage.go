package ocicost

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/usageapi"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

const (
	maxUsagePages = 16
	// maxRowAmount bounds one row's cost in currency units; more is a
	// corrupt answer, not a bill.
	maxRowAmount = 1e7
)

// UsageAPI is the slice of the OCI Usage API the reader calls.
type UsageAPI interface {
	RequestSummarizedUsages(ctx context.Context, request usageapi.RequestSummarizedUsagesRequest) (usageapi.RequestSummarizedUsagesResponse, error)
}

// Usage reads one OCI region's cost from the tenancy's Usage API: every
// compartment and environment in that region counts.
type Usage struct {
	Cell      string
	OCIRegion string
	TenancyID string
	API       UsageAPI
}

// Connect aims a Usage at the tenancy's home region, which serves the Usage
// API, through factory's principal.
func Connect(ctx context.Context, factory *ociclient.Factory, cell, ociRegion string) (*Usage, error) {
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return nil, fmt.Errorf("read the tenancy: %w", err)
	}
	if tenancy == "" {
		return nil, errors.New("principal has no tenancy")
	}
	home, err := factory.HomeRegion(ctx, tenancy)
	if err != nil {
		return nil, err
	}
	client, err := factory.Usage()
	if err != nil {
		return nil, err
	}
	client.SetRegion(home)
	return &Usage{Cell: cell, OCIRegion: ociRegion, TenancyID: tenancy, API: client}, nil
}

// usageSums holds one Read's running totals across its four queries.
type usageSums struct {
	currency      string
	days          map[int64]float64
	services      map[string]float64
	components    map[string]float64
	skuAmounts    map[string]float64
	skuQuantities map[string]float64
}

// Read returns the region's report at now. Four queries feed it: daily
// totals for the rate window, month-to-date cost by service and by component
// tag, and the rate window's amount and quantity by SKU.
func (u *Usage) Read(ctx context.Context, now time.Time) (Report, error) {
	now = now.UTC()
	today := now.Truncate(day)
	through := today.Add(-UsageLag)
	monthStart, _ := monthBounds(now)
	from := through.Add(-RateDays * day)
	if monthStart.Before(from) {
		from = monthStart
	}
	end := today.Add(day)
	sums := usageSums{days: map[int64]float64{}, services: map[string]float64{}, components: map[string]float64{},
		skuAmounts: map[string]float64{}, skuQuantities: map[string]float64{}}

	if err := u.each(ctx, usageapi.RequestSummarizedUsagesDetails{
		Granularity:      usageapi.RequestSummarizedUsagesDetailsGranularityDaily,
		TimeUsageStarted: &common.SDKTime{Time: from},
		TimeUsageEnded:   &common.SDKTime{Time: end},
	}, func(item usageapi.UsageSummary) error {
		start, err := rowStart(item, from, end)
		if err != nil {
			return err
		}
		amount, err := sums.amount(item)
		if err != nil {
			return err
		}
		sums.days[start.Unix()] += amount
		return nil
	}); err != nil {
		return Report{}, err
	}

	if err := u.each(ctx, usageapi.RequestSummarizedUsagesDetails{
		Granularity:      usageapi.RequestSummarizedUsagesDetailsGranularityMonthly,
		TimeUsageStarted: &common.SDKTime{Time: monthStart},
		TimeUsageEnded:   &common.SDKTime{Time: end},
		GroupBy:          []string{"service"},
	}, func(item usageapi.UsageSummary) error {
		if _, err := rowStart(item, monthStart, end); err != nil {
			return err
		}
		if item.Service == nil || *item.Service == "" {
			return errors.New("OCI usage row has no service")
		}
		amount, err := sums.amount(item)
		if err != nil {
			return err
		}
		sums.services[*item.Service] += amount
		return nil
	}); err != nil {
		return Report{}, err
	}

	// The API refuses a region filter together with GroupByTag, so the tag
	// comes back through the tag dimensions instead.
	if err := u.each(ctx, usageapi.RequestSummarizedUsagesDetails{
		Granularity:      usageapi.RequestSummarizedUsagesDetailsGranularityMonthly,
		TimeUsageStarted: &common.SDKTime{Time: monthStart},
		TimeUsageEnded:   &common.SDKTime{Time: end},
		GroupBy:          []string{"tagNamespace", "tagKey", "tagValue"},
	}, func(item usageapi.UsageSummary) error {
		if _, err := rowStart(item, monthStart, end); err != nil {
			return err
		}
		name := componentName(item)
		if name == "" {
			return nil
		}
		amount, err := sums.amount(item)
		if err != nil {
			return err
		}
		sums.components[name] += amount
		return nil
	}); err != nil {
		return Report{}, err
	}

	// Unit prices come from the rate window only, so a SKU's price tracks what it costs now.
	windowStart := through.Add(-RateDays * day)
	if err := u.each(ctx, usageapi.RequestSummarizedUsagesDetails{
		Granularity:      usageapi.RequestSummarizedUsagesDetailsGranularityDaily,
		TimeUsageStarted: &common.SDKTime{Time: windowStart},
		TimeUsageEnded:   &common.SDKTime{Time: end},
		GroupBy:          []string{"skuPartNumber"},
	}, func(item usageapi.UsageSummary) error {
		if _, err := rowStart(item, windowStart, end); err != nil {
			return err
		}
		if item.SkuPartNumber == nil || *item.SkuPartNumber == "" {
			return nil
		}
		amount, err := sums.amount(item)
		if err != nil {
			return err
		}
		quantity := 0.0
		if item.ComputedQuantity != nil {
			quantity = float64(*item.ComputedQuantity)
		}
		if math.IsNaN(quantity) || math.IsInf(quantity, 0) || quantity < 0 {
			return fmt.Errorf("OCI usage quantity %v is out of range", quantity)
		}
		sums.skuAmounts[*item.SkuPartNumber] += amount
		sums.skuQuantities[*item.SkuPartNumber] += quantity
		return nil
	}); err != nil {
		return Report{}, err
	}

	var days []Day
	for unix, amount := range sums.days {
		days = append(days, Day{Day: time.Unix(unix, 0).UTC(), Cents: cents(amount)})
	}
	slices.SortFunc(days, func(a, b Day) int { return a.Day.Compare(b.Day) })
	report := Report{Version: Version, Cell: u.Cell, OCIRegion: u.OCIRegion, Currency: sums.currency,
		ObservedAt: now, Through: through, Days: days, Services: lines(sums.services),
		Components: lines(sums.components), Prices: skuPrices(sums.skuAmounts, sums.skuQuantities)}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

// each runs one cost question for the region and visits its rows, following
// the API's pages. The page cap stops a runaway answer.
func (u *Usage) each(ctx context.Context, details usageapi.RequestSummarizedUsagesDetails, visit func(usageapi.UsageSummary) error) error {
	details.TenantId = common.String(u.TenancyID)
	details.QueryType = usageapi.RequestSummarizedUsagesDetailsQueryTypeCost
	details.Filter = &usageapi.Filter{Operator: usageapi.FilterOperatorAnd,
		Dimensions: []usageapi.Dimension{{Key: common.String("region"), Value: common.String(u.OCIRegion)}}}
	var page *string
	for range maxUsagePages {
		response, err := u.API.RequestSummarizedUsages(ctx, usageapi.RequestSummarizedUsagesRequest{
			RequestSummarizedUsagesDetails: details, Page: page})
		if err != nil {
			return fmt.Errorf("read OCI usage: %w", err)
		}
		for _, item := range response.Items {
			if err := visit(item); err != nil {
				return err
			}
		}
		if page = response.OpcNextPage; page == nil {
			return nil
		}
	}
	return fmt.Errorf("OCI usage spans more than %d pages", maxUsagePages)
}

// amount returns a row's cost in currency units, zero when OCI gave none. It
// refuses a row whose cost is absurd or whose currency breaks the report's.
func (s *usageSums) amount(item usageapi.UsageSummary) (float64, error) {
	if item.ComputedAmount == nil {
		return 0, nil
	}
	amount := float64(*item.ComputedAmount)
	if math.IsNaN(amount) || math.Abs(amount) > maxRowAmount {
		return 0, fmt.Errorf("OCI usage amount %v is out of range", amount)
	}
	currency := ""
	if item.Currency != nil {
		currency = *item.Currency
	}
	switch {
	case currency == "":
		if amount != 0 {
			return 0, errors.New("OCI usage row has a cost but no currency")
		}
	case s.currency != "" && currency != s.currency:
		return 0, fmt.Errorf("OCI usage mixes currencies %s and %s", s.currency, currency)
	default:
		s.currency = currency
	}
	return amount, nil
}

// rowStart returns when a row's usage begins, and refuses one that is not a
// UTC midnight inside [from, end).
func rowStart(item usageapi.UsageSummary, from, end time.Time) (time.Time, error) {
	if item.TimeUsageStarted == nil {
		return time.Time{}, errors.New("OCI usage row has no start")
	}
	start := item.TimeUsageStarted.Time.UTC()
	if !start.Equal(start.Truncate(day)) || start.Before(from) || !start.Before(end) {
		return time.Time{}, fmt.Errorf("OCI usage row for %s is not a UTC midnight in the requested days", start.Format(time.RFC3339))
	}
	return start, nil
}

// componentName returns the component named by the row's terrascale-component
// freeform tag, or "" when the row has no such tag or names an unknown one.
func componentName(item usageapi.UsageSummary) string {
	for _, tag := range item.Tags {
		if (tag.Namespace == nil || *tag.Namespace == "") && tag.Key != nil && *tag.Key == ComponentTag &&
			tag.Value != nil && slices.Contains(Components, *tag.Value) {
			return *tag.Value
		}
	}
	return ""
}

// lines turns summed amounts into lines, costliest first, then by name.
// OCI lists free services at zero; they are left out.
func lines(sums map[string]float64) []Line {
	var out []Line
	for name, amount := range sums {
		if amount := cents(amount); amount > 0 {
			out = append(out, Line{Name: name, Cents: amount})
		}
	}
	slices.SortFunc(out, func(a, b Line) int {
		return cmp.Or(cmp.Compare(b.Cents, a.Cents), cmp.Compare(a.Name, b.Name))
	})
	return out
}

// skuPrices divides each SKU's amount by its quantity, sorted by SKU. A SKU
// with no quantity has no unit to price, so it is left out.
func skuPrices(amounts, quantities map[string]float64) []Price {
	var out []Price
	for sku, quantity := range quantities {
		if quantity > 0 {
			out = append(out, Price{SKU: sku, PerUnit: max(amounts[sku], 0) / quantity})
		}
	}
	slices.SortFunc(out, func(a, b Price) int { return cmp.Compare(a.SKU, b.SKU) })
	return out
}

// cents rounds an amount up to whole cents; credits count as zero. The
// epsilon keeps float error from adding a cent to an exact amount.
func cents(amount float64) uint64 {
	return uint64(math.Ceil(max(amount, 0)*100 - 1e-6))
}
