package ocicost

import (
	"context"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/usageapi"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

const usageTenancy = "ocid1.tenancy.oc1..t"

// fakeUsageAPI answers each query kind from its own pages and records every
// request. Next-page tokens are page indexes.
type fakeUsageAPI struct {
	daily, services, components, skus [][]usageapi.UsageSummary
	endless                           bool
	err                               error
	requests                          []usageapi.RequestSummarizedUsagesRequest
}

func (f *fakeUsageAPI) RequestSummarizedUsages(_ context.Context, request usageapi.RequestSummarizedUsagesRequest,
) (usageapi.RequestSummarizedUsagesResponse, error) {
	f.requests = append(f.requests, request)
	if f.err != nil {
		return usageapi.RequestSummarizedUsagesResponse{}, f.err
	}
	pages := f.components
	switch {
	// The SKU query is daily too, so it is matched before the daily pages.
	case slices.Equal(request.GroupBy, []string{"skuPartNumber"}):
		pages = f.skus
	case request.Granularity == usageapi.RequestSummarizedUsagesDetailsGranularityDaily:
		pages = f.daily
	case len(request.GroupBy) == 1:
		pages = f.services
	}
	index := 0
	if request.Page != nil {
		index, _ = strconv.Atoi(*request.Page)
	}
	var response usageapi.RequestSummarizedUsagesResponse
	if index < len(pages) {
		response.Items = pages[index]
	}
	if f.endless || index+1 < len(pages) {
		response.OpcNextPage = common.String(strconv.Itoa(index + 1))
	}
	return response, nil
}

func usageRead(api UsageAPI, now time.Time) (Report, error) {
	return (&Usage{Cell: "gru", OCIRegion: "sa-saopaulo-1", TenancyID: usageTenancy, API: api}).Read(context.Background(), now)
}

func usageDay(dayOfMonth int) time.Time {
	return time.Date(2026, 10, dayOfMonth, 0, 0, 0, 0, time.UTC)
}

var (
	usageMid   = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	usageMonth = usageDay(1)
)

func usageRow(day time.Time, amount float32, currency string) usageapi.UsageSummary {
	return usageapi.UsageSummary{TimeUsageStarted: &common.SDKTime{Time: day},
		TimeUsageEnded: &common.SDKTime{Time: day.Add(24 * time.Hour)}, ComputedAmount: &amount,
		Currency: common.String(currency)}
}

func usageServiceRow(service string, amount float32, currency string) usageapi.UsageSummary {
	row := usageRow(usageMonth, amount, currency)
	row.Service = common.String(service)
	return row
}

func usageComponentRow(namespace *string, key, value string, amount float32) usageapi.UsageSummary {
	row := usageRow(usageMonth, amount, "USD")
	row.Tags = []usageapi.Tag{{Namespace: namespace, Key: common.String(key), Value: common.String(value)}}
	return row
}

func usageSKURow(day time.Time, sku string, amount, quantity float32) usageapi.UsageSummary {
	row := usageRow(day, amount, "USD")
	row.SkuPartNumber = common.String(sku)
	row.ComputedQuantity = common.Float32(quantity)
	return row
}

func TestUsageRequestShapes(t *testing.T) {
	api := &fakeUsageAPI{}
	if _, err := usageRead(api, usageMid); err != nil {
		t.Fatal(err)
	}
	if len(api.requests) != 4 {
		t.Fatalf("requests = %d, want 4", len(api.requests))
	}
	for _, request := range api.requests {
		if *request.TenantId != usageTenancy || request.QueryType != usageapi.RequestSummarizedUsagesDetailsQueryTypeCost ||
			request.Filter.Operator != usageapi.FilterOperatorAnd || len(request.Filter.Dimensions) != 1 ||
			*request.Filter.Dimensions[0].Key != "region" || *request.Filter.Dimensions[0].Value != "sa-saopaulo-1" ||
			request.GroupByTag != nil {
			t.Fatalf("request = %+v", request.RequestSummarizedUsagesDetails)
		}
	}
	days, services, components := api.requests[0], api.requests[1], api.requests[2]
	// now is Oct 16: the rate window starts Oct 7, so the month's Oct 1 is earlier.
	if days.Granularity != usageapi.RequestSummarizedUsagesDetailsGranularityDaily || days.GroupBy != nil ||
		!days.TimeUsageStarted.Equal(usageDay(1)) || !days.TimeUsageEnded.Equal(usageDay(17)) {
		t.Fatalf("days request = %+v", days.RequestSummarizedUsagesDetails)
	}
	if services.Granularity != usageapi.RequestSummarizedUsagesDetailsGranularityMonthly ||
		!slices.Equal(services.GroupBy, []string{"service"}) ||
		!services.TimeUsageStarted.Equal(usageDay(1)) || !services.TimeUsageEnded.Equal(usageDay(17)) {
		t.Fatalf("services request = %+v", services.RequestSummarizedUsagesDetails)
	}
	if components.Granularity != usageapi.RequestSummarizedUsagesDetailsGranularityMonthly ||
		!slices.Equal(components.GroupBy, []string{"tagNamespace", "tagKey", "tagValue"}) ||
		!components.TimeUsageStarted.Equal(usageDay(1)) || !components.TimeUsageEnded.Equal(usageDay(17)) {
		t.Fatalf("components request = %+v", components.RequestSummarizedUsagesDetails)
	}
	// The rate window is the 7 complete days before through (Oct 14), so it starts Oct 7.
	sku := api.requests[3]
	if sku.Granularity != usageapi.RequestSummarizedUsagesDetailsGranularityDaily ||
		!sku.TimeUsageStarted.Equal(usageDay(7)) || !sku.TimeUsageEnded.Equal(usageDay(17)) {
		t.Fatalf("sku request = %+v", sku.RequestSummarizedUsagesDetails)
	}
}

func TestUsageSKUPrices(t *testing.T) {
	api := &fakeUsageAPI{skus: [][]usageapi.UsageSummary{{
		usageSKURow(usageDay(9), "B93297", 2, 10),
		usageSKURow(usageDay(10), "B93297", 1, 20),
		usageSKURow(usageDay(9), "B91961", 0, 5),
		usageSKURow(usageDay(9), "B93298", 1, 0),
		{TimeUsageStarted: &common.SDKTime{Time: usageDay(9)}, ComputedAmount: common.Float32(3),
			ComputedQuantity: common.Float32(3)},
	}}}
	report, err := usageRead(api, usageMid)
	if err != nil {
		t.Fatal(err)
	}
	// Two days of B93297 sum to 3 over 30 units. B91961 is free, so it prices at zero;
	// B93298 has no quantity and the last row has no SKU, so neither is listed.
	if len(report.Prices) != 2 || report.Prices[0].SKU != "B91961" || report.Prices[0].PerUnit != 0 ||
		report.Prices[1].SKU != "B93297" || math.Abs(report.Prices[1].PerUnit-0.1) > 1e-9 {
		t.Fatalf("prices = %+v", report.Prices)
	}
}

func TestUsageWindowAtMonthEnd(t *testing.T) {
	api := &fakeUsageAPI{}
	report, err := usageRead(api, time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	// now is Nov 1 06:00: through is Oct 30, so the rate window starts Oct 23
	// and is earlier than the month's Nov 1.
	days, services := api.requests[0], api.requests[1]
	if !days.TimeUsageStarted.Equal(time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)) ||
		!days.TimeUsageEnded.Equal(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("days window = %v to %v", days.TimeUsageStarted, days.TimeUsageEnded)
	}
	if !services.TimeUsageStarted.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) ||
		!services.TimeUsageEnded.Equal(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("services window = %v to %v", services.TimeUsageStarted, services.TimeUsageEnded)
	}
	if !report.Through.Equal(usageDay(30)) {
		t.Fatalf("through = %v", report.Through)
	}
}

func TestUsagePagesAcrossTwoPages(t *testing.T) {
	api := &fakeUsageAPI{daily: [][]usageapi.UsageSummary{
		{usageRow(usageDay(1), 10, "USD")},
		{usageRow(usageDay(2), 20, "USD")},
	}}
	report, err := usageRead(api, usageMid)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Days) != 2 || report.Days[1].Cents != 2000 {
		t.Fatalf("days = %+v", report.Days)
	}
	if len(api.requests) != 5 || api.requests[1].Page == nil || *api.requests[1].Page != "1" {
		t.Fatalf("requests = %d", len(api.requests))
	}
}

func TestUsageStopsAfterSixteenPages(t *testing.T) {
	api := &fakeUsageAPI{endless: true}
	_, err := usageRead(api, usageMid)
	if err == nil || !strings.Contains(err.Error(), "more than 16 pages") {
		t.Fatalf("err = %v", err)
	}
	if len(api.requests) != maxUsagePages {
		t.Fatalf("requests = %d, want %d", len(api.requests), maxUsagePages)
	}
}

func TestUsageWrapsAPIError(t *testing.T) {
	sentinel := errors.New("NotAuthorizedOrNotFound")
	_, err := usageRead(&fakeUsageAPI{err: sentinel}, usageMid)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "read OCI usage") {
		t.Fatalf("err = %v", err)
	}
}

func TestUsageRoundsUpToCents(t *testing.T) {
	api := &fakeUsageAPI{daily: [][]usageapi.UsageSummary{{
		usageRow(usageDay(1), 0.0538, "USD"),
		usageRow(usageDay(2), 3, "USD"),
		usageRow(usageDay(2), -5, "USD"),
		usageRow(usageDay(3), 1.0000000001, "USD"),
	}}}
	report, err := usageRead(api, usageMid)
	if err != nil {
		t.Fatal(err)
	}
	// Day 2 sums to -2: a credit day counts as zero, not as a negative cost.
	want := []Day{{usageDay(1), 6}, {usageDay(2), 0}, {usageDay(3), 100}}
	if !slices.Equal(report.Days, want) {
		t.Fatalf("days = %+v, want %+v", report.Days, want)
	}
}

func TestUsageKeepsDayWithoutAmount(t *testing.T) {
	unpriced := usageapi.UsageSummary{TimeUsageStarted: &common.SDKTime{Time: usageDay(5)}}
	api := &fakeUsageAPI{daily: [][]usageapi.UsageSummary{{unpriced, usageRow(usageDay(6), 1, "USD")}}}
	report, err := usageRead(api, usageMid)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Days) != 2 || !report.Days[0].Day.Equal(usageDay(5)) || report.Days[0].Cents != 0 {
		t.Fatalf("days = %+v", report.Days)
	}
	if report.Currency != "USD" {
		t.Fatalf("currency = %q", report.Currency)
	}
}

func TestUsageFiltersComponents(t *testing.T) {
	api := &fakeUsageAPI{components: [][]usageapi.UsageSummary{{
		usageComponentRow(common.String("Oracle-Tags"), ComponentTag, "terrabase", 5),
		usageComponentRow(nil, "terrascale-resource", "terrabase", 5),
		usageComponentRow(nil, ComponentTag, "db", 5),
		usageComponentRow(common.String(""), ComponentTag, "terrabase", 1.5),
		usageComponentRow(nil, ComponentTag, "terrabase", 2.25),
		usageComponentRow(nil, ComponentTag, "controller", 0.5),
	}}}
	report, err := usageRead(api, usageMid)
	if err != nil {
		t.Fatal(err)
	}
	want := []Line{{"terrabase", 375}, {"controller", 50}}
	if !slices.Equal(report.Components, want) {
		t.Fatalf("components = %+v, want %+v", report.Components, want)
	}
}

func TestUsageReportIsSortedAndValid(t *testing.T) {
	api := &fakeUsageAPI{
		daily: [][]usageapi.UsageSummary{{usageRow(usageDay(3), 1, "USD"), usageRow(usageDay(1), 2, "USD")}},
		services: [][]usageapi.UsageSummary{{
			usageServiceRow("Block Storage", 10, "USD"),
			usageServiceRow("Compute", 30, "USD"),
			usageServiceRow("Audit", 30, "USD"),
		}},
		components: [][]usageapi.UsageSummary{{
			usageComponentRow(nil, ComponentTag, "terrabase", 3),
			usageComponentRow(nil, ComponentTag, "controller", 1),
		}},
	}
	report, err := usageRead(api, usageMid)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if !report.Days[0].Day.Equal(usageDay(1)) || !report.Days[1].Day.Equal(usageDay(3)) {
		t.Fatalf("days = %+v", report.Days)
	}
	wantServices := []Line{{"Audit", 3000}, {"Compute", 3000}, {"Block Storage", 1000}}
	if !slices.Equal(report.Services, wantServices) {
		t.Fatalf("services = %+v", report.Services)
	}
	if report.Components[0].Name != "terrabase" || report.Components[1].Name != "controller" {
		t.Fatalf("components = %+v", report.Components)
	}
	if report.Cell != "gru" || report.OCIRegion != "sa-saopaulo-1" || report.Currency != "USD" ||
		!report.ObservedAt.Equal(usageMid) || !report.Through.Equal(usageDay(14)) {
		t.Fatalf("report = %+v", report)
	}
}

func TestUsageRejectsBadAnswers(t *testing.T) {
	nan := float32(math.NaN())
	cases := map[string]*fakeUsageAPI{
		"mixed currency across queries": {
			daily:    [][]usageapi.UsageSummary{{usageRow(usageDay(12), 1, "USD")}},
			services: [][]usageapi.UsageSummary{{usageServiceRow("Compute", 1, "BRL")}}},
		"mixed currency in one query": {daily: [][]usageapi.UsageSummary{{
			usageRow(usageDay(12), 1, "USD"), usageRow(usageDay(13), 1, "BRL")}}},
		"cost without currency": {daily: [][]usageapi.UsageSummary{{usageRow(usageDay(12), 1, "")}}},
		"day at window end":     {daily: [][]usageapi.UsageSummary{{usageRow(usageDay(17), 1, "USD")}}},
		"day before window":     {daily: [][]usageapi.UsageSummary{{usageRow(usageDay(0), 1, "USD")}}},
		"unaligned day":         {daily: [][]usageapi.UsageSummary{{usageRow(usageDay(12).Add(time.Hour), 1, "USD")}}},
		"no start": {daily: [][]usageapi.UsageSummary{{
			{ComputedAmount: common.Float32(1), Currency: common.String("USD")}}}},
		"not a number":           {daily: [][]usageapi.UsageSummary{{usageRow(usageDay(12), nan, "USD")}}},
		"absurd amount":          {daily: [][]usageapi.UsageSummary{{usageRow(usageDay(12), 1e9, "USD")}}},
		"service without name":   {services: [][]usageapi.UsageSummary{{usageServiceRow("", 1, "USD")}}},
		"sku before rate window": {skus: [][]usageapi.UsageSummary{{usageSKURow(usageDay(6), "B93297", 1, 1)}}},
		"negative sku quantity":  {skus: [][]usageapi.UsageSummary{{usageSKURow(usageDay(9), "B93297", 1, -1)}}},
		"not a sku quantity":     {skus: [][]usageapi.UsageSummary{{usageSKURow(usageDay(9), "B93297", 1, nan)}}},
	}
	for name, api := range cases {
		if _, err := usageRead(api, usageMid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConnectRefusesMissingTenancy(t *testing.T) {
	factory, err := ociclient.New(usageTenancyProvider{}, ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Connect(context.Background(), factory, "gru", "sa-saopaulo-1"); err == nil ||
		!strings.Contains(err.Error(), "no tenancy") {
		t.Fatalf("err = %v", err)
	}
	sentinel := errors.New("no config")
	factory, err = ociclient.New(usageTenancyProvider{err: sentinel}, ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Connect(context.Background(), factory, "gru", "sa-saopaulo-1"); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v", err)
	}
}

// usageTenancyProvider answers only the tenancy, the one call Connect makes
// before it needs the network.
type usageTenancyProvider struct {
	common.ConfigurationProvider
	err error
}

func (p usageTenancyProvider) TenancyOCID() (string, error) { return "", p.err }
