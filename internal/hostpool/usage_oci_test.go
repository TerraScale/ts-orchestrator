package hostpool

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/usageapi"
)

type fakeUsage struct {
	requests []usageapi.RequestSummarizedUsagesRequest
	pages    [][]usageapi.UsageSummary
	err      error
	endless  bool
}

func (f *fakeUsage) RequestSummarizedUsages(_ context.Context, request usageapi.RequestSummarizedUsagesRequest,
) (usageapi.RequestSummarizedUsagesResponse, error) {
	f.requests = append(f.requests, request)
	if f.err != nil {
		return usageapi.RequestSummarizedUsagesResponse{}, f.err
	}
	index := len(f.requests) - 1
	var response usageapi.RequestSummarizedUsagesResponse
	if index < len(f.pages) {
		response.Items = f.pages[index]
	}
	if f.endless || index+1 < len(f.pages) {
		response.OpcNextPage = common.String("next")
	}
	return response, nil
}

func usageRow(day time.Time, amount float32, currency string) usageapi.UsageSummary {
	return usageapi.UsageSummary{TimeUsageStarted: &common.SDKTime{Time: day},
		TimeUsageEnded: &common.SDKTime{Time: day.Add(24 * time.Hour)}, ComputedAmount: &amount,
		Currency: common.String(currency)}
}

func october(dayOfMonth int) time.Time { return time.Date(2026, 10, dayOfMonth, 0, 0, 0, 0, time.UTC) }

func TestOCIUsageSumsCompleteDaysOfTheRegion(t *testing.T) {
	api := &fakeUsage{pages: [][]usageapi.UsageSummary{
		{usageRow(october(1), 10, "USD"), usageRow(october(10), 12.5, "USD")},
		{usageRow(october(11), 30, "USD"), usageRow(october(12), -5, "USD"), usageRow(october(13), 20.004, "USD"),
			{TimeUsageStarted: &common.SDKTime{Time: october(13)}}, usageRow(october(13), 0, "")},
	}}
	usage := &OCIUsage{Region: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1..t", API: api}
	spend, err := usage.Spend(context.Background(), midMonth)
	if err != nil {
		t.Fatal(err)
	}
	// Through is Oct 14: Oct 16 is today and Oct 14..15 may still be
	// arriving. Days round up to cents, credits (-5) count as zero, and the
	// peak is the costliest of Oct 11..13.
	want := Spend{Currency: "USD", MonthCents: 1000 + 1250 + 3000 + 2001, PeakDayCents: 3000, Through: october(14),
		ObservedAt: midMonth}
	if spend != want {
		t.Fatalf("spend = %+v, want %+v", spend, want)
	}
	if len(api.requests) != 2 || api.requests[1].Page == nil {
		t.Fatalf("requests = %d", len(api.requests))
	}
	details := api.requests[0].RequestSummarizedUsagesDetails
	if *details.TenantId != "ocid1.tenancy.oc1..t" || !details.TimeUsageStarted.Equal(october(1)) ||
		!details.TimeUsageEnded.Equal(october(14)) ||
		details.Granularity != usageapi.RequestSummarizedUsagesDetailsGranularityDaily ||
		details.QueryType != usageapi.RequestSummarizedUsagesDetailsQueryTypeCost ||
		len(details.Filter.Dimensions) != 1 || *details.Filter.Dimensions[0].Key != "region" ||
		*details.Filter.Dimensions[0].Value != "sa-saopaulo-1" {
		t.Fatalf("request = %+v", details)
	}
}

func TestOCIUsageReadsThePeakAcrossTheMonthBoundary(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	api := &fakeUsage{pages: [][]usageapi.UsageSummary{{
		usageRow(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC), 40, "USD"),
		usageRow(time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC), 7, "USD"),
	}}}
	spend, err := (&OCIUsage{Region: "sa-saopaulo-1", TenancyID: "t", API: api}).Spend(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	// Through is Sept 30, so October has no complete day; the peak window
	// is Sept 27..29.
	if spend.MonthCents != 0 || spend.PeakDayCents != 4000 || !spend.Through.Equal(time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("spend = %+v", spend)
	}
	if start := api.requests[0].TimeUsageStarted; !start.Equal(time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("start = %v", start)
	}
}

func TestOCIUsageRejectsBadAnswers(t *testing.T) {
	nan := float32(math.NaN())
	cases := map[string]*fakeUsage{
		"api error":       {err: errors.New("NotAuthorizedOrNotFound")},
		"endless pages":   {endless: true},
		"mixed currency":  {pages: [][]usageapi.UsageSummary{{usageRow(october(12), 1, "USD"), usageRow(october(13), 1, "BRL")}}},
		"day after data":  {pages: [][]usageapi.UsageSummary{{usageRow(october(14), 1, "USD")}}},
		"no currency":     {pages: [][]usageapi.UsageSummary{{usageRow(october(12), 1, "")}}},
		"day before data": {pages: [][]usageapi.UsageSummary{{usageRow(time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), 1, "USD")}}},
		"unaligned day":   {pages: [][]usageapi.UsageSummary{{usageRow(october(12).Add(time.Hour), 1, "USD")}}},
		"no day":          {pages: [][]usageapi.UsageSummary{{{ComputedAmount: common.Float32(1)}}}},
		"not a number":    {pages: [][]usageapi.UsageSummary{{usageRow(october(12), nan, "USD")}}},
		"absurd amount":   {pages: [][]usageapi.UsageSummary{{usageRow(october(12), 1e9, "USD")}}},
	}
	for name, api := range cases {
		_, err := (&OCIUsage{Region: "sa-saopaulo-1", TenancyID: "t", API: api}).Spend(context.Background(), midMonth)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := (&OCIUsage{Region: "sa-saopaulo-1", TenancyID: "t", API: &fakeUsage{endless: true}}).Spend(
		context.Background(), midMonth); err == nil || !strings.Contains(err.Error(), "pages") {
		t.Fatalf("endless pages: %v", err)
	}
}

func TestOCIUsageMarksAnAnswerWithoutRows(t *testing.T) {
	spend, err := (&OCIUsage{Region: "sa-saopaulo-1", TenancyID: "t", API: &fakeUsage{}}).Spend(context.Background(), midMonth)
	if err != nil || spend != (Spend{Empty: true, Through: october(14), ObservedAt: midMonth}) {
		t.Fatalf("spend = %+v, %v", spend, err)
	}
}
