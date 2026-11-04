package ocicost

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/usageapi"
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
