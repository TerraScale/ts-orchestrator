package hostpool

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/usageapi"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

const (
	maxUsagePages = 16
	// maxDayAmount bounds one day's cost in currency units; more is a
	// corrupt answer, not a bill.
	maxDayAmount = 1e7
)

// usageAPI is the slice of the OCI usage API the spend source calls.
type usageAPI interface {
	RequestSummarizedUsages(ctx context.Context, request usageapi.RequestSummarizedUsagesRequest) (usageapi.RequestSummarizedUsagesResponse, error)
}

// OCIUsage reads the daily cost of one OCI region of a tenancy: every
// compartment and environment in that region counts. Without an API it
// connects with the controller's instance principal on first use, to the
// tenancy's home region, which serves the usage API. One goroutine calls
// Spend at a time: the scaler's tick.
type OCIUsage struct {
	Region    string
	TenancyID string
	API       usageAPI
}

func (u *OCIUsage) connect(ctx context.Context) error {
	if u.API != nil {
		return nil
	}
	factory, err := ociclient.InstancePrincipal(u.Region)
	if err != nil {
		return err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return fmt.Errorf("read the instance principal tenancy: %w", err)
	}
	if tenancy == "" {
		return errors.New("instance principal has no tenancy")
	}
	home, err := factory.HomeRegion(ctx, tenancy)
	if err != nil {
		return err
	}
	client, err := factory.Usage()
	if err != nil {
		return err
	}
	client.SetRegion(home)
	u.TenancyID, u.API = tenancy, client
	return nil
}

// Spend sums the complete days of the month and finds the costliest of the
// PeakDays days before Through. Days round up to whole cents, negative days
// (credits) count as zero, and a row without an amount counts as no cost.
// The region filter takes the full region name; a wrong one matches no row,
// so an answer without rows is marked Empty for the scaler to judge.
func (u *OCIUsage) Spend(ctx context.Context, now time.Time) (Spend, error) {
	if err := u.connect(ctx); err != nil {
		return Spend{}, err
	}
	through := now.UTC().Truncate(day).Add(-UsageLag)
	monthStart, _ := monthBounds(now)
	peakStart := through.Add(-PeakDays * day)
	from := min(monthStart.Unix(), peakStart.Unix())
	details := usageapi.RequestSummarizedUsagesDetails{
		TenantId:         common.String(u.TenancyID),
		TimeUsageStarted: &common.SDKTime{Time: time.Unix(from, 0).UTC()},
		TimeUsageEnded:   &common.SDKTime{Time: through},
		Granularity:      usageapi.RequestSummarizedUsagesDetailsGranularityDaily,
		QueryType:        usageapi.RequestSummarizedUsagesDetailsQueryTypeCost,
		Filter: &usageapi.Filter{Operator: usageapi.FilterOperatorAnd,
			Dimensions: []usageapi.Dimension{{Key: common.String("region"), Value: common.String(u.Region)}}},
	}
	days := map[int64]float64{}
	currency, rows := "", 0
	var page *string
	for range maxUsagePages {
		response, err := u.API.RequestSummarizedUsages(ctx, usageapi.RequestSummarizedUsagesRequest{
			RequestSummarizedUsagesDetails: details, Page: page})
		if err != nil {
			return Spend{}, fmt.Errorf("read OCI usage: %w", err)
		}
		rows += len(response.Items)
		for _, item := range response.Items {
			if item.TimeUsageStarted == nil {
				return Spend{}, errors.New("OCI usage row has no day")
			}
			start := item.TimeUsageStarted.Time.UTC()
			if !start.Equal(start.Truncate(day)) || start.Unix() < from || !start.Before(through) {
				return Spend{}, fmt.Errorf("OCI usage row for %s is outside the requested days", start.Format(time.RFC3339))
			}
			if item.ComputedAmount == nil {
				continue
			}
			amount := float64(*item.ComputedAmount)
			if math.IsNaN(amount) || math.Abs(amount) > maxDayAmount {
				return Spend{}, fmt.Errorf("OCI usage amount %v is out of range", amount)
			}
			switch {
			case item.Currency == nil || *item.Currency == "":
				if amount != 0 {
					return Spend{}, errors.New("OCI usage row has a cost but no currency")
				}
			case currency != "" && currency != *item.Currency:
				return Spend{}, fmt.Errorf("OCI usage mixes currencies %s and %s", currency, *item.Currency)
			default:
				currency = *item.Currency
			}
			days[start.Unix()] += amount
		}
		if page = response.OpcNextPage; page == nil {
			spend := Spend{Currency: currency, Empty: rows == 0, Through: through, ObservedAt: now}
			for start, amount := range days {
				cents := uint64(math.Ceil(max(amount, 0)*100 - 1e-6))
				if start >= monthStart.Unix() {
					spend.MonthCents += cents
				}
				if start >= peakStart.Unix() {
					spend.PeakDayCents = max(spend.PeakDayCents, cents)
				}
			}
			return spend, nil
		}
	}
	return Spend{}, fmt.Errorf("OCI usage spans more than %d pages", maxUsagePages)
}
