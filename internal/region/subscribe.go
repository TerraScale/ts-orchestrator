package region

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Subscriptions is the identity API of the tenancy's home region, where region
// subscriptions are managed. identity.IdentityClient implements it.
type Subscriptions interface {
	ListRegionSubscriptions(context.Context, identity.ListRegionSubscriptionsRequest) (identity.ListRegionSubscriptionsResponse, error)
	CreateRegionSubscription(context.Context, identity.CreateRegionSubscriptionRequest) (identity.CreateRegionSubscriptionResponse, error)
}

// subscriptionPoll is how often OCI is asked whether a subscription is READY.
const subscriptionPoll = 10 * time.Second

func (c *Creation) subscribe(ctx context.Context, _ string) error {
	return subscribeRegion(ctx, c.Subscriptions, c.Tenancy, c.entry, c.Pause, c.Out)
}

// subscribeRegion subscribes the tenancy to entry's OCI region and waits until
// OCI reports it READY. A subscription OCI already holds is reused, so a rerun
// creates nothing.
func subscribeRegion(ctx context.Context, api Subscriptions, tenancy string, entry catalog.Entry,
	wait func(context.Context, time.Duration) error, out io.Writer,
) error {
	found, err := findSubscription(ctx, api, tenancy, entry)
	if err != nil {
		return err
	}
	if found == nil {
		response, err := api.CreateRegionSubscription(ctx, identity.CreateRegionSubscriptionRequest{TenancyId: &tenancy,
			CreateRegionSubscriptionDetails: identity.CreateRegionSubscriptionDetails{RegionKey: &entry.OCIRegionKey}})
		if err != nil {
			return fmt.Errorf("subscribe to region %s: %w", entry.OCIRegion, err)
		}
		requestID := ""
		if response.OpcRequestId != nil {
			requestID = *response.OpcRequestId
		}
		// A subscription has no OCID; the request ID is what support can find.
		fmt.Fprintf(out, "%s (%s): subscription requested, OCI request %s; subscriptions cannot be undone\n", entry.OCIRegion, entry.OCIRegionKey, requestID)
		found = &response.RegionSubscription
	}
	for found.Status == identity.RegionSubscriptionStatusInProgress {
		if err := wait(ctx, subscriptionPoll); err != nil {
			return fmt.Errorf("region %s subscription is not READY: %w", entry.OCIRegion, err)
		}
		if found, err = findSubscription(ctx, api, tenancy, entry); err != nil {
			return err
		}
		if found == nil {
			return fmt.Errorf("OCI no longer lists the subscription to region %s", entry.OCIRegion)
		}
	}
	if found.Status != identity.RegionSubscriptionStatusReady {
		return fmt.Errorf("region %s subscription is %s; OCI will not make it READY", entry.OCIRegion, found.Status)
	}
	return nil
}

// findSubscription returns the tenancy's subscription to entry's region,
// matched by region key or name, or nil when there is none.
func findSubscription(ctx context.Context, api Subscriptions, tenancy string, entry catalog.Entry) (*identity.RegionSubscription, error) {
	response, err := api.ListRegionSubscriptions(ctx, identity.ListRegionSubscriptionsRequest{TenancyId: &tenancy})
	if err != nil {
		return nil, fmt.Errorf("list region subscriptions: %w", err)
	}
	for _, item := range response.Items {
		if (item.RegionKey != nil && *item.RegionKey == entry.OCIRegionKey) || (item.RegionName != nil && *item.RegionName == entry.OCIRegion) {
			return &item, nil
		}
	}
	return nil, nil
}

// OperatorSubscriptions returns the tenancy's OCI identity API in its home
// region, and the tenancy, from the operator profile.
func OperatorSubscriptions(ctx context.Context) (Subscriptions, string, error) {
	factory, err := ociclient.OperatorConfig(catalog.OCIRegion(catalog.Bootstrap))
	if err != nil {
		return nil, "", err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return nil, "", err
	}
	home, err := factory.HomeRegion(ctx, tenancy)
	if err != nil {
		return nil, "", err
	}
	if factory, err = ociclient.OperatorConfig(home); err != nil {
		return nil, "", err
	}
	api, err := factory.Identity()
	return api, tenancy, err
}

// pause waits d, or until ctx ends.
func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
