package regionops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// ErrSubscriptionInProgress reports a region subscription OCI has accepted
// but not finished. The driver holds the step on it; the loop completes the
// step once an observation finds the subscription READY.
var ErrSubscriptionInProgress = fmt.Errorf("OCI region subscription is in progress: %w", ErrEffectPending)

// SubscriptionAPI is the identity capability the subscription effector
// needs. identity.IdentityClient implements it; the client must target the
// tenancy's home region, where region subscriptions are managed.
type SubscriptionAPI interface {
	ListRegions(ctx context.Context) (identity.ListRegionsResponse, error)
	ListRegionSubscriptions(ctx context.Context, request identity.ListRegionSubscriptionsRequest,
	) (identity.ListRegionSubscriptionsResponse, error)
	CreateRegionSubscription(ctx context.Context, request identity.CreateRegionSubscriptionRequest,
	) (identity.CreateRegionSubscriptionResponse, error)
}

// Subscription is the effector of regionlifecycle.StepSubscribe: it
// subscribes the tenancy to the proposal's OCI region. A region
// subscription is a tenancy-wide singleton keyed by region, so it carries no
// ownership tag; Observe finds it by region name, and the step's CreateKey
// is the opc-retry-token. Only regions OCI lists can be subscribed.
type Subscription struct {
	API       SubscriptionAPI
	TenancyID string
}

// region looks the proposal's OCI region up in OCI's list. The key OCI gives
// is the one the subscription uses, and the region must name the record's cell.
func (subscription Subscription) region(ctx context.Context, record regionlifecycle.Record) (identity.Region, error) {
	if subscription.API == nil || subscription.TenancyID == "" {
		return identity.Region{}, errors.New("region subscription effector needs an identity client and a tenancy")
	}
	listed, err := subscription.API.ListRegions(ctx)
	if err != nil {
		return identity.Region{}, fmt.Errorf("list OCI regions: %w", err)
	}
	for _, item := range listed.Items {
		if item.Name == nil || *item.Name != record.Proposal.OCIRegion {
			continue
		}
		if item.Key == nil || *item.Key == "" || catalog.CellOf(*item.Name, *item.Key) != record.Cell {
			return identity.Region{}, fmt.Errorf("region %s (%s) is not the OCI region of that cell", record.Cell, record.Proposal.OCIRegion)
		}
		return item, nil
	}
	return identity.Region{}, fmt.Errorf("region %s (%s) is not an OCI region", record.Cell, record.Proposal.OCIRegion)
}

// find returns the tenancy's subscription to region, if any.
func (subscription Subscription) find(ctx context.Context, region identity.Region) (*identity.RegionSubscription, error) {
	response, err := subscription.API.ListRegionSubscriptions(ctx,
		identity.ListRegionSubscriptionsRequest{TenancyId: &subscription.TenancyID})
	if err != nil {
		return nil, fmt.Errorf("list region subscriptions: %w", err)
	}
	for _, item := range response.Items {
		if item.RegionName != nil && *item.RegionName == *region.Name {
			return &item, nil
		}
	}
	return nil, nil
}

func (subscription Subscription) evidence(region identity.Region, status identity.RegionSubscriptionStatusEnum) string {
	digest := sha256.Sum256([]byte("terrascale-region-subscription-v1\x00" + subscription.TenancyID + "\x00" +
		*region.Key + "\x00" + *region.Name + "\x00" + string(status)))
	return hex.EncodeToString(digest[:])
}

func (subscription Subscription) Observe(ctx context.Context, record regionlifecycle.Record,
	intent regionlifecycle.StepIntent,
) (regionlifecycle.Observation, error) {
	region, err := subscription.region(ctx, record)
	if err != nil {
		return regionlifecycle.Observation{}, err
	}
	found, err := subscription.find(ctx, region)
	if err != nil {
		return regionlifecycle.Observation{}, err
	}
	observation := regionlifecycle.Observation{Step: intent.Step, CreateKey: intent.CreateKey}
	if found == nil {
		return observation, nil
	}
	if found.Status != identity.RegionSubscriptionStatusReady {
		// Neither absent (a retry would ask again) nor complete.
		return regionlifecycle.Observation{}, ErrSubscriptionInProgress
	}
	observation.Found = true
	observation.ResourceID = *region.Name
	observation.EvidenceDigest = subscription.evidence(region, found.Status)
	return observation, nil
}

func (subscription Subscription) Execute(ctx context.Context, record regionlifecycle.Record,
	intent regionlifecycle.StepIntent,
) (regionlifecycle.StepResult, error) {
	region, err := subscription.region(ctx, record)
	if err != nil {
		return regionlifecycle.StepResult{}, err
	}
	found, err := subscription.find(ctx, region)
	if err != nil {
		return regionlifecycle.StepResult{}, err
	}
	if found == nil {
		token := intent.CreateKey
		response, err := subscription.API.CreateRegionSubscription(ctx, identity.CreateRegionSubscriptionRequest{
			TenancyId:                       &subscription.TenancyID,
			CreateRegionSubscriptionDetails: identity.CreateRegionSubscriptionDetails{RegionKey: region.Key},
			OpcRetryToken:                   &token,
		})
		if err != nil {
			return regionlifecycle.StepResult{}, fmt.Errorf("subscribe to region %s: %w", *region.Name, err)
		}
		// A region subscription has no OCID, so the journal names it by region and request ID.
		requestID := ""
		if response.OpcRequestId != nil {
			requestID = *response.OpcRequestId
		}
		decisionlog.Record(ctx, decisionlog.Decision{Region: record.Cell, Actor: decisionlog.Actor{Slice: "regionops"},
			Kind: decisionlog.KindRegionStep, Subject: regionSubject(record),
			Summary: fmt.Sprintf("Subscribed the tenancy to region %s (%s)", *region.Name, *region.Key),
			Reason:  "OCI accepted the region subscription; it is in progress until OCI reports it ready.",
			Rule:    "regionops.subscription", Status: decisionlog.StatusInProgress,
			Attrs: map[string]string{"region": *region.Name, "region_key": *region.Key,
				"opc_request_id": requestID, "create_key": token}})
		found = &response.RegionSubscription
	}
	if found.Status != identity.RegionSubscriptionStatusReady {
		return regionlifecycle.StepResult{}, ErrSubscriptionInProgress
	}
	return regionlifecycle.StepResult{Step: intent.Step, CreateKey: intent.CreateKey, ResourceID: *region.Name,
		EvidenceDigest: subscription.evidence(region, found.Status)}, nil
}
