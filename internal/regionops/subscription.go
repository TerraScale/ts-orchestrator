package regionops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/identity"

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
	ListRegionSubscriptions(ctx context.Context, request identity.ListRegionSubscriptionsRequest,
	) (identity.ListRegionSubscriptionsResponse, error)
	CreateRegionSubscription(ctx context.Context, request identity.CreateRegionSubscriptionRequest,
	) (identity.CreateRegionSubscriptionResponse, error)
}

// Subscription is the effector of regionlifecycle.StepSubscribe: it
// subscribes the tenancy to the proposal's OCI region. A region
// subscription is a tenancy-wide singleton keyed by region, so it carries no
// ownership tag; Observe finds it by region name, and the step's CreateKey
// is the opc-retry-token. Only catalog regions can be subscribed.
type Subscription struct {
	API       SubscriptionAPI
	TenancyID string
}

func (subscription Subscription) region(record regionlifecycle.Record) (catalog.Entry, error) {
	entry, ok := catalog.CellForOCIRegion(record.Proposal.OCIRegion)
	if !ok || entry.Name() != record.Cell || entry.OCIRegionKey == "" {
		return catalog.Entry{}, fmt.Errorf("region %s (%s) is not a catalog region", record.Cell, record.Proposal.OCIRegion)
	}
	if subscription.API == nil || subscription.TenancyID == "" {
		return catalog.Entry{}, errors.New("region subscription effector needs an identity client and a tenancy")
	}
	return entry, nil
}

// find returns the tenancy's subscription to entry, if any.
func (subscription Subscription) find(ctx context.Context, entry catalog.Entry) (*identity.RegionSubscription, error) {
	response, err := subscription.API.ListRegionSubscriptions(ctx,
		identity.ListRegionSubscriptionsRequest{TenancyId: &subscription.TenancyID})
	if err != nil {
		return nil, fmt.Errorf("list region subscriptions: %w", err)
	}
	for _, item := range response.Items {
		if item.RegionName != nil && *item.RegionName == entry.OCIRegion {
			return &item, nil
		}
	}
	return nil, nil
}

func (subscription Subscription) evidence(entry catalog.Entry, status identity.RegionSubscriptionStatusEnum) string {
	digest := sha256.Sum256([]byte("terrascale-region-subscription-v1\x00" + subscription.TenancyID + "\x00" +
		entry.OCIRegionKey + "\x00" + entry.OCIRegion + "\x00" + string(status)))
	return hex.EncodeToString(digest[:])
}

func (subscription Subscription) Observe(ctx context.Context, record regionlifecycle.Record,
	intent regionlifecycle.StepIntent,
) (regionlifecycle.Observation, error) {
	entry, err := subscription.region(record)
	if err != nil {
		return regionlifecycle.Observation{}, err
	}
	found, err := subscription.find(ctx, entry)
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
	observation.ResourceID = entry.OCIRegion
	observation.EvidenceDigest = subscription.evidence(entry, found.Status)
	return observation, nil
}

func (subscription Subscription) Execute(ctx context.Context, record regionlifecycle.Record,
	intent regionlifecycle.StepIntent,
) (regionlifecycle.StepResult, error) {
	entry, err := subscription.region(record)
	if err != nil {
		return regionlifecycle.StepResult{}, err
	}
	found, err := subscription.find(ctx, entry)
	if err != nil {
		return regionlifecycle.StepResult{}, err
	}
	if found == nil {
		token := intent.CreateKey
		response, err := subscription.API.CreateRegionSubscription(ctx, identity.CreateRegionSubscriptionRequest{
			TenancyId:                       &subscription.TenancyID,
			CreateRegionSubscriptionDetails: identity.CreateRegionSubscriptionDetails{RegionKey: &entry.OCIRegionKey},
			OpcRetryToken:                   &token,
		})
		if err != nil {
			return regionlifecycle.StepResult{}, fmt.Errorf("subscribe to region %s: %w", entry.OCIRegion, err)
		}
		found = &response.RegionSubscription
	}
	if found.Status != identity.RegionSubscriptionStatusReady {
		return regionlifecycle.StepResult{}, ErrSubscriptionInProgress
	}
	return regionlifecycle.StepResult{Step: intent.Step, CreateKey: intent.CreateKey, ResourceID: entry.OCIRegion,
		EvidenceDigest: subscription.evidence(entry, found.Status)}, nil
}
