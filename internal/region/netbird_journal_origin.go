package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// netBirdJournalOriginalGrant is descriptive signed-source evidence only;
// regional callers still join genuine protected launches and native readbacks.
type netBirdJournalOriginalGrant struct {
	reference bootstrap.NetBirdJournalOriginReference
	purpose   bootstrap.NetBirdJournalPurpose
}

func (origin netBirdJournalOriginalGrant) Reference() bootstrap.NetBirdJournalOriginReference {
	return origin.reference
}
func (origin netBirdJournalOriginalGrant) Purpose() bootstrap.NetBirdJournalPurpose {
	return origin.purpose.Clone()
}
func (origin netBirdJournalOriginalGrant) GrantDigest() string { return origin.reference.GrantSHA256 }

func netBirdJournalOrigin(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, reference bootstrap.NetBirdJournalOriginReference, startedAt time.Time) (netBirdJournalOriginalGrant, error) {
	var zero netBirdJournalOriginalGrant
	documents, err := bootstrap.ReadNetBirdJournalOrigin(ctx, factory, genesis, reference, startedAt)
	if err != nil {
		return zero, err
	}
	envelope, err := trust.DecodeEnvelope(documents.GrantWire)
	if err != nil {
		return zero, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return zero, err
	}
	if err := validateNetBirdJournalPurposeAt(grant, envelope.ExpiresAt, startedAt); err != nil {
		return zero, err
	}
	for _, regional := range grant.Regions {
		if regional.NetBirdManager == nil {
			continue
		}
		purpose := regional.NetBirdManager.JournalPurpose
		if purpose.Storage.Namespace != reference.Namespace || purpose.Storage.HeadBucket != foundationDiscoveryBucket ||
			reference.GrantObject != strings.TrimSuffix(purpose.Storage.Prefix, "/")+"/"+foundationGrantObject ||
			envelope.Scope.DeploymentID != purpose.DeploymentID || envelope.Scope.Slot != purpose.ClusterID {
			return zero, errors.New("NetBird journal original archive differs from its signed source and storage domain")
		}
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		return netBirdJournalOriginalGrant{reference: reference, purpose: purpose.Clone()}, nil
	}
	return zero, errors.New("NetBird journal original grant has no signed journal purpose")
}
