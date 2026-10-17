package region

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// rootOperationLedgerPreparation describes observed protection only. It does
// not establish first namespace use or continuity of accepted-operation history.
type rootOperationLedgerPreparation struct {
	BucketID, RuleID string
	LockedAt         time.Time
	DurationSeconds  int64
}

func observeRootOperationLedgerPreparation(ctx context.Context, factory *ociclient.Factory, storage bootstrap.StorageDomain, compartment string) (rootOperationLedgerPreparation, error) {
	if ctx == nil || factory == nil || storage.Validate() != nil || !sourceCompartmentPattern.MatchString(compartment) ||
		!strings.HasPrefix(storage.LedgerKMSKeyOCID, "ocid1.key.oc1."+foundationHomeRegion+".") {
		return rootOperationLedgerPreparation{}, errors.New("root operation ledger observation requires exact home storage and compartment")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client, _, err := foundationHomeClient(factory)
	if err != nil {
		return rootOperationLedgerPreparation{}, err
	}
	readBucket := func() (string, error) {
		bucket, err := client.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{
			NamespaceName: new(storage.Namespace), BucketName: new(storage.LedgerBucket),
		})
		if err != nil || bucket.Id == nil || !validAuxiliaryID("ledger_bucket", *bucket.Id, foundationHomeRegion) ||
			deref(bucket.Namespace) != storage.Namespace || deref(bucket.Name) != storage.LedgerBucket ||
			deref(bucket.CompartmentId) != compartment || deref(bucket.KmsKeyId) != storage.LedgerKMSKeyOCID ||
			bucket.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess || bucket.Versioning != objectstorage.BucketVersioningDisabled {
			return "", errors.Join(errors.New("root operation ledger bucket differs from exact private encrypted home storage"), err, ctx.Err())
		}
		return *bucket.Id, nil
	}
	bucketID, err := readBucket()
	if err != nil {
		return rootOperationLedgerPreparation{}, err
	}
	request := objectstorage.ListRetentionRulesRequest{NamespaceName: new(storage.Namespace), BucketName: new(storage.LedgerBucket)}
	var selected objectstorage.RetentionRuleSummary
	count := 0
	pages := map[string]bool{}
	for {
		response, err := client.ListRetentionRules(ociclient.RequestContext(ctx), request)
		if err != nil {
			return rootOperationLedgerPreparation{}, err
		}
		for _, rule := range response.Items {
			count++
			if count > 1 || deref(rule.Id) == "" || deref(rule.DisplayName) != "ledger-retention" || deref(rule.Etag) == "" {
				return rootOperationLedgerPreparation{}, errors.New("root operation ledger requires one exact ledger-retention rule")
			}
			selected = rule
		}
		next := deref(response.OpcNextPage)
		if next == "" {
			break
		}
		if pages[next] {
			return rootOperationLedgerPreparation{}, errors.New("root operation ledger retention pagination repeated a page")
		}
		pages[next], request.Page = true, new(next)
	}
	if count != 1 {
		return rootOperationLedgerPreparation{}, errors.New("root operation ledger retention rule is absent")
	}
	rule, err := client.GetRetentionRule(ociclient.RequestContext(ctx), objectstorage.GetRetentionRuleRequest{
		NamespaceName: new(storage.Namespace), BucketName: new(storage.LedgerBucket), RetentionRuleId: selected.Id,
	})
	if err != nil || deref(rule.Id) != deref(selected.Id) || deref(rule.DisplayName) != "ledger-retention" ||
		deref(rule.Etag) != deref(selected.Etag) || deref(rule.RetentionRule.Etag) != deref(selected.Etag) ||
		rule.TimeRuleLocked == nil || rule.TimeRuleLocked.IsZero() || rule.TimeRuleLocked.After(time.Now()) ||
		rule.Duration == nil || rule.Duration.TimeAmount == nil || rule.Duration.TimeUnit != objectstorage.DurationTimeUnitDays ||
		*rule.Duration.TimeAmount <= 0 || *rule.Duration.TimeAmount > math.MaxInt64/86400 {
		return rootOperationLedgerPreparation{}, errors.Join(errors.New("root operation ledger requires an effective locked finite day retention rule"), err, ctx.Err())
	}
	seconds := *rule.Duration.TimeAmount * 86400
	if seconds < int64((31*time.Minute)/time.Second) {
		return rootOperationLedgerPreparation{}, errors.New("root operation ledger retention does not cover node freshness and execution")
	}
	currentBucketID, err := readBucket()
	if err != nil || currentBucketID != bucketID {
		return rootOperationLedgerPreparation{}, errors.Join(errors.New("root operation ledger bucket changed during retention observation"), err, ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return rootOperationLedgerPreparation{}, err
	}
	return rootOperationLedgerPreparation{BucketID: bucketID, RuleID: *rule.Id,
		LockedAt: rule.TimeRuleLocked.Time.UTC(), DurationSeconds: seconds}, nil
}
