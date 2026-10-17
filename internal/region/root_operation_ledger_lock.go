package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// rootOperationLedgerLockRequest describes exact SDK bytes, never authority.
func rootOperationLedgerLockRequest(purpose RootOperationLedgerLockPrelude) (objectstorage.UpdateRetentionRuleRequest, string, error) {
	if purpose.Storage.Validate() != nil || purpose.RuleID == "" || purpose.OriginalETag == "" ||
		strings.ContainsAny(purpose.OriginalETag, "\r\n") || purpose.DurationDays < 1 || purpose.DurationDays > math.MaxInt64/86400 ||
		purpose.LockedAt.IsZero() || purpose.LockedAt.Location() != time.UTC {
		return objectstorage.UpdateRetentionRuleRequest{}, "", errors.New("ledger lock request requires an exact finite existing target")
	}
	noRetry := common.NoRetryPolicy()
	request := objectstorage.UpdateRetentionRuleRequest{
		NamespaceName: new(purpose.Storage.Namespace), BucketName: new(purpose.Storage.LedgerBucket), RetentionRuleId: new(purpose.RuleID),
		DisplayName: new("ledger-retention"), Duration: &objectstorage.Duration{TimeAmount: new(purpose.DurationDays), TimeUnit: objectstorage.DurationTimeUnitDays},
		TimeRuleLocked: &common.SDKTime{Time: purpose.LockedAt}, IfMatch: new(purpose.OriginalETag),
		RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry},
	}
	httpRequest, err := request.HTTPRequest(http.MethodPut, "/n/{namespaceName}/b/{bucketName}/retentionRules/{retentionRuleId}", nil, nil)
	if err != nil {
		return objectstorage.UpdateRetentionRuleRequest{}, "", err
	}
	if httpRequest.Body == nil {
		return objectstorage.UpdateRetentionRuleRequest{}, "", errors.New("ledger lock SDK request has no body")
	}
	defer httpRequest.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpRequest.Body, foundationRecordLimit+1))
	if err != nil || len(body) > foundationRecordLimit {
		return objectstorage.UpdateRetentionRuleRequest{}, "", errors.Join(errors.New("ledger lock SDK request exceeds its bound"), err)
	}
	// Preserve the SDK body bytes as a string; include the actual escaped path
	// and precondition rather than hashing only the signed payload fields.
	wire, err := json.Marshal(struct {
		Region, Method, RequestURI, IfMatch, Body string
	}{foundationHomeRegion, httpRequest.Method, httpRequest.URL.RequestURI(), httpRequest.Header.Get("If-Match"), string(body)}, json.Deterministic(true))
	if err != nil {
		return objectstorage.UpdateRetentionRuleRequest{}, "", err
	}
	return request, digestSource(wire), nil
}

// applyRootOperationLedgerLockPrelude converges only the signed existing rule.
// Its descriptive result may be scheduled; strict preparation still requires
// the real lock to be effective and establishes no acceptance-history proof.
func applyRootOperationLedgerLockPrelude(ctx context.Context, factory *ociclient.Factory, operation verifiedRootOperationLedgerLockPrelude) (rootOperationLedgerPreparation, error) {
	if ctx == nil || factory == nil {
		return rootOperationLedgerPreparation{}, errors.New("ledger lock prelude requires its original call and authenticated operator")
	}
	purpose := operation.purpose
	guard := func(ctx context.Context) error {
		if err := operation.guard(ctx); err != nil {
			return err
		}
		operator, operatorErr := factory.Provider().UserOCID()
		tenancy, tenancyErr := factory.Provider().TenancyOCID()
		if operatorErr != nil || tenancyErr != nil || operator != purpose.OperatorID || tenancy != purpose.TenancyID {
			return errors.Join(errors.New("ledger lock operator differs from the signed exact principal and tenancy"), operatorErr, tenancyErr)
		}
		return operation.guard(ctx)
	}
	if err := guard(ctx); err != nil {
		return rootOperationLedgerPreparation{}, err
	}
	request, digest, err := rootOperationLedgerLockRequest(purpose)
	if err != nil || digest != purpose.RequestSHA256 {
		return rootOperationLedgerPreparation{}, errors.Join(errors.New("ledger lock differs from its signed exact SDK request"), err)
	}
	deadline := operation.expires
	if purpose.DispatchDeadline.Before(deadline) {
		deadline = purpose.DispatchDeadline
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	ctx = ociclient.WithRequestGuard(ociclient.WithAuthority(ctx, guard), guard)
	client, _, err := foundationHomeClient(factory)
	if err != nil {
		return rootOperationLedgerPreparation{}, err
	}
	readRule := func() (rootOperationLedgerLockOriginal, error) {
		observed, err := observeRootOperationLedgerLockPrelude(ctx, factory, purpose.Storage, purpose.CompartmentID)
		if err != nil || observed.BucketID != purpose.BucketID || observed.RuleID != purpose.RuleID {
			return rootOperationLedgerLockOriginal{}, errors.Join(errors.New("ledger lock differs from its exact signed physical target"), err)
		}
		return observed, nil
	}
	matches := func(rule rootOperationLedgerLockOriginal, days int64, lockedAt time.Time) bool {
		return rule.DurationDays == days && rule.LockedAt.Equal(lockedAt)
	}
	describe := func() (rootOperationLedgerPreparation, error) {
		if err := guard(ctx); err != nil {
			return rootOperationLedgerPreparation{}, err
		}
		return rootOperationLedgerPreparation{BucketID: purpose.BucketID, RuleID: purpose.RuleID,
			LockedAt: purpose.LockedAt, DurationSeconds: purpose.DurationDays * 86400}, nil
	}
	rule, err := readRule()
	if err != nil {
		return rootOperationLedgerPreparation{}, err
	}
	if matches(rule, purpose.DurationDays, purpose.LockedAt) {
		// Repeating TimeRuleLocked after the rule locks is prohibited by OCI.
		return describe()
	}
	if rule.ETag != purpose.OriginalETag || !matches(rule, purpose.OriginalDurationDays, purpose.OriginalLockedAt) {
		return rootOperationLedgerPreparation{}, errors.New("ledger rule differs from both the signed original and desired state")
	}
	if err := guard(ctx); err != nil {
		return rootOperationLedgerPreparation{}, err
	}
	response, updateErr := client.UpdateRetentionRule(ociclient.RequestContext(ctx), request)
	if updateErr == nil && (deref(response.Id) != purpose.RuleID || deref(response.DisplayName) != "ledger-retention" ||
		response.Duration == nil || response.Duration.TimeAmount == nil || *response.Duration.TimeAmount != purpose.DurationDays ||
		response.Duration.TimeUnit != objectstorage.DurationTimeUnitDays || response.TimeRuleLocked == nil ||
		!response.TimeRuleLocked.Equal(purpose.LockedAt) || deref(response.Etag) == "" || deref(response.RetentionRule.Etag) != deref(response.Etag)) {
		return rootOperationLedgerPreparation{}, errors.New("ledger lock update response differs from its exact signed request")
	}
	if err := guard(ctx); err != nil {
		return rootOperationLedgerPreparation{}, errors.Join(err, updateErr)
	}
	observed, err := readRule()
	if err != nil || !matches(observed, purpose.DurationDays, purpose.LockedAt) {
		return rootOperationLedgerPreparation{}, errors.Join(errors.New("signed ledger lock state was not observed exactly; refusing another update"), err, updateErr)
	}
	// An unknown write followed by this read proves desired state only.
	return describe()
}

// rootOperationLedgerLockOriginal is a plain storage observation, not permission.
type rootOperationLedgerLockOriginal struct {
	BucketID, RuleID, ETag string
	DurationDays           int64
	LockedAt               time.Time
}

func observeRootOperationLedgerLockPrelude(ctx context.Context, factory *ociclient.Factory, storage bootstrap.StorageDomain, compartment string) (rootOperationLedgerLockOriginal, error) {
	if ctx == nil || factory == nil || storage.Validate() != nil || !sourceCompartmentPattern.MatchString(compartment) ||
		!strings.HasPrefix(storage.LedgerKMSKeyOCID, "ocid1.key.oc1."+foundationHomeRegion+".") {
		return rootOperationLedgerLockOriginal{}, errors.New("ledger lock observation requires exact home storage and compartment")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client, _, err := foundationHomeClient(factory)
	if err != nil {
		return rootOperationLedgerLockOriginal{}, err
	}
	readBucket := func() (string, error) {
		bucket, err := client.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{
			NamespaceName: new(storage.Namespace), BucketName: new(storage.LedgerBucket),
		})
		if err != nil || !validAuxiliaryID("ledger_bucket", deref(bucket.Id), foundationHomeRegion) ||
			deref(bucket.Namespace) != storage.Namespace || deref(bucket.Name) != storage.LedgerBucket ||
			deref(bucket.CompartmentId) != compartment || deref(bucket.KmsKeyId) != storage.LedgerKMSKeyOCID ||
			bucket.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess || bucket.Versioning != objectstorage.BucketVersioningDisabled {
			return "", errors.Join(errors.New("ledger lock bucket differs from exact private encrypted home storage"), err, ctx.Err())
		}
		return *bucket.Id, nil
	}
	bucketID, err := readBucket()
	if err != nil {
		return rootOperationLedgerLockOriginal{}, err
	}
	list := objectstorage.ListRetentionRulesRequest{NamespaceName: new(storage.Namespace), BucketName: new(storage.LedgerBucket)}
	var selected objectstorage.RetentionRuleSummary
	count, pages := 0, map[string]bool{}
	for {
		response, err := client.ListRetentionRules(ociclient.RequestContext(ctx), list)
		if err != nil {
			return rootOperationLedgerLockOriginal{}, err
		}
		for _, rule := range response.Items {
			count++
			if count > 1 || deref(rule.Id) == "" || deref(rule.DisplayName) != "ledger-retention" || deref(rule.Etag) == "" {
				return rootOperationLedgerLockOriginal{}, errors.New("ledger lock observation requires one exact ledger-retention rule")
			}
			selected = rule
		}
		next := deref(response.OpcNextPage)
		if next == "" {
			break
		}
		if pages[next] {
			return rootOperationLedgerLockOriginal{}, errors.New("ledger lock retention pagination repeated a page")
		}
		pages[next], list.Page = true, new(next)
	}
	if count != 1 {
		return rootOperationLedgerLockOriginal{}, errors.New("ledger retention rule is absent; refusing creation or adoption")
	}
	response, err := client.GetRetentionRule(ociclient.RequestContext(ctx), objectstorage.GetRetentionRuleRequest{
		NamespaceName: list.NamespaceName, BucketName: list.BucketName, RetentionRuleId: selected.Id,
	})
	if err != nil || deref(response.Id) != deref(selected.Id) || deref(response.DisplayName) != "ledger-retention" ||
		deref(response.Etag) != deref(selected.Etag) || deref(response.RetentionRule.Etag) != deref(selected.Etag) ||
		response.Duration == nil || response.Duration.TimeAmount == nil || *response.Duration.TimeAmount != rootOperationLedgerRetentionDays ||
		response.Duration.TimeUnit != objectstorage.DurationTimeUnitDays || response.TimeRuleLocked != nil && response.TimeRuleLocked.IsZero() {
		return rootOperationLedgerLockOriginal{}, errors.Join(errors.New("ledger lock requires consistent exact SDK readback of finite 35 day retention"), err, ctx.Err())
	}
	currentBucketID, err := readBucket()
	if err != nil || currentBucketID != bucketID {
		return rootOperationLedgerLockOriginal{}, errors.Join(errors.New("ledger lock bucket changed during retention observation"), err, ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return rootOperationLedgerLockOriginal{}, err
	}
	lockedAt := time.Time{}
	if response.TimeRuleLocked != nil {
		lockedAt = response.TimeRuleLocked.Time.UTC()
	}
	return rootOperationLedgerLockOriginal{BucketID: bucketID, RuleID: *response.Id, ETag: *response.Etag,
		DurationDays: *response.Duration.TimeAmount, LockedAt: lockedAt}, nil
}
