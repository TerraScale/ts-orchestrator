package bucket

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

const maxPages = 8

type sdkAPI struct {
	objects objectstorage.ObjectStorageClient
}

// NewSDKAPI builds the bucket API on the shared rate-limited factory.
func NewSDKAPI(factory *ociclient.Factory) (API, error) { return newSDKAPI(factory, "") }

// newSDKAPI pins the client to endpoint when set; only tests pass one.
func newSDKAPI(factory *ociclient.Factory, endpoint string) (API, error) {
	objects, err := factory.ObjectStorage()
	if err != nil {
		return nil, err
	}
	ociclient.PinHost(&objects.BaseClient, endpoint)
	return sdkAPI{objects: objects}, nil
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func notFound(err error) bool {
	serviceErr, ok := common.IsServiceError(err)
	return ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound
}

func (a sdkAPI) GetBucket(ctx context.Context, namespace, bucket string) (Bucket, error) {
	response, err := a.objects.GetBucket(ctx, objectstorage.GetBucketRequest{NamespaceName: new(namespace), BucketName: new(bucket)})
	if err != nil {
		if notFound(err) {
			return Bucket{}, fmt.Errorf("get OCI bucket: %w: %w", ociresource.ErrGone, err)
		}
		return Bucket{}, fmt.Errorf("get OCI bucket: %w", err)
	}
	etag := deref(response.ETag)
	if etag == "" {
		etag = deref(response.Etag)
	}
	return Bucket{Namespace: deref(response.Namespace), Name: deref(response.Name), ETag: etag,
		Versioning: string(response.Versioning),
		Tags:       ociresource.Tags{Freeform: response.FreeformTags, Defined: response.DefinedTags}}, nil
}

func (a sdkAPI) ListRetentionRules(ctx context.Context, namespace, bucket string) ([]Rule, error) {
	var rules []Rule
	var page *string
	for range maxPages {
		response, err := a.objects.ListRetentionRules(ctx, objectstorage.ListRetentionRulesRequest{
			NamespaceName: new(namespace), BucketName: new(bucket), Page: page})
		if err != nil {
			return nil, fmt.Errorf("list OCI retention rules: %w", err)
		}
		for _, item := range response.Items {
			rule := Rule{ID: deref(item.Id), DisplayName: deref(item.DisplayName), ETag: deref(item.Etag),
				Locked: item.TimeRuleLocked != nil}
			if item.Duration != nil && item.Duration.TimeAmount != nil {
				rule.Amount, rule.Unit = *item.Duration.TimeAmount, string(item.Duration.TimeUnit)
			}
			rules = append(rules, rule)
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return rules, nil
		}
		page = response.OpcNextPage
	}
	return nil, errors.New("OCI retention rule list exceeds its page bound")
}

func (a sdkAPI) UpdateBucket(ctx context.Context, namespace, bucket, etag, versioning string, tags ociresource.Tags) error {
	if etag == "" {
		return errors.New("update OCI bucket requires an ETag")
	}
	details := objectstorage.UpdateBucketDetails{FreeformTags: maps.Clone(tags.Freeform), DefinedTags: tags.Defined,
		Versioning: objectstorage.UpdateBucketDetailsVersioningEnum(versioning)}
	if _, err := a.objects.UpdateBucket(ctx, objectstorage.UpdateBucketRequest{NamespaceName: new(namespace),
		BucketName: new(bucket), IfMatch: new(etag), UpdateBucketDetails: details}); err != nil {
		return fmt.Errorf("update OCI bucket: %w", err)
	}
	return nil
}

func duration(amount int64, unit string) *objectstorage.Duration {
	return &objectstorage.Duration{TimeAmount: new(amount), TimeUnit: objectstorage.DurationTimeUnitEnum(unit)}
}

func (a sdkAPI) CreateRetentionRule(ctx context.Context, namespace, bucket, displayName string, amount int64, unit string) error {
	// TimeRuleLocked stays unset: the reconciler never locks a rule.
	if _, err := a.objects.CreateRetentionRule(ctx, objectstorage.CreateRetentionRuleRequest{NamespaceName: new(namespace),
		BucketName: new(bucket), CreateRetentionRuleDetails: objectstorage.CreateRetentionRuleDetails{
			DisplayName: new(displayName), Duration: duration(amount, unit)}}); err != nil {
		return fmt.Errorf("create OCI retention rule: %w", err)
	}
	return nil
}

func (a sdkAPI) UpdateRetentionRule(ctx context.Context, namespace, bucket, id, etag string, amount int64, unit string) error {
	request := objectstorage.UpdateRetentionRuleRequest{NamespaceName: new(namespace), BucketName: new(bucket),
		RetentionRuleId: new(id), UpdateRetentionRuleDetails: objectstorage.UpdateRetentionRuleDetails{Duration: duration(amount, unit)}}
	if etag != "" {
		request.IfMatch = new(etag)
	}
	if _, err := a.objects.UpdateRetentionRule(ctx, request); err != nil {
		return fmt.Errorf("update OCI retention rule: %w", err)
	}
	return nil
}

func (a sdkAPI) DeleteRetentionRule(ctx context.Context, namespace, bucket, id, etag string) error {
	request := objectstorage.DeleteRetentionRuleRequest{NamespaceName: new(namespace), BucketName: new(bucket),
		RetentionRuleId: new(id)}
	if etag != "" {
		request.IfMatch = new(etag)
	}
	_, err := a.objects.DeleteRetentionRule(ctx, request)
	if err != nil && !notFound(err) {
		return fmt.Errorf("delete OCI retention rule: %w", err)
	}
	return nil
}
