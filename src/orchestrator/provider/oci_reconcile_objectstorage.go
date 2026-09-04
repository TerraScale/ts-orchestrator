package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// The object storage reconciler creates and repairs each Region's buckets
// and their lifecycle policies (D-29): Litestream segments older than 24 h
// move to Infrequent Access and older than 7 days to Archive. Buckets are
// per Region; D-04 keeps every durable copy inside OCI.

// Lifecycle action vocabulary. OCI's wire enum is upper-case; the estate
// declares lower-case actions.
const (
	LifecycleActionInfrequentAccess = "infrequent-access"
	LifecycleActionArchive          = "archive"
	LifecycleActionDelete           = "delete"
)

func lifecycleWireAction(action string) (string, bool) {
	switch action {
	case LifecycleActionInfrequentAccess:
		return "INFREQUENT_ACCESS", true
	case LifecycleActionArchive:
		return "ARCHIVE", true
	case LifecycleActionDelete:
		return "DELETE", true
	default:
		return "", false
	}
}

type LifecycleRuleSpec struct {
	Name      string
	Prefix    string
	Action    string
	AfterDays uint16
}

type ObservedLifecycleRule struct {
	Name      string
	Prefix    string
	Action    string
	AfterDays uint16
}

type ObservedBucket struct {
	Name             string
	Versioning       bool
	LifecycleRules   []ObservedLifecycleRule
	LifecyclePresent bool
}

type ObjectStorageObserved struct {
	Namespace string
	Buckets   []ObservedBucket
}

// ObjectStorageGateway is the OCI object-storage seam for bucket
// reconciliation. The namespace is discovered, never configured.
type ObjectStorageGateway interface {
	GetNamespace(ctx context.Context) (string, error)
	ListBuckets(ctx context.Context, namespace string) ([]ObservedBucket, error)
	CreateBucket(ctx context.Context, namespace, name string, versioning bool) error
	SetVersioning(ctx context.Context, namespace, bucket string, enabled bool) error
	SetLifecycleRules(ctx context.Context, namespace, bucket string, rules []LifecycleRuleSpec) error
}

type CreateBucketAction struct {
	Name       string
	Versioning bool
}

func (a CreateBucketAction) Kind() OCIActionKind { return OCIActionCreateBucket }
func (a CreateBucketAction) Summary() string     { return "create bucket " + a.Name }

type SetBucketVersioningAction struct {
	Name    string
	Enabled bool
}

func (a SetBucketVersioningAction) Kind() OCIActionKind { return OCIActionSetBucketVersioning }
func (a SetBucketVersioningAction) Summary() string {
	return "set versioning " + strconv.FormatBool(a.Enabled) + " on bucket " + a.Name
}

type SetBucketLifecycleAction struct {
	Name  string
	Rules []LifecycleRuleSpec
}

func (a SetBucketLifecycleAction) Kind() OCIActionKind { return OCIActionSetBucketLifecycle }
func (a SetBucketLifecycleAction) Summary() string {
	return "apply " + strconv.Itoa(len(a.Rules)) + " lifecycle rules to bucket " + a.Name
}

// ObjectStorageReconciler converges one Region's buckets toward the
// declaration.
type ObjectStorageReconciler struct {
	Object ObjectStorageGateway
}

var _ OCIReconciler[estate.Region, ObjectStorageObserved] = (*ObjectStorageReconciler)(nil)

func (r *ObjectStorageReconciler) Observe(ctx context.Context, declared estate.Region) (ObjectStorageObserved, error) {
	if r == nil || r.Object == nil {
		return ObjectStorageObserved{}, &InvalidOperationError{Message: "object storage reconciler is unavailable"}
	}
	if ctx == nil {
		return ObjectStorageObserved{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return ObjectStorageObserved{}, err
	}
	namespace, err := r.Object.GetNamespace(ctx)
	if err != nil {
		return ObjectStorageObserved{}, err
	}
	buckets, err := r.Object.ListBuckets(ctx, namespace)
	if err != nil {
		return ObjectStorageObserved{}, err
	}
	return ObjectStorageObserved{Namespace: namespace, Buckets: buckets}, nil
}

// LifecycleRuleSpecs converts the estate's declared rules into provider
// specs. KeepLatest is validated but has no OCI lifecycle-policy equivalent:
// noncurrent-version pruning rides the same DELETE rules the engine runs.
func LifecycleRuleSpecs(bucket estate.Bucket) ([]LifecycleRuleSpec, error) {
	specs := make([]LifecycleRuleSpec, 0, len(bucket.LifecycleRules))
	for _, rule := range bucket.LifecycleRules {
		if _, known := lifecycleWireAction(rule.Action); !known {
			return nil, &errs.Argument{Message: "declared lifecycle action is unsupported"}
		}
		if rule.AfterDays == 0 {
			return nil, &errs.Argument{Message: "declared lifecycle rule has no age"}
		}
		specs = append(specs, LifecycleRuleSpec{Name: rule.Name, Prefix: rule.Prefix, Action: rule.Action, AfterDays: rule.AfterDays})
	}
	return specs, nil
}

func (r *ObjectStorageReconciler) Reconcile(ctx context.Context, declared estate.Region, observed ObjectStorageObserved) (OCIPlan, error) {
	if ctx == nil {
		return OCIPlan{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return OCIPlan{}, err
	}
	byName := make(map[string]ObservedBucket, len(observed.Buckets))
	for _, bucket := range observed.Buckets {
		byName[bucket.Name] = bucket
	}
	plan := OCIPlan{}
	for _, declaredBucket := range declared.Buckets {
		observedBucket, exists := byName[declaredBucket.Name]
		if !exists {
			plan.Actions = append(plan.Actions, CreateBucketAction{Name: declaredBucket.Name, Versioning: declaredBucket.Versioning})
			continue
		}
		if observedBucket.Versioning != declaredBucket.Versioning {
			plan.Actions = append(plan.Actions, SetBucketVersioningAction{Name: declaredBucket.Name, Enabled: declaredBucket.Versioning})
		}
		specs, err := LifecycleRuleSpecs(declaredBucket)
		if err != nil {
			return OCIPlan{}, err
		}
		if !lifecycleMatches(specs, observedBucket) {
			plan.Actions = append(plan.Actions, SetBucketLifecycleAction{Name: declaredBucket.Name, Rules: specs})
		}
	}
	return plan, nil
}

// lifecycleMatches reports whether the observed policy already equals the
// declared rules, ignoring rule order.
func lifecycleMatches(declared []LifecycleRuleSpec, observed ObservedBucket) bool {
	if len(observed.LifecycleRules) != len(declared) {
		return false
	}
	remaining := append([]ObservedLifecycleRule(nil), observed.LifecycleRules...)
	for _, rule := range declared {
		found := -1
		for i, candidate := range remaining {
			if candidate.Name == rule.Name && candidate.Prefix == rule.Prefix && candidate.Action == rule.Action && candidate.AfterDays == rule.AfterDays {
				found = i
				break
			}
		}
		if found < 0 {
			return false
		}
		remaining = append(remaining[:found], remaining[found+1:]...)
	}
	return true
}

func (r *ObjectStorageReconciler) Apply(ctx context.Context, declared estate.Region, observed ObjectStorageObserved, plan OCIPlan) error {
	if r == nil || r.Object == nil {
		return &InvalidOperationError{Message: "object storage reconciler is unavailable"}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, action := range plan.Actions {
		switch a := action.(type) {
		case CreateBucketAction:
			if err := r.Object.CreateBucket(ctx, observed.Namespace, a.Name, a.Versioning); err != nil {
				return err
			}
		case SetBucketVersioningAction:
			if err := r.Object.SetVersioning(ctx, observed.Namespace, a.Name, a.Enabled); err != nil {
				return err
			}
		case SetBucketLifecycleAction:
			if err := r.Object.SetLifecycleRules(ctx, observed.Namespace, a.Name, a.Rules); err != nil {
				return err
			}
		default:
			return &InvalidOperationError{Message: "object storage reconciler received a foreign action"}
		}
	}
	return nil
}

// OCIObjectStorageGateway is the real object-storage gateway over the signed
// transport. Lifecycle GETs use the raw transport because a missing policy
// is an ordinary 404, not an error.
type OCIObjectStorageGateway struct {
	Object         *OCIHTTPTransport
	CompartmentID  string
	MaxBucketsList int
}

var _ ObjectStorageGateway = (*OCIObjectStorageGateway)(nil)

// NewOCIObjectStorageGateway validates the transport and compartment scope.
func NewOCIObjectStorageGateway(object *OCIHTTPTransport, compartmentID string) (*OCIObjectStorageGateway, error) {
	if object == nil || object.Config.Service != OCIServiceObjectStorage {
		return nil, &errs.Argument{Message: "object storage gateway requires the object-storage transport"}
	}
	if !isOCID(compartmentID, "compartment") {
		return nil, &errs.Argument{Message: "object storage gateway requires a compartment identity"}
	}
	return &OCIObjectStorageGateway{Object: object, CompartmentID: compartmentID, MaxBucketsList: 128}, nil
}

func (g *OCIObjectStorageGateway) GetNamespace(ctx context.Context) (string, error) {
	var namespace string
	if err := doOCIJSON(ctx, g.Object, http.MethodGet, "/n", nil, nil, &namespace); err != nil {
		return "", err
	}
	if len(namespace) < 1 || len(namespace) > 128 || !validObjectPart(namespace, 128, false) {
		return "", &InvalidDataError{Message: "OCI object storage namespace response is invalid"}
	}
	return namespace, nil
}

type ociBucketDocument struct {
	Name       string `json:"name"`
	Versioning string `json:"versioning"`
}

func (g *OCIObjectStorageGateway) ListBuckets(ctx context.Context, namespace string) ([]ObservedBucket, error) {
	if !validObjectPart(namespace, 128, false) {
		return nil, &errs.Argument{Message: "object storage namespace is invalid"}
	}
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	query.Set("limit", strconv.Itoa(g.MaxBucketsList))
	var list struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Object, http.MethodGet, "/n/"+url.PathEscape(namespace)+"/b/?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	if len(list.Items) > g.MaxBucketsList {
		return nil, &InvalidDataError{Message: "OCI bucket list exceeds the reconciliation bound"}
	}
	buckets := make([]ObservedBucket, 0, len(list.Items))
	for _, item := range list.Items {
		if !validObjectPart(item.Name, 256, false) {
			return nil, &InvalidDataError{Message: "OCI bucket response is invalid"}
		}
		observed := ObservedBucket{Name: item.Name}
		var document ociBucketDocument
		if err := doOCIJSON(ctx, g.Object, http.MethodGet, "/n/"+url.PathEscape(namespace)+"/b/"+url.PathEscape(item.Name), nil, nil, &document); err != nil {
			return nil, err
		}
		observed.Versioning = document.Versioning == "Enabled"
		rules, err := g.getLifecycleRules(ctx, namespace, item.Name)
		if err != nil {
			return nil, err
		}
		observed.LifecycleRules = rules
		observed.LifecyclePresent = rules != nil
		buckets = append(buckets, observed)
	}
	return buckets, nil
}

type ociLifecycleFilter struct {
	InclusionPrefixes []string `json:"inclusionPrefixes,omitempty"`
}

type ociLifecycleItem struct {
	Name             string              `json:"name"`
	Action           string              `json:"action"`
	TimeAmount       uint16              `json:"timeAmount"`
	TimeUnit         string              `json:"timeUnit"`
	IsEnabled        bool                `json:"isEnabled"`
	ObjectNameFilter *ociLifecycleFilter `json:"objectNameFilter,omitempty"`
}

type ociLifecyclePolicy struct {
	Items []ociLifecycleItem `json:"items"`
}

func observedLifecycleRule(item ociLifecycleItem) (ObservedLifecycleRule, bool) {
	action := ""
	switch item.Action {
	case "INFREQUENT_ACCESS":
		action = LifecycleActionInfrequentAccess
	case "ARCHIVE":
		action = LifecycleActionArchive
	case "DELETE":
		action = LifecycleActionDelete
	default:
		return ObservedLifecycleRule{}, false
	}
	prefix := ""
	var prefixes []string
	if item.ObjectNameFilter != nil {
		prefixes = item.ObjectNameFilter.InclusionPrefixes
	}
	if len(prefixes) == 1 {
		prefix = prefixes[0]
	} else if len(prefixes) > 1 {
		return ObservedLifecycleRule{}, false
	}
	return ObservedLifecycleRule{Name: item.Name, Prefix: prefix, Action: action, AfterDays: item.TimeAmount}, true
}

func (g *OCIObjectStorageGateway) getLifecycleRules(ctx context.Context, namespace, bucket string) ([]ObservedLifecycleRule, error) {
	resp, err := g.Object.Do(ctx, http.MethodGet, "/n/"+url.PathEscape(namespace)+"/b/"+url.PathEscape(bucket)+"/lifecyclePolicy", nil)
	if err != nil {
		return nil, err
	}
	body, err := ReadBoundedBody(resp, g.Object.Config.MaxBodyBytes)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &InvalidDataError{Message: "OCI lifecycle policy request was rejected"}
	}
	var policy ociLifecyclePolicy
	if len(body) == 0 {
		return nil, nil
	}
	if json.Unmarshal(body, &policy) != nil || len(policy.Items) > 64 {
		return nil, &InvalidDataError{Message: "OCI lifecycle policy response is invalid"}
	}
	rules := make([]ObservedLifecycleRule, 0, len(policy.Items))
	for _, item := range policy.Items {
		rule, ok := observedLifecycleRule(item)
		if !ok {
			return nil, &InvalidDataError{Message: "OCI lifecycle policy response is invalid"}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (g *OCIObjectStorageGateway) CreateBucket(ctx context.Context, namespace, name string, versioning bool) error {
	if !validObjectPart(namespace, 128, false) || !validObjectPart(name, 256, false) {
		return &errs.Argument{Message: "bucket create request is invalid"}
	}
	payload := struct {
		Name          string `json:"name"`
		CompartmentID string `json:"compartmentId"`
		Versioning    string `json:"versioning,omitempty"`
	}{Name: name, CompartmentID: g.CompartmentID}
	if versioning {
		payload.Versioning = "Enabled"
	}
	return doOCIJSON[struct{}](ctx, g.Object, http.MethodPost, "/n/"+url.PathEscape(namespace)+"/b/", payload, nil, nil)
}

func (g *OCIObjectStorageGateway) SetVersioning(ctx context.Context, namespace, bucket string, enabled bool) error {
	if !validObjectPart(namespace, 128, false) || !validObjectPart(bucket, 256, false) {
		return &errs.Argument{Message: "bucket versioning request is invalid"}
	}
	value := "Suspended"
	if enabled {
		value = "Enabled"
	}
	return doOCIJSON[struct{}](ctx, g.Object, http.MethodPut, "/n/"+url.PathEscape(namespace)+"/b/"+url.PathEscape(bucket), struct {
		Versioning string `json:"versioning"`
	}{Versioning: value}, nil, nil)
}

func (g *OCIObjectStorageGateway) SetLifecycleRules(ctx context.Context, namespace, bucket string, rules []LifecycleRuleSpec) error {
	if !validObjectPart(namespace, 128, false) || !validObjectPart(bucket, 256, false) {
		return &errs.Argument{Message: "bucket lifecycle request is invalid"}
	}
	items := make([]ociLifecycleItem, 0, len(rules))
	for _, rule := range rules {
		action, known := lifecycleWireAction(rule.Action)
		if !known || rule.AfterDays == 0 || !validObjectPart(rule.Name, 256, false) {
			return &errs.Argument{Message: "bucket lifecycle request is invalid"}
		}
		item := ociLifecycleItem{Name: rule.Name, Action: action, TimeAmount: rule.AfterDays, TimeUnit: "DAYS", IsEnabled: true}
		if rule.Prefix != "" {
			item.ObjectNameFilter = &ociLifecycleFilter{InclusionPrefixes: []string{rule.Prefix}}
		}
		items = append(items, item)
	}
	return doOCIJSON[struct{}](ctx, g.Object, http.MethodPut, "/n/"+url.PathEscape(namespace)+"/b/"+url.PathEscape(bucket)+"/lifecyclePolicy", ociLifecyclePolicy{Items: items}, nil, nil)
}
