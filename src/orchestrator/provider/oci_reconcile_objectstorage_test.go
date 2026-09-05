package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func testObjectRegion() estate.Region {
	region := testNetworkRegion()
	region.Buckets = []estate.Bucket{
		{
			Name:       "terrascale-backups-gru",
			Purpose:    "database-backup",
			Versioning: true,
			LifecycleRules: []estate.BucketLifecycleRule{
				{Name: "segments-24h-infrequent", Action: "infrequent-access", AfterDays: 1},
				{Name: "segments-7d-archive", Action: "archive", AfterDays: 7},
			},
		},
	}
	return region
}

// fakeObjectGateway models buckets, versioning, and lifecycle policies.
type fakeObjectGateway struct {
	namespace  string
	buckets    map[string]ObservedBucket
	creates    []string
	versioned  []string
	lifecycles []string
}

func (f *fakeObjectGateway) GetNamespace(ctx context.Context) (string, error) {
	return f.namespace, nil
}

func (f *fakeObjectGateway) ListBuckets(ctx context.Context, namespace string) ([]ObservedBucket, error) {
	buckets := make([]ObservedBucket, 0, len(f.buckets))
	for _, bucket := range f.buckets {
		buckets = append(buckets, bucket)
	}
	return buckets, nil
}

func (f *fakeObjectGateway) CreateBucket(ctx context.Context, namespace, name string, versioning bool) error {
	f.creates = append(f.creates, name)
	f.buckets[name] = ObservedBucket{Name: name, Versioning: versioning, LifecycleRules: nil}
	return nil
}

func (f *fakeObjectGateway) SetVersioning(ctx context.Context, namespace, bucket string, enabled bool) error {
	f.versioned = append(f.versioned, bucket)
	updated := f.buckets[bucket]
	updated.Versioning = enabled
	f.buckets[bucket] = updated
	return nil
}

func (f *fakeObjectGateway) SetLifecycleRules(ctx context.Context, namespace, bucket string, rules []LifecycleRuleSpec) error {
	f.lifecycles = append(f.lifecycles, bucket)
	updated := f.buckets[bucket]
	observed := make([]ObservedLifecycleRule, 0, len(rules))
	for _, rule := range rules {
		observed = append(observed, ObservedLifecycleRule{Name: rule.Name, Prefix: rule.Prefix, Action: rule.Action, AfterDays: rule.AfterDays})
	}
	updated.LifecycleRules = observed
	updated.LifecyclePresent = true
	f.buckets[bucket] = updated
	return nil
}

func TestObjectStorageReconcilePlans(t *testing.T) {
	declared := testObjectRegion()
	cases := []struct {
		name      string
		observed  ObjectStorageObserved
		wantKinds []OCIActionKind
	}{
		{
			name:      "no buckets plans the declared bucket",
			observed:  ObjectStorageObserved{Namespace: "ts-ns"},
			wantKinds: []OCIActionKind{OCIActionCreateBucket},
		},
		{
			name: "matching bucket and rules plan nothing",
			observed: ObjectStorageObserved{Namespace: "ts-ns", Buckets: []ObservedBucket{{
				Name: "terrascale-backups-gru", Versioning: true, LifecyclePresent: true,
				LifecycleRules: []ObservedLifecycleRule{
					{Name: "segments-7d-archive", Action: "archive", AfterDays: 7},
					{Name: "segments-24h-infrequent", Action: "infrequent-access", AfterDays: 1},
				},
			}}},
			wantKinds: nil,
		},
		{
			name: "versioning drift and missing rules plan repair",
			observed: ObjectStorageObserved{Namespace: "ts-ns", Buckets: []ObservedBucket{{
				Name: "terrascale-backups-gru", Versioning: false, LifecyclePresent: true,
				LifecycleRules: []ObservedLifecycleRule{{Name: "stale", Action: "delete", AfterDays: 30}},
			}}},
			wantKinds: []OCIActionKind{OCIActionSetBucketVersioning, OCIActionSetBucketLifecycle},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler := &ObjectStorageReconciler{Object: &fakeObjectGateway{}}
			plan, err := reconciler.Reconcile(context.Background(), declared, tc.observed)
			if err != nil {
				t.Fatalf("Reconcile() failed: %v", err)
			}
			got := plan.Kinds()
			if len(got) != len(tc.wantKinds) {
				t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
			}
			for i := range got {
				if got[i] != tc.wantKinds[i] {
					t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
				}
			}
		})
	}
}

func TestObjectStorageReconcileRejectsDuplicateBucketNames(t *testing.T) {
	declared := testObjectRegion()
	reconciler := &ObjectStorageReconciler{Object: &fakeObjectGateway{}}
	_, err := reconciler.Reconcile(context.Background(), declared, ObjectStorageObserved{
		Namespace: "ts-ns",
		Buckets: []ObservedBucket{
			{Name: "terrascale-backups-gru", Versioning: true},
			{Name: "terrascale-backups-gru", Versioning: true},
		},
	})
	if err == nil {
		t.Fatal("duplicate bucket identity was accepted")
	}
}

func TestObjectStorageBootstrapConvergenceRequiresPolicy(t *testing.T) {
	declared := testObjectRegion()
	reconciler := &ObjectStorageReconciler{Object: &fakeObjectGateway{}}
	converged, err := reconciler.bootstrapConverged(ObjectStorageObserved{
		Namespace: "ts-ns",
		Buckets:   []ObservedBucket{{Name: "terrascale-backups-gru", Versioning: true}},
	}, declared)
	if err != nil || converged {
		t.Fatalf("missing policy convergence = %v, %v; want false, nil", converged, err)
	}
}

func TestObjectStorageApplyConvergesIdempotently(t *testing.T) {
	declared := testObjectRegion()
	gateway := &fakeObjectGateway{namespace: "ts-ns", buckets: map[string]ObservedBucket{}}
	reconciler := &ObjectStorageReconciler{Object: gateway}
	ctx := context.Background()
	for pass := 0; pass < 3; pass++ {
		observed, err := reconciler.Observe(ctx, declared)
		if err != nil {
			t.Fatalf("observe failed: %v", err)
		}
		plan, err := reconciler.Reconcile(ctx, declared, observed)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}
		if plan.Empty() {
			bucket := gateway.buckets["terrascale-backups-gru"]
			if !bucket.Versioning || len(bucket.LifecycleRules) != 2 {
				t.Fatalf("bucket state = %+v, want versioned with 2 rules", bucket)
			}
			if len(gateway.creates) != 1 || len(gateway.lifecycles) != 1 {
				t.Fatalf("create calls = %v, lifecycle calls = %v, want exactly one each (idempotent)", gateway.creates, gateway.lifecycles)
			}
			return
		}
		if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
	}
	t.Fatal("object storage did not converge in three passes")
}

func TestLifecycleRuleSpecsRejectUnknownAction(t *testing.T) {
	if _, err := LifecycleRuleSpecs(estate.Bucket{LifecycleRules: []estate.BucketLifecycleRule{{Name: "x", Action: "glacier", AfterDays: 3}}}); err == nil {
		t.Fatal("unknown lifecycle action accepted")
	}
}

func TestOCIObjectStorageGatewayLifecycleContract(t *testing.T) {
	var requestBody map[string]any
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPut || request.URL.Path != "/n/ts-ns/b/terrascale-backups-gru/lifecyclePolicy" {
			t.Fatalf("unexpected lifecycle request %s %s", request.Method, request.URL.String())
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		return testHTTPResponse(http.StatusOK, `{}`, http.Header{}), nil
	})
	gateway, err := NewOCIObjectStorageGateway(transport, "ocid1.compartment.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	err = gateway.SetLifecycleRules(context.Background(), "ts-ns", "terrascale-backups-gru", []LifecycleRuleSpec{
		{Name: "segments-24h-infrequent", Action: "infrequent-access", AfterDays: 1},
		{Name: "segments-7d-archive", Action: "archive", AfterDays: 7, Prefix: "segments/"},
	})
	if err != nil {
		t.Fatalf("SetLifecycleRules failed: %v", err)
	}
	items := requestBody["items"].([]any)
	first := items[0].(map[string]any)
	second := items[1].(map[string]any)
	if first["action"] != "INFREQUENT_ACCESS" || first["timeAmount"] != float64(1) || first["timeUnit"] != "DAYS" {
		t.Fatalf("first lifecycle item = %+v", first)
	}
	filter := second["objectNameFilter"].(map[string]any)
	if second["action"] != "ARCHIVE" || filter["inclusionPrefixes"].([]any)[0] != "segments/" {
		t.Fatalf("second lifecycle item = %+v", second)
	}
	if requestBody == nil {
		t.Fatal("lifecycle request body was not captured")
	}
}

func TestOCIObjectStorageGatewayReusesStableRetryToken(t *testing.T) {
	var tokens []string
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/n/ts-ns/b/" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		tokens = append(tokens, request.Header.Get("opc-retry-token"))
		return testHTTPResponse(http.StatusOK, `{}`, http.Header{}), nil
	})
	gateway, err := NewOCIObjectStorageGateway(transport, "ocid1.compartment.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := gateway.CreateBucket(context.Background(), "ts-ns", "terrascale-backups-gru", true); err != nil {
			t.Fatal(err)
		}
	}
	if len(tokens) != 2 || tokens[0] == "" || tokens[0] != tokens[1] {
		t.Fatalf("retry tokens = %q, want one stable non-empty token", tokens)
	}
}

func TestOCIObjectStorageGatewayTreatsMissingPolicyAsEmpty(t *testing.T) {
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/n" {
			return testHTTPResponse(http.StatusOK, `"ts-ns"`, http.Header{}), nil
		}
		if request.Method == http.MethodGet && request.URL.Path == "/n/ts-ns/b/" {
			return testHTTPResponse(http.StatusOK, `[{"name":"terrascale-backups-gru"}]`, http.Header{}), nil
		}
		if request.Method == http.MethodGet && request.URL.Path == "/n/ts-ns/b/terrascale-backups-gru" {
			return testHTTPResponse(http.StatusOK, `{"name":"terrascale-backups-gru","versioning":"Enabled"}`, http.Header{}), nil
		}
		if request.Method == http.MethodGet && request.URL.Path == "/n/ts-ns/b/terrascale-backups-gru/lifecyclePolicy" {
			return testHTTPResponse(http.StatusNotFound, `{"code":"LifecyclePolicyNotFound"}`, http.Header{}), nil
		}
		t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		return nil, nil
	})
	gateway, err := NewOCIObjectStorageGateway(transport, "ocid1.compartment.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	buckets, err := gateway.ListBuckets(context.Background(), "ts-ns")
	if err != nil || len(buckets) != 1 {
		t.Fatalf("ListBuckets = %+v, %v", buckets, err)
	}
	if buckets[0].LifecyclePresent || buckets[0].LifecycleRules != nil {
		t.Fatalf("missing policy must observe as empty, got %+v", buckets[0])
	}
	if !buckets[0].Versioning {
		t.Fatal("versioning not observed")
	}
}
