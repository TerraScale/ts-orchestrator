package ocicost

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/resourcesearch"
)

const testCompartmentA = "ocid1.compartment.oc1..aaa"

func TestOCITagsQueryScopesCompartments(t *testing.T) {
	search := &fakeSearch{}
	tags := &OCITags{search: search}
	if _, err := tags.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	tags.Compartments = []string{testCompartmentA, "ocid1.compartment.oc1..bbb"}
	if _, err := tags.Resources(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := searchQuery + " && (compartmentId = '" + testCompartmentA + "' || compartmentId = 'ocid1.compartment.oc1..bbb')"
	if got := search.queries; len(got) != 2 || got[0] != searchQuery || got[1] != want {
		t.Fatalf("queries = %q, want [%q %q]", got, searchQuery, want)
	}
}

func TestOCITagsRefusesCompartmentValue(t *testing.T) {
	search := &fakeSearch{}
	tags := &OCITags{search: search, Compartments: []string{"ocid1.compartment.oc1..aaa' || 1 = 1"}}
	if _, err := tags.Resources(t.Context()); err == nil || !strings.Contains(err.Error(), "not a compartment OCID") {
		t.Fatalf("error = %v, want a refused compartment", err)
	}
	if len(search.queries) != 0 {
		t.Fatalf("searched %d times with a refused compartment", len(search.queries))
	}
}

func TestOCITagsPagesAndMapsResources(t *testing.T) {
	created := common.SDKTime{Time: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	search := &fakeSearch{pages: [][]resourcesearch.ResourceSummary{
		{{ResourceType: common.String("Instance"), Identifier: common.String("ocid1.instance.a"),
			DisplayName: common.String("gru-1-ctl-1"), CompartmentId: common.String(testCompartmentA),
			TimeCreated: &created, FreeformTags: map[string]string{"k": "v"}}},
		{{ResourceType: common.String("Bucket"), Identifier: common.String("ocid1.bucket.b"), DisplayName: common.String("gru-1-head")}},
	}}
	tags := &OCITags{search: search}
	resources, err := tags.Resources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 || len(search.pageArgs) != 2 || search.pageArgs[1] == nil || *search.pageArgs[1] != "next" {
		t.Fatalf("resources %d, page requests %v", len(resources), search.pageArgs)
	}
	first := resources[0]
	if first.ID != "ocid1.instance.a" || first.Type != "Instance" || first.Name != "gru-1-ctl-1" ||
		first.Compartment != testCompartmentA || !first.Created.Equal(created.Time) || first.Tags["k"] != "v" {
		t.Fatalf("first resource = %+v", first)
	}
	if resources[1].Type != "Bucket" || resources[1].Name != "gru-1-head" {
		t.Fatalf("second resource = %+v", resources[1])
	}
}

func TestOCITagsStopsAtPageLimit(t *testing.T) {
	search := &fakeSearch{pages: make([][]resourcesearch.ResourceSummary, maxSearchPages+1)}
	tags := &OCITags{search: search}
	if _, err := tags.Resources(t.Context()); err == nil {
		t.Fatal("Resources succeeded past the page limit")
	}
	if len(search.queries) != maxSearchPages {
		t.Fatalf("searched %d pages, want %d", len(search.queries), maxSearchPages)
	}
}

func TestOCITagsRetagMergesAndSendsIfMatch(t *testing.T) {
	compute := &fakeCompute{instance: core.Instance{FreeformTags: map[string]string{"owner": "a", RegionTag: "gru"}}, etag: "e1"}
	tags := &OCITags{compute: compute}
	err := tags.Retag(t.Context(), Resource{ID: "ocid1.instance.a", Type: "Instance"},
		map[string]string{RegionTag: "GRU", ComponentTag: "controller"})
	if err != nil {
		t.Fatal(err)
	}
	if len(compute.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(compute.updates))
	}
	update := compute.updates[0]
	want := map[string]string{"owner": "a", RegionTag: "GRU", ComponentTag: "controller"}
	if *update.IfMatch != "e1" || !maps.Equal(update.UpdateInstanceDetails.FreeformTags, want) {
		t.Fatalf("update if-match %q tags %v, want e1 and %v", *update.IfMatch, update.UpdateInstanceDetails.FreeformTags, want)
	}
}

func TestOCITagsRetagUnchangedSendsNothing(t *testing.T) {
	compute := &fakeCompute{instance: core.Instance{FreeformTags: map[string]string{RegionTag: "GRU", ComponentTag: "controller"}}, etag: "e1"}
	tags := &OCITags{compute: compute}
	if err := tags.Retag(t.Context(), Resource{ID: "ocid1.instance.a", Type: "Instance"},
		map[string]string{RegionTag: "GRU", ComponentTag: "controller"}); err != nil {
		t.Fatal(err)
	}
	if len(compute.updates) != 0 {
		t.Fatalf("unchanged tags sent %d updates", len(compute.updates))
	}
}

func TestOCITagsRetagMapsOCIAnswers(t *testing.T) {
	stamp := map[string]string{ComponentTag: "controller"}
	resource := Resource{ID: "ocid1.instance.a", Type: "Instance"}
	for _, test := range []struct {
		name    string
		compute *fakeCompute
		want    error
	}{
		{name: "precondition failed", compute: &fakeCompute{updateErr: statusError{http.StatusPreconditionFailed}}, want: ErrChanged},
		{name: "not found", compute: &fakeCompute{getErr: statusError{http.StatusNotFound}}, want: ErrNotPermitted},
		{name: "forbidden", compute: &fakeCompute{updateErr: statusError{http.StatusForbidden}}, want: ErrNotPermitted},
		{name: "server error", compute: &fakeCompute{updateErr: statusError{http.StatusInternalServerError}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := (&OCITags{compute: test.compute}).Retag(t.Context(), resource, stamp)
			if err == nil {
				t.Fatal("Retag succeeded")
			}
			if test.want == nil && (errors.Is(err, ErrChanged) || errors.Is(err, ErrNotPermitted)) {
				t.Fatalf("error %v maps to a pass sentinel, want a plain error", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error %v, want %v", err, test.want)
			}
		})
	}
}

func TestOCITagsBucketUsesCachedNamespace(t *testing.T) {
	objects := &fakeObjects{namespace: "ns", bucket: objectstorage.Bucket{Etag: new("be"), FreeformTags: map[string]string{}}}
	tags := &OCITags{objects: objects}
	for _, name := range []string{"gru-1-head", "gru-1-backup"} {
		if err := tags.Retag(t.Context(), Resource{Type: "Bucket", Name: name}, map[string]string{ComponentTag: "releases"}); err != nil {
			t.Fatal(err)
		}
	}
	if objects.namespaceCalls != 1 {
		t.Fatalf("namespace read %d times, want 1", objects.namespaceCalls)
	}
	if len(objects.updates) != 2 || *objects.updates[1].NamespaceName != "ns" || *objects.updates[1].BucketName != "gru-1-backup" {
		t.Fatalf("bucket updates = %+v", objects.updates)
	}
}

func TestOCITagsRefusesUnknownType(t *testing.T) {
	err := (&OCITags{}).Retag(t.Context(), Resource{Type: "Network"}, map[string]string{ComponentTag: "network"})
	if err == nil || !strings.Contains(err.Error(), `"Network"`) {
		t.Fatalf("error = %v, want the unknown type named", err)
	}
}

type statusError struct{ status int }

func (e statusError) Error() string           { return fmt.Sprintf("OCI status %d", e.status) }
func (e statusError) GetHTTPStatusCode() int  { return e.status }
func (e statusError) GetMessage() string      { return e.Error() }
func (e statusError) GetCode() string         { return "test" }
func (e statusError) GetOpcRequestID() string { return "" }

type fakeSearch struct {
	searchAPI
	pages    [][]resourcesearch.ResourceSummary
	queries  []string
	pageArgs []*string
}

func (f *fakeSearch) SearchResources(_ context.Context, request resourcesearch.SearchResourcesRequest) (resourcesearch.SearchResourcesResponse, error) {
	index := len(f.queries)
	f.queries = append(f.queries, *request.SearchDetails.(resourcesearch.StructuredSearchDetails).Query)
	f.pageArgs = append(f.pageArgs, request.Page)
	response := resourcesearch.SearchResourcesResponse{}
	if index < len(f.pages) {
		response.Items = f.pages[index]
	}
	if index+1 < len(f.pages) {
		response.OpcNextPage = common.String("next")
	}
	return response, nil
}

type fakeCompute struct {
	computeAPI
	instance  core.Instance
	etag      string
	getErr    error
	updateErr error
	updates   []core.UpdateInstanceRequest
}

func (f *fakeCompute) GetInstance(context.Context, core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	if f.getErr != nil {
		return core.GetInstanceResponse{}, f.getErr
	}
	return core.GetInstanceResponse{Instance: f.instance, Etag: common.String(f.etag)}, nil
}

func (f *fakeCompute) UpdateInstance(_ context.Context, request core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error) {
	f.updates = append(f.updates, request)
	return core.UpdateInstanceResponse{}, f.updateErr
}

type fakeObjects struct {
	objectAPI
	namespace      string
	namespaceCalls int
	bucket         objectstorage.Bucket
	updates        []objectstorage.UpdateBucketRequest
}

func (f *fakeObjects) GetNamespace(context.Context, objectstorage.GetNamespaceRequest) (objectstorage.GetNamespaceResponse, error) {
	f.namespaceCalls++
	return objectstorage.GetNamespaceResponse{Value: common.String(f.namespace)}, nil
}

func (f *fakeObjects) GetBucket(context.Context, objectstorage.GetBucketRequest) (objectstorage.GetBucketResponse, error) {
	return objectstorage.GetBucketResponse{Bucket: f.bucket}, nil
}

func (f *fakeObjects) UpdateBucket(_ context.Context, request objectstorage.UpdateBucketRequest) (objectstorage.UpdateBucketResponse, error) {
	f.updates = append(f.updates, request)
	return objectstorage.UpdateBucketResponse{}, nil
}
