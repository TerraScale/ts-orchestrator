package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestBootstrapControlMembersReadOnlyExactOwnedSlots(t *testing.T) {
	compartment := "ocid1.compartment.oc1.test.control"
	tenancy := "ocid1.tenancy.oc1.test.owner"
	members := []map[string]any{{"id": "ocid1.instance.oc1.test.one", "displayName": "terrascale-gru-1", "compartmentId": compartment, "lifecycleState": "RUNNING", "freeformTags": map[string]string{provider.OCIManagedTag: ManagedMemberTagValue, provider.OCIScopeTag: "gru", MemberIndexTag: "1"}}}
	requests := 0
	transport := func(service provider.OCIService) *provider.OCIHTTPTransport {
		return testOCITransport(t, service, func(request *http.Request) (*http.Response, error) {
			requests++
			if request.Method != http.MethodGet {
				t.Fatal("receipt resolver mutated OCI")
			}
			var value any
			if strings.Contains(request.URL.Path, "compartments") {
				value = []map[string]string{{"id": compartment, "name": "terrascale", "compartmentId": tenancy, "lifecycleState": "ACTIVE"}}
			} else {
				value = members
			}
			raw, _ := json.Marshal(value)
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
		})
	}
	core, identity := transport(provider.OCIServiceCore), transport(provider.OCIServiceIdentity)
	id, got, err := ReadBootstrapControlMembers(context.Background(), core, identity, tenancy, "terrascale", "gru", 1)
	if err != nil || id != compartment || len(got) != 1 || got[0].ID != "ocid1.instance.oc1.test.one" || requests != 2 {
		t.Fatalf("receipt=%s %+v %v requests=%d", id, got, err, requests)
	}
	members = append(members, members[0])
	if _, _, err := ReadBootstrapControlMembers(context.Background(), core, identity, tenancy, "terrascale", "gru", 1); err == nil {
		t.Fatal("duplicate slot admitted")
	}
	members = members[:1]
	members[0]["displayName"] = "other"
	if _, _, err := ReadBootstrapControlMembers(context.Background(), core, identity, tenancy, "terrascale", "gru", 1); err == nil {
		t.Fatal("unowned display identity admitted")
	}
	members = nil
	if _, _, err := ReadBootstrapControlMembers(context.Background(), core, identity, tenancy, "terrascale", "gru", 1); err == nil {
		t.Fatal("missing instance manufactured")
	}
}

func TestBootstrapControlListRejectsNullAndWrappedCollections(t *testing.T) {
	for _, body := range []string{"null", `{"items":[]}`, "[]"} {
		t.Run(body, func(t *testing.T) {
			transport := testOCITransport(t, provider.OCIServiceCore, func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			_, err := provider.ReadOCICollection[json.RawMessage](context.Background(), transport, "/20160918/instances", url.Values{})
			if (err == nil) != (body == "[]") {
				t.Fatalf("collection %s: %v", body, err)
			}
		})
	}
}

func TestMemberGatewayReadsCanonicalPaginatedAvailabilityDomains(t *testing.T) {
	requests := 0
	transport := testOCITransport(t, provider.OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/20160918/availabilityDomains" || request.URL.Query().Get("compartmentId") != "ocid1.compartment.oc1.test.control" {
			t.Fatalf("unexpected request: %s", request.URL)
		}
		headers := http.Header{}
		body := `[{"name":"AD-1"}]`
		if requests == 1 {
			headers.Set("opc-next-page", "next-domain")
		} else {
			if requests != 2 || request.URL.Query().Get("page") != "next-domain" {
				t.Fatalf("unexpected page: %s", request.URL)
			}
			body = `[{"name":"AD-2"}]`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	gateway := &ociMemberGateway{Core: transport, CompartmentID: "ocid1.compartment.oc1.test.control"}
	domains, err := gateway.ListAvailabilityDomains(context.Background())
	if err != nil || requests != 2 || !reflect.DeepEqual(domains, []string{"AD-1", "AD-2"}) {
		t.Fatalf("domains=%v requests=%d err=%v", domains, requests, err)
	}
}
