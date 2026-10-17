package journal

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestMutationAllowsOnlyImplementedAccountEffects(t *testing.T) {
	for _, route := range []string{
		"POST /api/groups", "POST /api/policies", "POST /api/setup-keys", "POST /api/dns/zones", "POST /api/dns/zones/zone_1/records",
		"PUT /api/groups/id-1", "PUT /api/policies/id-1", "PUT /api/accounts/id-1", "PUT /api/peers/id-1", "PUT /api/setup-keys/id-1",
		"PUT /api/dns/settings", "PUT /api/dns/zones/id-1", "PUT /api/dns/zones/id-1/records/record_1",
		"DELETE /api/peers/id-1", "DELETE /api/policies/id-1", "DELETE /api/dns/zones/id-1/records/record_1",
	} {
		t.Run(route, func(t *testing.T) {
			method, path, _ := strings.Cut(route, " ")
			mutation := Mutation{Method: method, Path: path}
			if method != http.MethodDelete {
				mutation.Body = []byte(`{"name":"original"}`)
			}
			if err := mutation.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, route := range []string{
		"GET /api/groups", "PATCH /api/peers/id", "POST /api/networks", "DELETE /api/dns/zones/id", "PUT /api/groups",
		"PUT /api/groups/", "PUT /api/groups/../accounts/id", "PUT /api/groups/%2faccounts", "PUT /api/groups/id?x=1",
		"PUT /api/groups/id#x", "PUT /api/groups/id/", "PUT /api//groups/id", "PUT /api/groups/é", "PUT /api/groups/.",
	} {
		method, path, _ := strings.Cut(route, " ")
		if err := (Mutation{Method: method, Path: path, Body: []byte(`{}`)}).Validate(); err == nil {
			t.Fatalf("unexpected account effect accepted: %s", route)
		}
	}
}

func TestFreezePreservesExactBodyWithoutCredentials(t *testing.T) {
	body := []byte("{ \"name\": \"original\" }")
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18081/api/groups", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Token private-credential")
	mutation, err := Freeze(request)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := mutation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	copy(body, bytes.Repeat([]byte("x"), len(body)))
	request.URL.Path = "/api/policies"
	request.Header.Set("Authorization", "Token changed-credential")
	if string(mutation.Body) != "{ \"name\": \"original\" }" || mutation.Path != "/api/groups" {
		t.Fatal("caller mutation changed frozen request")
	}
	compacted := Mutation{Method: mutation.Method, Path: mutation.Path, Body: []byte(`{"name":"original"}`)}
	compactedDigest, err := compacted.Digest()
	if err != nil || digest == compactedDigest {
		t.Fatal("request digest normalized exact body bytes")
	}
	if strings.Contains(fmt.Sprintf("%#v", mutation), "original") {
		t.Fatal("mutation formatting disclosed body")
	}
}

func TestFreezeRejectsAlternateOriginsAndAmbiguousRequests(t *testing.T) {
	for _, target := range []string{
		"https://127.0.0.1:18081/api/groups", "http://localhost:18081/api/groups", "http://127.0.0.1:18082/api/groups",
		"http://user@127.0.0.1:18081/api/groups", "http://127.0.0.1:18081/api/groups?x=1", "http://127.0.0.1:18081/api/groups#x",
		"http://127.0.0.1:18081/api/groups?", "http://127.0.0.1:18081/api/%67roups",
	} {
		request, err := http.NewRequest(http.MethodPost, target, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Freeze(request); err == nil {
			t.Fatalf("alternate request target accepted: %s", target)
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Host = "forwarded.example" },
		func(r *http.Request) { r.RequestURI = "/api/groups" },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		func(r *http.Request) { r.ContentLength = 1 },
		func(r *http.Request) { r.ContentLength = -2 },
		func(r *http.Request) { r.Body = nil },
		func(r *http.Request) { r.URL = nil },
	} {
		request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18081/api/groups", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		change(request)
		if _, err := Freeze(request); err == nil {
			t.Fatal("ambiguous loopback request accepted")
		}
	}
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18081/api/groups", strings.NewReader(strings.Repeat(" ", MaxBodyBytes+1)))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	if _, err := Freeze(request); err == nil {
		t.Fatal("unbounded streamed request body accepted")
	}
}

func TestMutationRejectsNonObjectOrDuplicateJSONAndDeleteBodies(t *testing.T) {
	for _, body := range []string{"", "null", "[]", "true", `{"name":"one","name":"two"}`, `{} {}`} {
		if _, err := (Mutation{Method: http.MethodPost, Path: "/api/groups", Body: []byte(body)}).Digest(); err == nil {
			t.Fatal("invalid or ambiguous JSON body accepted")
		}
	}
	if err := (Mutation{Method: http.MethodDelete, Path: "/api/peers/id", Body: []byte(`{}`)}).Validate(); err == nil {
		t.Fatal("DELETE with unbound effect body accepted")
	}
}
