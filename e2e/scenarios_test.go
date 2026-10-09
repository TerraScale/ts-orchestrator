package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	tb "terrascale.tech/sdk/v1"
)

func TestCleanupProjectRevokesPagedKeysBeforeDeletingOwnedProject(t *testing.T) {
	const org = "00000000000000000000000001"
	const project = "00000000000000000000000002"
	const key = "00000000000000000000000003"
	const database = "00000000000000000000000004"
	const actor = "00000000000000000000000005"
	const other = "00000000000000000000000006"
	root := "/v1/management/organizations/" + org + "/projects"
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.RequestURI() {
		case "GET " + root + "?limit=100":
			fmt.Fprintf(w, `{"items":[{"id":%q,"organizationId":%q,"name":"unrelated"},{"id":%q,"organizationId":%q,"name":"e2e-owned"}]}`, other, org, project, org)
		case "GET " + root + "/" + project + "/api-keys?limit=100":
			fmt.Fprintf(w, `{"items":[{"id":%q,"projectId":%q}],"next":"second"}`, key, project)
		case "GET " + root + "/" + project + "/api-keys?after=second&limit=100":
			fmt.Fprint(w, `{"items":[]}`)
		case "GET " + root + "/" + project + "/databases?limit=100":
			fmt.Fprintf(w, `{"items":[{"id":%q,"projectId":%q,"name":"main"}]}`, database, project)
		case "DELETE " + root + "/" + project + "/api-keys/" + key,
			"DELETE " + root + "/" + project + "/databases/" + database,
			"DELETE " + root + "/" + project:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected cleanup request %s", r.URL.RequestURI())
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	m, err := tb.NewManagement(tb.Config{BaseURL: server.URL, Token: "test-management-credential-00000000", MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	if err = cleanupProject(t.Context(), m.As(actor), org, "e2e-owned"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET " + root + "?limit=100",
		"GET " + root + "/" + project + "/api-keys?limit=100",
		"DELETE " + root + "/" + project + "/api-keys/" + key,
		"GET " + root + "/" + project + "/api-keys?after=second&limit=100",
		"GET " + root + "/" + project + "/databases?limit=100",
		"DELETE " + root + "/" + project + "/databases/" + database,
		"DELETE " + root + "/" + project,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup requests=%v, want %v", calls, want)
	}
}
