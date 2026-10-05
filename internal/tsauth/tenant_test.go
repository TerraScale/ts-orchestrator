package tsauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnsureRecoversCreateConflictByRereading(t *testing.T) {
	gets, posts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/management/organizations" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			gets++
			if gets == 1 {
				fmt.Fprint(w, `{"items":[]}`)
				return
			}
			fmt.Fprint(w, `{"items":[{"id":"org-1","name":"terrascale-internal"}]}`)
		case http.MethodPost:
			posts++
			http.Error(w, "already exists", http.StatusConflict)
		default:
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	terraBase := TerraBase{HTTP: server.Client(), ClientURL: server.URL, Credential: "credential"}
	id, err := terraBase.ensure(t.Context(), "", "/v1/management/organizations", OrganizationName)
	if err != nil || id != "org-1" {
		t.Fatalf("id %q, err %v", id, err)
	}
	if gets != 2 || posts != 1 {
		t.Fatalf("GETs=%d POSTs=%d, want 2 and 1", gets, posts)
	}
}

func TestEnsureKeepsDuplicateRejectionAfterCreateConflict(t *testing.T) {
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			gets++
			if gets == 1 {
				fmt.Fprint(w, `{"items":[]}`)
				return
			}
			fmt.Fprint(w, `{"items":[{"id":"org-1","name":"terrascale-internal"},{"id":"org-2","name":"terrascale-internal"}]}`)
		case http.MethodPost:
			http.Error(w, "already exists", http.StatusConflict)
		default:
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	terraBase := TerraBase{HTTP: server.Client(), ClientURL: server.URL, Credential: "credential"}
	_, err := terraBase.ensure(t.Context(), "", "/v1/management/organizations", OrganizationName)
	if err == nil || !strings.Contains(err.Error(), "two named") {
		t.Fatalf("duplicate result: %v", err)
	}
}
