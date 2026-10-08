package tsauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementRejectsNoncanonicalActorsAndOwners(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid identity reached TerraBase")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	for _, id := range []string{"ts-orchestrator", "usr_mario", "01a1105a-7350-7f48-a96e-d71bbb45d7a8", "01k78000000000000000001001", "81K78000000000000000001001", "01K7800000000000000000100I"} {
		client := TerraBase{HTTP: server.Client(), ClientURL: server.URL, User: id}
		if err := client.management(t.Context(), http.MethodGet, "", "/v1/management/organizations", nil, http.StatusOK, nil); err == nil || !strings.Contains(err.Error(), "canonical uppercase ULID") {
			t.Errorf("actor %q: %v", id, err)
		}
		client.User = ""
		if _, err := client.EnsureOwner(t.Context(), "01K78000000000000000002001", id, "owner@example.com"); err == nil || !strings.Contains(err.Error(), "canonical uppercase") {
			t.Errorf("owner %q: %v", id, err)
		}
	}
	client := TerraBase{HTTP: server.Client(), ClientURL: server.URL}
	for _, id := range []string{"", BootstrapUser} {
		if _, err := client.EnsureOwner(t.Context(), "01K78000000000000000002001", id, "owner@example.com"); err == nil {
			t.Errorf("accepted owner %q", id)
		}
	}
}

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
			fmt.Fprint(w, `{"items":[{"id":"01K78000000000000000002001","name":"terrascale"}]}`)
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
	if err != nil || id != "01K78000000000000000002001" {
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
			fmt.Fprint(w, `{"items":[{"id":"01K78000000000000000002001","name":"terrascale"},{"id":"01K78000000000000000002002","name":"terrascale"}]}`)
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
