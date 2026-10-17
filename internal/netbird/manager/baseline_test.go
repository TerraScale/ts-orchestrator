package manager

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRestrictBaselineRefusesChangedPolicyAndLostAuthority(t *testing.T) {
	for _, scenario := range []string{"exact", "changed", "ambiguous", "authority-lost"} {
		t.Run(scenario, func(t *testing.T) {
			const description = "This is a default rule that allows connections between all the resources"
			policy := apiPolicy{ID: "genesis", Name: "Default", Description: description, Enabled: true, Rules: []apiRule{{ID: "genesis", Name: "Default", Description: description, Enabled: true, Action: "accept", Bidirectional: true, Protocol: "all", Sources: []groupMinimum{{ID: "all"}}, Destinations: []groupMinimum{{ID: "all"}}}}}
			if scenario == "changed" {
				policy.Rules[0].Sources = append(policy.Rules[0].Sources, groupMinimum{ID: "unexpected"})
			}
			policies := []apiPolicy{policy, {ID: "managed", Name: "operators-to-gru-servers-ssh"}}
			if scenario == "ambiguous" {
				policies = append(policies, policy)
			}
			deletes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "GET" && r.URL.Path == "/api/groups":
					_ = json.MarshalWrite(w, []apiGroup{{ID: "all", Name: "All", Issued: "api"}})
				case r.Method == "GET" && r.URL.Path == "/api/policies":
					_ = json.MarshalWrite(w, policies)
				case r.Method == "DELETE" && r.URL.Path == "/api/policies/genesis":
					deletes++
					policies = policies[1:]
					w.WriteHeader(204)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			api, err := NewFencedAPI(server.URL, testPAT, func() error {
				if scenario == "authority-lost" {
					return context.Canceled
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			err = RestrictBaseline(t.Context(), api)
			if scenario == "exact" {
				if err != nil || deletes != 1 || len(policies) != 1 || policies[0].ID != "managed" {
					t.Fatalf("baseline deletion differs: deletes=%d error=%v", deletes, err)
				}
				if err := RestrictBaseline(t.Context(), api); err != nil || deletes != 1 {
					t.Fatalf("baseline replay differs: %v", err)
				}
			} else if err == nil || deletes != 0 || scenario == "authority-lost" && !errors.Is(err, context.Canceled) {
				t.Fatalf("unsafe baseline mutated: deletes=%d error=%v", deletes, err)
			}
		})
	}
}

func TestManagerCLIHasNoCredentialOrMutationEntryPoint(t *testing.T) {
	for _, command := range []string{"sync", "prune-peers", "remove-peers", "setup-key", "inventory"} {
		if err := Run(t.Context(), []string{command}, io.Discard); err == nil {
			t.Fatalf("manual manager command %s remained reachable", command)
		}
	}
}
