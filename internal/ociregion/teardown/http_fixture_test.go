package teardown

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// teardownAPI speaks OCI's HTTP protocol; teardown always uses the real SDK.
type teardownAPI struct {
	mu       sync.Mutex
	provider *SDKProvider
	state    map[string]Observed
	contents map[string][]Resource
	deleted  []string
	out      *strings.Builder
	onDelete func(Resource)
	deny     string
}

func newTeardownAPI(t *testing.T, api *teardownAPI) *teardownAPI {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected OCI request: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusForbidden)
	})
	for path, kind := range map[string]string{"secrets": "vault-secret", "keys": "kms-key", "vaults": "kms-vault", "compartments": "compartment"} {
		version := "20180608"
		if kind == "compartment" {
			version = "20160918"
		}
		base := "/" + version + "/" + path
		mux.HandleFunc("GET "+base, func(w http.ResponseWriter, r *http.Request) { api.serve(t, w, r, kind, false) })
		mux.HandleFunc("GET "+base+"/{id}", func(w http.ResponseWriter, r *http.Request) { api.serve(t, w, r, kind, false) })
		mutation := "POST " + base + "/{id}/actions/scheduleDeletion"
		if kind == "compartment" {
			mutation = "DELETE " + base + "/{id}"
		}
		mux.HandleFunc(mutation, func(w http.ResponseWriter, r *http.Request) { api.serve(t, w, r, kind, true) })
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	api.provider = sdkProvider(t, server)
	return api
}

func (api *teardownAPI) teardown(t *testing.T, plan Plan, apply bool, out io.Writer) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	// Synchronize fixture edits and observations with HTTP handler goroutines.
	api.mu.Lock()
	api.mu.Unlock()
	err := Teardown(ctx, plan, api.provider, apply, out)
	api.mu.Lock()
	api.mu.Unlock()
	return err
}

func (api *teardownAPI) serve(t *testing.T, w http.ResponseWriter, r *http.Request, kind string, mutate bool) {
	t.Helper()
	api.mu.Lock()
	defer api.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(value any) {
		if err := json.MarshalWrite(w, value); err != nil {
			t.Errorf("write OCI response: %v", err)
		}
	}
	if api.deny == r.Method+" "+r.URL.Path {
		w.WriteHeader(http.StatusForbidden)
		write(map[string]string{"code": "NotAuthorized", "message": "permission denied"})
		return
	}
	id := r.PathValue("id")
	if id == "" {
		var items []map[string]any
		if kind == "compartment" {
			compartments := map[string]bool{cellCompartment: true}
			for _, contents := range api.contents {
				for _, resource := range contents {
					compartments[resource.Compartment] = true
				}
			}
			for compartment := range compartments {
				items = append(items, map[string]any{"id": compartment, "lifecycleState": "ACTIVE"})
			}
		} else {
			for _, resource := range api.contents["vault"] {
				if resource.Kind == kind && resource.Compartment == r.URL.Query().Get("compartmentId") {
					items = append(items, map[string]any{"id": resource.ID, "displayName": resource.Name, "secretName": resource.Name,
						"compartmentId": resource.Compartment, "vaultId": resource.VaultID, "lifecycleState": "PENDING_DELETION"})
				}
			}
		}
		if items == nil {
			items = []map[string]any{}
		}
		write(items)
		return
	}
	o, ok := api.state[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		write(map[string]string{"code": "NotAuthorizedOrNotFound", "message": "unreadable or absent"})
		return
	}
	if mutate {
		if kind != "compartment" {
			var body struct {
				TimeOfDeletion time.Time `json:"timeOfDeletion"`
			}
			if err := json.UnmarshalRead(r.Body, &body); err != nil {
				t.Errorf("read deletion request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			window := 7*24*time.Hour + time.Hour
			if kind == "vault-secret" {
				window = 25 * time.Hour
			}
			if remaining := time.Until(body.TimeOfDeletion); remaining < window-time.Minute || remaining > window+time.Minute {
				t.Errorf("%s deletion window = %s, want %s", kind, remaining, window)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			o.State, o.DeleteAt = "PENDING_DELETION", &body.TimeOfDeletion
		} else {
			o.State = "DELETING"
		}
		api.state[id] = o
		api.deleted = append(api.deleted, id)
		if api.onDelete != nil {
			api.onDelete(Resource{Kind: kind, ID: id})
		}
		if kind == "vault-secret" || kind == "compartment" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	value := map[string]any{"id": id, "displayName": o.Name, "secretName": o.Name, "name": o.Name,
		"compartmentId": o.Compartment, "lifecycleState": o.State}
	if kind == "kms-vault" {
		value["managementEndpoint"] = "http://" + r.Host
	}
	if o.DeleteAt != nil {
		value["timeOfDeletion"] = o.DeleteAt.Format(time.RFC3339Nano)
	}
	write(value)
}

func (f *teardownAPI) purge() {
	for id, o := range f.state {
		switch o.State {
		case "DELETING":
			o.State = "DELETED"
			f.state[id] = o
		case "PENDING_DELETION":
			delete(f.state, id)
		}
	}
}
