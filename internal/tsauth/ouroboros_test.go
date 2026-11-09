package tsauth

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestOuroborosTSAuthUserLookup(t *testing.T) {
	const key = "sk_SENTINEL-0123456789abcdef"
	var users []map[string]any
	var cursors []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/terrascale/users" || r.Header.Get("Authorization") != "Bearer "+key || r.URL.Query().Get("limit") != "100" {
			http.Error(w, "unauthorized: "+r.Header.Get("Authorization"), http.StatusUnauthorized)
			return
		}
		after := r.URL.Query().Get("starting_after")
		cursors = append(cursors, after)
		start := 0
		if after != "" {
			start = slices.IndexFunc(users, func(user map[string]any) bool { return user["id"] == after }) + 1
		}
		_ = json.MarshalWrite(w, map[string]any{"data": users[start:min(start+100, len(users))]})
	}))
	t.Cleanup(server.Close)
	lookup := TSAuthUsers{HTTP: server.Client(), URL: server.URL, Instance: "terrascale", Key: key}
	const email = "mariogk@terrascale.tech"
	set := func(owners ...map[string]any) {
		users = nil
		for index := range 120 {
			users = append(users, map[string]any{"id": fmt.Sprintf("%026d", index+1000), "email": fmt.Sprintf("user%d@example.com", index), "email_verified": true})
		}
		users = append(users, owners...)
		cursors = nil
	}

	set(map[string]any{"id": "01K78000000000000000001001", "email": "MarioGK@TerraScale.tech", "email_verified": true})
	if id, err := lookup.UserID(t.Context(), email); err != nil || id != "01K78000000000000000001001" || fmt.Sprint(cursors) != "[ 00000000000000000000001099]" {
		t.Fatalf("user %q, cursors %v: %v", id, cursors, err)
	}
	wrong := lookup
	wrong.Key = "sk_wrong-SENTINEL"
	if _, err := wrong.UserID(t.Context(), email); err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("wrong key: %v", err)
	}
}

// TestManagementOnAdminListener: from TerraBase TS-519 the Management service
// credential works only on the loopback admin listener, so with
// ManagementOnAdmin every Management request goes there and none to the
// client listener.
func TestManagementOnAdminListener(t *testing.T) {
	var seen []string
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer credential" || r.Header.Get("X-TerraBase-User-Id") != BootstrapUser || !entityid.Valid(r.Header.Get("X-TerraBase-User-Id")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet {
			_ = json.MarshalWrite(w, map[string]any{"items": []any{}})
			return
		}
		var body named
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.MarshalWrite(w, named{ID: fmt.Sprintf("%026d", len(seen)), Name: body.Name})
	}))
	t.Cleanup(admin.Close)
	terraBase := TerraBase{HTTP: admin.Client(), ClientURL: "https://127.0.0.1:1", AdminURL: admin.URL, Credential: "credential", ManagementOnAdmin: true}
	tenant, err := terraBase.EnsureTenant(t.Context(), dashboard)
	if err != nil || tenant != (Tenant{OrganizationID: "00000000000000000000000002", Project: "ts-dashboard", ProjectID: "00000000000000000000000004", DatabaseID: "00000000000000000000000006", Database: "dashboard"}) {
		t.Fatalf("tenant %+v: %v", tenant, err)
	}
	if got := fmt.Sprint(seen); got != "[GET /v1/management/organizations POST /v1/management/organizations "+
		"GET /v1/management/organizations/00000000000000000000000002/projects POST /v1/management/organizations/00000000000000000000000002/projects "+
		"GET /v1/projects/00000000000000000000000004/databases POST /v1/projects/00000000000000000000000004/databases]" {
		t.Fatal(got)
	}
}

// TestEnsureOwnerAddsTransfersAndKeepsTheBootstrapAdmin runs phase B against
// a fake admin listener that keeps TerraBase's role rules: confirming a
// transfer leaves its starter a member. From every state an interrupted run
// can leave, it takes only the remaining steps, each as the right user; once
// the organization is handed over it adds nobody else.
func TestEnsureOwnerAddsTransfersAndKeepsTheBootstrapAdmin(t *testing.T) {
	const org, mario, email = "01K78000000000000000002001", "01K78000000000000000001001", "mariogk@terrascale.tech"
	const add, start, confirm, relist, readmin = "01M4EB0GDPPHGJPPVY77EMZQKT PUT /members/01K78000000000000000001001", "01M4EB0GDPPHGJPPVY77EMZQKT POST /ownership-transfer",
		"01K78000000000000000001001 POST /ownership-transfer/confirm", "01K78000000000000000001001 GET /members", "01K78000000000000000001001 PUT /members/01M4EB0GDPPHGJPPVY77EMZQKT/role"
	const list = "01M4EB0GDPPHGJPPVY77EMZQKT GET /members"
	for _, test := range []struct {
		name    string
		roles   map[string]string
		nominee string
		owner   string
		steps   string
		calls   []string
		err     string
	}{
		{"fresh", map[string]string{BootstrapUser: "owner"}, "", mario,
			"[added transferred kept 01M4EB0GDPPHGJPPVY77EMZQKT as admin]", []string{list, add, start, confirm, relist, readmin}, ""},
		{"done", map[string]string{BootstrapUser: "admin", mario: "owner"}, "", mario, "[]", []string{list}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			roles, nominee := test.roles, test.nominee
			var calls []string
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actor := r.Header.Get("X-TerraBase-User-Id")
				if r.Header.Get("Authorization") != "Bearer credential" || roles[actor] == "" {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				path := strings.TrimPrefix(r.URL.Path, "/v1/management/organizations/"+org)
				calls = append(calls, actor+" "+r.Method+" "+path)
				var body map[string]string
				_ = json.UnmarshalRead(r.Body, &body)
				switch {
				case r.Method == http.MethodGet && path == "/members":
					var items []map[string]string
					for user, role := range roles {
						items = append(items, map[string]string{"userId": user, "role": role})
					}
					_ = json.MarshalWrite(w, map[string]any{"items": items})
				case r.Method == http.MethodPut && path == "/members/"+test.owner && (roles[actor] == "admin" || roles[actor] == "owner") && body["email"] != "":
					roles[test.owner] = "member"
					_ = json.MarshalWrite(w, map[string]string{"userId": test.owner, "role": "member"})
				case r.Method == http.MethodPost && path == "/ownership-transfer" && roles[actor] == "owner" && roles[body["userId"]] == "member":
					nominee = body["userId"]
					w.WriteHeader(http.StatusCreated)
					_ = json.MarshalWrite(w, map[string]string{"toUserId": nominee})
				case r.Method == http.MethodPost && path == "/ownership-transfer/confirm" && actor == nominee:
					roles[actor], roles[BootstrapUser], nominee = "owner", "member", ""
					_ = json.MarshalWrite(w, map[string]string{"userId": actor, "role": "owner"})
				case r.Method == http.MethodPut && path == "/members/"+BootstrapUser+"/role" && roles[actor] == "owner" && body["role"] == "admin":
					roles[BootstrapUser] = "admin"
					_ = json.MarshalWrite(w, map[string]string{"userId": BootstrapUser, "role": "admin"})
				default:
					http.Error(w, "refused", http.StatusForbidden)
				}
			}))
			t.Cleanup(admin.Close)
			terraBase := TerraBase{HTTP: admin.Client(), ClientURL: "https://127.0.0.1:1", AdminURL: admin.URL, Credential: "credential", ManagementOnAdmin: true}
			steps, err := terraBase.EnsureOwner(t.Context(), org, test.owner, email)
			if (err == nil) != (test.err == "") || err != nil && !strings.Contains(err.Error(), test.err) || fmt.Sprint(steps) != test.steps ||
				strings.Join(calls, "; ") != strings.Join(test.calls, "; ") {
				t.Fatalf("steps %v, err %v, calls:\n%s", steps, err, strings.Join(calls, "\n"))
			}
			if test.err == "" && (roles[mario] != "owner" || roles[BootstrapUser] != "admin") || test.err != "" && roles["01K78000000000000000001002"] != "" {
				t.Fatalf("roles %v", roles)
			}
		})
	}
}
