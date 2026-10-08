package tsauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
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
	for name, owners := range map[string][]map[string]any{
		"sign in once":     nil,
		"must have verifi": {{"id": "01K78000000000000000001001", "email": email}},
		"neither anonymou": {{"id": "01K78000000000000000001001", "email": email, "email_verified": true, "banned": true}},
		"has 2 users":      {{"id": "01K78000000000000000001003", "email": email, "email_verified": true}, {"id": "01K78000000000000000001004", "email": email, "email_verified": true}},
		"unusable id":      {{"id": BootstrapUser, "email": email, "email_verified": true}},
	} {
		set(owners...)
		if _, err := lookup.UserID(t.Context(), email); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, id := range []string{"", "usr_mario", "01a1105a-7350-7f48-a96e-d71bbb45d7a8", strings.ToLower("01K78000000000000000001001"), "81K78000000000000000001001", "01K7800000000000000000100I"} {
		set(map[string]any{"id": id, "email": email, "email_verified": true})
		if _, err := lookup.UserID(t.Context(), email); err == nil || !strings.Contains(err.Error(), "noncanonical user ID") {
			t.Errorf("accepted noncanonical owner %q: %v", id, err)
		}
	}
	wrong := lookup
	wrong.Key = "sk_wrong-SENTINEL"
	if _, err := wrong.UserID(t.Context(), email); err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestOuroborosFlySecrets(t *testing.T) {
	const projectID, key = "01K78000000000000000000001", "tb_SENTINEL-0123456789abcdef"
	clientSecret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("C"), 32))
	newDashboardVault := func() *fakeVault {
		return newVault(t).withSecrets("gru-1", map[string]string{dashboard.ProjectIDKey: projectID, dashboard.APIKeyKey: key,
			EnvDashboardClientSecret: clientSecret})
	}
	// The dashboard's ts-auth client is the one ts-auth registers: its
	// issuer, client id and callback.
	settings := map[string]any{"TERRABASE_URL": "https://gru.api.terrascale.tech", "TERRABASE_PROJECT_ID": projectID, "TERRABASE_DATABASE": "dashboard",
		"TS_AUTH_ISSUER": "https://gru.auth.terrascale.tech/terrascale", "TS_AUTH_CLIENT_ID": DashboardClientID,
		"TS_AUTH_REDIRECT_URL": "https://dash.terrascale.tech/login/callback"}
	check := func(output string, staged bool) {
		t.Helper()
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err != nil || strings.Count(output, "\n") != 1 || strings.Contains(output, key) ||
			strings.Contains(output, clientSecret) || result["app"] != "ts-dashboard" || result["staged"] != staged ||
			result["api_key_secret"] != "gru-1-ts-dashboard-terrabase-api-key" ||
			result["client_secret_secret"] != "gru-1-ts-auth-dashboard-client-secret" || fmt.Sprint(result["settings"]) != fmt.Sprint(settings) {
			t.Fatalf("output %q: %v", output, err)
		}
	}

	// Without a Fly token the key is not even read.
	t.Setenv("FLY_API_TOKEN", "")
	vault := newDashboardVault()
	var output bytes.Buffer
	if err := flySecrets(t.Context(), vault, testTarget.VaultID, "gru-1", &output); err != nil {
		t.Fatal(err)
	}
	check(output.String(), false)
	if len(vault.reads) != 1 || *vault.reads[0].SecretName != "gru-1-ts-dashboard-terrabase-project-id" {
		t.Fatalf("reads %d secrets", len(vault.reads))
	}

	// With one, flyctl stages all eight, the values on stdin only.
	stub := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$FLY_STUB/args\"\ncat > \"$FLY_STUB/stdin\"\n" +
		"if [ -n \"$FLY_STUB_FAIL\" ]; then cat \"$FLY_STUB/stdin\" >&2; exit 1; fi\n"
	if err := os.WriteFile(filepath.Join(stub, "flyctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", stub+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FLY_STUB", stub)
	t.Setenv("FLY_API_TOKEN", "fly-token")
	output.Reset()
	if err := flySecrets(t.Context(), newDashboardVault(), testTarget.VaultID, "gru-1", &output); err != nil {
		t.Fatal(err)
	}
	check(output.String(), true)
	args, _ := os.ReadFile(filepath.Join(stub, "args"))
	stdin, _ := os.ReadFile(filepath.Join(stub, "stdin"))
	lines := strings.Split(strings.TrimSuffix(string(stdin), "\n"), "\n")
	slices.Sort(lines)
	if string(args) != "secrets import --app ts-dashboard --stage\n" || fmt.Sprint(lines) != "[TERRABASE_API_KEY="+key+
		" TERRABASE_DATABASE=dashboard TERRABASE_PROJECT_ID="+projectID+" TERRABASE_URL=https://gru.api.terrascale.tech"+
		" TS_AUTH_CLIENT_ID="+DashboardClientID+" TS_AUTH_CLIENT_SECRET="+clientSecret+" TS_AUTH_ISSUER=https://gru.auth.terrascale.tech/terrascale"+
		" TS_AUTH_REDIRECT_URL=https://dash.terrascale.tech/login/callback]" {
		t.Fatalf("flyctl %q with stdin %q", args, stdin)
	}

	// A Vault prepared before the dashboard client secret existed stages
	// nothing and names the command that creates it.
	t.Setenv("FLY_STUB_FAIL", "")
	_ = os.Remove(filepath.Join(stub, "args"))
	older := newVault(t).withSecrets("gru-1", map[string]string{dashboard.ProjectIDKey: projectID, dashboard.APIKeyKey: key})
	if err := flySecrets(t.Context(), older, testTarget.VaultID, "gru-1", &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "ts-orch ts-auth secrets") || strings.Contains(err.Error(), key) {
		t.Fatalf("Vault without the client secret: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stub, "args")); !os.IsNotExist(err) {
		t.Fatal("flyctl ran without the client secret")
	}

	// A failing flyctl may echo its input; the error never carries the key.
	t.Setenv("FLY_STUB_FAIL", "1")
	err := flySecrets(t.Context(), newDashboardVault(), testTarget.VaultID, "gru-1", &bytes.Buffer{})
	if err == nil || strings.Contains(err.Error(), key) || strings.Contains(err.Error(), clientSecret) ||
		!strings.Contains(err.Error(), "TERRABASE_API_KEY=[redacted]") || !strings.Contains(err.Error(), "TS_AUTH_CLIENT_SECRET=[redacted]") {
		t.Fatalf("failing flyctl: %v", err)
	}
}

func TestRunOuroborosRejectsIncompleteCommands(t *testing.T) {
	var output bytes.Buffer
	if err := RunOuroboros(t.Context(), nil, &output, nil); err != nil || !strings.HasPrefix(output.String(), "Usage: ts-orch ouroboros") ||
		!strings.Contains(output.String(), "ts-dashboard (database dashboard)") {
		t.Fatalf("usage %q: %v", output.String(), err)
	}
	member := []string{"bootstrap", "--plan", "/nonexistent/plan.json", "--client-url", "https://127.0.0.1:1", "--admin-url", "http://127.0.0.1:2",
		"--member", "gru-1-db-1", "--member-ca", "/nonexistent/ca.pem", "--dashboard-credential-file", "/nonexistent/credential"}
	key := writeFile(t, "sk_test\n", 0o600)
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"rotate"}, "unknown ouroboros command"},
		{[]string{"bootstrap", "--plan", "plan.json"}, "bootstrap requires"},
		{[]string{"fly-secrets"}, "fly-secrets requires"},
		{append(slices.Clone(member), "--management-listener", "public"), "client or admin"},
		{[]string{"fly-secrets", "--plan", "plan.json", "extra"}, "unexpected"},
		{append(slices.Clone(member), "--owner-email", "mariogk@terrascale.tech", "--ts-auth-key-file", key), "--owner-email needs"},
		{append(slices.Clone(member), "--ts-auth-instance", "terrascale", "--ts-auth-key-file", key), "--owner-email needs"},
		{append(slices.Clone(member), "--owner-email", "Mario <mariogk@terrascale.tech>", "--ts-auth-instance", "terrascale", "--ts-auth-key-file", key), "--owner-email needs"},
		{append(slices.Clone(member), "--owner-email", "mariogk@terrascale.tech", "--ts-auth-instance", "terrascale", "--ts-auth-key-file", key),
			"--management-listener admin"},
		{append(slices.Clone(member), "--management-listener", "admin", "--owner-email", "mariogk@terrascale.tech", "--ts-auth-instance", "terrascale",
			"--ts-auth-key-file", key, "--ts-auth-url", "http://gru.auth.terrascale.tech"), "must be https"},
		{append(slices.Clone(member), "--management-listener", "admin", "--owner-email", "mariogk@terrascale.tech", "--ts-auth-instance", "terrascale",
			"--ts-auth-key-file", writeFile(t, "sk_test\n", 0o644)), "owner-only"},
	} {
		if err := RunOuroboros(t.Context(), test.args, &bytes.Buffer{}, nil); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%v: %v, want %q", test.args, err, test.want)
		}
	}
}

func TestOuroborosSecretNames(t *testing.T) {
	var names []string
	for _, project := range Projects {
		names = append(names, project.Name+"/"+project.Database, SecretName("gru-1", project.ProjectIDKey), SecretName("gru-1", project.APIKeyKey))
		if validSecret(project.ProjectIDKey, "01K78000000000000000000001") != nil || validSecret(project.ProjectIDKey, "auth") == nil ||
			validSecret(project.APIKeyKey, "tb_key") != nil || validSecret(project.APIKeyKey, "tb key") == nil {
			t.Errorf("%s secrets validated wrongly", project.Name)
		}
	}
	if OrganizationName != "terrascale" {
		t.Fatalf("organization %s", OrganizationName)
	}
	if got := fmt.Sprint(names); got != "[ts-auth/auth gru-1-ts-auth-terrascale-project-id gru-1-ts-auth-terrascale-api-key "+
		"ts-dashboard/dashboard gru-1-ts-dashboard-terrabase-project-id gru-1-ts-dashboard-terrabase-api-key "+
		"atlas/atlas gru-1-atlas-terrabase-project-id gru-1-atlas-store-key]" {
		t.Fatal(got)
	}
	if validSecret("TS_DASHBOARD_OTHER", "tb_key") == nil {
		t.Fatal("accepted a key outside the table")
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
		"GET /v1/management/organizations/00000000000000000000000002/projects/00000000000000000000000004/databases POST /v1/management/organizations/00000000000000000000000002/projects/00000000000000000000000004/databases]" {
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
		{"after the add", map[string]string{BootstrapUser: "owner", mario: "member"}, "", mario,
			"[transferred kept 01M4EB0GDPPHGJPPVY77EMZQKT as admin]", []string{list, start, confirm, relist, readmin}, ""},
		{"after the offer", map[string]string{BootstrapUser: "owner", mario: "member"}, mario, mario,
			"[transferred kept 01M4EB0GDPPHGJPPVY77EMZQKT as admin]", []string{list, start, confirm, relist, readmin}, ""},
		{"after the confirm", map[string]string{BootstrapUser: "member", mario: "owner"}, "", mario,
			"[kept 01M4EB0GDPPHGJPPVY77EMZQKT as admin]", []string{list, readmin}, ""},
		{"done", map[string]string{BootstrapUser: "admin", mario: "owner"}, "", mario, "[]", []string{list}, ""},
		{"another address", map[string]string{BootstrapUser: "admin", mario: "owner"}, "", "01K78000000000000000001002", "[]", []string{list}, "owned by another user"},
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
