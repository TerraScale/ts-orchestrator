package tsauth

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
			users = append(users, map[string]any{"id": fmt.Sprintf("usr_%03d", index), "email": fmt.Sprintf("user%d@example.com", index), "email_verified": true})
		}
		users = append(users, owners...)
		cursors = nil
	}

	set(map[string]any{"id": "usr_mario", "email": "MarioGK@TerraScale.tech", "email_verified": true})
	if id, err := lookup.UserID(t.Context(), email); err != nil || id != "usr_mario" || fmt.Sprint(cursors) != "[ usr_099]" {
		t.Fatalf("user %q, cursors %v: %v", id, cursors, err)
	}
	for name, owners := range map[string][]map[string]any{
		"sign in once":     nil,
		"must have verifi": {{"id": "usr_mario", "email": email}},
		"neither anonymou": {{"id": "usr_mario", "email": email, "email_verified": true, "banned": true}},
		"has 2 users":      {{"id": "usr_a", "email": email, "email_verified": true}, {"id": "usr_b", "email": email, "email_verified": true}},
		"unusable id":      {{"id": BootstrapUser, "email": email, "email_verified": true}},
	} {
		set(owners...)
		if _, err := lookup.UserID(t.Context(), email); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	wrong := lookup
	wrong.Key = "sk_wrong-SENTINEL"
	if _, err := wrong.UserID(t.Context(), email); err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestOuroborosFlySecrets(t *testing.T) {
	const projectID, key = "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d", "tb_SENTINEL-0123456789abcdef"
	newDashboardVault := func() *fakeVault {
		return newVault(t).withSecrets("gru-1", map[string]string{dashboard.ProjectIDKey: projectID, dashboard.APIKeyKey: key})
	}
	settings := map[string]any{"TERRABASE_URL": "https://gru.api.terrascale.tech", "TERRABASE_PROJECT_ID": projectID, "TERRABASE_DATABASE": "dashboard"}
	check := func(output string, staged bool) {
		t.Helper()
		var result map[string]any
		if err := json.Unmarshal([]byte(output), &result); err != nil || strings.Count(output, "\n") != 1 || strings.Contains(output, key) ||
			result["app"] != "ts-dashboard" || result["staged"] != staged || result["api_key_secret"] != "gru-1-ts-dashboard-terrabase-api-key" ||
			fmt.Sprint(result["settings"]) != fmt.Sprint(settings) {
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

	// With one, flyctl stages all four, the values on stdin only.
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
		" TERRABASE_DATABASE=dashboard TERRABASE_PROJECT_ID="+projectID+" TERRABASE_URL=https://gru.api.terrascale.tech]" {
		t.Fatalf("flyctl %q with stdin %q", args, stdin)
	}

	// A failing flyctl may echo its input; the error never carries the key.
	t.Setenv("FLY_STUB_FAIL", "1")
	err := flySecrets(t.Context(), newDashboardVault(), testTarget.VaultID, "gru-1", &bytes.Buffer{})
	if err == nil || strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "TERRABASE_API_KEY=[redacted]") {
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
		{append(slices.Clone(member), "--owner-email", "mariogk@terrascale.tech", "--ts-auth-instance", "terrascale", "--ts-auth-key-file", key,
			"--ts-auth-url", "http://auth.terrascale.tech"), "must be https"},
		{append(slices.Clone(member), "--owner-email", "mariogk@terrascale.tech", "--ts-auth-instance", "terrascale",
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
		if validSecret(project.ProjectIDKey, "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d") != nil || validSecret(project.ProjectIDKey, "auth") == nil ||
			validSecret(project.APIKeyKey, "tb_key") != nil || validSecret(project.APIKeyKey, "tb key") == nil {
			t.Errorf("%s secrets validated wrongly", project.Name)
		}
	}
	if OrganizationName != "terrascale" {
		t.Fatalf("organization %s", OrganizationName)
	}
	if got := fmt.Sprint(names); got != "[ts-auth/auth gru-1-ts-auth-terrascale-project-id gru-1-ts-auth-terrascale-api-key "+
		"ts-dashboard/dashboard gru-1-ts-dashboard-terrabase-project-id gru-1-ts-dashboard-terrabase-api-key]" {
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
		if r.Header.Get("Authorization") != "Bearer credential" || r.Header.Get("X-TerraBase-User-Id") != BootstrapUser {
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
		_ = json.MarshalWrite(w, named{ID: fmt.Sprintf("id-%d", len(seen)), Name: body.Name})
	}))
	t.Cleanup(admin.Close)
	terraBase := TerraBase{HTTP: admin.Client(), ClientURL: "https://127.0.0.1:1", AdminURL: admin.URL, Credential: "credential", ManagementOnAdmin: true}
	tenant, err := terraBase.EnsureTenant(t.Context(), dashboard)
	if err != nil || tenant != (Tenant{OrganizationID: "id-2", Project: "ts-dashboard", ProjectID: "id-4", DatabaseID: "id-6", Database: "dashboard"}) {
		t.Fatalf("tenant %+v: %v", tenant, err)
	}
	if got := fmt.Sprint(seen); got != "[GET /v1/management/organizations POST /v1/management/organizations "+
		"GET /v1/management/organizations/id-2/projects POST /v1/management/organizations/id-2/projects "+
		"GET /v1/management/organizations/id-2/projects/id-4/databases POST /v1/management/organizations/id-2/projects/id-4/databases]" {
		t.Fatal(got)
	}
}
