package tsauth

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// TestBootstrapAgainstTerraBaseRelease runs ouroboros bootstrap against one
// member of the real TerraBase release, configured like a gru-1 member: its
// client listener serves the member certificate of the cell CA and the
// Management API with a dashboard credential, and its loopback admin
// listener issues API keys. The first run creates organization
// OrganizationName and, for every project of Projects, its project,
// database and a key that reaches the database, and stores the project IDs
// and keys in a fake Vault; a rerun finds all of them and issues no key.
// Neither project's key reads the other's database. Phase B then hands the
// organization to a ts-auth user of a fake ts-auth users API: it stops while
// no user has the address, replaces an invitation an interrupted run left,
// transfers the ownership and keeps the bootstrap identity as an admin, and
// a rerun of either phase changes nothing. A wrong credential or member name
// is refused without printing the credential.
//
// TS_TERRABASE_BINARY names a terrabase-linux-<arch> release asset with its
// .sha256 asset beside it.
func TestBootstrapAgainstTerraBaseRelease(t *testing.T) {
	release := tier.Qualification(t, "TS_TERRABASE_BINARY")[0]
	if _, err := terrabase.VerifyRelease(release, release+".sha256"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, filepath.Base(release))
	data, err := os.ReadFile(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, data, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caPEM, caKey, err := terrabase.NewCA("gru-1", now)
	if err != nil {
		t.Fatal(err)
	}
	caPath := writeFile(t, string(caPEM), 0o600)
	ca, err := terrabase.LoadCA(caPath, writeFile(t, string(caKey), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	adminPort, peerPort, clientPort := freePort(t), freePort(t), freePort(t)
	member := terrabase.Peer{Name: "gru-1-db-1", Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(peerPort))}
	layout := terrabase.Layout(filepath.Join(dir, "member"))
	for _, path := range []string{string(layout), layout.TLS(), layout.Data(), layout.Bundle()} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key, csr, err := terrabase.NewMemberKey()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := ca.Issue(csr, member, now)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{layout.Key(): key, layout.Certificate(): certificate, layout.CA(): ca.CertificatePEM()} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	credential, err := Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := writeFile(t, credential+"\n", 0o600)
	env := layout.Env(map[string]string{terrabase.EnvAdminPort: strconv.Itoa(adminPort), terrabase.EnvPeerPort: strconv.Itoa(peerPort),
		terrabase.EnvClientPort: strconv.Itoa(clientPort), terrabase.EnvPeers: member.Name + "=" + member.Address.String()},
		terrabase.Profile{PeerPort: peerPort, ClientPort: clientPort})
	env["TERRABASE_DASHBOARD_CREDENTIAL_FILE"] = credentialPath
	log := startTerraBase(t, binary, env, adminPort)

	clientURL, adminURL := "https://127.0.0.1:"+strconv.Itoa(clientPort), "http://127.0.0.1:"+strconv.Itoa(adminPort)
	terraBase, err := memberClient(clientURL, adminURL, member.Name, caPath, credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	vault := newVault(t)
	type result struct {
		Tenant  Tenant   `json:"tenant"`
		Secrets []Stored `json:"secrets"`
	}
	run := func() []result {
		t.Helper()
		var output bytes.Buffer
		if _, err := bootstrap(t.Context(), terraBase, vault, vault, testTarget, "gru-1", &output); err != nil {
			t.Fatalf("bootstrap: %v\n%s", err, readLog(log))
		}
		var results []result
		for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
			var parsed result
			if err := json.Unmarshal([]byte(line), &parsed, json.RejectUnknownMembers(true)); err != nil {
				t.Fatalf("line %q: %v", line, err)
			}
			results = append(results, parsed)
		}
		for _, project := range Projects {
			if strings.Contains(output.String(), vault.stored(SecretName("gru-1", project.APIKeyKey))) {
				t.Fatalf("output carries the %s API key", project.Name)
			}
		}
		return results
	}
	first := run()
	if len(first) != len(Projects) || len(vault.creates) != 2*len(Projects) {
		t.Fatalf("first run: %+v, %d Vault creates", first, len(vault.creates))
	}
	tenants := map[string]Tenant{}
	for index, project := range Projects {
		tenant, stored := first[index].Tenant, first[index].Secrets
		if tenant.OrganizationID != first[0].Tenant.OrganizationID || tenant.Project != project.Name || tenant.ProjectID == "" ||
			tenant.DatabaseID == "" || tenant.Database != project.Database || len(stored) != 2 || !stored[0].Created || !stored[1].Created ||
			stored[0].Secret != SecretName("gru-1", project.ProjectIDKey) || stored[1].Secret != SecretName("gru-1", project.APIKeyKey) ||
			vault.stored(stored[0].Secret) != tenant.ProjectID || !strings.HasPrefix(vault.stored(stored[1].Secret), "tb_") {
			t.Fatalf("first run, project %s: tenant %+v, secrets %+v", project.Name, tenant, stored)
		}
		tenants[project.Name] = tenant
	}
	if tenants[ProjectName].ProjectID == tenants["ts-dashboard"].ProjectID || vault.stored("gru-1-ts-auth-terrascale-api-key") == vault.stored("gru-1-ts-dashboard-terrabase-api-key") {
		t.Fatal("the projects share a project or key")
	}
	issued := map[string]string{}
	for _, project := range Projects {
		issued[project.Name] = vault.stored(SecretName("gru-1", project.APIKeyKey))
	}
	rerun := func() {
		t.Helper()
		again := run()
		for index, project := range Projects {
			if again[index].Tenant != tenants[project.Name] || again[index].Secrets[0].Created || again[index].Secrets[1].Created ||
				vault.stored(SecretName("gru-1", project.APIKeyKey)) != issued[project.Name] {
				t.Fatalf("rerun, project %s: %+v", project.Name, again[index])
			}
		}
		if len(vault.creates) != 2*len(Projects) {
			t.Fatalf("rerun created Vault secrets: %d", len(vault.creates))
		}
	}
	rerun()
	// The organization, projects and databases have the decided names.
	var organizations struct {
		Items []named `json:"items"`
	}
	if err := terraBase.management(t.Context(), "GET", "", "/v1/management/organizations", nil, 200, &organizations); err != nil {
		t.Fatal(err)
	}
	if len(organizations.Items) != 1 || organizations.Items[0] != (named{ID: first[0].Tenant.OrganizationID, Name: OrganizationName}) {
		t.Fatalf("organizations %+v", organizations.Items)
	}
	// Each key reaches its own database only.
	if err := terraBase.CheckKey(t.Context(), tenants[ProjectName], issued["ts-dashboard"]); err == nil {
		t.Fatal("ts-dashboard's key reached ts-auth's database")
	}
	if err := terraBase.CheckKey(t.Context(), tenants["ts-dashboard"], issued[ProjectName]); err == nil {
		t.Fatal("ts-auth's key reached ts-dashboard's database")
	}
	tenant := tenants[ProjectName]

	// Phase B: the owner is a ts-auth user, found by its verified address.
	const email = "mariogk@terrascale.tech"
	var tsAuthUsers []map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/terrascale/users" || r.Header.Get("Authorization") != "Bearer sk_test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.MarshalWrite(w, map[string]any{"data": tsAuthUsers})
	}))
	t.Cleanup(server.Close)
	users := TSAuthUsers{HTTP: server.Client(), URL: server.URL, Instance: "terrascale", Key: "sk_test"}
	organization := tenant.OrganizationID
	owned := func() map[string]any {
		t.Helper()
		var output bytes.Buffer
		if err := own(t.Context(), terraBase, users, organization, email, &output); err != nil {
			t.Fatalf("own: %v\n%s", err, readLog(log))
		}
		var result map[string]any
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || strings.Count(output.String(), "\n") != 1 {
			t.Fatalf("output %q: %v", output.String(), err)
		}
		return result
	}
	if err := own(t.Context(), terraBase, users, organization, email, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "sign in once") {
		t.Fatalf("missing user: %v", err)
	}
	tsAuthUsers = []map[string]any{{"id": "usr_other", "email": "someone@terrascale.tech", "email_verified": true},
		{"id": "usr_mario", "email": "MarioGK@terrascale.tech", "email_verified": true}}
	// An invitation of an interrupted run is replaced: its token is lost.
	if _, err := terraBase.invite(t.Context(), organization, email); err != nil {
		t.Fatal(err)
	}
	if result := owned(); fmt.Sprint(result["steps"]) != "[joined transferred kept ts-orchestrator as admin]" ||
		result["owner"] != "usr_mario" || result["admin"] != BootstrapUser || result["organization_id"] != organization {
		t.Fatalf("ownership: %v", result)
	}
	roles, err := TerraBase{HTTP: terraBase.HTTP, ClientURL: clientURL, Credential: terraBase.Credential, User: "usr_mario"}.roles(t.Context(), organization)
	if err != nil || len(roles) != 2 || roles["usr_mario"] != "owner" || roles[BootstrapUser] != "admin" {
		t.Fatalf("roles %v: %v", roles, err)
	}
	if result := owned(); fmt.Sprint(result["steps"]) != "[]" {
		t.Fatalf("ownership rerun: %v", result)
	}
	// As an admin the bootstrap identity still finds everything.
	rerun()

	// A Vault holding another project's ID stops a bootstrap before any key
	// is issued or stored.
	stale := newVault(t)
	stale.add(SecretName("gru-1", EnvProjectID), "ACTIVE")
	stale.withSecrets("gru-1", map[string]string{EnvProjectID: "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d"})
	if _, err := bootstrap(t.Context(), terraBase, stale, stale, testTarget, "gru-1", &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "names project") || len(stale.creates) != 0 {
		t.Fatalf("stale project ID: %v, %d Vault creates", err, len(stale.creates))
	}

	// A key for another tenant does not reach this database.
	foreign, err := TerraBase{HTTP: terraBase.HTTP, ClientURL: clientURL, AdminURL: adminURL, Credential: terraBase.Credential,
		User: "someone-else"}.EnsureTenant(t.Context(), Projects[0])
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, err := terraBase.IssueKey(t.Context(), foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := terraBase.CheckKey(t.Context(), tenant, foreignKey); err == nil {
		t.Fatal("another tenant's key reached ts-auth's database")
	}

	wrong := terraBase
	wrong.Credential = "wrong-credential-SENTINEL-0123456789abcdef"
	if _, err := wrong.EnsureTenant(t.Context(), Projects[0]); err == nil || !strings.Contains(err.Error(), "HTTP 401") ||
		strings.Contains(err.Error(), wrong.Credential) {
		t.Fatalf("wrong credential: %v", err)
	}
	other, err := memberClient(clientURL, adminURL, "gru-1-db-2", caPath, credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.EnsureTenant(t.Context(), Projects[0]); err == nil {
		t.Fatal("trusted a member certificate that names another member")
	}
}

// startTerraBase starts the release with the host's base environment and
// waits until its admin listener answers; the member is stopped at cleanup.
func startTerraBase(t *testing.T, binary string, env map[string]string, adminPort int) string {
	t.Helper()
	command := exec.Command(binary)
	command.Env = []string{"HOME=/", "LANG=C", "PATH=/usr/bin:/bin"}
	for key, value := range env {
		command.Env = append(command.Env, key+"="+value)
	}
	log := filepath.Join(t.TempDir(), "terrabase.log")
	file, err := os.Create(log)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	command.Stdout, command.Stderr = file, file
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(40 * time.Second):
			_ = command.Process.Kill()
		}
	})
	deadline := time.After(60 * time.Second)
	for {
		err := terrabase.Healthy(t.Context(), adminPort)
		if err == nil {
			return log
		}
		select {
		case exit := <-exited:
			t.Fatalf("terrabase exited before it was healthy: %v\n%s", exit, readLog(log))
		case <-deadline:
			t.Fatalf("terrabase never became healthy: %v\n%s", err, readLog(log))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func readLog(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
