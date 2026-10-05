package tsauth

import (
	"bytes"
	"encoding/json/v2"
	"net"
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

// TestBootstrapAgainstTerraBaseRelease runs terrabase-bootstrap against one
// member of the real TerraBase release, configured like a gru-1 member: its
// client listener serves the member certificate of the cell CA and the
// Management API with a dashboard credential, and its loopback admin
// listener issues API keys. The first run creates organization
// terrascale-internal, project auth, database auth and a key that reaches the
// database, and stores the project ID and key in a fake Vault; a rerun finds
// all of them and issues no key. A wrong credential or member name is refused
// without printing the credential.
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
	run := func() (Tenant, []Stored) {
		t.Helper()
		var output bytes.Buffer
		if err := bootstrap(t.Context(), terraBase, vault, vault, testTarget, "gru-1", &output); err != nil {
			t.Fatalf("bootstrap: %v\n%s", err, readLog(log))
		}
		if strings.Count(output.String(), "\n") != 1 || strings.Contains(output.String(), vault.stored(SecretName("gru-1", EnvAPIKey))) {
			t.Fatalf("output is not one line without the API key: %q", output.String())
		}
		var result struct {
			Tenant  Tenant   `json:"tenant"`
			Secrets []Stored `json:"secrets"`
		}
		if err := json.Unmarshal(output.Bytes(), &result, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		return result.Tenant, result.Secrets
	}
	tenant, stored := run()
	if tenant.OrganizationID == "" || tenant.ProjectID == "" || tenant.DatabaseID == "" || tenant.Database != "auth" ||
		len(stored) != 2 || !stored[0].Created || !stored[1].Created ||
		vault.stored("gru-1-ts-auth-terrascale-project-id") != tenant.ProjectID {
		t.Fatalf("first run: tenant %+v, secrets %+v", tenant, stored)
	}
	issued := vault.stored("gru-1-ts-auth-terrascale-api-key")
	if !strings.HasPrefix(issued, "tb_") {
		t.Fatal("the Vault holds no TerraBase API key")
	}
	again, storedAgain := run()
	if again != tenant || storedAgain[0].Created || storedAgain[1].Created || len(vault.creates) != 2 ||
		vault.stored("gru-1-ts-auth-terrascale-api-key") != issued {
		t.Fatalf("rerun: tenant %+v, secrets %+v, %d Vault creates", again, storedAgain, len(vault.creates))
	}
	// The organization, project and database have the decided names.
	var organizations struct {
		Items []named `json:"items"`
	}
	if err := terraBase.management(t.Context(), "GET", "", "/v1/management/organizations", nil, 200, &organizations); err != nil {
		t.Fatal(err)
	}
	if len(organizations.Items) != 1 || organizations.Items[0] != (named{ID: tenant.OrganizationID, Name: "terrascale-internal"}) {
		t.Fatalf("organizations %+v", organizations.Items)
	}

	// A Vault holding another project's ID stops a bootstrap before any key
	// is issued or stored.
	stale := newVault(t)
	stale.add(SecretName("gru-1", EnvProjectID), "ACTIVE")
	stale.withSecrets("gru-1", map[string]string{EnvProjectID: "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d"})
	if err := bootstrap(t.Context(), terraBase, stale, stale, testTarget, "gru-1", &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "names project") || len(stale.creates) != 0 {
		t.Fatalf("stale project ID: %v, %d Vault creates", err, len(stale.creates))
	}

	// A key for another tenant does not reach this database.
	foreign, err := TerraBase{HTTP: terraBase.HTTP, ClientURL: clientURL, AdminURL: adminURL, Credential: terraBase.Credential,
		User: "someone-else"}.EnsureTenant(t.Context())
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
	if _, err := wrong.EnsureTenant(t.Context()); err == nil || !strings.Contains(err.Error(), "HTTP 401") ||
		strings.Contains(err.Error(), wrong.Credential) {
		t.Fatalf("wrong credential: %v", err)
	}
	other, err := memberClient(clientURL, adminURL, "gru-1-db-2", caPath, credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.EnsureTenant(t.Context()); err == nil {
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
