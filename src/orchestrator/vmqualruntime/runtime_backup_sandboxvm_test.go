//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/objectstore"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualartifact"
	"testing"
	"time"
)

// curl supplies an independent SigV4 producer and verifies the generated CA and hostname.
func TestBackupFixtureTLSAndSignedObjectRoundtrip(t *testing.T) {
	store, err := objectstore.New(objectstore.Config{Namespace: "vmqual-backup"})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &qualificationBackupFixture{store: store, credentials: []backupFixtureCredential{{access: []byte("fixture-access"), secret: []byte("fixture-secret"), bucket: "fixture", region: "auto"}}}
	defer fixture.close(context.Background())
	root := store.Root()
	response := httptest.NewRecorder()
	store.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://fixture/n/vmqual-backup/b", strings.NewReader(`{"name":"fixture"}`)))
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
	certificate, ca, err := vmqualartifact.GenerateCertificate("releases.terrascale.tech", time.Now(), backupFixtureHostname)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(fixture)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	address, _ := url.Parse(server.URL)
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, ca, 0600); err != nil {
		t.Fatal(err)
	}
	request := func(method, secret string, body []byte) ([]byte, error) {
		args := []string{"--silent", "--show-error", "--fail", "--noproxy", "*", "--cacert", path, "--connect-to", backupFixtureHostname + ":443:" + address.Host, "--aws-sigv4", "aws:amz:auto:s3", "--user", "fixture-access:" + secret, "--request", method, "https://" + backupFixtureHostname + "/fixture/backup/member.tbv3e"}
		if body != nil {
			args = append(args, "--data-binary", "@-")
		}
		command := exec.CommandContext(t.Context(), "curl", args...)
		command.Stdin = bytes.NewReader(body)
		return command.CombinedOutput()
	}
	ciphertext := []byte{0x54, 0x42, 0x56, 0x33, 0xe1, 0x99, 0x00, 0x81}
	if out, err := request("PUT", "fixture-secret", ciphertext); err != nil {
		t.Fatalf("signed TLS PUT: %v %s", err, out)
	}
	got, err := request("GET", "fixture-secret", nil)
	if err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatalf("signed TLS GET: %v %x", err, got)
	}
	if _, err := request("PUT", "wrong-secret", []byte("tamper")); err == nil {
		t.Fatal("wrong signature accepted")
	}
	got, err = request("GET", "fixture-secret", nil)
	if err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatal("rejected mutation changed object")
	}
	server.Close()
	if err := fixture.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("fixture store survived cleanup")
	}
}

func TestQualificationBackupLoaderRejectsMissingBackupBeforeMaterialEffects(t *testing.T) {
	declarationPath := filepath.Join(t.TempDir(), "declaration.json")
	declaration := []byte(`{"databases":[{"backup":null}]}`)
	if err := os.WriteFile(declarationPath, declaration, 0600); err != nil {
		t.Fatal(err)
	}

	fixture, err := loadQualificationBackup(declarationPath)
	if fixture != nil {
		fixture.close(t.Context())
		t.Fatal("missing backup policy created a fixture")
	}
	if err == nil || !strings.Contains(err.Error(), "requires backup policy") {
		t.Fatalf("missing backup policy error = %v", err)
	}
}

func TestQualificationBackupLoaderAcceptsDeclaredBackup(t *testing.T) {
	temp := t.TempDir()
	accessPath := filepath.Join(temp, "access")
	secretPath := filepath.Join(temp, "secret")
	if err := os.WriteFile(accessPath, []byte("access"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	declarationPath := filepath.Join(temp, "declaration.json")
	declaration := []byte(`{"databases":[{"backup":{"destinations":[{"provider":"tigris","endpoint":"https://fly.storage.tigris.dev","signingRegion":"auto","bucket":"fixture","accessKeyFile":"` + accessPath + `","secretKeyFile":"` + secretPath + `"}]}}]}`)
	if err := os.WriteFile(declarationPath, declaration, 0600); err != nil {
		t.Fatal(err)
	}

	fixture, err := loadQualificationBackup(declarationPath)
	if err != nil {
		t.Fatal(err)
	}
	if fixture == nil || len(fixture.credentials) != 1 {
		t.Fatalf("declared backup fixture = %#v", fixture)
	}
	if err := fixture.close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestQualificationBackupLoaderRejectsMissingBackupAfterValidDatabase(t *testing.T) {
	temp := t.TempDir()
	declarationPath := filepath.Join(temp, "declaration.json")
	declaration := []byte(`{"databases":[{"backup":{"destinations":[{"provider":"tigris","endpoint":"https://fly.storage.tigris.dev","signingRegion":"auto","bucket":"fixture","accessKeyFile":"/does-not-exist/access","secretKeyFile":"/does-not-exist/secret"}]}}, {"backup":null}]}`)
	if err := os.WriteFile(declarationPath, declaration, 0600); err != nil {
		t.Fatal(err)
	}

	fixture, err := loadQualificationBackup(declarationPath)
	if fixture != nil {
		fixture.close(t.Context())
		t.Fatal("mixed declaration created a fixture")
	}
	if err == nil || !strings.Contains(err.Error(), "requires backup policy") {
		t.Fatalf("mixed declaration error = %v", err)
	}
}
