package bootstrapstart

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

func credentialPathFixture(t *testing.T) (LiveCredentials, map[string]string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "material")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(directory, name) }
	tlsFiles := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path("cert.pem"), KeyFile: path("key.pem")}
	config := natscell.Config{Cell: "gru", Instance: "broker-a", Replicas: 1,
		CredentialsFile: path("controller.creds"), TLS: tlsFiles,
		Embedded: &natscell.Embedded{TLS: tlsFiles, RouteTLS: tlsFiles,
			OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"),
			CellJWTFile: path("cell.jwt"), SystemCredentialsFile: path("system.creds"),
			TicketPublicKeyFile: path("ticket.pub")},
	}
	expected := map[string]string{}
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem", "controller.creds", "operator.jwt", "system.jwt", "cell.jwt", "system.creds", "ticket.pub", "response.key", "ticket.key"} {
		content := []byte("signed fixture " + name)
		expected[name] = digest(content)
		if err := os.WriteFile(path(name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return LiveCredentials{Config: config, ServiceUID: uint32(os.Getuid()), ServiceGID: uint32(os.Getgid()),
		ResponseKeyFile: path("response.key"), BrokerTicketKeyFile: path("ticket.key"),
		ValidateControllerKeys: func() error { return nil }, directory: directory, allowUnsafeAncestors: true}, expected
}

func TestCredentialCheckerBindsPathsAndExactInventory(t *testing.T) {
	check, expected := credentialPathFixture(t)
	if err := check.verifyPaths(expected); err != nil {
		t.Fatal(err)
	}
	if err := check.verifyInventory(expected); err != nil {
		t.Fatal(err)
	}
	wrongPath := check
	wrongConfig := wrongPath.Config
	wrongEmbedded := *wrongConfig.Embedded
	wrongConfig.Embedded = &wrongEmbedded
	wrongEmbedded.SystemJWTFile = filepath.Join(t.TempDir(), "system.jwt")
	wrongPath.Config = wrongConfig
	if err := wrongPath.verifyPaths(expected); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("unbound path = %v, want refusal", err)
	}
	delete(expected, "system.jwt")
	if err := check.verifyPaths(expected); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("missing signed credential = %v, want refusal", err)
	}
	expected["system.jwt"] = digest([]byte("signed fixture system.jwt"))
	expected["unreferenced.key"] = digest([]byte("unreferenced"))
	if err := check.verifyPaths(expected); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("unassigned signed material = %v, want refusal", err)
	}
}

func TestCredentialCheckerRejectsExtraAndChangedInstalledFiles(t *testing.T) {
	check, expected := credentialPathFixture(t)
	path := filepath.Join(check.directory, "controller.creds")
	if err := os.WriteFile(path, []byte("changed credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check.verifyInventory(expected); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("changed digest = %v, want refusal", err)
	}
	if err := os.WriteFile(path, []byte("signed fixture controller.creds"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(check.directory, "extra.key"), []byte("unpinned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check.verifyInventory(expected); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("extra credential file = %v, want refusal", err)
	}
}
