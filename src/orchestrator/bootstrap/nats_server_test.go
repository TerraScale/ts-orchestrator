package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

func TestValidateNatsServerConfigFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(path, []byte("jetstream: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		config NatsServerConfig
	}{
		{name: "missing", config: NatsServerConfig{ConfigPath: filepath.Join(dir, "missing.conf")}},
		{name: "relative", config: NatsServerConfig{ConfigPath: "server.conf"}},
		{name: "noncanonical", config: NatsServerConfig{ConfigPath: dir + string(os.PathSeparator) + "." + string(os.PathSeparator) + "server.conf"}},
		{name: "negative timeout", config: NatsServerConfig{ConfigPath: path, ReadinessTimeout: -time.Second}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewNatsServerRunner(test.config); err == nil {
				t.Fatal("expected configuration rejection")
			}
		})
	}

	link := filepath.Join(dir, "server-link.conf")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNatsServerRunner(NatsServerConfig{ConfigPath: link}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNatsServerRunner(NatsServerConfig{ConfigPath: path}); err == nil || !strings.Contains(err.Error(), "accessible") {
		t.Fatalf("expected permission rejection, got %v", err)
	}
}

func TestValidateNatsServerOptionsRequiresProductionSecurity(t *testing.T) {
	t.Parallel()
	options := &server.Options{}
	if err := validateNatsServerOptions(options); err == nil {
		t.Fatal("expected JetStream rejection")
	}
	options.JetStream = true
	options.StoreDir = filepath.Join(t.TempDir(), "store")
	if err := validateNatsServerOptions(options); err == nil {
		t.Fatal("expected TLS rejection")
	}
}

func TestLoadNatsServerOptionsRejectsIncludes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(path, []byte("include \"secrets.conf\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNatsServerOptions(path); err == nil || !strings.Contains(err.Error(), "must not use include") {
		t.Fatalf("include error = %v", err)
	}
	for _, safe := range [][]byte{
		[]byte("# include \"ignored.conf\"\nport: 4222\n"),
		[]byte("description: \"include is documentation\"\nport: 4222\n"),
	} {
		if containsNatsIncludeDirective(safe) {
			t.Fatalf("safe text was classified as an include: %q", safe)
		}
	}
}

func TestParserErrorDoesNotExposeConfigurationSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.conf")
	const secret = "marker-password-must-not-leak"
	configuration := "authorization: { password: \"" + secret + "\" }\ninvalid_field: [\n"
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadNatsServerOptions(path)
	if err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("parser error exposed secret: %v", err)
	}
}

func TestRunNatsServerCancellation(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := makeCertificate(t, nil, nil, true)
	serverCert, serverKey := makeCertificate(t, caCert, caKey, false)
	for name, data := range map[string][]byte{
		"ca.pem":         caCert,
		"ca-key.pem":     caKey,
		"server.pem":     serverCert,
		"server-key.pem": serverKey,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	storeDir := filepath.Join(dir, "store")
	if err := os.Mkdir(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "server.conf")
	config := fmt.Sprintf(`listen: "127.0.0.1:0"
jetstream: { store_dir: %q }
tls: {
  cert_file: %q
  key_file: %q
  ca_file: %q
  verify: true
  min_version: "1.3"
}
accounts: {
  CONTROL: { users: [{ user: "runner", password: "test-only" }] }
}
`, storeDir, filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"), filepath.Join(dir, "ca.pem"))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- RunNatsServer(ctx, NatsServerConfig{ConfigPath: configPath, ReadinessTimeout: 10 * time.Second})
	}()
	// The runner only returns after startup or failure. Waiting briefly before
	// cancellation also exercises the normal Start -> readiness path.
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not shut down after cancellation")
	}
}

// makeCertificate returns PEM certificate and PKCS#1 private key. It keeps
// this test self-contained and does not add development trust material to the
// repository.
func makeCertificate(t *testing.T, parentCertPEM, parentKeyPEM []byte, isCA bool) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-nats"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.ExtKeyUsage = nil
	}
	var parent *x509.Certificate
	parentKey := any(key)
	if len(parentCertPEM) != 0 {
		block, _ := pem.Decode(parentCertPEM)
		parent, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		keyBlock, _ := pem.Decode(parentKeyPEM)
		parentKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentOrSelf(parent, template), key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func parentOrSelf(parent *x509.Certificate, self *x509.Certificate) *x509.Certificate {
	if parent != nil {
		return parent
	}
	return self
}
