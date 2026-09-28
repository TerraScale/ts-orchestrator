//go:build linux

package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagedClientMaterialPinsFilesAndDeterministicPaths(t *testing.T) {
	material := t.TempDir()
	identity := WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	digest := func(data []byte) string {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	write := func(name string, data []byte) {
		t.Helper()
		path := filepath.Join(material, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0440); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0440); err != nil {
			t.Fatal(err)
		}
	}
	chain, key, registry := []byte("certificate chain"), []byte("private key"), []byte(`{"keys":[]}`)
	write(managedClientChainName, chain)
	write(managedClientKeyName, key)
	write(managedClientRegistryName, registry)
	config := managedClientConfig{
		Version: 1, ListenAddress: "10.251.0.21:9465",
		CertificateChain: filepath.Join(material, managedClientChainName),
		PrivateKey:       filepath.Join(material, managedClientKeyName),
		APIKeyRegistry:   filepath.Join(material, managedClientRegistryName),
	}
	writeConfig := func() string {
		t.Helper()
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		write(managedClientConfigName, data)
		manifest := managedClientManifest{Version: 1, ClientConfigSHA256: digest(data),
			CertificateChainSHA256: digest(chain), PrivateKeySHA256: digest(key), APIKeyRegistrySHA256: digest(registry)}
		manifestBytes, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		write(managedClientManifestName, manifestBytes)
		return digest(manifestBytes)
	}
	pin := writeConfig()
	args, err := readManagedClientMaterial(material, pin, "", "", identity, identity.UID)
	if err != nil || !slices.Contains(args, "--client-allow-nonloopback") || !slices.Contains(args, pin) {
		t.Fatalf("valid pinned client material = %v, %v", args, err)
	}
	for address, nonloopback := range map[string]bool{
		"": false, "127.0.0.1:9465": false, "10.251.0.21:9465": true, "172.16.0.5:9465": true, "192.168.1.2:9465": true,
	} {
		config.ListenAddress = address
		args, err := readManagedClientMaterial(material, writeConfig(), "", "", identity, identity.UID)
		if err != nil || slices.Contains(args, "--client-allow-nonloopback") != nonloopback {
			t.Fatalf("private or loopback listener %q = %v, %v", address, args, err)
		}
	}
	for _, address := range []string{"192.0.2.10:9465", "8.8.8.8:9465", "0.0.0.0:9465", "169.254.169.254:9465",
		"[::1]:9465", "[fd00::1]:9465", "10.251.0.21:0", "10.251.0.21", "localhost:9465", "010.251.0.21:9465"} {
		config.ListenAddress = address
		if _, err := readManagedClientMaterial(material, writeConfig(), "", "", identity, identity.UID); err == nil {
			t.Fatalf("non-private client listener %q was accepted", address)
		}
	}
	config.ListenAddress = "10.251.0.21:9465"
	config.CertificateChain = filepath.Join(material, "foreign.pem")
	pin = writeConfig()
	if _, err := readManagedClientMaterial(material, pin, "", "", identity, identity.UID); err == nil {
		t.Fatal("signed config redirected a client material path")
	}
	config.CertificateChain = filepath.Join(material, managedClientChainName)
	pin = writeConfig()
	if err := os.Chmod(filepath.Join(material, managedClientKeyName), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedClientMaterial(material, pin, "", "", identity, identity.UID); err == nil {
		t.Fatal("workload-only key mode was accepted")
	}
	if err := os.Chmod(filepath.Join(material, managedClientKeyName), 0440); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(material, managedClientConfigName)
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(configPath, 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedClientMaterial(material, pin, "", "", identity, identity.UID); err == nil {
		t.Fatal("FIFO client config was accepted")
	}
}

func TestManagedClientMaterialRequiresPinnedPrivateSQLBundleAndSocket(t *testing.T) {
	material := t.TempDir()
	identity := WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	digest := func(data []byte) string {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	write := func(name string, data []byte) {
		t.Helper()
		path := filepath.Join(material, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0440); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0440); err != nil {
			t.Fatal(err)
		}
	}
	chain, key, registry := []byte("certificate chain"), []byte("private key"), []byte(`{"keys":[]}`)
	write(managedClientChainName, chain)
	write(managedClientKeyName, key)
	write(managedClientRegistryName, registry)
	sqlBundle := []byte("TBSQB001 test bytes")
	write(sqlSchemaBundleName, sqlBundle)
	config := managedClientConfig{
		Version: 1, ListenAddress: "10.77.39.11:9465", SQLListenAddress: "10.77.39.11:5432",
		CertificateChain: filepath.Join(material, managedClientChainName),
		PrivateKey:       filepath.Join(material, managedClientKeyName),
		APIKeyRegistry:   filepath.Join(material, managedClientRegistryName),
	}
	writeConfig := func() string {
		t.Helper()
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		write(managedClientConfigName, data)
		manifest := managedClientManifest{Version: 1, ClientConfigSHA256: digest(data),
			CertificateChainSHA256: digest(chain), PrivateKeySHA256: digest(key), APIKeyRegistrySHA256: digest(registry)}
		manifestBytes, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		write(managedClientManifestName, manifestBytes)
		return digest(manifestBytes)
	}
	manifestDigest := writeConfig()
	sqlDigest := digest(sqlBundle)
	args, err := readManagedClientMaterial(material, manifestDigest, sqlDigest, "10.77.39.11:7000",
		identity, identity.UID)
	if err != nil || !slices.Contains(args, "--sql-schema-bundle") ||
		!slices.Contains(args, filepath.Join(material, sqlSchemaBundleName)) {
		t.Fatalf("valid pinned SQL bundle was not passed by absolute path: args=%v err=%v", args, err)
	}
	if _, err := readManagedClientMaterial(material, manifestDigest, "", "10.77.39.11:7000",
		identity, identity.UID); err == nil {
		t.Fatal("configured SQL listener was accepted without a signed SQL bundle pin")
	}

	for _, address := range []string{"0.0.0.0:5432", "8.8.8.8:5432", "10.77.39.11:7000"} {
		config.SQLListenAddress = address
		manifestDigest = writeConfig()
		if _, err := readManagedClientMaterial(material, manifestDigest, sqlDigest, "10.77.39.11:7000",
			identity, identity.UID); err == nil {
			t.Fatalf("unsafe SQL listener %q was accepted", address)
		}
	}
	config.SQLListenAddress = "10.77.39.11:5432"
	manifestDigest = writeConfig()
	if _, err := readManagedClientMaterial(material, manifestDigest, strings.Repeat("a", 64), "10.77.39.11:7000",
		identity, identity.UID); err == nil {
		t.Fatal("SQL bundle with a mismatched signed digest was accepted")
	}
}
