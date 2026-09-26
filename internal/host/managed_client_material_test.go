//go:build linux

package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
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
		Version: 1, ListenAddress: "192.0.2.10:9465",
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
	args, err := readManagedClientMaterial(material, pin, identity, identity.UID)
	if err != nil || !slices.Contains(args, "--client-allow-nonloopback") || !slices.Contains(args, pin) {
		t.Fatalf("valid pinned client material = %v, %v", args, err)
	}
	config.CertificateChain = filepath.Join(material, "foreign.pem")
	pin = writeConfig()
	if _, err := readManagedClientMaterial(material, pin, identity, identity.UID); err == nil {
		t.Fatal("signed config redirected a client material path")
	}
	config.CertificateChain = filepath.Join(material, managedClientChainName)
	pin = writeConfig()
	if err := os.Chmod(filepath.Join(material, managedClientKeyName), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedClientMaterial(material, pin, identity, identity.UID); err == nil {
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
	if _, err := readManagedClientMaterial(material, pin, identity, identity.UID); err == nil {
		t.Fatal("FIFO client config was accepted")
	}
}
