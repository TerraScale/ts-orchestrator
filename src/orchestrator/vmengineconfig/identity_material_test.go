package vmengineconfig_test

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func TestIdentityAuthorityProvisioningUsesNativeOwnedPrivateFiles(t *testing.T) {
	declaration, path := testengineconfig.Declaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
	dir := t.TempDir()
	servicePath, ringPath := filepath.Join(dir, "service.key"), filepath.Join(dir, "lease.json")
	service := strings.Repeat("identity-service-", 3)
	ring := []byte(`{"keys":[{"keyId":"lease","key":"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd","notBefore":1,"notAfter":4102444800}]}`)
	if err := os.WriteFile(servicePath, []byte(service), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ringPath, ring, 0600); err != nil {
		t.Fatal(err)
	}
	declaration.PublicAPI = &vmengineconfig.PublicAPI{Listen: "0.0.0.0:8080", DataRoot: "/var/lib/terrascale/terrabase", Identity: &vmengineconfig.PublicIdentity{Endpoint: "https://app.terrascale.tech/api/internal/identity/introspect", Issuer: "https://app.terrascale.tech", Audience: "https://api.terrascale.tech", ServiceKeyFile: servicePath, AuthorizationLeaseKeysFile: ringPath}}
	save := func() {
		t.Helper()
		raw, err := json.Marshal(declaration)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	materials, err := vmengineconfig.Load(path, declaration.ArtifactSHA256, declaration.Release, bindings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, material := range materials {
			material.Clear()
		}
	}()
	for _, material := range materials {
		files := material.IdentityFiles()
		if len(files) != 2 || !bytes.Equal(files[vmengineconfig.IdentityServiceKeyPath], []byte(service)) || !bytes.Equal(files[vmengineconfig.AuthorizationLeaseKeysPath], ring) {
			t.Fatal("private identity material changed")
		}
		config := manifest(t, material).Components[0].Configuration
		if !strings.Contains(config, "[public_api.identity]") || !strings.Contains(config, `authorization_lease_keys_file = "`+vmengineconfig.AuthorizationLeaseKeysPath+`"`) || strings.Contains(config, service) || strings.Contains(config, string(ring)) {
			t.Fatal("identity configuration missing or exposes secrets")
		}
		if material.ControlFiles()[vmengineconfig.IdentityServiceKeyPath] != nil {
			t.Fatal("native identity credential assigned to orchestrator")
		}
		files[vmengineconfig.IdentityServiceKeyPath][0] = 'x'
		clone := material.Clone()
		clone.Clear()
		if material.IdentityFiles()[vmengineconfig.IdentityServiceKeyPath][0] == 'x' {
			t.Fatal("private buffers alias caller or clone")
		}
	}
	if err := os.Chmod(ringPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := vmengineconfig.Load(path, declaration.ArtifactSHA256, declaration.Release, bindings); err == nil {
		t.Fatal("public lease key file admitted")
	}
	if err := os.Chmod(ringPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(servicePath, []byte(strings.Repeat("A", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ringPath, []byte(`{"keys":[{"keyId":"lease","key":"`+strings.Repeat("41", 32)+`","notBefore":1,"notAfter":4102444800}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vmengineconfig.Load(path, declaration.ArtifactSHA256, declaration.Release, bindings); err == nil {
		t.Fatal("identity credential reuses decoded lease key bytes")
	}
	declaration.PublicAPI.Identity.AuthorizationLeaseKeysFile = ""
	save()
	if _, err := vmengineconfig.Load(path, declaration.ArtifactSHA256, declaration.Release, bindings); err == nil {
		t.Fatal("identity admitted without lease verification keys")
	}
}
