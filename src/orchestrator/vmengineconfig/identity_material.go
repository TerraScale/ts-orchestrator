package vmengineconfig

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorizationlease"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
)

const IdentityServiceKeyPath = "/etc/terrascale/terrabase/identity/service.key"
const AuthorizationLeaseKeysPath = "/etc/terrascale/terrabase/identity/authorization-lease-keys.json"

// PublicIdentity pins the existing identity authority. Credentials are private
// file references; the host receives verification keys, never a lease signer.
type PublicIdentity struct {
	Endpoint                   string `json:"endpoint"`
	Issuer                     string `json:"issuer"`
	Audience                   string `json:"audience"`
	ServiceKeyFile             string `json:"serviceKeyFile"`
	AuthorizationLeaseKeysFile string `json:"authorizationLeaseKeysFile"`
}

func IsIdentityPath(path string) bool {
	return path == IdentityServiceKeyPath || path == AuthorizationLeaseKeysPath
}

func (m *Material) IdentityFiles() map[string][]byte {
	files := make(map[string][]byte, len(m.identityFiles))
	for path, raw := range m.identityFiles {
		files[path] = bytes.Clone(raw)
	}
	return files
}

func validatePublicIdentity(identity *PublicIdentity) error {
	if identity == nil {
		return nil
	}
	if authorizationlease.ValidateAudience(identity.Audience) != nil || authorizationlease.ValidateAudience(identity.Issuer) != nil || authorizationlease.ValidateAudience(identity.Endpoint) != nil {
		return errors.New("vmengineconfig: invalid identity authority binding")
	}
	endpoint, err := url.Parse(identity.Endpoint)
	if err != nil || endpoint.Path != "/api/internal/identity/introspect" || identity.ServiceKeyFile == "" || identity.AuthorizationLeaseKeysFile == "" {
		return errors.New("vmengineconfig: incomplete identity authority configuration")
	}
	return nil
}

func renderPublicIdentity(out *strings.Builder, identity *PublicIdentity) error {
	if err := validatePublicIdentity(identity); err != nil {
		return err
	}
	if identity == nil {
		return nil
	}
	fmt.Fprintf(out, "\n[public_api.identity]\nendpoint = %q\nissuer = %q\naudience = %q\nservice_key_file = %q\nauthorization_lease_keys_file = %q\n", identity.Endpoint, identity.Issuer, identity.Audience, IdentityServiceKeyPath, AuthorizationLeaseKeysPath)
	return nil
}

func preparePublicIdentity(m *Material, api *PublicAPI) error {
	if api == nil || api.Identity == nil {
		return nil
	}
	identity := api.Identity
	if err := validatePublicIdentity(identity); err != nil {
		return err
	}
	ring, err := authorizationlease.Read(identity.AuthorizationLeaseKeysFile)
	if err != nil || !ring.Active(time.Now().Unix()) {
		return errors.New("vmengineconfig: authorization lease keys unavailable")
	}
	raw, err := bootstrapcredentials.ReadFile(identity.ServiceKeyFile, true, 4096)
	if err != nil {
		return errors.New("vmengineconfig: identity service credential unavailable")
	}
	defer clear(raw)
	key := strings.TrimSpace(string(raw))
	if len(key) < 32 || strings.ContainsAny(key, "\r\n\x00 \t") {
		return errors.New("vmengineconfig: invalid identity service credential")
	}
	for _, leaseKey := range ring.Keys {
		if key == leaseKey.Key {
			return errors.New("vmengineconfig: identity credential reuses lease verification key")
		}
	}
	encoded, err := json.Marshal(ring)
	if err != nil {
		return errors.New("vmengineconfig: authorization lease key encoding failed")
	}
	m.identityFiles = map[string][]byte{IdentityServiceKeyPath: []byte(key), AuthorizationLeaseKeysPath: encoded}
	return nil
}
