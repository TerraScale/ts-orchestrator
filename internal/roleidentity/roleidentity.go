// Package roleidentity is the NATS identity of the roles ts-orch places
// (TS-651): which KV buckets each role's members use, and the cell account's
// one "role" scoped signer that grants them.
package roleidentity

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// A role the orchestrator places gets a NATS identity of its own (TS-651):
// a user JWT from the cell account's one "role" scoped signer and a client
// certificate from the host TLS issuer. The scope's template grants each user
// the KV buckets its "kv" tags name, so a new bucket needs a new controller
// release, never a new account claim.

// Bucket is one KV bucket a role's members use. The controller creates it with
// this configuration before it issues the role's credentials: roles get no
// stream API beyond reads, since a stream create names any subjects.
type Bucket struct {
	Name    string
	TTL     time.Duration // the bucket's max_age; zero keeps entries
	History uint8
	Memory  bool
}

// Grant is what one role's members may reach on the cell's NATS.
type Grant struct {
	// EnvPrefix names the launch settings the host adds: <prefix>URL,
	// <prefix>CREDENTIALS_FILE, <prefix>CERTIFICATE, <prefix>PRIVATE_KEY and
	// <prefix>CA.
	EnvPrefix string
	// Buckets start with the role's name, "-" written "_".
	Buckets []Bucket
}

// Grants is the per-role list. Add a role or a bucket here; its members get
// it at their next credential renewal.
var Grants = map[string]Grant{
	// TS-633's backup shipper lease; TerraBase's NatsLeaseStore binds it.
	"terrabase": {EnvPrefix: "TERRABASE_NATS_", Buckets: []Bucket{
		{Name: "terrabase_backup_leases", TTL: 15 * time.Second, History: 1, Memory: true},
	}},
}

// Reserved reports whether key is a launch setting the host sets for role's
// NATS identity, which a profile may not set.
func Reserved(role, key string) bool {
	grant, granted := Grants[role]
	return granted && strings.HasPrefix(key, grant.EnvPrefix)
}

// Signer derives the cell's role signing key from its host NATS issuer
// seed. Every controller holds that seed, so none needs new material, and the
// operator computes the same public key from the offline material to add
// Scope to the cell account.
func Signer(hostIssuer nkeys.KeyPair) (nkeys.KeyPair, error) {
	// Seed returns the key's own bytes: decode a copy, never clear them.
	seed, err := hostIssuer.Seed()
	if err != nil {
		return nil, err
	}
	prefix, raw, err := nkeys.DecodeSeed(seed)
	if err != nil || prefix != nkeys.PrefixByteAccount {
		return nil, errors.New("host NATS issuer seed is not an account key")
	}
	derived, err := hkdf.Key(sha256.New, raw, nil, "terrascale-role-nats-signer-v1", 32)
	clear(raw)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	return nkeys.FromRawSeed(nkeys.PrefixByteAccount, derived)
}

// Scope is the role signer's scope: a user reaches only the buckets its
// kv tags name. Tags are lowercase, so no tag can name the controllers'
// upper-case TS_ buckets.
func Scope(key string) *jwt.UserScope {
	scope := jwt.NewUserScope()
	scope.Key = key
	scope.Role = "role"
	kv := "{{tag(kv)}}"
	scope.Template.Pub.Allow = jwt.StringList{"$KV." + kv + ".>",
		"$JS.API.STREAM.INFO.KV_" + kv, "$JS.API.STREAM.MSG.GET.KV_" + kv,
		"$JS.API.DIRECT.GET.KV_" + kv, "$JS.API.DIRECT.GET.KV_" + kv + ".>"}
	// ponytail: role users share NATS clients' default reply prefix, so one
	// role can see another role's JetStream replies; ts-orch's own users
	// reply on private prefixes. Template _INBOX.{{subject()}}.> once roles
	// set a private inbox prefix (TerraBase's NatsLeaseStore does not).
	scope.Template.Sub.Allow = jwt.StringList{"_INBOX.>"}
	return scope
}
