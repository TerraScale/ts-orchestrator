//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/qualificationstate"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type qualificationStoredIdentity struct {
	Seed        []byte `json:"seed"`
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"privateKey"`
}

type qualificationStoredAuthority struct {
	Version        int                                    `json:"version"`
	PlanSHA256     string                                 `json:"planSha256"`
	CA             []byte                                 `json:"ca"`
	Server         qualificationStoredIdentity            `json:"server"`
	Controller     qualificationStoredIdentity            `json:"controller"`
	Guests         map[string]qualificationStoredIdentity `json:"guests"`
	MembershipKeys map[string][]byte                      `json:"membershipKeys"`
	CommandKeys    map[string][]byte                      `json:"commandKeys"`
}

// persistQualificationAuthority preserves all fixture TLS, NKey, membership
// and command identities before any guest can receive them. A corrupt or
// expired existing record is an error, never permission to create new keys.
// The supplied freshly generated template is always closed by this function.
func persistQualificationAuthority(path string, plan vmnet.NetworkPlan, template *qualificationNATSAuthority) (*qualificationNATSAuthority, error) {
	defer template.close()
	store, err := qualificationstate.Open(path)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	planBytes, err := json.Marshal(plan, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(planBytes)
	planSHA := hex.EncodeToString(digest[:])
	parse := func(raw []byte) (*qualificationNATSAuthority, error) {
		return restoreQualificationAuthority(raw, planSHA, template)
	}
	raw, err := store.LoadOrCreate("transport-authority.json", 4<<20, func() ([]byte, error) {
		identity := func(value *qualificationNATSIdentity) qualificationStoredIdentity {
			return qualificationStoredIdentity{Seed: value.seed, Certificate: value.certificate, PrivateKey: value.privateKey}
		}
		serverKey, err := x509.MarshalPKCS8PrivateKey(template.server.PrivateKey)
		if err != nil {
			return nil, err
		}
		defer clear(serverKey)
		serverPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKey})
		defer clear(serverPEM)
		var certificate []byte
		for _, der := range template.server.Certificate {
			certificate = append(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		value := qualificationStoredAuthority{Version: 1, PlanSHA256: planSHA, CA: template.ca,
			Server: qualificationStoredIdentity{Certificate: certificate, PrivateKey: serverPEM}, Controller: identity(template.controller),
			Guests: map[string]qualificationStoredIdentity{}, MembershipKeys: map[string][]byte{}, CommandKeys: map[string][]byte{}}
		for host, current := range template.guests {
			value.Guests[host] = identity(current)
		}
		for host, current := range template.memberships {
			value.MembershipKeys[host] = current.PrivatePEM
		}
		for candidate, current := range template.commandSigners {
			value.CommandKeys[candidate] = current.PrivatePEM
		}
		return json.Marshal(value, json.Deterministic(true))
	}, func(raw []byte) error {
		authority, err := parse(raw)
		if authority != nil {
			authority.close()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return parse(raw)
}

func restoreQualificationAuthority(raw []byte, planSHA string, template *qualificationNATSAuthority) (_ *qualificationNATSAuthority, resultErr error) {
	bad := errors.New("vmqual: stored qualification authority differs from the admitted network or identity inventory")
	var record qualificationStoredAuthority
	defer func() {
		clear(record.Server.PrivateKey)
		clear(record.Controller.Seed)
		clear(record.Controller.PrivateKey)
		for _, identity := range record.Guests {
			clear(identity.Seed)
			clear(identity.PrivateKey)
		}
		for _, key := range record.MembershipKeys {
			clear(key)
		}
		for _, key := range record.CommandKeys {
			clear(key)
		}
	}()
	if json.Unmarshal(raw, &record, json.RejectUnknownMembers(true)) != nil || record.Version != 1 || record.PlanSHA256 != planSHA || len(record.Guests) != len(template.guests) || len(record.MembershipKeys) != len(template.memberships) || len(record.CommandKeys) != len(template.commandSigners) {
		return nil, bad
	}
	result := &qualificationNATSAuthority{ca: bytes.Clone(record.CA), roots: x509.NewCertPool(), serverName: template.serverName, guests: map[string]*qualificationNATSIdentity{}, memberships: map[string]*qualificationMembershipIdentity{}, commandSigners: map[string]*qualificationMembershipIdentity{}}
	defer func() {
		if resultErr != nil {
			result.close()
		}
	}()
	if !result.roots.AppendCertsFromPEM(result.ca) {
		return nil, bad
	}
	certificate := func(stored qualificationStoredIdentity, uri, hostname string) (tls.Certificate, error) {
		pair, err := tls.X509KeyPair(stored.Certificate, stored.PrivateKey)
		if err != nil || len(pair.Certificate) != 1 {
			return tls.Certificate{}, bad
		}
		if _, ok := pair.PrivateKey.(ed25519.PrivateKey); !ok {
			return tls.Certificate{}, bad
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != uri {
			return tls.Certificate{}, bad
		}
		usage := x509.ExtKeyUsageClientAuth
		if hostname != "" {
			usage = x509.ExtKeyUsageServerAuth
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: result.roots, DNSName: hostname, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return tls.Certificate{}, bad
		}
		return pair, nil
	}
	serverLeaf, err := x509.ParseCertificate(template.server.Certificate[0])
	if err != nil || len(serverLeaf.URIs) != 1 || len(record.Server.Seed) != 0 {
		return nil, bad
	}
	result.server, err = certificate(record.Server, serverLeaf.URIs[0].String(), result.serverName)
	if err != nil {
		return nil, err
	}
	identity := func(stored qualificationStoredIdentity, uri string) (*qualificationNATSIdentity, error) {
		pair, err := nkeys.FromSeed(stored.Seed)
		if err != nil {
			return nil, bad
		}
		public, err := pair.PublicKey()
		if err != nil || !nkeys.IsValidPublicUserKey(public) {
			pair.Wipe()
			return nil, bad
		}
		tlsIdentity, err := certificate(stored, uri, "")
		if err != nil {
			pair.Wipe()
			return nil, err
		}
		return &qualificationNATSIdentity{seed: bytes.Clone(stored.Seed), certificate: bytes.Clone(stored.Certificate), privateKey: bytes.Clone(stored.PrivateKey), pair: pair, publicKey: public, uri: uri, tls: tlsIdentity}, nil
	}
	result.controller, err = identity(record.Controller, template.controller.uri)
	if err != nil {
		return nil, err
	}
	replacements := map[string]string{template.controller.publicKey: result.controller.publicKey}
	seenNKeys := map[string]bool{result.controller.publicKey: true}
	for host, original := range template.guests {
		current, err := identity(record.Guests[host], original.uri)
		if err != nil {
			return nil, err
		}
		result.guests[host] = current
		if seenNKeys[current.publicKey] {
			return nil, bad
		}
		seenNKeys[current.publicKey] = true
		replacements[original.publicKey] = current.publicKey
	}
	seenSigningKeys := make(map[string]bool)
	for _, entry := range []struct {
		keys   map[string][]byte
		wanted map[string]*qualificationMembershipIdentity
		output map[string]*qualificationMembershipIdentity
	}{{record.MembershipKeys, template.memberships, result.memberships}, {record.CommandKeys, template.commandSigners, result.commandSigners}} {
		for id := range entry.wanted {
			key := entry.keys[id]
			keyID, public, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(key)
			if err != nil || seenSigningKeys[public] {
				return nil, bad
			}
			seenSigningKeys[public] = true
			entry.output[id] = &qualificationMembershipIdentity{PrivatePEM: bytes.Clone(key), KeyID: keyID, PublicKey: public}
		}
	}
	for _, user := range template.users {
		copy := *user
		copy.Nkey = replacements[user.Nkey]
		if copy.Nkey == "" {
			return nil, bad
		}
		result.users = append(result.users, &copy)
	}
	return result, nil
}
