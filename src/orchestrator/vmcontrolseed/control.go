// Package vmcontrolseed renders the explicitly selected initial GRU controller
// identities and launch configuration. It does not create stores or leases.
package vmcontrolseed

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
)

const Directory = "/etc/terrascale/orchestrator"
const NKeyPath = Directory + "/regional/user.seed"
const CAPath = Directory + "/regional/ca.pem"
const CertificatePath = Directory + "/regional/client.pem"
const PrivateKeyPath = Directory + "/regional/client.key"
const ServerCertificatePath = Directory + "/regional/server.pem"
const ServerPrivateKeyPath = Directory + "/regional/server.key"
const ServerConfigPath = Directory + "/regional/server.conf"
const CommandKeyPath = Directory + "/command.key"
const StorePath = "/var/lib/terrascale/orchestrator/nats"
const ServiceUser = "terrascale-orchestrator"

func CommandTrustPath(index int) string { return fmt.Sprintf(Directory+"/command-trust-%d.pem", index) }
func IsFilePath(path string) bool {
	switch path {
	case NKeyPath, CAPath, CertificatePath, PrivateKeyPath, ServerCertificatePath, ServerPrivateKeyPath, ServerConfigPath, CommandKeyPath:
		return true
	}
	for i := 0; i < 3; i++ {
		if path == CommandTrustPath(i) {
			return true
		}
	}
	return false
}

var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

type Guest struct {
	ID, Address       string
	CommandPrivateKey []byte
}
type Material struct {
	HostID, Address, Settings string
	Selected                  bool
	Files                     map[string][]byte
}

func (m Material) Clone() Material {
	copy := m
	copy.Files = map[string][]byte{}
	for path, data := range m.Files {
		copy.Files[path] = append([]byte(nil), data...)
	}
	return copy
}
func (m Material) Clear() {
	for _, data := range m.Files {
		clear(data)
	}
}

// GenerateGRU enrolls at most three declared initial candidates. The first
// lexically ordered guest is the sole R1 server; no other Region is implied.
func GenerateGRU(runID string, guests []Guest) (map[string]Material, error) {
	if !identifierPattern.MatchString(runID) || len(guests) == 0 || len(guests) > 3 {
		return nil, errors.New("vmcontrolseed: initial GRU requires one to three declared candidates")
	}
	ordered := append([]Guest(nil), guests...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	seen := map[string]bool{}
	trust := map[string][]byte{}
	for _, guest := range ordered {
		ip, err := netip.ParseAddr(guest.Address)
		if err != nil || !ip.Is4() || !ip.IsPrivate() || !identifierPattern.MatchString(guest.ID) || seen[guest.ID] || seen[guest.Address] {
			return nil, errors.New("vmcontrolseed: invalid declared guest identity or address")
		}
		seen[guest.ID], seen[guest.Address] = true, true
		_, public, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(guest.CommandPrivateKey)
		if err != nil {
			return nil, errors.New("vmcontrolseed: explicit candidate command signer required")
		}
		// Derive the SPKI from the same actual P256 private key, never a test ID.
		block, _ := pem.Decode(guest.CommandPrivateKey)
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key := parsed.(*ecdsa.PrivateKey)
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		key.D.SetInt64(0)
		clear(block.Bytes)
		if err != nil {
			return nil, err
		}
		if seen[public] {
			return nil, errors.New("vmcontrolseed: candidate command keys must be distinct")
		}
		seen[public] = true
		trust[guest.ID] = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(caPrivate)
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vmqual guest GRU control " + runID}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issue := func(guest Guest, server bool) ([]byte, []byte, error) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		defer clear(private)
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			return nil, nil, err
		}
		role := "orchestrator"
		usage := x509.ExtKeyUsageClientAuth
		if server {
			role = "regional-nats"
			usage = x509.ExtKeyUsageServerAuth
		}
		uri := &url.URL{Scheme: "spiffe", Host: "vmqual.terrascale.test", Path: "/" + runID + "/" + role + "/" + guest.ID}
		leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: role + "-" + guest.ID}, URIs: []*url.URL{uri}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if server {
			leaf.IPAddresses = []net.IP{net.ParseIP(guest.Address)}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caPrivate)
		if err != nil {
			return nil, nil, err
		}
		key, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, nil, err
		}
		defer clear(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
	}
	result := map[string]Material{}
	completed := false
	defer func() {
		if !completed {
			for _, m := range result {
				m.Clear()
			}
		}
	}()
	var users []map[string]string
	for index, guest := range ordered {
		pair, err := nkeys.CreateUser()
		if err != nil {
			return nil, err
		}
		raw, err := pair.Seed()
		if err != nil {
			pair.Wipe()
			return nil, err
		}
		seed := append([]byte(nil), raw...)
		public, err := pair.PublicKey()
		pair.Wipe()
		if err != nil {
			clear(seed)
			return nil, err
		}
		cert, key, err := issue(guest, false)
		if err != nil {
			clear(seed)
			return nil, err
		}
		files := map[string][]byte{NKeyPath: seed, CAPath: append([]byte(nil), caPEM...), CertificatePath: cert, PrivateKeyPath: key, CommandKeyPath: append([]byte(nil), guest.CommandPrivateKey...)}
		var trustPaths []string
		for n, peer := range ordered {
			path := CommandTrustPath(n)
			files[path] = append([]byte(nil), trust[peer.ID]...)
			trustPaths = append(trustPaths, path)
		}
		settings := map[string]string{"TS_ORCH_CELL": "gru", "TS_ORCH_INSTANCE": guest.ID, "TS_ORCH_REPLICAS": "1", "TS_ORCH_PROVIDER": "oci", "TS_ORCH_NATS_URL": "tls://" + net.JoinHostPort(ordered[0].Address, "4222"), "TS_ORCH_NATS_NKEY_FILE": NKeyPath, "TS_ORCH_NATS_TLS_CA_FILE": CAPath, "TS_ORCH_NATS_TLS_CERT_FILE": CertificatePath, "TS_ORCH_NATS_TLS_KEY_FILE": PrivateKeyPath, "TS_ORCH_COMMAND_SIGNING_KEY_FILE": CommandKeyPath, "TS_ORCH_COMMAND_TRUST_KEY_FILES": strings.Join(trustPaths, ":"), "TS_ORCH_COMMAND_AGGREGATE_ID": "delivery", "TS_ORCH_MEMBERSHIP_SIGNING_KEY_FILE": Directory + "/identity.pem", "TS_ORCH_MEMBERSHIP_PINS_FILE": Directory + "/membership-pins.json"}
		if index == 0 {
			settings["TS_ORCH_NATS_SERVER_CONFIG_FILE"] = ServerConfigPath
			settings["TS_ORCH_NATS_SERVER_READINESS_TIMEOUT"] = "30s"
		}
		encoded, err := json.Marshal(settings)
		if err != nil {
			return nil, err
		}
		result[guest.ID] = Material{HostID: guest.ID, Address: guest.Address, Selected: index == 0, Settings: string(encoded), Files: files}
		users = append(users, map[string]string{"nkey": public})
	}
	first := result[ordered[0].ID]
	cert, key, err := issue(ordered[0], true)
	if err != nil {
		return nil, err
	}
	first.Files[ServerCertificatePath], first.Files[ServerPrivateKeyPath] = cert, key
	config := brokerConfig(ordered[0].ID, ordered[0].Address, users)
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	first.Files[ServerConfigPath] = encoded
	completed = true
	return result, nil
}

// Validate verifies immutable seed material before NoCloud adds ownership.
func (m Material) Validate() error {
	if !identifierPattern.MatchString(m.HostID) || len(m.Settings) > 64<<10 || m.Settings == "" || len(m.Files) < 6 || len(m.Files) > 12 {
		return errors.New("vmcontrolseed: incomplete controller material")
	}
	for path, data := range m.Files {
		if !IsFilePath(path) || len(data) == 0 || len(data) > 64<<10 {
			return errors.New("vmcontrolseed: unbounded or unowned controller file")
		}
	}
	ip, addressErr := netip.ParseAddr(m.Address)
	if addressErr != nil || !ip.Is4() || !ip.IsPrivate() {
		return errors.New("vmcontrolseed: invalid guest address")
	}
	var settings map[string]string
	if json.Unmarshal([]byte(m.Settings), &settings) != nil {
		return errors.New("vmcontrolseed: invalid controller settings")
	}
	required := map[string]string{"TS_ORCH_CELL": "gru", "TS_ORCH_INSTANCE": m.HostID, "TS_ORCH_PROVIDER": "oci", "TS_ORCH_REPLICAS": "1", "TS_ORCH_NATS_NKEY_FILE": NKeyPath, "TS_ORCH_NATS_TLS_CA_FILE": CAPath, "TS_ORCH_NATS_TLS_CERT_FILE": CertificatePath, "TS_ORCH_NATS_TLS_KEY_FILE": PrivateKeyPath, "TS_ORCH_COMMAND_SIGNING_KEY_FILE": CommandKeyPath, "TS_ORCH_COMMAND_AGGREGATE_ID": "delivery", "TS_ORCH_MEMBERSHIP_SIGNING_KEY_FILE": Directory + "/identity.pem", "TS_ORCH_MEMBERSHIP_PINS_FILE": Directory + "/membership-pins.json"}
	var paths []string
	for i := 0; i < 3; i++ {
		if len(m.Files[CommandTrustPath(i)]) != 0 {
			paths = append(paths, CommandTrustPath(i))
		}
	}
	if len(paths) == 0 {
		return errors.New("vmcontrolseed: declared command trust missing")
	}
	required["TS_ORCH_COMMAND_TRUST_KEY_FILES"] = strings.Join(paths, ":")
	endpoint, err := url.Parse(settings["TS_ORCH_NATS_URL"])
	if err != nil {
		return errors.New("vmcontrolseed: invalid regional endpoint")
	}
	broker, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !broker.Is4() || !broker.IsPrivate() || endpoint.String() != "tls://"+net.JoinHostPort(broker.String(), "4222") {
		return errors.New("vmcontrolseed: invalid regional endpoint")
	}
	required["TS_ORCH_NATS_URL"] = endpoint.String()
	if m.Selected {
		required["TS_ORCH_NATS_SERVER_CONFIG_FILE"] = ServerConfigPath
		required["TS_ORCH_NATS_SERVER_READINESS_TIMEOUT"] = "30s"
		if broker.String() != m.Address {
			return errors.New("vmcontrolseed: selected broker address mismatch")
		}
	}
	if len(required) != len(settings) {
		return errors.New("vmcontrolseed: unexpected controller settings")
	}
	for key, value := range required {
		if settings[key] != value {
			return errors.New("vmcontrolseed: controller settings mismatch")
		}
	}
	pair, err := nkeys.FromSeed(m.Files[NKeyPath])
	if err != nil {
		return errors.New("vmcontrolseed: invalid controller user seed")
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return errors.New("vmcontrolseed: controller seed is not a user identity")
	}
	identity, err := tls.X509KeyPair(m.Files[CertificatePath], m.Files[PrivateKeyPath])
	if err != nil {
		return errors.New("vmcontrolseed: invalid controller mTLS identity")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(m.Files[CAPath]) {
		return errors.New("vmcontrolseed: controller CA missing")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return err
	}
	if len(leaf.URIs) != 1 {
		return errors.New("vmcontrolseed: controller SPIFFE identity missing")
	}
	uri := leaf.URIs[0]
	parts := strings.Split(strings.TrimPrefix(uri.Path, "/"), "/")
	if len(parts) != 3 || !identifierPattern.MatchString(parts[0]) || parts[1] != "orchestrator" || parts[2] != m.HostID || uri.String() != "spiffe://vmqual.terrascale.test/"+strings.Join(parts, "/") {
		return errors.New("vmcontrolseed: controller SPIFFE identity mismatch")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("vmcontrolseed: controller client identity is untrusted")
	}
	block, _ := pem.Decode(m.Files[CommandKeyPath])
	if block == nil {
		return errors.New("vmcontrolseed: command signing key missing")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("vmcontrolseed: command signing key invalid")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return errors.New("vmcontrolseed: command signer must be P256")
	}
	key.D.SetInt64(0)
	clear(block.Bytes)
	_, ownCommand, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(m.Files[CommandKeyPath])
	if err != nil {
		return err
	}
	ownTrusted := false
	seenTrust := map[string]bool{}
	for _, path := range paths {
		block, rest := pem.Decode(m.Files[path])
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("vmcontrolseed: invalid command trust PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return errors.New("vmcontrolseed: command trust must be P256")
		}
		public := base64.StdEncoding.EncodeToString(block.Bytes)
		if seenTrust[public] {
			return errors.New("vmcontrolseed: duplicate command trust")
		}
		seenTrust[public] = true
		ownTrusted = ownTrusted || public == ownCommand
	}
	if !ownTrusted {
		return errors.New("vmcontrolseed: command signer missing from declared trust")
	}
	if m.Selected && (len(m.Files[ServerConfigPath]) == 0 || len(m.Files[ServerPrivateKeyPath]) == 0 || len(m.Files[ServerCertificatePath]) == 0) {
		return errors.New("vmcontrolseed: selected broker material is incomplete")
	}
	if !m.Selected && (len(m.Files[ServerConfigPath]) != 0 || len(m.Files[ServerPrivateKeyPath]) != 0 || len(m.Files[ServerCertificatePath]) != 0) {
		return errors.New("vmcontrolseed: unselected host cannot receive broker identity")
	}
	if m.Selected {
		var wire struct {
			Accounts map[string]struct {
				Users []map[string]string `json:"users"`
			} `json:"accounts"`
		}
		if json.Unmarshal(m.Files[ServerConfigPath], &wire) != nil {
			return errors.New("vmcontrolseed: invalid broker configuration")
		}
		users := wire.Accounts["GRU_CONTROL"].Users
		if len(users) < 1 || len(users) > 3 {
			return errors.New("vmcontrolseed: invalid broker users")
		}
		seen := map[string]bool{}
		for _, user := range users {
			if len(user) != 1 || !nkeys.IsValidPublicUserKey(user["nkey"]) || seen[user["nkey"]] {
				return errors.New("vmcontrolseed: invalid broker user")
			}
			seen[user["nkey"]] = true
		}
		expected, _ := json.Marshal(brokerConfig(m.HostID, m.Address, users))
		if !seen[public] || !bytes.Equal(expected, m.Files[ServerConfigPath]) {
			return errors.New("vmcontrolseed: broker configuration binding mismatch")
		}

		server, err := tls.X509KeyPair(m.Files[ServerCertificatePath], m.Files[ServerPrivateKeyPath])
		if err != nil {
			return errors.New("vmcontrolseed: invalid broker TLS identity")
		}
		cert, err := x509.ParseCertificate(server.Certificate[0])
		if err != nil {
			return err
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: m.Address, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return errors.New("vmcontrolseed: untrusted broker TLS identity")
		}
	}
	return nil
}

func brokerConfig(host, address string, users []map[string]string) map[string]any {
	config := map[string]any{"server_name": host, "listen": net.JoinHostPort(address, "4222"), "max_payload": 4 << 20, "jetstream": map[string]any{"store_dir": StorePath, "max_memory_store": 32 << 20, "max_file_store": 256 << 20}, "tls": map[string]any{"cert_file": ServerCertificatePath, "key_file": ServerPrivateKeyPath, "ca_file": CAPath, "verify": true, "min_version": "1.3"}, "accounts": map[string]any{"GRU_CONTROL": map[string]any{"jetstream": "enabled", "users": users}}}
	return config
}
