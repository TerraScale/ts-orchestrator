package managedmaterial

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const recipientDomain = "TB-CUSTOMER-RECIPIENT-V1\x00"
const sqlRecipientDomain = "TB-CUSTOMER-RECIPIENT-V2\x00"

// InitialMember fixes the two initial seats before certificate and file hashes
// are admitted. MaterialDirectory is the deterministic directory for attempt 1.
type InitialMember struct {
	SeatID            string `json:"seat_id"`
	MemberID          string `json:"member_id"`
	Incarnation       string `json:"incarnation"`
	ServerName        string `json:"server_name"`
	FailureDomain     string `json:"failure_domain"`
	MaterialDirectory string `json:"material_directory"`
	ReplicationIP     string `json:"replication_ip"`
	ReplicationPort   uint16 `json:"replication_port"`
	ClientIP          string `json:"client_ip"`
	ClientPort        uint16 `json:"client_port"`
	SQLListenPort     uint16 `json:"sql_listen_port,omitzero"`
}

// RecipientGrant is signed by the customer recipient signer pinned by the
// controller's regional configuration. It authorizes one X25519 key and one
// shard scope until ExpiresAt. The raw token is never returned by the producer.
type RecipientGrant struct {
	PublicKey []byte    `json:"public_key"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature []byte    `json:"signature"`
}

type InitialSpec struct {
	PlacementDatabaseID string                `json:"placement_database_id"`
	PartitionID         string                `json:"partition_id"`
	Scope               AuthorityScope        `json:"scope"`
	LiveS3              LiveS3Target          `json:"live_s3"`
	Backup              *InitialBackupSpec    `json:"backup,omitempty"`
	Catalogs            []InitialCatalogInput `json:"catalogs"`
	SQLTables           []InitialSQLTable     `json:"sql_tables,omitempty"`
	Members             [2]InitialMember      `json:"members"`
	Recipient           RecipientGrant        `json:"recipient"`
}

// File is one exact host file and its placement digest. Contents are sensitive
// even though the digest is public; callers must only send them encrypted.
type File struct {
	Contents []byte
	SHA256   string
}

type MemberBundle struct {
	MemberID      string
	TLSLeafSHA256 string
	Files         map[string]File
}

// RetainedSecrets are controller-only rotation continuity keys. They are never
// added to MemberBundle.Files or the customer ciphertext.
type RetainedSecrets struct {
	AuthoritySigner ed25519.PrivateKey
	ReplicationCA   []byte
	HTTPSCA         []byte
}

type CustomerEnvelope struct {
	Version            uint64 `json:"version"`
	TokenID            string `json:"token_id"`
	VerifierSHA256     string `json:"verifier_sha256"`
	HTTPSCASHA256      string `json:"https_ca_sha256"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

type InitialBundle struct {
	Authority SignedAuthority
	Members   [2]MemberBundle
	Customer  CustomerEnvelope
	Retained  RetainedSecrets
}

type apiKeyRegistry struct {
	Version uint64        `json:"version"`
	Keys    []apiKeyEntry `json:"keys"`
}

type apiKeyEntry struct {
	ID             string   `json:"id"`
	VerifierSHA256 string   `json:"verifier_sha256"`
	Tenant         string   `json:"tenant"`
	Database       string   `json:"database"`
	Shard          string   `json:"shard"`
	Collections    []string `json:"collections"`
	TableIDs       []string `json:"table_ids,omitempty"`
	Permissions    []string `json:"permissions"`
	Revoked        bool     `json:"revoked"`
}

// GenerateInitial creates one fresh two-member shard bundle. It must be called
// only after a create-only repository miss under a current fenced lease. A
// retry reads the retained object rather than generating a second bundle.
func GenerateInitial(spec InitialSpec, trustedRecipientSigner ed25519.PublicKey, now time.Time) (InitialBundle, error) {
	if err := validateInitialSpec(spec, trustedRecipientSigner, now); err != nil {
		return InitialBundle{}, err
	}
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return InitialBundle{}, err
	}
	replicationCA, replicationKey, err := generateCA("TerraBase replication", now)
	if err != nil {
		return InitialBundle{}, err
	}
	httpsCA, httpsKey, err := generateCA("TerraBase HTTPS", now)
	if err != nil {
		return InitialBundle{}, err
	}
	var authorityMembers [2]AuthorityMember
	var members [2]MemberBundle
	for index, seat := range spec.Members {
		replicationDER, replicationPEM, replicationPrivate, leafErr := generateLeaf(
			replicationCA, replicationKey, leafKeyEd25519, seat.ServerName, nil, now,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		if leafErr != nil {
			return InitialBundle{}, leafErr
		}
		if len(replicationDER) == 0 || len(replicationDER) > 4096 {
			return InitialBundle{}, ErrMaterialConflict
		}
		_, httpsPEM, httpsPrivate, leafErr := generateLeaf(
			httpsCA, httpsKey, leafKeyP256, seat.ServerName, net.ParseIP(seat.ClientIP), now,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		if leafErr != nil {
			return InitialBundle{}, leafErr
		}
		authorityMembers[index] = AuthorityMember{
			MemberID: seat.MemberID, Incarnation: seat.Incarnation,
			ServerName: seat.ServerName, FailureDomain: seat.FailureDomain, LeafDER: replicationDER,
		}
		files := map[string]File{
			"server.crt":             makeFile(append(replicationPEM, replicationCA.RawPEM...)),
			"server.key":             makeFile(replicationPrivate),
			"server-ca.pem":          makeFile(replicationCA.RawPEM),
			"client-ca.pem":          makeFile(replicationCA.RawPEM),
			"client-chain.pem":       makeFile(append(httpsPEM, httpsCA.RawPEM...)),
			"client-private-key.pem": makeFile(httpsPrivate),
		}
		members[index] = MemberBundle{MemberID: seat.MemberID, Files: files}
	}
	catalogs, err := initialCatalogs(spec.Catalogs)
	if err != nil {
		return InitialBundle{}, err
	}
	authority, err := SignInitialAuthorityV2(spec.Scope, authorityMembers, catalogs, authorityKey)
	if err != nil {
		return InitialBundle{}, err
	}
	backupManifest, backupConfig, err := generateBackupMaterial(spec, authority, authorityKey)
	if err != nil {
		return InitialBundle{}, err
	}
	var sqlSchemaBundle []byte
	if len(spec.SQLTables) > 0 {
		sqlSchemaBundle, err = encodeSQLSchemaBundle(spec.Scope, authority.ConfigurationID, spec.SQLTables, authorityKey)
		if err != nil {
			return InitialBundle{}, err
		}
	}
	var tokenID [16]byte
	var tokenSecret [32]byte
	if _, err := rand.Read(tokenID[:]); err != nil {
		return InitialBundle{}, err
	}
	if _, err := rand.Read(tokenSecret[:]); err != nil {
		return InitialBundle{}, err
	}
	defer clear(tokenSecret[:])
	verifier := sha256.New()
	verifier.Write([]byte("TB-APIKEY-V1\x00"))
	verifier.Write(tokenID[:])
	verifier.Write(tokenSecret[:])
	verifierHex := hex.EncodeToString(verifier.Sum(nil))
	token := "tbk1." + base64.RawURLEncoding.EncodeToString(tokenID[:]) + "." + base64.RawURLEncoding.EncodeToString(tokenSecret[:])
	for index, seat := range spec.Members {
		files := members[index].Files
		files["authority.tbca"] = makeFile(authority.Certificate)
		files["trusted-public-key"] = makeFile(authority.TrustedKey)
		if spec.Backup != nil {
			files[backupManifestName] = backupManifest
			files[backupConfigName] = backupConfig
		}
		if len(sqlSchemaBundle) > 0 {
			files[sqlSchemaBundleFileName] = makeFile(sqlSchemaBundle)
		}
		liveS3, err := spec.LiveS3.ConfigJSON()
		if err != nil {
			return InitialBundle{}, err
		}
		files["signed-v2-s3-config.json"] = makeFile(liveS3)
		registry, err := json.Marshal(apiKeyRegistry{Version: 1, Keys: []apiKeyEntry{{
			ID: base64.RawURLEncoding.EncodeToString(tokenID[:]), VerifierSHA256: verifierHex,
			Tenant: spec.Scope.TenantID, Database: spec.Scope.DatabaseID,
			Shard: strconv.FormatUint(spec.Scope.ShardID, 10), Collections: initialCollectionIDs(spec.Catalogs),
			TableIDs:    initialSQLTableIDs(spec.SQLTables),
			Permissions: []string{"read", "write"}, Revoked: false}}})
		if err != nil {
			return InitialBundle{}, err
		}
		files["client-api-keys.json"] = makeFile(registry)
		config, err := json.Marshal(struct {
			Version          uint64 `json:"version"`
			ListenAddress    string `json:"listen_addr"`
			SQLListenAddress string `json:"sql_listen_addr,omitempty"`
			CertificateChain string `json:"certificate_chain"`
			PrivateKey       string `json:"private_key"`
			APIKeyRegistry   string `json:"api_key_registry"`
		}{Version: 1, ListenAddress: net.JoinHostPort(seat.ClientIP, strconv.Itoa(int(seat.ClientPort))),
			SQLListenAddress: sqlListenAddress(seat),
			CertificateChain: filepath.Join(seat.MaterialDirectory, "client-chain.pem"),
			PrivateKey:       filepath.Join(seat.MaterialDirectory, "client-private-key.pem"),
			APIKeyRegistry:   filepath.Join(seat.MaterialDirectory, "client-api-keys.json")})
		if err != nil {
			return InitialBundle{}, err
		}
		files["client-config.json"] = makeFile(config)
		manifest, err := json.Marshal(struct {
			Version                uint64 `json:"version"`
			ClientConfigSHA256     string `json:"client_config_sha256"`
			CertificateChainSHA256 string `json:"certificate_chain_sha256"`
			PrivateKeySHA256       string `json:"private_key_sha256"`
			APIKeyRegistrySHA256   string `json:"api_key_registry_sha256"`
		}{1, files["client-config.json"].SHA256, files["client-chain.pem"].SHA256,
			files["client-private-key.pem"].SHA256, files["client-api-keys.json"].SHA256})
		if err != nil {
			return InitialBundle{}, err
		}
		files["client-managed-manifest.json"] = makeFile(manifest)
		members[index].TLSLeafSHA256 = authority.MemberLeafPins[index]
	}
	customer, err := encryptCustomerToken(spec, token, verifierHex, httpsCA.RawPEM)
	if err != nil {
		return InitialBundle{}, err
	}
	return InitialBundle{Authority: authority, Members: members, Customer: customer,
		Retained: RetainedSecrets{AuthoritySigner: authorityKey, ReplicationCA: replicationKey,
			HTTPSCA: httpsKey}}, nil
}

type certificateAuthority struct {
	*x509.Certificate
	RawPEM []byte
}

func generateCA(name string, now time.Time) (certificateAuthority, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return certificateAuthority{}, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return certificateAuthority{}, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLen: 0, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return certificateAuthority{}, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return certificateAuthority{}, nil, err
	}
	return certificateAuthority{Certificate: parsed, RawPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
		private, nil
}

// leafKey selects a leaf's key type. Member replication stays Ed25519; the
// client HTTPS leaf is ECDSA P-256 because Cloudflare's origin client and
// browsers do not accept Ed25519 server certificates.
type leafKey int

const (
	leafKeyEd25519 leafKey = iota
	leafKeyP256
)

func generateLeaf(ca certificateAuthority, caPrivate []byte, kind leafKey, name string, ip net.IP, now time.Time,
	usages []x509.ExtKeyUsage,
) ([]byte, []byte, []byte, error) {
	var public crypto.PublicKey
	var private crypto.Signer
	switch kind {
	case leafKeyP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		public, private = &key.PublicKey, key
	default:
		edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		public, private = edPublic, edPrivate
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, DNSNames: []string{name}}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, public, ed25519.PrivateKey(caPrivate))
	if err != nil {
		return nil, nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, nil, err
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func makeFile(data []byte) File {
	copy := slices.Clone(data)
	sum := sha256.Sum256(copy)
	return File{Contents: copy, SHA256: hex.EncodeToString(sum[:])}
}

func validateInitialSpec(spec InitialSpec, signer ed25519.PublicKey, now time.Time) error {
	if err := spec.LiveS3.Validate(); err != nil {
		return err
	}
	if spec.Backup != nil {
		if err := spec.Backup.Validate(spec.LiveS3, spec.Members, now); err != nil {
			return err
		}
	}
	if len(signer) != ed25519.PublicKeySize || len(spec.Recipient.PublicKey) != 32 ||
		len(spec.Recipient.Signature) != ed25519.SignatureSize || now.IsZero() ||
		!spec.Recipient.ExpiresAt.Equal(spec.Recipient.ExpiresAt.UTC().Truncate(time.Second)) ||
		!now.Before(spec.Recipient.ExpiresAt) || spec.Recipient.ExpiresAt.After(now.Add(30*24*time.Hour)) {
		return errors.New("initial material recipient grant is invalid")
	}
	if _, err := canonicalUUID(spec.Scope.TenantID); err != nil {
		return err
	}
	if _, err := canonicalUUID(spec.Scope.DatabaseID); err != nil {
		return err
	}
	if _, err := initialCatalogs(spec.Catalogs); err != nil {
		return err
	}
	if err := spec.ValidateSQLConfiguration(); err != nil {
		return err
	}
	if !repositoryToken.MatchString(spec.PlacementDatabaseID) || !repositoryToken.MatchString(spec.PartitionID) {
		return errors.New("initial material placement database or partition ID is invalid")
	}
	cluster, err := hex.DecodeString(spec.Scope.ClusterID)
	if err != nil || len(cluster) != 16 || allZero(cluster) || spec.Scope.ShardID == 0 || spec.Scope.Epoch != 1 {
		return errors.New("initial material shard scope is invalid")
	}
	if !ed25519.Verify(signer, recipientGrantMessage(spec), spec.Recipient.Signature) {
		return errors.New("initial material recipient signature is invalid")
	}
	for _, member := range spec.Members {
		if _, err := canonicalUUID(member.MemberID); err != nil {
			return err
		}
		incarnation, err := hex.DecodeString(member.Incarnation)
		if err != nil || len(incarnation) != 16 || allZero(incarnation) ||
			!repositoryToken.MatchString(member.SeatID) ||
			!validServerName(member.ServerName) || !validFailureDomain(member.FailureDomain) ||
			!filepath.IsAbs(member.MaterialDirectory) || filepath.Clean(member.MaterialDirectory) != member.MaterialDirectory ||
			member.MaterialDirectory == "/" || len(member.MaterialDirectory) > 100 ||
			!validPrivateIP(member.ReplicationIP) || member.ClientIP != member.ReplicationIP ||
			member.ReplicationPort == 0 || member.ClientPort == 0 {
			return errors.New("initial material member binding is invalid")
		}
	}
	if spec.Members[0].MemberID >= spec.Members[1].MemberID ||
		spec.Members[0].SeatID == spec.Members[1].SeatID ||
		spec.Members[0].ClientIP == spec.Members[1].ClientIP ||
		spec.Members[0].ServerName == spec.Members[1].ServerName ||
		spec.Members[0].MaterialDirectory == spec.Members[1].MaterialDirectory ||
		spec.Members[0].FailureDomain == spec.Members[1].FailureDomain {
		return errors.New("initial material members are duplicate or out of authority order")
	}
	return nil
}

func validPrivateIP(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() != nil && ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified()
}

// RecipientGrantMessage is the exact message a customer signer authorizes.
// The caller must pin the signer independently of this signed grant.
func RecipientGrantMessage(spec InitialSpec) []byte { return recipientGrantMessage(spec) }

func recipientGrantMessage(spec InitialSpec) []byte {
	if len(spec.SQLTables) > 0 {
		tableDigest, err := sqlTableSetDigest(spec.SQLTables)
		if err != nil {
			return nil
		}
		return []byte(sqlRecipientDomain + spec.PlacementDatabaseID + "/" + spec.PartitionID + "/" + spec.Scope.ClusterID + "/" + spec.Scope.TenantID + "/" +
			spec.Scope.DatabaseID + "/" + strconv.FormatUint(spec.Scope.ShardID, 10) + "/" +
			catalogSetDigest(spec.Catalogs) + "/" + tableDigest + "/" + hex.EncodeToString(spec.Recipient.PublicKey) + "/" +
			strconv.FormatInt(spec.Recipient.ExpiresAt.UTC().Unix(), 10))
	}
	return []byte(recipientDomain + spec.PlacementDatabaseID + "/" + spec.PartitionID + "/" + spec.Scope.ClusterID + "/" + spec.Scope.TenantID + "/" +
		spec.Scope.DatabaseID + "/" + strconv.FormatUint(spec.Scope.ShardID, 10) + "/" +
		catalogSetDigest(spec.Catalogs) + "/" + hex.EncodeToString(spec.Recipient.PublicKey) + "/" +
		strconv.FormatInt(spec.Recipient.ExpiresAt.UTC().Unix(), 10))
}

func catalogSetDigest(inputs []InitialCatalogInput) string {
	hash := sha256.New()
	for _, input := range inputs {
		hash.Write([]byte(input.CollectionID))
		var length [4]byte
		binary.LittleEndian.PutUint32(length[:], uint32(len(input.CanonicalCatalog)))
		hash.Write(length[:])
		hash.Write(input.CanonicalCatalog)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func initialCollectionIDs(inputs []InitialCatalogInput) []string {
	ids := make([]string, 0, len(inputs))
	for _, input := range inputs {
		ids = append(ids, input.CollectionID)
	}
	return ids
}

func customerEnvelopeAAD(spec InitialSpec, tokenID, verifier, caSHA string) []byte {
	return []byte("TB-CUSTOMER-TOKEN-V2\x00" + string(recipientGrantMessage(spec)) + "/" +
		tokenID + "/" + verifier + "/" + caSHA)
}

func encryptCustomerToken(spec InitialSpec, token, verifierHex string, caPEM []byte) (CustomerEnvelope, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "tbk1" {
		return CustomerEnvelope{}, errors.New("customer token grammar is invalid")
	}
	id, idErr := base64.RawURLEncoding.DecodeString(parts[1])
	secret, secretErr := base64.RawURLEncoding.DecodeString(parts[2])
	verifier := sha256.New()
	verifier.Write([]byte("TB-APIKEY-V1\x00"))
	verifier.Write(id)
	verifier.Write(secret)
	if idErr != nil || secretErr != nil || len(id) != 16 || len(secret) != 32 ||
		verifierHex != hex.EncodeToString(verifier.Sum(nil)) {
		return CustomerEnvelope{}, errors.New("customer token differs from API verifier")
	}
	defer clear(secret)
	caDigest := sha256.Sum256(caPEM)
	caSHA := hex.EncodeToString(caDigest[:])
	curve := ecdh.X25519()
	recipient, err := curve.NewPublicKey(spec.Recipient.PublicKey)
	if err != nil {
		return CustomerEnvelope{}, err
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return CustomerEnvelope{}, err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return CustomerEnvelope{}, err
	}
	defer clear(shared)
	associated := customerEnvelopeAAD(spec, parts[1], verifierHex, caSHA)
	key, err := hkdf.Key(sha256.New, shared, associated, "TB-CUSTOMER-TOKEN-V2", 32)
	if err != nil {
		return CustomerEnvelope{}, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return CustomerEnvelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return CustomerEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return CustomerEnvelope{}, err
	}
	plaintext, err := json.Marshal(struct {
		Version    uint64 `json:"version"`
		Token      string `json:"token"`
		HTTPSCAPEM string `json:"https_ca_pem"`
	}{1, token, string(caPEM)})
	if err != nil {
		return CustomerEnvelope{}, fmt.Errorf("encode customer secret: %w", err)
	}
	defer clear(plaintext)
	ciphertext := aead.Seal(nil, nonce, plaintext, associated)
	return CustomerEnvelope{Version: 2, TokenID: parts[1], VerifierSHA256: verifierHex,
		HTTPSCASHA256:      caSHA,
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Nonce:              base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:         base64.RawURLEncoding.EncodeToString(ciphertext)}, nil
}
