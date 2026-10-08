//go:build linux

package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

type backupFullMaterialPacket struct {
	Version                  uint64             `json:"version"`
	Scope                    AuthorityScope     `json:"scope"`
	CatalogPath              string             `json:"catalog_path"`
	CollectionID             string             `json:"collection_id"`
	AuthorityCertificatePath string             `json:"authority_certificate_path"`
	SourceS3ConfigPath       string             `json:"source_s3_config_path"`
	BackupS3ConfigPath       string             `json:"backup_s3_config_path"`
	BackupManifestPath       string             `json:"backup_manifest_path"`
	BackupCredentialsPath    string             `json:"backup_credentials_path"`
	BackupDataKeyPath        string             `json:"backup_data_key_path"`
	MemberCACertificatePath  string             `json:"member_ca_certificate_path"`
	MemberCAPrivateKeyPath   string             `json:"member_ca_private_key_path"`
	ClientCACertificatePath  string             `json:"client_ca_certificate_path"`
	ClientCAPrivateKeyPath   string             `json:"client_ca_private_key_path"`
	ClientChainPath          string             `json:"client_chain_path"`
	ClientPrivateKeyPath     string             `json:"client_private_key_path"`
	SQLSchemaBundlePath      string             `json:"sql_schema_bundle_path"`
	SQLTable                 InitialSQLTable    `json:"sql_table"`
	Roster                   []backupFullMember `json:"roster"`
}

type backupFullMember struct {
	MemberID             string `json:"member_id"`
	ServerPrivateKeyPath string `json:"server_private_key_path"`
	ServerName           string `json:"server_name"`
	FailureDomain        string `json:"failure_domain"`
}

type backupFullMaterial struct {
	preparation PreparationService
	receipt     PreparationReceipt
	bundle      InitialBundle
	manifest    BackupManifestPayload
	sequence    uint64
}

func backupFullProcessMaterial(t *testing.T, ctx context.Context, runtime *authority.Runtime,
	packet backupProcessPacket, signer ed25519.PrivateKey, path string,
) backupFullMaterial {
	t.Helper()
	wire := backupFullReadFile(t, path, 16<<10, true)
	var input backupFullMaterialPacket
	if err := json.Unmarshal(wire, &input, json.RejectUnknownMembers(true)); err != nil ||
		input.Version != 1 || len(input.Roster) != len(packet.Roster) {
		t.Fatal("invalid root-only full material packet", err)
	}
	if input.Scope.Epoch != 1 || input.CollectionID == "" || input.SQLTable.TableID == "" {
		t.Fatal("full material scope, catalog or SQL table is missing")
	}
	manifestWire := backupFullReadFile(t, input.BackupManifestPath, 16<<10, false)
	var manifest BackupManifestPayload
	if err := decodeCanonicalBackupSigned(manifestWire, backupManifestDomain,
		signer.Public().(ed25519.PublicKey), 16<<10, &manifest); err != nil {
		t.Fatal("Rust backup manifest signature is invalid:", err)
	}
	if manifest.SourceScopeDigest != packet.SourceScopeDigest ||
		manifest.SourceAuthoritySHA256 != packet.SourceAuthoritySHA256 ||
		manifest.SourceConfigurationID != packet.SourceConfigurationID ||
		manifest.SourceTargetDigest != packet.SourceTargetDigest ||
		manifest.BackupSet != packet.BackupSet || manifest.BackupTargetDigest != packet.BackupTargetDigest ||
		manifest.SignerKeyID != packet.SignerKeyID || manifest.OwnerMemberID != packet.OwnerMemberID ||
		manifest.ClusterID != input.Scope.ClusterID || manifest.TenantID != input.Scope.TenantID ||
		manifest.DatabaseID != input.Scope.DatabaseID || manifest.ShardID != input.Scope.ShardID {
		t.Fatal("authenticated full manifest differs from live process packet or scope")
	}
	sourceConfig := backupFullReadFile(t, input.SourceS3ConfigPath, 16<<10, false)
	backupConfig := backupFullReadFile(t, input.BackupS3ConfigPath, 16<<10, false)
	var source struct {
		Version    uint64 `json:"version"`
		AckProfile string `json:"ack_profile"`
		Bucket     string `json:"bucket"`
		Region     string `json:"region"`
		Endpoint   string `json:"endpoint,omitempty"`
	}
	var target struct {
		Version  uint64 `json:"version"`
		Bucket   string `json:"bucket"`
		Region   string `json:"region"`
		Endpoint string `json:"endpoint,omitempty"`
	}
	if err := json.Unmarshal(sourceConfig, &source, json.RejectUnknownMembers(true)); err != nil ||
		source.Version != 1 || source.AckProfile != "object_durable" ||
		source.Region != "sa-saopaulo-1" {
		t.Fatal("Rust source S3 config is not the D10 GRU variant", err)
	}
	if err := json.Unmarshal(backupConfig, &target, json.RejectUnknownMembers(true)); err != nil ||
		target.Version != 1 || target.Region != "sa-saopaulo-1" {
		t.Fatal("Rust backup S3 config is not the D10 GRU variant", err)
	}
	credential := backupFullReadFile(t, input.BackupCredentialsPath, 16<<10, true)
	dataKey := backupFullReadFile(t, input.BackupDataKeyPath, 256, true)
	credentialSHA := sha256.Sum256(credential)
	dataKeySHA := sha256.Sum256(dataKey)
	if hex.EncodeToString(credentialSHA[:]) != manifest.BackupS3CredentialSHA256 ||
		hex.EncodeToString(dataKeySHA[:]) != manifest.BackupDataKeySHA256 ||
		backupSHA(backupConfig) != manifest.BackupS3ConfigSHA256 {
		t.Fatal("Rust backup credential, key or config differs from signed manifest")
	}
	const vaultRegion = "ocid1.vaultsecret.oc1.sa-saopaulo-1."
	spec := InitialSpec{PlacementDatabaseID: packet.DatabaseID, PartitionID: packet.PartitionID,
		Scope: input.Scope,
		LiveS3: LiveS3Target{Bucket: source.Bucket, Region: source.Region, Endpoint: source.Endpoint,
			Credential: oci.SecretVersionReference{SecretOCID: vaultRegion + "d10-live", VersionNumber: 1}},
		Backup: &InitialBackupSpec{Target: BackupS3Target{Bucket: target.Bucket,
			Region: target.Region, Endpoint: target.Endpoint,
			Credential:       oci.SecretVersionReference{SecretOCID: vaultRegion + "d10-backup", VersionNumber: 2},
			CredentialSHA256: manifest.BackupS3CredentialSHA256},
			OwnerMemberID: manifest.OwnerMemberID,
			DataKey:       oci.SecretVersionReference{SecretOCID: vaultRegion + "d10-key", VersionNumber: 3},
			DataKeyID:     manifest.BackupDataKeyID, DataKeySHA256: manifest.BackupDataKeySHA256,
			RetentionPolicyID:    manifest.RetentionPolicyID,
			RetentionUntilUnixMS: manifest.RetentionUntilUnixMS,
			MaxPointCadenceMS:    manifest.MaxPointCadenceMS},
		Catalogs: []InitialCatalogInput{{CollectionID: input.CollectionID,
			CanonicalCatalog: backupFullReadFile(t, input.CatalogPath, maxCatalogBytes, false)}},
		SQLTables: []InitialSQLTable{input.SQLTable}}
	// Rust's json! source file and Go's typed config can order JSON members
	// differently. The authenticated target digest binds the same three S3
	// endpoint fields; the Go bundle stores its own canonical config bytes.
	if digest, err := spec.LiveS3.Digest(); err != nil || digest != manifest.SourceTargetDigest {
		t.Fatal("Go source S3 target differs from live Rust target digest", err)
	}
	if digest, err := spec.Backup.Target.Digest(); err != nil || digest != manifest.BackupTargetDigest {
		t.Fatal("Go backup S3 target differs from live Rust target digest", err)
	}
	if got, err := spec.Backup.Target.ConfigJSON(); err != nil || !bytes.Equal(got, backupConfig) {
		t.Fatal("Go backup S3 config differs from exact Rust bytes", err)
	}
	for index, member := range packet.Roster {
		full := input.Roster[index]
		if full.MemberID != member.MemberID {
			t.Fatal("full material member order differs from process-bound roster")
		}
		ip := "10.0.0." + strconv.Itoa(11+index)
		seatID := "d10-" + strconv.Itoa(index+1)
		spec.Members[index] = InitialMember{SeatID: seatID, MemberID: member.MemberID,
			Incarnation: member.Incarnation, ServerName: full.ServerName,
			FailureDomain:     full.FailureDomain,
			MaterialDirectory: "/var/lib/terrabase/d10-full/" + seatID,
			ReplicationIP:     ip, ReplicationPort: 9443, ClientIP: ip, ClientPort: 9465,
			SQLListenPort: 5432}
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, recipientSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec.Recipient = RecipientGrant{PublicKey: recipient.PublicKey().Bytes(),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second)}
	spec.Recipient.Signature = ed25519.Sign(recipientSigner, recipientGrantMessage(spec))
	if err := validateInitialSpec(spec, recipientPublic, time.Now().UTC()); err != nil {
		t.Fatal("D10 full material spec is not valid:", err)
	}
	bundle := backupFullBundle(t, packet, input, spec, manifestWire, signer)
	if err := validateBundleForSpec(spec, bundle); err != nil {
		t.Fatal("D10 live Rust material cannot form a valid Go bundle:", err)
	}
	_, controllerSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	objects := new(fakeMaterialObjectClient)
	repository, err := NewRepository(RepositoryConfig{Region: oci.RegionGRU, Cell: "gru",
		Namespace: "terrascale", Bucket: "d10-full-material",
		KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.d10-material"}, objects, runtime)
	if err != nil {
		t.Fatal(err)
	}
	epoch := runtime.Current().Epoch
	object, err := repository.CreateInitial(ctx, epoch, spec.PartitionID, spec, bundle, controllerSigner)
	if err != nil || objects.putCount != 1 || objects.getCount == 0 {
		t.Fatal("create/read exact versioned Go material object:", err)
	}
	now := time.Now().UTC()
	receipt, err := SignPreparationReceipt("gru", spec.PartitionID, spec, bundle, object,
		controllerSigner, now)
	if err != nil {
		t.Fatal("sign Go material receipt:", err)
	}
	receiptWire, err := protocol.EncodeJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := runtime.CommitMaterialReceipt(ctx, epoch, spec.PlacementDatabaseID,
		spec.PartitionID, "material-g1-"+receipt.SpecSHA256[:24], 0, receiptWire)
	if err != nil {
		t.Fatal("commit signed Go material receipt to R3:", err)
	}
	service := PreparationService{Cell: "gru", Repository: repository, Receipts: runtime,
		Fencer: runtime, ControllerKey: controllerSigner, RecipientSigner: recipientPublic,
		AllowedSubnetCIDR: "10.0.0.0/24"}
	observed, currentBundle, err := service.CurrentBundle(ctx, spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil || observed.Signature != receipt.Signature ||
		!bytes.Equal(currentBundle.Authority.Certificate, bundle.Authority.Certificate) ||
		!bytes.Equal(currentBundle.Members[0].Files[backupManifestName].Contents, manifestWire) {
		t.Fatal("CurrentBundle did not authenticate exact Rust authority and manifest:", err)
	}
	sqlWire := backupFullReadFile(t, input.SQLSchemaBundlePath, 64<<10, false)
	for _, member := range currentBundle.Members {
		if !bytes.Equal(member.Files[sqlSchemaBundleFileName].Contents, sqlWire) {
			t.Fatal("CurrentBundle did not retain the exact Rust SQL schema bundle")
		}
	}
	t.Logf("CurrentBundle authenticated R3 material receipt sequence=%d object_sha256=%s receipt_sha256=%s",
		sequence, object.SHA256, backupSHA(receiptWire))
	t.Logf("CurrentBundle retained SQL schema bundle sha256=%s in both member bundles", backupSHA(sqlWire))
	return backupFullMaterial{preparation: service, receipt: receipt, bundle: bundle,
		manifest: manifest, sequence: sequence}
}

func backupFullBundle(t *testing.T, packet backupProcessPacket, input backupFullMaterialPacket,
	spec InitialSpec, manifestWire []byte, signer ed25519.PrivateKey,
) InitialBundle {
	t.Helper()
	authorityWire := backupFullReadFile(t, input.AuthorityCertificatePath, maxAuthorityPayload, false)
	replicationCA := backupFullReadFile(t, input.MemberCACertificatePath, 16<<10, false)
	clientCA := backupFullReadFile(t, input.ClientCACertificatePath, 16<<10, false)
	clientChain := backupFullReadFile(t, input.ClientChainPath, 16<<10, false)
	clientKey := backupFullReadFile(t, input.ClientPrivateKeyPath, 16<<10, true)
	replicationCAKey := backupFullPrivateKey(t, input.MemberCAPrivateKeyPath)
	clientCAKey := backupFullPrivateKey(t, input.ClientCAPrivateKeyPath)
	_, clientCARemainder := pem.Decode(clientChain)
	if len(clientCARemainder) == 0 || !bytes.Equal(bytes.TrimSpace(clientCARemainder), bytes.TrimSpace(clientCA)) {
		t.Fatal("Rust client chain lacks its exact pinned CA")
	}
	catalogs, err := initialCatalogs(spec.Catalogs)
	if err != nil {
		t.Fatal(err)
	}
	var members [2]AuthorityMember
	for index, member := range packet.Roster {
		certificate := backupFullReadFile(t, member.ServerCertificatePath, 16<<10, false)
		leaf, remainder := pem.Decode(certificate)
		if leaf == nil || !bytes.Equal(bytes.TrimSpace(remainder), bytes.TrimSpace(replicationCA)) {
			t.Fatal("Rust replication chain lacks its exact pinned CA")
		}
		members[index] = AuthorityMember{MemberID: member.MemberID,
			Incarnation: member.Incarnation, ServerName: spec.Members[index].ServerName,
			FailureDomain: spec.Members[index].FailureDomain, LeafDER: leaf.Bytes}
	}
	authority, err := SignInitialAuthorityV2(spec.Scope, members, catalogs, signer)
	if err != nil || !bytes.Equal(authority.Certificate, authorityWire) ||
		authority.ConfigurationID != packet.SourceConfigurationID ||
		backupSHA(authorityWire) != packet.SourceAuthoritySHA256 {
		t.Fatal("Go authority recreation differs from exact live Rust authority", err)
	}
	tokenID, _ := entityid.Parse(entityid.New())
	var tokenSecret [32]byte
	if _, err := rand.Read(tokenSecret[:]); err != nil {
		t.Fatal(err)
	}
	defer clear(tokenSecret[:])
	verifier := sha256.New()
	verifier.Write([]byte("TB-APIKEY-V1\x00"))
	verifier.Write(tokenID[:])
	verifier.Write(tokenSecret[:])
	verifierHex := hex.EncodeToString(verifier.Sum(nil))
	encodedID := tokenID.String()
	token := "tbk1." + encodedID + "." + base64.RawURLEncoding.EncodeToString(tokenSecret[:])
	registry, err := json.Marshal(apiKeyRegistry{Version: 1, Keys: []apiKeyEntry{{
		ID: encodedID, VerifierSHA256: verifierHex,
		Tenant: spec.Scope.TenantID, Database: spec.Scope.DatabaseID,
		Shard:       strconv.FormatUint(spec.Scope.ShardID, 10),
		Collections: initialCollectionIDs(spec.Catalogs),
		TableIDs:    initialSQLTableIDs(spec.SQLTables),
		Permissions: []string{"read", "write"}, Revoked: false,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	customer, err := encryptCustomerToken(spec, token, verifierHex, clientCARemainder)
	if err != nil {
		t.Fatal(err)
	}
	liveConfig, err := spec.LiveS3.ConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	backupConfig := backupFullReadFile(t, input.BackupS3ConfigPath, 16<<10, false)
	sqlBundle := backupFullReadFile(t, input.SQLSchemaBundlePath, 64<<10, false)
	var output [2]MemberBundle
	for index, member := range packet.Roster {
		seat := spec.Members[index]
		serverChain := backupFullReadFile(t, member.ServerCertificatePath, 16<<10, false)
		serverKey := backupFullReadFile(t, input.Roster[index].ServerPrivateKeyPath, 16<<10, true)
		files := map[string]File{
			"authority.tbca":           makeFile(authorityWire),
			"trusted-public-key":       makeFile(authority.TrustedKey),
			"server.crt":               makeFile(serverChain),
			"server.key":               makeFile(serverKey),
			"server-ca.pem":            makeFile(replicationCA),
			"client-ca.pem":            makeFile(replicationCA),
			"client-chain.pem":         makeFile(clientChain),
			"client-private-key.pem":   makeFile(clientKey),
			"client-api-keys.json":     makeFile(registry),
			"signed-v2-s3-config.json": makeFile(liveConfig),
			backupManifestName:         makeFile(manifestWire),
			backupConfigName:           makeFile(backupConfig),
			sqlSchemaBundleFileName:    makeFile(sqlBundle),
		}
		config, err := json.Marshal(struct {
			Version          uint64 `json:"version"`
			ListenAddress    string `json:"listen_addr"`
			SQLListenAddress string `json:"sql_listen_addr,omitempty"`
			CertificateChain string `json:"certificate_chain"`
			PrivateKey       string `json:"private_key"`
			APIKeyRegistry   string `json:"api_key_registry"`
		}{1, net.JoinHostPort(seat.ClientIP, strconv.Itoa(int(seat.ClientPort))),
			sqlListenAddress(seat), filepath.Join(seat.MaterialDirectory, "client-chain.pem"),
			filepath.Join(seat.MaterialDirectory, "client-private-key.pem"),
			filepath.Join(seat.MaterialDirectory, "client-api-keys.json")})
		if err != nil {
			t.Fatal(err)
		}
		files["client-config.json"] = makeFile(config)
		clientManifest, err := json.Marshal(struct {
			Version                uint64 `json:"version"`
			ClientConfigSHA256     string `json:"client_config_sha256"`
			CertificateChainSHA256 string `json:"certificate_chain_sha256"`
			PrivateKeySHA256       string `json:"private_key_sha256"`
			APIKeyRegistrySHA256   string `json:"api_key_registry_sha256"`
		}{1, files["client-config.json"].SHA256, files["client-chain.pem"].SHA256,
			files["client-private-key.pem"].SHA256, files["client-api-keys.json"].SHA256})
		if err != nil {
			t.Fatal(err)
		}
		files["client-managed-manifest.json"] = makeFile(clientManifest)
		output[index] = MemberBundle{MemberID: member.MemberID,
			TLSLeafSHA256: member.TLSLeafSHA256, Files: files}
	}
	return InitialBundle{Authority: authority, Members: output, Customer: customer,
		Retained: RetainedSecrets{AuthoritySigner: signer, ReplicationCA: replicationCAKey,
			HTTPSCA: clientCAKey}}
}

func backupFullReadFile(t *testing.T, path string, limit int, private bool) []byte {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatal("full material path is not absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > int64(limit) {
		t.Fatal("full material path is not a bounded regular file:", path, err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != 0 ||
		private && info.Mode().Perm() != 0o600 {
		t.Fatal("full material path owner or mode is invalid:", path)
	}
	wire, err := os.ReadFile(path)
	if err != nil || len(wire) < 1 || len(wire) > limit {
		t.Fatal("read bounded full material file:", path, err)
	}
	return wire
}

func backupFullPrivateKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	wire := backupFullReadFile(t, path, 16<<10, true)
	block, _ := pem.Decode(wire)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("full material CA private key is not PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		t.Fatal("full material CA private key is not Ed25519:", err)
	}
	return key
}
