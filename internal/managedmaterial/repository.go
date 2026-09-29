package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const maxStoredBundleBytes = 8 << 20
const provisioningDomain = "TS-MANAGED-MATERIAL-PROVISIONING-V2\x00"

var repositoryToken = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var (
	ErrMaterialConflict = errors.New("managed material object conflicts with its immutable generation")
	ErrMaterialUnknown  = errors.New("managed material object outcome is unknown")
	ErrMaterialNotFound = errors.New("managed material object was not found")
)

// RepositoryConfig must come from independently signed regional configuration.
// OCI IAM must allow exact-object create and read, and deny overwrite, delete,
// and list to the controller principal. This type cannot grant those IAM rights.
type RepositoryConfig struct {
	Region    oci.Region
	Cell      string
	Namespace string
	Bucket    string
	KMSKeyID  string
}

func (config RepositoryConfig) Validate() error {
	if _, err := config.Region.OCIRegion(); err != nil {
		return err
	}
	if !repositoryToken.MatchString(config.Cell) || !repositoryToken.MatchString(config.Namespace) ||
		!repositoryToken.MatchString(config.Bucket) ||
		!strings.HasPrefix(config.KMSKeyID, "ocid1.key.") || len(config.KMSKeyID) > 255 ||
		strings.ContainsAny(config.KMSKeyID, " \t\r\n/") {
		return errors.New("managed material repository pin is invalid")
	}
	return nil
}

type ObjectClient interface {
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
}

type objectServiceError interface {
	error
	GetHTTPStatusCode() int
}

type ObjectReference struct {
	Name       string `json:"name"`
	VersionID  string `json:"version_id"`
	ETag       string `json:"etag"`
	SHA256     string `json:"sha256"`
	SpecSHA256 string `json:"spec_sha256"`
}

type storedBundle struct {
	Version               uint64        `json:"version"`
	Region                string        `json:"region"`
	Cell                  string        `json:"cell"`
	Namespace             string        `json:"namespace"`
	Bucket                string        `json:"bucket"`
	KMSKeyID              string        `json:"kms_key_id"`
	ObjectName            string        `json:"object_name"`
	Generation            uint64        `json:"generation"`
	SpecSHA256            string        `json:"spec_sha256"`
	Spec                  InitialSpec   `json:"spec"`
	Bundle                InitialBundle `json:"bundle"`
	ProvisioningSignature string        `json:"provisioning_signature"`
}

func (stored storedBundle) provisioningInput() ([]byte, error) {
	unsigned := struct {
		Version    uint64        `json:"version"`
		Region     string        `json:"region"`
		Cell       string        `json:"cell"`
		Namespace  string        `json:"namespace"`
		Bucket     string        `json:"bucket"`
		KMSKeyID   string        `json:"kms_key_id"`
		ObjectName string        `json:"object_name"`
		Generation uint64        `json:"generation"`
		SpecSHA256 string        `json:"spec_sha256"`
		Spec       InitialSpec   `json:"spec"`
		Bundle     InitialBundle `json:"bundle"`
	}{stored.Version, stored.Region, stored.Cell, stored.Namespace, stored.Bucket, stored.KMSKeyID,
		stored.ObjectName, stored.Generation,
		stored.SpecSHA256, stored.Spec, stored.Bundle}
	wire, err := protocol.EncodeJSON(unsigned)
	if err != nil {
		return nil, err
	}
	return append([]byte(provisioningDomain), wire...), nil
}

func (stored storedBundle) verifyProvisioning(controllerKey ed25519.PublicKey) bool {
	if stored.Version != 2 || len(controllerKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(stored.ProvisioningSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	input, err := stored.provisioningInput()
	return err == nil && ed25519.Verify(controllerKey, input, signature)
}

type Repository struct {
	config RepositoryConfig
	client ObjectClient
	fencer authority.Fencer
}

func NewRepository(config RepositoryConfig, client ObjectClient, fencer authority.Fencer) (*Repository, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if client == nil || fencer == nil {
		return nil, errors.New("managed material repository requires OCI client and authority fencer")
	}
	return &Repository{config: config, client: client, fencer: fencer}, nil
}

// NewOCIRepository uses instance principal identity in the pinned product
// region. The namespace, bucket, and KMS key still come from signed config.
func NewOCIRepository(config RepositoryConfig, fencer authority.Fencer) (*Repository, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	region, _ := config.Region.OCIRegion()
	provider, err := auth.InstancePrincipalConfigurationProviderForRegion(common.Region(region))
	if err != nil {
		return nil, fmt.Errorf("managed material OCI instance principal: %w", err)
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("managed material OCI client: %w", err)
	}
	return NewRepository(config, &client, fencer)
}

func specDigest(spec InitialSpec) (string, error) {
	wire, err := protocol.EncodeJSON(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

func (repository *Repository) objectName(database, partition string, generation uint64, specSHA string) (string, error) {
	if repository == nil || !repositoryToken.MatchString(database) || !repositoryToken.MatchString(partition) || generation != 1 ||
		len(specSHA) != 64 || !lowerHexDigest(specSHA) {
		return "", errors.New("managed material object scope is invalid")
	}
	return fmt.Sprintf("material/v2/%s/%s/%s/g1-%s.json", repository.config.Cell, database, partition, specSHA), nil
}

func lowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

// CreateInitial writes a single create-only, KMS-encrypted object. A failed
// acknowledgement is reconciled by an exact-key read; only exact byte equality
// and an observed version and ETag can produce a reference. The reference is
// evidence, never placement authority until a fenced R3 receipt commits.
func (repository *Repository) CreateInitial(ctx context.Context, epoch uint64, partition string,
	spec InitialSpec, bundle InitialBundle, controllerKey ed25519.PrivateKey,
) (ObjectReference, error) {
	if repository == nil || ctx == nil || epoch == 0 || spec.PartitionID != partition ||
		len(controllerKey) != ed25519.PrivateKeySize {
		return ObjectReference{}, errors.New("managed material repository call is invalid")
	}
	if err := repository.fencer.Guard(ctx, epoch); err != nil {
		return ObjectReference{}, err
	}
	specSHA, err := specDigest(spec)
	if err != nil {
		return ObjectReference{}, err
	}
	name, err := repository.objectName(spec.PlacementDatabaseID, partition, 1, specSHA)
	if err != nil {
		return ObjectReference{}, err
	}
	if err := validateBundleForSpec(spec, bundle); err != nil {
		return ObjectReference{}, err
	}
	stored := storedBundle{Version: 2, Region: string(repository.config.Region), Cell: repository.config.Cell,
		Namespace: repository.config.Namespace, Bucket: repository.config.Bucket, KMSKeyID: repository.config.KMSKeyID,
		ObjectName: name, Generation: 1, SpecSHA256: specSHA, Spec: spec, Bundle: bundle}
	input, err := stored.provisioningInput()
	if err != nil {
		return ObjectReference{}, err
	}
	stored.ProvisioningSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(controllerKey, input))
	body, err := protocol.EncodeJSON(stored)
	if err != nil || len(body) == 0 || len(body) > maxStoredBundleBytes {
		return ObjectReference{}, errors.New("managed material bundle exceeds its object bound")
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	length := int64(len(body))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	response, putErr := repository.client.PutObject(ctx, objectstorage.PutObjectRequest{
		NamespaceName: new(repository.config.Namespace), BucketName: new(repository.config.Bucket),
		ObjectName: new(name), PutObjectBody: io.NopCloser(bytes.NewReader(body)),
		ContentLength: new(length), ContentType: new("application/json"),
		IfNoneMatch: new("*"), OpcSseKmsKeyId: new(repository.config.KMSKeyID),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     new(checksum),
	})
	// A failed Put may have committed. The read must still match the exact
	// request bytes; a different object is a conflict, not an adopted signer.
	observed, readErr := repository.read(ctx, name, "", "", sha, controllerKey.Public().(ed25519.PublicKey))
	if readErr != nil {
		if errors.Is(readErr, ErrMaterialConflict) {
			return ObjectReference{}, ErrMaterialConflict
		}
		return ObjectReference{}, fmt.Errorf("%w: put: %v; read: %v", ErrMaterialUnknown, putErr, readErr)
	}
	if !bytes.Equal(observed.bytes, body) {
		return ObjectReference{}, ErrMaterialConflict
	}
	if putErr == nil && (response.ETag == nil || *response.ETag != observed.ref.ETag ||
		response.VersionId == nil || *response.VersionId != observed.ref.VersionID) {
		return ObjectReference{}, ErrMaterialConflict
	}
	if err := repository.fencer.Guard(ctx, epoch); err != nil {
		return ObjectReference{}, err
	}
	observed.ref.SpecSHA256 = specSHA
	return observed.ref, nil
}

type observedBundle struct {
	ref    ObjectReference
	bytes  []byte
	bundle InitialBundle
}

// ReadPinned retrieves one exact immutable version from a committed receipt.
// The caller must obtain ref from R3, not a caller-supplied object locator.
func (repository *Repository) ReadPinned(ctx context.Context, ref ObjectReference,
	controllerKey ed25519.PublicKey,
) (InitialBundle, error) {
	if repository == nil || ctx == nil || ref.VersionID == "" || ref.ETag == "" ||
		!lowerHexDigest(ref.SHA256) || !lowerHexDigest(ref.SpecSHA256) ||
		!repository.validObjectName(ref.Name, ref.SpecSHA256) {
		return InitialBundle{}, errors.New("managed material reference is invalid")
	}
	observed, err := repository.read(ctx, ref.Name, ref.VersionID, ref.ETag, ref.SHA256, controllerKey)
	if err != nil {
		return InitialBundle{}, err
	}
	if observed.ref.VersionID != ref.VersionID || observed.ref.ETag != ref.ETag ||
		observed.ref.SHA256 != ref.SHA256 || observed.ref.SpecSHA256 != ref.SpecSHA256 {
		return InitialBundle{}, ErrMaterialConflict
	}
	return observed.bundle, nil
}

// LookupInitial recovers an object written before its R3 receipt. It returns
// bytes only; the caller must commit a new signed receipt before admission.
func (repository *Repository) LookupInitial(ctx context.Context, partition string, spec InitialSpec,
	controllerKey ed25519.PublicKey,
) (InitialBundle, ObjectReference, error) {
	if repository == nil || ctx == nil || spec.PartitionID != partition ||
		len(controllerKey) != ed25519.PublicKeySize {
		return InitialBundle{}, ObjectReference{}, errors.New("managed material lookup is invalid")
	}
	specSHA, err := specDigest(spec)
	if err != nil {
		return InitialBundle{}, ObjectReference{}, err
	}
	name, err := repository.objectName(spec.PlacementDatabaseID, partition, 1, specSHA)
	if err != nil {
		return InitialBundle{}, ObjectReference{}, err
	}
	observed, err := repository.read(ctx, name, "", "", "", controllerKey)
	if err != nil {
		return InitialBundle{}, ObjectReference{}, err
	}
	if observed.ref.SpecSHA256 != specSHA {
		return InitialBundle{}, ObjectReference{}, ErrMaterialConflict
	}
	return observed.bundle, observed.ref, nil
}

func (repository *Repository) validObjectName(name, specSHA string) bool {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "material" || parts[1] != "v2" ||
		parts[2] != repository.config.Cell || !repositoryToken.MatchString(parts[4]) ||
		parts[5] != "g1-"+specSHA+".json" {
		return false
	}
	return repositoryToken.MatchString(parts[3])
}

func (repository *Repository) read(ctx context.Context, name, versionID, etag, wantSHA string,
	controllerKey ed25519.PublicKey,
) (observedBundle, error) {
	request := objectstorage.GetObjectRequest{NamespaceName: new(repository.config.Namespace),
		BucketName: new(repository.config.Bucket), ObjectName: new(name)}
	if versionID != "" {
		request.VersionId = new(versionID)
	}
	if etag != "" {
		request.IfMatch = new(etag)
	}
	response, err := repository.client.GetObject(ctx, request)
	if err != nil {
		if service, ok := errors.AsType[objectServiceError](err); ok &&
			service.GetHTTPStatusCode() == http.StatusNotFound {
			return observedBundle{}, ErrMaterialNotFound
		}
		return observedBundle{}, err
	}
	if response.Content == nil {
		return observedBundle{}, ErrMaterialConflict
	}
	defer response.Content.Close()
	if response.ContentLength == nil || *response.ContentLength < 1 || *response.ContentLength > maxStoredBundleBytes ||
		response.ETag == nil || *response.ETag == "" || response.VersionId == nil || *response.VersionId == "" {
		return observedBundle{}, ErrMaterialConflict
	}
	body, err := io.ReadAll(io.LimitReader(response.Content, maxStoredBundleBytes+1))
	if err != nil {
		return observedBundle{}, err
	}
	if len(body) != int(*response.ContentLength) || len(body) > maxStoredBundleBytes {
		return observedBundle{}, ErrMaterialConflict
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	if wantSHA != "" && sha != wantSHA || versionID != "" && *response.VersionId != versionID ||
		etag != "" && *response.ETag != etag {
		return observedBundle{}, ErrMaterialConflict
	}
	var stored storedBundle
	if err := json.Unmarshal(body, &stored, json.RejectUnknownMembers(true)); err != nil ||
		stored.Region != string(repository.config.Region) || stored.Cell != repository.config.Cell ||
		stored.Namespace != repository.config.Namespace || stored.Bucket != repository.config.Bucket ||
		stored.KMSKeyID != repository.config.KMSKeyID ||
		stored.ObjectName != name || stored.Generation != 1 ||
		!stored.verifyProvisioning(controllerKey) ||
		!lowerHexDigest(stored.SpecSHA256) || validateBundleForSpec(stored.Spec, stored.Bundle) != nil {
		return observedBundle{}, ErrMaterialConflict
	}
	canonical, err := protocol.EncodeJSON(stored)
	if err != nil || !bytes.Equal(body, canonical) {
		return observedBundle{}, ErrMaterialConflict
	}
	specSHA, err := specDigest(stored.Spec)
	if err != nil || specSHA != stored.SpecSHA256 ||
		!repository.validObjectName(name, specSHA) {
		return observedBundle{}, ErrMaterialConflict
	}
	return observedBundle{ref: ObjectReference{Name: name, VersionID: *response.VersionId,
		ETag: *response.ETag, SHA256: sha, SpecSHA256: stored.SpecSHA256},
		bytes: body, bundle: stored.Bundle}, nil
}

func validateStoredBundle(bundle InitialBundle) error {
	if len(bundle.Authority.TrustedKey) != 32 || len(bundle.Retained.AuthoritySigner) != 64 ||
		!bytes.Equal(bundle.Retained.AuthoritySigner.Public().(ed25519.PublicKey), bundle.Authority.TrustedKey) ||
		len(bundle.Retained.ReplicationCA) != 64 || len(bundle.Retained.HTTPSCA) != 64 ||
		len(bundle.Authority.Certificate) == 0 || !lowerHexDigest(bundle.Authority.ConfigurationID) ||
		bundle.Customer.Version != 2 || !lowerHexDigest(bundle.Customer.VerifierSHA256) ||
		!lowerHexDigest(bundle.Customer.HTTPSCASHA256) {
		return ErrMaterialConflict
	}
	identifier, idErr := base64.RawURLEncoding.DecodeString(bundle.Customer.TokenID)
	public, publicErr := base64.RawURLEncoding.DecodeString(bundle.Customer.EphemeralPublicKey)
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(bundle.Customer.Nonce)
	ciphertext, ciphertextErr := base64.RawURLEncoding.DecodeString(bundle.Customer.Ciphertext)
	if idErr != nil || len(identifier) != 16 || publicErr != nil || len(public) != 32 ||
		nonceErr != nil || len(nonce) != 12 || ciphertextErr != nil || len(ciphertext) < 16 ||
		len(ciphertext) > 16<<10 {
		return ErrMaterialConflict
	}
	if _, err := ecdh.X25519().NewPublicKey(public); err != nil {
		return ErrMaterialConflict
	}
	var sqlBundleBytes []byte
	for index, member := range bundle.Members {
		sqlFile, hasSQL := member.Files[sqlSchemaBundleFileName]
		wantFileCount := len(initialHostFiles)
		if hasSQL {
			wantFileCount++
		}
		_, hasBackup := member.Files[backupManifestName]
		if hasBackup {
			wantFileCount += 2
			if _, hasConfig := member.Files[backupConfigName]; !hasConfig {
				return ErrMaterialConflict
			}
		}
		if _, err := canonicalUUID(member.MemberID); err != nil || len(member.Files) != wantFileCount {
			return ErrMaterialConflict
		}
		if index == 0 {
			if hasSQL {
				sqlBundleBytes = sqlFile.Contents
			}
		} else if hasSQL != (sqlBundleBytes != nil) || hasSQL && !bytes.Equal(sqlBundleBytes, sqlFile.Contents) {
			return ErrMaterialConflict
		}
		for _, name := range initialHostFiles {
			if _, exists := member.Files[name]; !exists {
				return ErrMaterialConflict
			}
		}
		for _, file := range member.Files {
			sum := sha256.Sum256(file.Contents)
			if len(file.Contents) == 0 || hex.EncodeToString(sum[:]) != file.SHA256 {
				return ErrMaterialConflict
			}
		}
		for name := range member.Files {
			if !slices.Contains(initialHostFiles[:], name) && name != sqlSchemaBundleFileName &&
				name != backupManifestName && name != backupConfigName {
				return ErrMaterialConflict
			}
		}
	}
	return nil
}

func validateBundleForSpec(spec InitialSpec, bundle InitialBundle) error {
	if err := validateStoredBundle(bundle); err != nil {
		return err
	}
	if validateSQLTables(spec.SQLTables, spec.Catalogs) != nil ||
		verifyStoredBackupMaterial(spec, bundle) != nil {
		return ErrMaterialConflict
	}
	catalogs, err := initialCatalogs(spec.Catalogs)
	if err != nil {
		return ErrMaterialConflict
	}
	var authorityMembers [2]AuthorityMember
	for index, seat := range spec.Members {
		member := bundle.Members[index]
		_, hasSQL := member.Files[sqlSchemaBundleFileName]
		if member.MemberID != seat.MemberID || hasSQL != (len(spec.SQLTables) > 0) {
			return ErrMaterialConflict
		}
		server := member.Files["server.crt"].Contents
		block, _ := pem.Decode(server)
		if block == nil || block.Type != "CERTIFICATE" {
			return ErrMaterialConflict
		}
		if _, err := tls.X509KeyPair(server, member.Files["server.key"].Contents); err != nil {
			return ErrMaterialConflict
		}
		if !bytes.Equal(member.Files["server-ca.pem"].Contents, member.Files["client-ca.pem"].Contents) ||
			!verifyStoredLiveS3(spec, member) ||
			!bytes.Contains(server, member.Files["server-ca.pem"].Contents) ||
			verifyStoredTLS(seat, member, bundle.Retained) != nil ||
			verifyStoredClientConfig(spec, seat, member) != nil ||
			verifyStoredRegistry(spec, member, bundle.Customer) != nil {
			return ErrMaterialConflict
		}
		_, caPEM := pem.Decode(member.Files["client-chain.pem"].Contents)
		caDigest := sha256.Sum256(caPEM)
		if bundle.Customer.HTTPSCASHA256 != hex.EncodeToString(caDigest[:]) {
			return ErrMaterialConflict
		}
		authorityMembers[index] = AuthorityMember{MemberID: seat.MemberID, Incarnation: seat.Incarnation,
			ServerName: seat.ServerName, FailureDomain: seat.FailureDomain, LeafDER: block.Bytes}
		if !bytes.Equal(member.Files["authority.tbca"].Contents, bundle.Authority.Certificate) ||
			!bytes.Equal(member.Files["trusted-public-key"].Contents, bundle.Authority.TrustedKey) ||
			member.TLSLeafSHA256 != bundle.Authority.MemberLeafPins[index] {
			return ErrMaterialConflict
		}
	}
	recreated, err := SignInitialAuthorityV2(spec.Scope, authorityMembers, catalogs, bundle.Retained.AuthoritySigner)
	if err != nil || !bytes.Equal(recreated.Certificate, bundle.Authority.Certificate) ||
		recreated.ConfigurationID != bundle.Authority.ConfigurationID ||
		!bytes.Equal(recreated.TrustedKey, bundle.Authority.TrustedKey) {
		return ErrMaterialConflict
	}
	if len(spec.SQLTables) > 0 {
		wantSQLBundle, err := encodeSQLSchemaBundle(spec.Scope, recreated.ConfigurationID,
			spec.SQLTables, bundle.Retained.AuthoritySigner)
		if err != nil || !bytes.Equal(wantSQLBundle, bundle.Members[0].Files[sqlSchemaBundleFileName].Contents) ||
			!bytes.Equal(bundle.Members[0].Files[sqlSchemaBundleFileName].Contents,
				bundle.Members[1].Files[sqlSchemaBundleFileName].Contents) {
			return ErrMaterialConflict
		}
	}
	return nil
}

func verifyStoredTLS(seat InitialMember, member MemberBundle, retained RetainedSecrets) error {
	serverPair, err := tls.X509KeyPair(member.Files["server.crt"].Contents, member.Files["server.key"].Contents)
	if err != nil || len(serverPair.Certificate) == 0 {
		return ErrMaterialConflict
	}
	serverLeaf, err := x509.ParseCertificate(serverPair.Certificate[0])
	if err != nil {
		return ErrMaterialConflict
	}
	replicationRoots := x509.NewCertPool()
	if !replicationRoots.AppendCertsFromPEM(member.Files["server-ca.pem"].Contents) {
		return ErrMaterialConflict
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := serverLeaf.Verify(x509.VerifyOptions{Roots: replicationRoots, DNSName: seat.ServerName,
			KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return ErrMaterialConflict
		}
	}
	httpsPair, err := tls.X509KeyPair(member.Files["client-chain.pem"].Contents,
		member.Files["client-private-key.pem"].Contents)
	if err != nil || len(httpsPair.Certificate) == 0 {
		return ErrMaterialConflict
	}
	httpsLeaf, err := x509.ParseCertificate(httpsPair.Certificate[0])
	if err != nil {
		return ErrMaterialConflict
	}
	httpsRoots := x509.NewCertPool()
	if !httpsRoots.AppendCertsFromPEM(member.Files["client-chain.pem"].Contents) {
		return ErrMaterialConflict
	}
	if _, err := httpsLeaf.Verify(x509.VerifyOptions{Roots: httpsRoots, DNSName: seat.ClientIP,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return ErrMaterialConflict
	}
	_, httpsCAContents := pem.Decode(member.Files["client-chain.pem"].Contents)
	for _, check := range []struct {
		contents []byte
		private  []byte
	}{
		{member.Files["server-ca.pem"].Contents, retained.ReplicationCA},
		{httpsCAContents, retained.HTTPSCA},
	} {
		block, _ := pem.Decode(check.contents)
		if block == nil {
			return ErrMaterialConflict
		}
		if len(check.private) != ed25519.PrivateKeySize {
			return ErrMaterialConflict
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return ErrMaterialConflict
		}
		public, ok := certificate.PublicKey.(ed25519.PublicKey)
		if !ok || !certificate.IsCA ||
			!bytes.Equal(public, ed25519.PrivateKey(check.private).Public().(ed25519.PublicKey)) {
			return ErrMaterialConflict
		}
	}
	return nil
}

func verifyStoredClientConfig(spec InitialSpec, seat InitialMember, member MemberBundle) error {
	var config struct {
		Version          uint64 `json:"version"`
		ListenAddress    string `json:"listen_addr"`
		SQLListenAddress string `json:"sql_listen_addr,omitempty"`
		CertificateChain string `json:"certificate_chain"`
		PrivateKey       string `json:"private_key"`
		APIKeyRegistry   string `json:"api_key_registry"`
	}
	if err := json.Unmarshal(member.Files["client-config.json"].Contents, &config, json.RejectUnknownMembers(true)); err != nil ||
		config.Version != 1 || config.ListenAddress != net.JoinHostPort(seat.ClientIP, strconv.Itoa(int(seat.ClientPort))) ||
		config.SQLListenAddress != sqlListenAddress(seat) || (len(spec.SQLTables) > 0) != (config.SQLListenAddress != "") ||
		config.CertificateChain != filepath.Join(seat.MaterialDirectory, "client-chain.pem") ||
		config.PrivateKey != filepath.Join(seat.MaterialDirectory, "client-private-key.pem") ||
		config.APIKeyRegistry != filepath.Join(seat.MaterialDirectory, "client-api-keys.json") {
		return ErrMaterialConflict
	}
	var manifest struct {
		Version                uint64 `json:"version"`
		ClientConfigSHA256     string `json:"client_config_sha256"`
		CertificateChainSHA256 string `json:"certificate_chain_sha256"`
		PrivateKeySHA256       string `json:"private_key_sha256"`
		APIKeyRegistrySHA256   string `json:"api_key_registry_sha256"`
	}
	if err := json.Unmarshal(member.Files["client-managed-manifest.json"].Contents, &manifest, json.RejectUnknownMembers(true)); err != nil ||
		manifest.Version != 1 || manifest.ClientConfigSHA256 != member.Files["client-config.json"].SHA256 ||
		manifest.CertificateChainSHA256 != member.Files["client-chain.pem"].SHA256 ||
		manifest.PrivateKeySHA256 != member.Files["client-private-key.pem"].SHA256 ||
		manifest.APIKeyRegistrySHA256 != member.Files["client-api-keys.json"].SHA256 {
		return ErrMaterialConflict
	}
	return nil
}

func verifyStoredRegistry(spec InitialSpec, member MemberBundle, customer CustomerEnvelope) error {
	var registry apiKeyRegistry
	if err := json.Unmarshal(member.Files["client-api-keys.json"].Contents, &registry, json.RejectUnknownMembers(true)); err != nil ||
		registry.Version != 1 || len(registry.Keys) != 1 {
		return ErrMaterialConflict
	}
	key := registry.Keys[0]
	id, err := base64.RawURLEncoding.DecodeString(key.ID)
	if err != nil || len(id) != 16 || !lowerHexDigest(key.VerifierSHA256) ||
		key.ID != customer.TokenID || key.VerifierSHA256 != customer.VerifierSHA256 ||
		key.Tenant != spec.Scope.TenantID || key.Database != spec.Scope.DatabaseID ||
		key.Shard != strconv.FormatUint(spec.Scope.ShardID, 10) ||
		!slices.Equal(key.Collections, initialCollectionIDs(spec.Catalogs)) ||
		!slices.Equal(key.TableIDs, initialSQLTableIDs(spec.SQLTables)) ||
		len(key.Permissions) != 2 || key.Permissions[0] != "read" || key.Permissions[1] != "write" ||
		key.Revoked || bytes.Contains(member.Files["client-api-keys.json"].Contents, []byte("tbk1.")) {
		return ErrMaterialConflict
	}
	return nil
}
