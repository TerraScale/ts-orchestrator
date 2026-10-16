package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

const MaxSecretBytes int64 = 1 << 20

var (
	ErrVaultSecretMismatch = errors.New("Vault secret does not match its signed reference")
	ErrMaterialization     = errors.New("bootstrap secret materialization failed")
)

// SecretBundle is the exact, base64-encoded response data for one immutable
// Vault secret version. It is separate from the OCI SDK type for offline tests.
type SecretBundle struct {
	SecretOCID    string
	VersionNumber int64
	ContentType   string
	ContentBase64 string
}

// SecretBundleReader fetches one explicitly named secret version. It must not
// resolve mutable stages such as CURRENT or LATEST.
type SecretBundleReader interface {
	GetSecretBundle(context.Context, string, int64) (SecretBundle, error)
}

// Vault retrieves and safely materializes references authorized by both a
// currently verified manifest and its current exact-instance receipt.
type Vault struct {
	reader SecretBundleReader
	now    func() time.Time
}

type ociSecretBundleClient interface {
	GetSecretBundle(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error)
}

type ociSecretBundleReader struct {
	client ociSecretBundleClient
}

// NewInstancePrincipalVault constructs an OCI Secrets client from the
// anchor-scoped instance-principal provider shared by bootstrap observers.
// IAM must grant only the intended secret OCIDs and versions.
func NewInstancePrincipalVault(region oci.Region, provider common.ConfigurationProvider) (*Vault, error) {
	ociRegion, err := region.OCIRegion()
	if err != nil || provider == nil {
		return nil, errors.New("bootstrap Vault requires a supported region and verified instance-principal provider")
	}
	providerRegion, err := provider.Region()
	if err != nil || providerRegion != ociRegion {
		return nil, errors.New("bootstrap Vault provider region differs from the anchored region")
	}
	client, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Secrets client: %w", err)
	}
	client.SetRegion(ociRegion)
	client.HTTPClient, err = NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("configure OCI Secrets HTTP transport: %w", err)
	}
	return &Vault{reader: ociSecretBundleReader{client: client}, now: time.Now}, nil
}

// Materialize checks the current manifest and receipt for one exact secret.
// The production admission path uses MaterializeCurrent to additionally bind
// each Vault read and file install to its still-current root proof chain.
func (vault *Vault) Materialize(ctx context.Context, manifest StartupAuthority, receipt VerifiedReceipt, reference SecretReference, destinationDirectory string) error {
	return vault.materialize(ctx, manifest, receipt, reference, destinationDirectory, nil)
}

// MaterializeCurrent additionally rechecks the whole current bootstrap proof
// immediately before the Vault request and before installing its response.
func (vault *Vault) MaterializeCurrent(ctx context.Context, manifest StartupAuthority, receipt VerifiedReceipt,
	reference SecretReference, destinationDirectory string, verifyCurrent func(time.Time) error,
) error {
	if verifyCurrent == nil {
		return ErrMaterialization
	}
	return vault.materialize(ctx, manifest, receipt, reference, destinationDirectory, verifyCurrent)
}

func (vault *Vault) materialize(ctx context.Context, manifest StartupAuthority, receipt VerifiedReceipt,
	reference SecretReference, destinationDirectory string, verifyCurrent func(time.Time) error,
) error {
	if vault == nil || vault.reader == nil {
		return errors.New("bootstrap Vault reader is not configured")
	}
	clock := time.Now
	if vault.now != nil {
		clock = vault.now
	}
	now := clock()
	if verifyCurrent != nil {
		if err := verifyCurrent(now); err != nil {
			return fmt.Errorf("current bootstrap proof before Vault read: %w", err)
		}
	}
	if err := authorizeSecretMaterialization(manifest, receipt, reference, now); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bundle, err := vault.reader.GetSecretBundle(ctx, reference.SecretOCID, reference.VersionNumber)
	if err != nil {
		return fmt.Errorf("get exact OCI Vault secret bundle: %w", err)
	}
	now = clock()
	if verifyCurrent != nil {
		if err := verifyCurrent(now); err != nil {
			return fmt.Errorf("current bootstrap proof before secret install: %w", err)
		}
	}
	if err := authorizeSecretMaterialization(manifest, receipt, reference, now); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	content, err := decodeSecretBundle(bundle, reference)
	if err != nil {
		return err
	}
	defer clear(content)
	if err := materializeSecret(destinationDirectory, reference.TargetFile, content); err != nil {
		return err
	}
	return nil
}

// ReadGenerationSecret reads the exact secret version a material generation
// pins and returns its bytes once they match the pinned digest and size.
// The caller verified the generation and holds reference's slot.
func (vault *Vault) ReadGenerationSecret(ctx context.Context, reference SecretReference) ([]byte, error) {
	if vault == nil || vault.reader == nil {
		return nil, errors.New("bootstrap Vault reader is not configured")
	}
	bundle, err := vault.reader.GetSecretBundle(ctx, reference.SecretOCID, reference.VersionNumber)
	if err != nil {
		return nil, fmt.Errorf("get exact OCI Vault secret bundle: %w", err)
	}
	return decodeSecretBundle(bundle, reference)
}

func (reader ociSecretBundleReader) GetSecretBundle(ctx context.Context, secretOCID string, version int64) (SecretBundle, error) {
	response, err := reader.client.GetSecretBundle(ctx, secrets.GetSecretBundleRequest{
		SecretId: new(secretOCID), VersionNumber: new(version),
	})
	if err != nil {
		return SecretBundle{}, err
	}
	bundle := response.SecretBundle
	if bundle.SecretId == nil || bundle.VersionNumber == nil || bundle.SecretBundleContent == nil {
		return SecretBundle{}, ErrVaultSecretMismatch
	}
	content, ok := bundle.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok {
		if pointer, pointerOK := bundle.SecretBundleContent.(*secrets.Base64SecretBundleContentDetails); pointerOK && pointer != nil {
			content = *pointer
			ok = true
		}
	}
	if !ok || content.Content == nil {
		return SecretBundle{}, ErrVaultSecretMismatch
	}
	return SecretBundle{
		SecretOCID: *bundle.SecretId, VersionNumber: *bundle.VersionNumber,
		ContentType: "BASE64", ContentBase64: *content.Content,
	}, nil
}

func authorizeSecretMaterialization(manifest StartupAuthority, receipt VerifiedReceipt, reference SecretReference, now time.Time) error {
	if err := validateStartupAuthority(manifest); err != nil {
		return err
	}
	payload := manifest.Manifest()
	if !receipt.verified || !now.Before(receipt.expiresAt) || !now.Before(manifest.ExpiresAt()) ||
		receipt.manifestDigest != manifest.Digest() || receipt.receipt.ManifestDigest != manifest.Digest() ||
		receipt.receipt.DeploymentID != payload.DeploymentID || receipt.receipt.Environment != payload.Environment ||
		receipt.receipt.ClusterID != payload.ClusterID || receipt.receipt.Cell != payload.Cell ||
		receipt.receipt.OCIRegion != payload.OCIRegion || receipt.receipt.IntentGeneration != payload.IntentGeneration ||
		receipt.receipt.ManifestIntentSHA256 != payload.IntentSHA256 || receipt.receipt.Role != payload.ControllerRole ||
		receipt.receipt.Slot != payload.Slot {
		return fmt.Errorf("%w: secret retrieval requires a current receipt for this manifest and exact instance slot", ErrReceiptInvalid)
	}
	if err := reference.validate(payload); err != nil {
		return err
	}
	if !slices.Contains(payload.Secrets, reference) {
		return fmt.Errorf("%w: secret reference is not present in the signed manifest", ErrManifestInvalid)
	}
	switch reference.Purpose {
	case SecretRegionalShared, SecretHostIssuer:
		return nil
	case SecretSeedFounder, SecretSeedLedgerSigner:
		if receipt.receipt.Slot != payload.SeedSlot {
			return fmt.Errorf("%w: seed signer secret requires the exact seed receipt", ErrReceiptInvalid)
		}
	case SecretController:
		if reference.Slot != receipt.receipt.Slot {
			return fmt.Errorf("%w: controller secret is bound to a different slot", ErrReceiptInvalid)
		}
	default:
		return fmt.Errorf("%w: unknown secret purpose", ErrManifestInvalid)
	}
	return nil
}

func decodeSecretBundle(bundle SecretBundle, reference SecretReference) ([]byte, error) {
	maxEncoded := base64.StdEncoding.EncodedLen(int(reference.MaxBytes))
	if bundle.SecretOCID != reference.SecretOCID || bundle.VersionNumber != reference.VersionNumber ||
		bundle.ContentType != "BASE64" || len(bundle.ContentBase64) == 0 || len(bundle.ContentBase64) > maxEncoded {
		return nil, ErrVaultSecretMismatch
	}
	content, err := base64.StdEncoding.Strict().DecodeString(bundle.ContentBase64)
	if err != nil || int64(len(content)) > reference.MaxBytes ||
		base64.StdEncoding.EncodeToString(content) != bundle.ContentBase64 || digestBytes(content) != reference.SHA256 {
		clear(content)
		return nil, ErrVaultSecretMismatch
	}
	return content, nil
}

func materializeSecret(directory, target string, content []byte) error {
	return materializeSecretWith(directory, target, content, func(writer io.Writer, value []byte) error {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written != len(value) {
			return io.ErrShortWrite
		}
		return nil
	})
}

func materializeSecretWith(directory, target string, content []byte, write func(io.Writer, []byte) error) error {
	if !filepath.IsAbs(directory) || !fileNameRE.MatchString(target) || strings.Contains(target, "..") || write == nil {
		return fmt.Errorf("%w: destination must be an absolute directory and a simple file name", ErrMaterialization)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("%w: inspect destination directory: %v", ErrMaterialization, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: destination must be a non-symlink directory", ErrMaterialization)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("%w: open destination directory: %v", ErrMaterialization, err)
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil || !rootInfo.IsDir() {
		return fmt.Errorf("%w: opened destination is not a directory", ErrMaterialization)
	}
	var temporary string
	var file *os.File
	for range 8 {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("%w: generate temporary name: %v", ErrMaterialization, err)
		}
		temporary = ".ts-secret-" + hex.EncodeToString(nonce[:]) + ".tmp"
		file, err = root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: create temporary file: %v", ErrMaterialization, err)
		}
	}
	if file == nil {
		return fmt.Errorf("%w: could not reserve a unique temporary file", ErrMaterialization)
	}
	defer root.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("%w: set temporary file mode: %v", ErrMaterialization, err)
	}
	if err := write(file, content); err != nil {
		_ = file.Close()
		return fmt.Errorf("%w: write temporary file: %v", ErrMaterialization, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("%w: sync temporary file: %v", ErrMaterialization, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("%w: close temporary file: %v", ErrMaterialization, err)
	}
	if err := root.Link(temporary, target); err != nil {
		return fmt.Errorf("%w: atomically install without overwrite: %v", ErrMaterialization, err)
	}
	directoryFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("%w: open destination directory for sync: %v", ErrMaterialization, err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("%w: sync destination directory: %v", ErrMaterialization, err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("%w: close destination directory: %v", ErrMaterialization, err)
	}
	return nil
}
