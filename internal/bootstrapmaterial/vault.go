package bootstrapmaterial

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

const (
	journalName     = "publication.json"
	journalTempName = ".publication.tmp"
	journalLockName = "publication.lock"
	retryWindow     = 23 * time.Hour // OCI retry tokens expire after 24 hours.
)

var (
	ErrProvision   = errors.New("controller material Vault publication needs operator inspection")
	compartmentRE  = regexp.MustCompile(`^ocid1\.compartment\.oc1\.\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
	resourcePartRE = regexp.MustCompile(`^[a-z0-9]+(?:\.[a-z0-9]+)*$`)
)

type VaultTarget struct {
	CompartmentOCID string `json:"compartmentOcid"`
	VaultOCID       string `json:"vaultOcid"`
	KMSKeyOCID      string `json:"kmsKeyOcid"`
}

// supportedMaterialRegion admits exactly the OCI regions of the region
// catalog, so adding a cell there is the only change material publication
// needs.
func supportedMaterialRegion(region string) bool { return catalog.IsOCIRegion(region) }

func regionalResourceOCID(id, kind, region string) bool {
	prefix := "ocid1." + kind + ".oc1." + region + "."
	return strings.HasPrefix(id, prefix) && resourcePartRE.MatchString(strings.TrimPrefix(id, prefix))
}

func (target VaultTarget) validate(region string) error {
	if !supportedMaterialRegion(region) || !compartmentRE.MatchString(target.CompartmentOCID) ||
		!regionalResourceOCID(target.VaultOCID, "vault", region) ||
		!regionalResourceOCID(target.KMSKeyOCID, "key", region) {
		return ErrProvision
	}
	return nil
}

// Validate binds the control-compartment Vault target to a mapped OCI region.
func (target VaultTarget) Validate(region string) error { return target.validate(region) }

type VaultClient interface {
	CreateSecret(context.Context, ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error)
	GetSecret(context.Context, ocivault.GetSecretRequest) (ocivault.GetSecretResponse, error)
	ListSecrets(context.Context, ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error)
}

type BundleClient interface {
	GetSecretBundle(context.Context, ocisecrets.GetSecretBundleRequest) (ocisecrets.GetSecretBundleResponse, error)
}

type PublicReference struct {
	SecretName string                    `json:"secretName"`
	Reference  bootstrap.SecretReference `json:"reference"`
}

type Publication struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Target         VaultTarget       `json:"target"`
	MaterialSHA256 string            `json:"materialSha256"`
	References     []PublicReference `json:"references"`
}

func secretName(cfg Config, file File) string {
	slot := file.Slot
	if slot == "" {
		slot = "shared"
	}
	sum := sha256.Sum256([]byte(cfg.DeploymentID + "\x00" + cfg.ClusterID))
	return "ts-" + cfg.Environment + "-" + cfg.Region + "-" + strings.ReplaceAll(cfg.DeploymentID, ":", "-") +
		"-" + hex.EncodeToString(sum[:8]) + "-" +
		string(file.Purpose) + "-" + slot + "-" + strings.ReplaceAll(file.Name, ".", "-")
}
