package functionmaterial

import (
	"context"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// NewStartupPublicTrust pins first-boot function delivery to the checked sealed
// source inventory, shared by all slots without a material-generation signature.
func NewStartupPublicTrust(ctx context.Context, authority bootstrap.DerivedStartupAuthority, operatorJWT, brokerCA []byte, brokerURL string) (PublicTrust, error) {
	now := time.Now()
	if !authority.IsVerified() || authority.VerifyCurrent(ctx, now) != nil {
		return PublicTrust{}, ErrMaterial
	}
	wire := authority.MaterialRecord()
	var record bootstrapmaterial.Record
	if len(wire) == 0 || len(wire) > 1<<20 || sum(wire) != authority.MaterialSHA256() ||
		json.Unmarshal(wire, &record, json.RejectUnknownMembers(true)) != nil || record.SchemaVersion != 1 || record.Config.Validate() != nil ||
		record.IssuedAt.IsZero() || now.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) ||
		record.ExpiresAt.Sub(record.IssuedAt) != time.Duration(record.Config.ValidityHours)*time.Hour {
		return PublicTrust{}, ErrMaterial
	}
	manifest := authority.Manifest()
	if record.Config.Environment != manifest.Environment || record.Config.Cell != strings.ToLower(string(manifest.Cell)) ||
		record.Config.Region != catalog.OCIRegion(string(manifest.Cell)) || record.Config.DeploymentID != manifest.DeploymentID || record.Config.ClusterID != manifest.ClusterID {
		return PublicTrust{}, ErrMaterial
	}
	files := make(map[string]bootstrapmaterial.File, len(record.Files))
	for _, file := range record.Files {
		if _, duplicate := files[file.Name]; duplicate || file.Name == "" || !materialDigest(file.SHA256) || file.MaxBytes <= 0 || file.MaxBytes > bootstrap.MaxSecretBytes {
			return PublicTrust{}, ErrMaterial
		}
		files[file.Name] = file
	}
	pinned := func(name string, value []byte) bool {
		file, ok := files[name]
		return ok && file.Purpose == bootstrap.SecretRegionalShared && file.Slot == "" && len(value) > 0 && int64(len(value)) <= file.MaxBytes && sum(value) == file.SHA256
	}
	issuer, signer := files["controller-tls-issuer-cert.pem"], files["controller-account-signer.seed"]
	if !pinned("operator.jwt", operatorJWT) || !pinned("ca.pem", brokerCA) ||
		issuer.Purpose != bootstrap.SecretControllerIssuer || issuer.Slot != "" || signer.Purpose != bootstrap.SecretControllerIssuer || signer.Slot != "" {
		return PublicTrust{}, ErrMaterial
	}
	return newPublicTrust(PublicTrust{fingerprint: authority.MaterialSHA256(), cell: string(manifest.Cell), environment: manifest.Environment,
		cellAccount: record.Public.CellAccountNKey, accountSigner: record.Public.ControllerAccountSignerNKey, issuerSHA256: issuer.SHA256,
		expiresAt: minTime(authority.ExpiresAt(), record.ExpiresAt)}, record.Public.OperatorNKey, operatorJWT, brokerCA, brokerURL)
}
