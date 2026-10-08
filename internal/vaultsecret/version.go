package vaultsecret

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// VersionClient is the conditional publication API used by rotating owners.
type VersionClient interface {
	GetSecret(context.Context, ocivault.GetSecretRequest) (ocivault.GetSecretResponse, error)
	UpdateSecret(context.Context, ocivault.UpdateSecretRequest) (ocivault.UpdateSecretResponse, error)
}

var ErrVersionConflict = errors.New("Vault CURRENT version changed; reread before publishing")

// PublishVersion adds one CURRENT version only while the version the owner
// read is still current. If-Match prevents concurrent rotations overwriting
// each other. It never generates a value or deletes a historical version.
func PublishVersion(ctx context.Context, client VersionClient, ref Ref, id string, expected int64, value []byte) (Stored, error) {
	if err := safeEnv(); err != nil {
		return Stored{}, err
	}
	if ref.region() == "" || !nameRE.MatchString(ref.Name) || len(ref.Name) > 255 ||
		!secretOCIDRE.MatchString(id) || strings.Split(id, ".")[3] != ref.region() || expected < 1 || len(value) == 0 || len(value) > maxValue {
		return Stored{}, errors.New("Vault publication requires a regional named secret, an expected version and 1 to 16384 bytes")
	}
	before, err := client.GetSecret(ctx, ocivault.GetSecretRequest{SecretId: new(id)})
	if err != nil {
		return Stored{}, fmt.Errorf("read Vault metadata for %s failed", ref.Name)
	}
	if before.Id == nil || *before.Id != id || before.VaultId == nil || *before.VaultId != ref.Vault ||
		before.SecretName == nil || *before.SecretName != ref.Name ||
		before.LifecycleState != ocivault.SecretLifecycleStateActive || before.Etag == nil || *before.Etag == "" {
		return Stored{}, errors.New("Vault publication target differs from its named regional reference")
	}
	if before.CurrentVersionNumber == nil || *before.CurrentVersionNumber != expected {
		return Stored{}, ErrVersionConflict
	}
	content := base64.StdEncoding.EncodeToString(value)
	after, err := client.UpdateSecret(ctx, ocivault.UpdateSecretRequest{
		SecretId: new(id), IfMatch: before.Etag,
		UpdateSecretDetails: ocivault.UpdateSecretDetails{SecretContent: ocivault.Base64SecretContentDetails{
			Content: new(content), Stage: ocivault.SecretContentDetailsStageCurrent,
		}},
	})
	if err != nil {
		return Stored{}, fmt.Errorf("publish Vault secret %s failed; reread CURRENT before retrying", ref.Name)
	}
	if after.Id == nil || *after.Id != id || after.CurrentVersionNumber == nil || *after.CurrentVersionNumber <= expected {
		return Stored{}, errors.New("Vault publication returned uncertain version metadata; reread CURRENT before retrying")
	}
	return Stored{Secret: ref.Name, ID: id}, nil
}
