package fixturegen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// BuildFounderSelectionSource creates a separate host-only exact-key Object
// Storage reader for verifying the selected founder authority while staging
// durable floor artifacts. It is never included in the completed restart
// simulator route inventory, which must take the historical branch without a
// selector request.
func BuildFounderSelectionSource(ctx context.Context, recipe SignedHistoryRecipe) (*CapturingObjectStorage, error) {
	if !recipe.Anchor.IsVerified() {
		return nil, errors.New("founder selection source needs a verified anchor")
	}
	plan, err := bootstrap.VerifyFounderPlan(recipe.FounderPlanWire, recipe.Roots, recipe.Anchor.Wire(),
		recipe.ManifestWires, recipe.Now,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	if err != nil {
		return nil, err
	}
	if _, err := recipe.verifyFounderSelection(plan); err != nil {
		return nil, err
	}
	store, err := NewCapturingObjectStorage(recipe.Now)
	if err != nil {
		return nil, err
	}
	anchor := recipe.Anchor.Anchor()
	domain := anchor.StorageDomain
	put := func(bucket, keyID, name string, body []byte) error {
		digest := sha256.Sum256(body)
		_, err := store.PutObject(ctx, objectstorage.PutObjectRequest{
			NamespaceName: new(domain.Namespace), BucketName: new(bucket), ObjectName: new(name),
			PutObjectBody: io.NopCloser(bytes.NewReader(body)), ContentLength: new(int64(len(body))),
			IfNoneMatch: new("*"), OpcSseKmsKeyId: new(keyID),
			OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
			OpcContentSha256:     new(base64.StdEncoding.EncodeToString(digest[:])),
		})
		return err
	}
	for _, wire := range [][]byte{recipe.FounderPlanWire, recipe.Anchor.Wire(),
		recipe.ManifestWires["controller-a"], recipe.ManifestWires["controller-b"], recipe.ManifestWires["seed-a"]} {
		name := bootstrapstart.FounderImmutableObjectName(domain, anchor.DeploymentID, string(anchor.Cell),
			anchor.Environment, historyDigest(wire))
		if err := put(domain.LedgerBucket, domain.LedgerKMSKeyOCID, name, wire); err != nil {
			return nil, fmt.Errorf("stage root-signed founder source object: %w", err)
		}
	}
	selectorName := bootstrapstart.FounderSelectionObjectName(domain, anchor.DeploymentID,
		string(anchor.Cell), anchor.Environment)
	if err := put(domain.HeadBucket, domain.HeadKMSKeyOCID, selectorName,
		recipe.FounderSelectionWire); err != nil {
		return nil, fmt.Errorf("stage root-signed founder selector: %w", err)
	}
	return store, nil
}
