package functionmaterial

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func (reader Reader) currentFunction(ctx context.Context, tenant, function string) (release.VerifiedFunction, uint64, error) {
	if reader.Authority == nil || reader.Artifacts == nil || reader.Roots == nil {
		return release.VerifiedFunction{}, 0, ErrMaterial
	}
	entry, err := reader.Authority.ReadFunctionIntent(ctx, tenant, function)
	if err != nil {
		return release.VerifiedFunction{}, 0, err
	}
	intent, err := authority.DecodeFunctionIntent(entry)
	if err != nil {
		return release.VerifiedFunction{}, 0, err
	}
	claim := intent.Claim
	info, err := reader.Artifacts.GetInfo(ctx, "sha256-"+claim.Digest)
	if err != nil {
		return release.VerifiedFunction{}, 0, err
	}
	if info.Size != uint64(claim.Bytes) || info.Size == 0 || info.Size > release.MaxFunctionModuleBytes || info.Opts != nil && info.Opts.Link != nil {
		return release.VerifiedFunction{}, 0, ErrMaterial
	}
	object, err := reader.Artifacts.Get(ctx, "sha256-"+claim.Digest)
	if err != nil {
		return release.VerifiedFunction{}, 0, err
	}
	module, readErr := io.ReadAll(io.LimitReader(object, release.MaxFunctionModuleBytes+1))
	closeErr := object.Close()
	if readErr != nil || closeErr != nil || len(module) > release.MaxFunctionModuleBytes {
		return release.VerifiedFunction{}, 0, ErrMaterial
	}
	proof, err := release.VerifyFunctionCurrent(intent.Envelope, intent.Delegation, module, reader.Roots(), release.FunctionExpectation{
		Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID,
		Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: claim.Sequence,
	}, time.Now())
	if err != nil || proof.EnvelopeSHA256() != intent.EnvelopeSHA256 {
		return release.VerifiedFunction{}, 0, ErrMaterial
	}
	return proof, entry.Sequence, nil
}

// CurrentFunction resolves the durable desired release without granting a task.
func (reader Reader) CurrentFunction(ctx context.Context, tenant, function string) (release.VerifiedFunction, error) {
	proof, _, err := reader.currentFunction(ctx, tenant, function)
	return proof, err
}

// Current reads only the exact grant of this independently admitted recipient.
// The caller's task fields select records; the durable grant supplies authority.
func (reader Reader) Current(ctx context.Context, binding Binding) (VerifiedDelivery, error) {
	if reader.Authority == nil || reader.Bundles == nil || reader.AuthorizeRecipient == nil || reader.Recipient != (Recipient{NodeID: binding.NodeID, InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID}) {
		return VerifiedDelivery{}, ErrMaterial
	}
	if err := reader.AuthorizeRecipient(ctx, binding); err != nil {
		return VerifiedDelivery{}, err
	}
	entry, err := reader.Authority.ReadFunctionGrant(ctx, binding.TaskID)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	grant, err := authority.DecodeFunctionGrant(entry)
	if err != nil || grant.Binding != bindingGrant(binding, grant.Binding.MaterialManifestSHA256) {
		return VerifiedDelivery{}, ErrMaterial
	}
	proof, intentSequence, err := reader.currentFunction(ctx, grant.TenantID, grant.FunctionID)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	if grant.EnvelopeSHA256 != proof.EnvelopeSHA256() || grant.Sequence != proof.Claim().Sequence || catalog.OCIRegion(proof.Claim().Cell) != binding.Region {
		return VerifiedDelivery{}, ErrMaterial
	}
	account, err := reader.currentAccount(ctx, proof)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	ref, err := secretRef(reader.VaultID, binding)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	if err := vaultsecret.ValidateDeliveryRefs(strings.ToLower(reader.Trust.cell), "function-worker", map[string]vaultsecret.Ref{"FUNCTION_MATERIAL_FILE": ref}, nil); err != nil {
		return VerifiedDelivery{}, err
	}
	current, err := vaultsecret.ReadCurrent(ctx, reader.Bundles, ref)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	wire := []byte(current.Value())
	defer clear(wire)
	if sum(wire) != grant.Binding.MaterialManifestSHA256 {
		return VerifiedDelivery{}, ErrMaterial
	}
	material, err := decodeMaterial(wire)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	expires, err := reader.verifyMaterial(material, binding, proof, intentSequence, account)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	files, err := filesFor(proof, proof.Claim().Sequence, reader.Roots(), material, reader.Trust.brokerURL)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	latest, latestSequence, err := reader.currentFunction(ctx, grant.TenantID, grant.FunctionID)
	if err != nil || latestSequence != intentSequence || latest.EnvelopeSHA256() != proof.EnvelopeSHA256() {
		return VerifiedDelivery{}, ErrMaterial
	}
	after, err := reader.currentAccount(ctx, proof)
	if err != nil || after.Sequence != account.Sequence || after.Hash != account.Hash {
		return VerifiedDelivery{}, ErrMaterial
	}
	if err := reader.AuthorizeRecipient(ctx, binding); err != nil {
		return VerifiedDelivery{}, err
	}
	return VerifiedDelivery{binding: binding, function: proof, minimum: proof.Claim().Sequence, expires: expires, files: files}, nil
}

func decodeMaterial(wire []byte) (storedMaterial, error) {
	var material storedMaterial
	if len(wire) == 0 || len(wire) > 16384 || json.Unmarshal(wire, &material, json.RejectUnknownMembers(true)) != nil || material.Schema != 1 || len(material.Files) != 5 {
		return storedMaterial{}, ErrMaterial
	}
	for _, name := range []string{"broker.creds", "broker-ca.pem", "ingress-cert.pem", "ingress-key.pem", "ingress-ca.pem"} {
		if len(material.Files[name]) == 0 {
			return storedMaterial{}, ErrMaterial
		}
	}
	return material, nil
}

func (reader Reader) verifyMaterial(material storedMaterial, binding Binding, proof release.VerifiedFunction, intentSequence uint64, account brokerauth.Claim) (time.Time, error) {
	claim := proof.Claim()
	if material.Binding != binding || material.TenantID != claim.TenantID || material.FunctionID != claim.FunctionID || material.EnvelopeSHA256 != proof.EnvelopeSHA256() ||
		material.IntentSequence != intentSequence || material.AccountSequence != account.Sequence || material.Generation != reader.Trust.fingerprint ||
		!bytes.Equal(material.Files["broker-ca.pem"], reader.Trust.brokerCA) {
		return time.Time{}, ErrMaterial
	}
	if sum(material.Files["ingress-ca.pem"]) != reader.Trust.issuerSHA256 {
		return time.Time{}, ErrMaterial
	}
	identity, err := functions.VerifyWorkerCredentials(proof, account.Account, account.JWT, material.Files["broker.creds"])
	if err != nil {
		return time.Time{}, err
	}
	tlsExpiry, err := verifyTLS(material.Files, proof)
	if err != nil {
		return time.Time{}, err
	}
	expires := minTime(proof.ExpiresAt(), identity.ExpiresAt, tlsExpiry, reader.Trust.expiresAt)
	if material.ExpiresAt.After(expires) || !time.Now().Before(material.ExpiresAt) {
		return time.Time{}, ErrMaterial
	}
	return material.ExpiresAt, nil
}

func minTime(values ...time.Time) time.Time {
	minimum := values[0]
	for _, value := range values[1:] {
		if value.Before(minimum) {
			minimum = value
		}
	}
	return minimum
}
