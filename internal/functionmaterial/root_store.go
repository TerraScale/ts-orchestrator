package functionmaterial

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/jwt/v2"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

func (store RootStore) guard(ctx context.Context) error {
	if store.Guard == nil || store.Seal == nil || store.Reader.Authority == nil || store.Vault == nil || store.Bundles == nil || store.Versions == nil {
		return ErrMaterial
	}
	if err := store.Guard(ctx); err != nil {
		return err
	}
	return store.Seal(ctx)
}

func (store RootStore) grant(ctx context.Context, binding Binding, manifest, tenant, function, envelope string) (bool, error) {
	entry, err := store.Reader.Authority.ReadFunctionGrant(ctx, binding.TaskID)
	if errors.Is(err, authority.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	grant, err := authority.DecodeFunctionGrant(entry)
	if err != nil || manifest == "" || grant.Binding != bindingGrant(binding, manifest) || grant.TenantID != tenant || grant.FunctionID != function || grant.EnvelopeSHA256 != envelope {
		return true, ErrMaterial
	}
	return true, nil
}

// issueTaskMaterial publishes only inside root, then returns the provider's exact bytes.
func (store RootStore) issueTaskMaterial(ctx context.Context, issuer *bootstrapmaterial.ControllerIssuer, binding Binding, tenant, function string) ([]byte, error) {
	if issuer == nil || store.Reader.AuthorizeRecipient == nil {
		return nil, ErrMaterial
	}
	if err := store.guard(ctx); err != nil {
		return nil, err
	}
	if _, err := store.Reader.Authority.ReadFunctionGrant(ctx, binding.TaskID); err == nil {
		return store.readTaskMaterial(ctx, issuer, binding, tenant, function)
	} else if !errors.Is(err, authority.ErrNotFound) {
		return nil, err
	}
	ref, err := secretRef(store.Target.VaultID, binding)
	if err != nil {
		return nil, err
	}
	stored, err := vaultsecret.Ensure(ctx, store.Vault, store.Target, ref.Name, "Admitted function task material", func(ctx context.Context) (string, error) {
		if err := store.guard(ctx); err != nil {
			return "", err
		}
		wire, err := store.candidate(ctx, issuer, binding, tenant, function)
		if err != nil {
			return "", err
		}
		defer clear(wire)
		if _, err := store.grant(ctx, binding, "", tenant, function, ""); err != nil {
			return "", err
		}
		if err := store.guard(ctx); err != nil {
			return "", err
		}
		return string(wire), nil
	})
	if err != nil || stored.Provisioning {
		return nil, ErrMaterial
	}
	current, err := vaultsecret.ReadCurrent(ctx, store.Bundles, ref)
	if err != nil || current.ID != stored.ID {
		return nil, ErrMaterial
	}
	proof, sequence, err := store.Reader.currentFunction(ctx, tenant, function)
	if err != nil {
		return nil, err
	}
	account, err := store.Reader.currentAccount(ctx, proof)
	if err != nil {
		return nil, err
	}
	wire := []byte(current.Value())
	defer func() { clear(wire) }()
	material, err := decodeMaterial(wire)
	if err != nil {
		return nil, err
	}
	// A unique-name create race can select another producer's valid packet.
	validity, verifyErr := store.Reader.verifyMaterial(material, binding, proof, sequence, account)
	if verifyErr != nil || validity.credentials.After(issuer.ExpiresAt()) {
		if _, err := store.grant(ctx, binding, "", tenant, function, ""); err != nil {
			return nil, err
		}
		next, err := store.candidate(ctx, issuer, binding, tenant, function)
		if err != nil {
			return nil, err
		}
		defer clear(next)
		if err := store.guard(ctx); err != nil {
			return nil, err
		}
		if _, err := store.grant(ctx, binding, "", tenant, function, ""); err != nil {
			return nil, err
		}
		_, publishErr := vaultsecret.PublishVersion(ctx, store.Versions, ref, current.ID, current.Version, next)
		// Lost replies and concurrent CAS winners are resolved from CURRENT, never by replaying.
		after, err := vaultsecret.ReadCurrent(ctx, store.Bundles, ref)
		if err != nil || after.ID != current.ID || after.Version <= current.Version {
			return nil, errors.Join(ErrMaterial, publishErr)
		}
		winner := []byte(after.Value())
		defer clear(winner)
		renewed, err := decodeMaterial(winner)
		if err != nil || !sameWorkerSeed(material.Files["broker.creds"], renewed.Files["broker.creds"]) {
			return nil, ErrMaterial
		}
		validity, err = store.Reader.verifyMaterial(renewed, binding, proof, sequence, account)
		if err != nil || validity.credentials.After(issuer.ExpiresAt()) {
			return nil, ErrMaterial
		}
		clear(wire)
		wire, current, material = bytes.Clone(winner), after, renewed
	}
	if _, err := store.grant(ctx, binding, sum(wire), tenant, function, proof.EnvelopeSHA256()); err != nil {
		return nil, err
	}
	if err := store.Reader.AuthorizeRecipient(ctx, binding); err != nil {
		return nil, err
	}
	if err := store.confirm(ctx, ref, current); err != nil {
		return nil, err
	}
	if err := store.recheck(ctx, material); err != nil {
		return nil, err
	}
	if err := store.guard(ctx); err != nil {
		return nil, err
	}
	return bytes.Clone(wire), nil
}

func sameWorkerSeed(before, after []byte) bool {
	first, err := jwt.ParseDecoratedUserNKey(before)
	if err != nil {
		return false
	}
	defer first.Wipe()
	second, err := jwt.ParseDecoratedUserNKey(after)
	if err != nil {
		return false
	}
	defer second.Wipe()
	left, err := first.PublicKey()
	right, nextErr := second.PublicKey()
	return err == nil && nextErr == nil && left == right
}

func (store RootStore) confirm(ctx context.Context, ref vaultsecret.Ref, current vaultsecret.Current) error {
	metadata, err := store.retirementMetadata(ctx, store.Versions, current.ID, ref.Name)
	if err != nil || metadata.CurrentVersionNumber == nil || *metadata.CurrentVersionNumber != current.Version || metadata.TimeOfDeletion != nil || metadata.LifecycleState != ocivault.SecretLifecycleStateActive {
		return ErrMaterial
	}
	after, err := vaultsecret.ReadCurrent(ctx, store.Bundles, ref)
	if err != nil || after.ID != current.ID || after.Version != current.Version || after.Value() != current.Value() {
		return ErrMaterial
	}
	latest, err := store.retirementMetadata(ctx, store.Versions, current.ID, ref.Name)
	if err != nil || *latest.Etag != *metadata.Etag || latest.CurrentVersionNumber == nil || *latest.CurrentVersionNumber != current.Version || latest.TimeOfDeletion != nil || latest.LifecycleState != ocivault.SecretLifecycleStateActive {
		return ErrMaterial
	}
	return nil
}

func (store RootStore) ReadRootTaskMaterial(ctx context.Context, issuer *bootstrapmaterial.ControllerIssuer, binding Binding, tenant, function string) ([]byte, error) {
	if os.Geteuid() != 0 {
		return nil, ErrMaterial
	}
	return store.readTaskMaterial(ctx, issuer, binding, tenant, function)
}

func (store RootStore) readTaskMaterial(ctx context.Context, issuer *bootstrapmaterial.ControllerIssuer, binding Binding, tenant, function string) ([]byte, error) {
	if issuer == nil {
		return nil, ErrMaterial
	}
	if err := store.guard(ctx); err != nil {
		return nil, err
	}
	if store.Reader.AuthorizeRecipient == nil {
		return nil, ErrMaterial
	}
	if err := store.Reader.AuthorizeRecipient(ctx, binding); err != nil {
		return nil, err
	}
	entry, err := store.Reader.Authority.ReadFunctionGrant(ctx, binding.TaskID)
	if err != nil {
		return nil, err
	}
	grant, err := authority.DecodeFunctionGrant(entry)
	if err != nil || grant.TenantID != tenant || grant.FunctionID != function || grant.Binding != bindingGrant(binding, grant.Binding.MaterialManifestSHA256) {
		return nil, ErrMaterial
	}
	proof, sequence, err := store.Reader.currentFunction(ctx, grant.TenantID, grant.FunctionID)
	if err != nil {
		return nil, err
	}
	if grant.Sequence != proof.Claim().Sequence || grant.EnvelopeSHA256 != proof.EnvelopeSHA256() {
		return nil, ErrMaterial
	}
	account, err := store.Reader.currentAccount(ctx, proof)
	if err != nil {
		return nil, err
	}
	ref, err := secretRef(store.Target.VaultID, binding)
	if err != nil {
		return nil, err
	}
	current, err := vaultsecret.ReadCurrent(ctx, store.Bundles, ref)
	if err != nil {
		return nil, err
	}
	wire := []byte(current.Value())
	defer clear(wire)
	material, err := decodeMaterial(wire)
	if err != nil {
		return nil, err
	}
	validity, err := store.Reader.verifyMaterial(material, binding, proof, sequence, account)
	if err != nil || validity.credentials.After(issuer.ExpiresAt()) {
		return nil, ErrMaterial
	}
	if sum(wire) != grant.Binding.MaterialManifestSHA256 {
		return nil, ErrMaterial
	}
	if err := store.confirm(ctx, ref, current); err != nil {
		return nil, err
	}
	if err := store.Reader.AuthorizeRecipient(ctx, binding); err != nil {
		return nil, err
	}
	if err := store.recheck(ctx, material); err != nil {
		return nil, err
	}
	present, err := store.grant(ctx, binding, sum(wire), tenant, function, proof.EnvelopeSHA256())
	if err != nil || !present {
		return nil, ErrMaterial
	}
	if err := store.guard(ctx); err != nil {
		return nil, err
	}
	return bytes.Clone(wire), nil
}

func (store RootStore) recheck(ctx context.Context, material storedMaterial) error {
	proof, sequence, err := store.Reader.currentFunction(ctx, material.TenantID, material.FunctionID)
	if err != nil || sequence != material.IntentSequence || proof.EnvelopeSHA256() != material.EnvelopeSHA256 {
		return ErrMaterial
	}
	account, err := store.Reader.currentAccount(ctx, proof)
	if err != nil || account.Sequence != material.AccountSequence {
		return ErrMaterial
	}
	if _, err := store.Reader.verifyMaterial(material, material.Binding, proof, sequence, account); err != nil {
		return err
	}
	return store.Reader.AuthorizeRecipient(ctx, material.Binding)
}

func secretRef(vault string, binding Binding) (vaultsecret.Ref, error) {
	if err := bindingGrant(binding, strings.Repeat("a", 64)).Validate(); err != nil {
		return vaultsecret.Ref{}, ErrMaterial
	}
	region, known := catalog.CellForOCIRegion(binding.Region)
	if !known {
		return vaultsecret.Ref{}, ErrMaterial
	}
	wire, err := json.Marshal(binding)
	if err != nil {
		return vaultsecret.Ref{}, err
	}
	ref := vaultsecret.Ref{Vault: vault, Name: region.Name() + "-function-worker-" + sum(wire)}
	if err := vaultsecret.ValidateDeliveryRefs(region.Name(), "function-worker", map[string]vaultsecret.Ref{"FUNCTION_MATERIAL_FILE": ref}, nil); err != nil {
		return vaultsecret.Ref{}, err
	}
	return ref, nil
}
