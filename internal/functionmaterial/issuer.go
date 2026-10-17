package functionmaterial

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// TaskMaterialReader selects only root's actual current task grant.
type TaskMaterialReader interface {
	ReadFunctionTaskMaterial(context.Context, string) ([]byte, error)
}

// TaskIssuer selects root's actual assigned task, never caller-provided grants.
type TaskIssuer interface {
	RetireExpiredFunctionMaterial(context.Context) (int, error)
	IssueFunctionTaskMaterial(context.Context, string) ([]byte, error)
	IssueFunctionObservationIdentity(context.Context, string) (certificate, key, ca []byte, err error)
}

// CurrentAccount reads the independently verified current regional account.
func (reader Reader) CurrentAccount(ctx context.Context, proof release.VerifiedFunction) (brokerauth.Claim, error) {
	return reader.currentAccount(ctx, proof)
}

// RootStore owns all function Vault access inside the root service.
// Guard retains genuine root Call, credential and runtime lease admission.
type RootStore struct {
	Reader   Reader
	Vault    vaultsecret.VaultClient
	Versions vaultsecret.VersionClient
	Bundles  vaultsecret.BundleClient
	Target   vaultsecret.Target
	Guard    func(context.Context) error
	Seal     func(context.Context) error
}

func (store RootStore) IssueRootTaskMaterial(ctx context.Context, issuer *bootstrapmaterial.ControllerIssuer, binding Binding, tenant, function string) ([]byte, error) {
	if os.Geteuid() != 0 {
		return nil, ErrMaterial
	}
	return store.issueTaskMaterial(ctx, issuer, binding, tenant, function)
}

func (store RootStore) candidate(ctx context.Context, issuer *bootstrapmaterial.ControllerIssuer, binding Binding, tenant, function string) ([]byte, error) {
	reader, vault, target := store.Reader, store.Vault, store.Target

	if issuer == nil || store.Bundles == nil || reader.AuthorizeRecipient == nil || vault == nil || target.VaultID == "" {
		return nil, ErrMaterial
	}
	if err := reader.AuthorizeRecipient(ctx, binding); err != nil {
		return nil, err
	}
	proof, sequence, err := reader.currentFunction(ctx, tenant, function)
	if err != nil {
		return nil, err
	}
	account, err := reader.currentAccount(ctx, proof)
	if err != nil {
		return nil, err
	}
	ref, err := secretRef(target.VaultID, binding)
	if err != nil {
		return nil, err
	}
	metadata, err := vaultsecret.LookupMetadata(ctx, vault, target, ref.Name)
	if err != nil || metadata.Provisioning {
		return nil, ErrMaterial
	}
	current, err := vaultsecret.ReadCurrent(ctx, store.Bundles, ref)
	absent := vaultsecret.Absent(err)
	recheck := func() error {
		latest, latestSequence, err := reader.currentFunction(ctx, tenant, function)
		if err != nil || latestSequence != sequence || latest.EnvelopeSHA256() != proof.EnvelopeSHA256() {
			return ErrMaterial
		}
		confirmed, err := reader.currentAccount(ctx, proof)
		if err != nil || confirmed.Sequence != account.Sequence || confirmed.Hash != account.Hash {
			return ErrMaterial
		}
		metadataAfter, err := vaultsecret.LookupMetadata(ctx, vault, target, ref.Name)
		if err != nil || metadataAfter.Provisioning || metadataAfter.ID != metadata.ID {
			return ErrMaterial
		}
		currentAfter, err := vaultsecret.ReadCurrent(ctx, store.Bundles, ref)
		if absent {
			if metadataAfter.ID != "" || !vaultsecret.Absent(err) {
				return ErrMaterial
			}
		} else if err != nil || currentAfter.ID != current.ID || currentAfter.Version != current.Version || currentAfter.Value() != current.Value() {
			return ErrMaterial
		}
		if err := reader.AuthorizeRecipient(ctx, binding); err != nil {
			return err
		}
		return store.guard(ctx)
	}
	var existing []byte
	if err == nil {
		if metadata.ID != current.ID {
			return nil, ErrMaterial
		}
		wire := []byte(current.Value())
		defer clear(wire)
		material, err := decodeMaterial(wire)
		if err != nil || material.Binding != binding || material.TenantID != tenant || material.FunctionID != function || material.EnvelopeSHA256 != proof.EnvelopeSHA256() || material.IntentSequence != sequence || material.Generation != reader.Trust.fingerprint {
			return nil, ErrMaterial
		}
		if validity, err := reader.verifyMaterial(material, binding, proof, sequence, account); err == nil && !validity.credentials.After(issuer.ExpiresAt()) {
			if err := recheck(); err != nil {
				return nil, err
			}
			return bytes.Clone(wire), nil
		}
		existing = material.Files["broker.creds"]
		defer clear(existing)
	} else if metadata.ID != "" || !vaultsecret.Absent(err) {
		return nil, err
	}
	credentials, identity, err := issuer.IssueFunctionCredentials(proof, account.JWT, existing)
	if err != nil {
		return nil, err
	}
	cert, key, ca, err := issuer.IssueFunctionTLS(proof)
	if err != nil {
		clear(credentials)
		return nil, err
	}
	files := map[string][]byte{"broker.creds": credentials, "broker-ca.pem": bytes.Clone(reader.Trust.brokerCA), "ingress-cert.pem": cert, "ingress-key.pem": key, "ingress-ca.pem": ca}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	tlsExpiry, err := verifyTLS(files, proof)
	if err != nil {
		return nil, err
	}
	material := storedMaterial{Schema: 1, Binding: binding, TenantID: tenant, FunctionID: function, EnvelopeSHA256: proof.EnvelopeSHA256(), IntentSequence: sequence, AccountSequence: account.Sequence, Generation: reader.Trust.fingerprint, ExpiresAt: minTime(proof.ExpiresAt(), identity.ExpiresAt, tlsExpiry, reader.Trust.expiresAt, issuer.ExpiresAt()), Files: files}
	if err := recheck(); err != nil {
		return nil, err
	}
	return encodeMaterial(material)
}

func encodeMaterial(material storedMaterial) ([]byte, error) {
	if !time.Now().Before(material.ExpiresAt) {
		return nil, ErrMaterial
	}
	wire, err := json.Marshal(material)
	if err != nil {
		return nil, err
	}
	if len(wire) > 16384 {
		clear(wire)
		return nil, errors.New("function credentials and TLS material exceed Vault's 16 KiB bound")
	}
	return wire, nil
}
