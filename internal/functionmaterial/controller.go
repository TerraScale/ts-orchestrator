package functionmaterial

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nats.go"
)

// Controller is the trusted regional producer. Recipient authorization must
// inspect the actual scheduler task and authenticated host admission.
type Controller struct {
	Reader             Reader
	Authority          *authority.Runtime
	Conn               *nats.Conn
	Issuer             *bootstrapmaterial.ControllerIssuer
	Vault              vaultsecret.VaultClient
	Versions           vaultsecret.VersionClient
	Target             vaultsecret.Target
	AuthorizeRecipient func(context.Context, Binding) error
}

// Prepare recovers publication before committing the immutable task grant.
// Existing Vault material retains its worker key, including after a lost reply.
func (controller Controller) Prepare(ctx context.Context, tenant, function string, binding Binding) (VerifiedDelivery, error) {
	if controller.Authority == nil || controller.Conn == nil || controller.Issuer == nil || controller.Vault == nil || controller.Versions == nil || controller.AuthorizeRecipient == nil || controller.Target.VaultID != controller.Reader.VaultID {
		return VerifiedDelivery{}, ErrMaterial
	}
	if err := controller.AuthorizeRecipient(ctx, binding); err != nil {
		return VerifiedDelivery{}, err
	}
	reader := controller.Reader
	reader.Authority = controller.Authority
	reader.AuthorizeRecipient = controller.AuthorizeRecipient
	reader.Recipient = Recipient{NodeID: binding.NodeID, InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID}
	ref, err := secretRef(reader.VaultID, binding)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	proof, sequence, err := reader.currentFunction(ctx, tenant, function)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	account, err := reader.currentAccount(ctx, proof)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	if entry, err := controller.Authority.ReadFunctionGrant(ctx, binding.TaskID); err == nil {
		grant, err := authority.DecodeFunctionGrant(entry)
		if err != nil || grant.TenantID != tenant || grant.FunctionID != function || grant.EnvelopeSHA256 != proof.EnvelopeSHA256() {
			return VerifiedDelivery{}, ErrMaterial
		}
		return reader.Current(ctx, binding)
	} else if !errors.Is(err, authority.ErrNotFound) {
		return VerifiedDelivery{}, err
	}
	epoch := controller.Authority.Current().Epoch
	guard := func() error { return controller.Authority.Guard(ctx, epoch) }
	if err := guard(); err != nil {
		return VerifiedDelivery{}, err
	}
	if err := functions.ProvisionQueue(ctx, controller.Conn, proof); err != nil {
		return VerifiedDelivery{}, err
	}
	_, err = vaultsecret.Ensure(ctx, controller.Vault, controller.Target, ref.Name, "Admitted function task material", func(ctx context.Context) (string, error) {
		if err := guard(); err != nil {
			return "", err
		}
		material, err := controller.issue(reader, proof, sequence, account, binding, nil)
		if err != nil {
			return "", err
		}
		wire, err := encodeMaterial(material)
		if err != nil {
			return "", err
		}
		defer clear(wire)
		return string(wire), nil
	})
	if err != nil {
		return VerifiedDelivery{}, err
	}
	current, err := vaultsecret.ReadCurrent(ctx, reader.Bundles, ref)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	wire := []byte(current.Value())
	defer func() { clear(wire) }()
	material, err := decodeMaterial(wire)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	if material.Binding != binding || material.TenantID != tenant || material.FunctionID != function || material.EnvelopeSHA256 != proof.EnvelopeSHA256() || material.IntentSequence != sequence {
		return VerifiedDelivery{}, ErrMaterial
	}
	// Issuance validates old grants and keeps the key even when renewal is needed.
	credentials, _, err := controller.Issuer.IssueFunctionCredentials(proof, account.JWT, material.Files["broker.creds"])
	if err != nil {
		return VerifiedDelivery{}, err
	}
	defer clear(credentials)
	if _, err := reader.verifyMaterial(material, binding, proof, sequence, account); err != nil {
		material, err = controller.issue(reader, proof, sequence, account, binding, material.Files["broker.creds"])
		if err != nil {
			return VerifiedDelivery{}, err
		}
		next, err := encodeMaterial(material)
		if err != nil {
			return VerifiedDelivery{}, err
		}
		defer clear(next)
		if err := controller.recheck(ctx, reader, proof, sequence, account, binding, epoch); err != nil {
			return VerifiedDelivery{}, err
		}
		if _, err := vaultsecret.PublishVersion(ctx, controller.Versions, ref, current.ID, current.Version, next); err != nil {
			return VerifiedDelivery{}, err
		}
		readback, err := vaultsecret.ReadCurrent(ctx, reader.Bundles, ref)
		if err != nil {
			return VerifiedDelivery{}, err
		}
		if readback.ID != current.ID || readback.Version <= current.Version || !bytes.Equal([]byte(readback.Value()), next) {
			return VerifiedDelivery{}, ErrMaterial
		}
		clear(wire)
		wire = bytes.Clone(next)
	}
	if _, err := reader.verifyMaterial(material, binding, proof, sequence, account); err != nil {
		return VerifiedDelivery{}, err
	}
	if err := controller.recheck(ctx, reader, proof, sequence, account, binding, epoch); err != nil {
		return VerifiedDelivery{}, err
	}
	manifest := sum(wire)
	operation := entityid.Derive("function-material", binding.TaskID, proof.EnvelopeSHA256(), manifest)
	if _, err := controller.Authority.CommitFunctionGrant(ctx, epoch, operation, 0, proof, bindingGrant(binding, manifest)); err != nil {
		return VerifiedDelivery{}, err
	}
	return reader.Current(ctx, binding)
}

func (controller Controller) recheck(ctx context.Context, reader Reader, proof release.VerifiedFunction, sequence uint64, account brokerauth.Claim, binding Binding, epoch uint64) error {
	if err := controller.Authority.Guard(ctx, epoch); err != nil {
		return err
	}
	if err := controller.AuthorizeRecipient(ctx, binding); err != nil {
		return err
	}
	next, nextSequence, err := reader.currentFunction(ctx, proof.Claim().TenantID, proof.Claim().FunctionID)
	if err != nil {
		return err
	}
	if nextSequence != sequence || next.EnvelopeSHA256() != proof.EnvelopeSHA256() {
		return ErrMaterial
	}
	after, err := reader.currentAccount(ctx, proof)
	if err != nil {
		return err
	}
	if after.Sequence != account.Sequence || after.Hash != account.Hash {
		return ErrMaterial
	}
	return nil
}

func (controller Controller) issue(reader Reader, proof release.VerifiedFunction, sequence uint64, account brokerauth.Claim, binding Binding, existing []byte) (storedMaterial, error) {
	credentials, identity, err := controller.Issuer.IssueFunctionCredentials(proof, account.JWT, existing)
	if err != nil {
		return storedMaterial{}, err
	}
	cert, key, issuer, err := controller.Issuer.IssueFunctionTLS(proof)
	if err != nil {
		clear(credentials)
		return storedMaterial{}, err
	}
	files := map[string][]byte{"broker.creds": credentials, "broker-ca.pem": bytes.Clone(reader.Trust.brokerCA), "ingress-cert.pem": cert, "ingress-key.pem": key, "ingress-ca.pem": issuer}
	tlsExpiry, err := verifyTLS(files, proof)
	if err != nil {
		for _, value := range files {
			clear(value)
		}
		return storedMaterial{}, err
	}
	return storedMaterial{Schema: 1, Binding: binding, TenantID: proof.Claim().TenantID, FunctionID: proof.Claim().FunctionID, EnvelopeSHA256: proof.EnvelopeSHA256(), IntentSequence: sequence, AccountSequence: account.Sequence, Generation: reader.Trust.generation.Fingerprint(), ExpiresAt: minTime(proof.ExpiresAt(), identity.ExpiresAt, tlsExpiry, reader.Trust.generation.ExpiresAt()), Files: files}, nil
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
