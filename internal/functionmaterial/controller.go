package functionmaterial

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/nats.go"
)

// Controller is the trusted regional producer. Recipient authorization must
// inspect the actual scheduler task and authenticated host admission.
type Controller struct {
	Reader             Reader
	Authority          *authority.Runtime
	Conn               *nats.Conn
	Issuer             TaskIssuer
	AuthorizeRecipient func(context.Context, Binding) error
}

// Prepare recovers publication before committing the immutable task grant.
// Existing Vault material retains its worker key, including after a lost reply.
func (controller Controller) Prepare(ctx context.Context, tenant, function string, binding Binding) (VerifiedDelivery, error) {
	if controller.Authority == nil || controller.Conn == nil || controller.Issuer == nil || controller.AuthorizeRecipient == nil || controller.Reader.Materials == nil {
		return VerifiedDelivery{}, ErrMaterial
	}
	if err := controller.AuthorizeRecipient(ctx, binding); err != nil {
		return VerifiedDelivery{}, err
	}
	reader := controller.Reader
	reader.Authority = controller.Authority
	reader.AuthorizeRecipient = controller.AuthorizeRecipient
	reader.Recipient = Recipient{NodeID: binding.NodeID, InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID}
	proof, sequence, err := reader.currentFunction(ctx, tenant, function)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	if catalog.OCIRegion(proof.Claim().Cell) != binding.Region {
		return VerifiedDelivery{}, ErrMaterial
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
	wire, err := controller.Issuer.IssueFunctionTaskMaterial(ctx, binding.TaskID)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	defer clear(wire)
	material, err := decodeMaterial(wire)
	if err != nil {
		return VerifiedDelivery{}, err
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
