package foundation

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
)

// CreateIdentity contains no payloads. The regional journal binds it to its
// authenticated operation and signed intent before OCI receives the request.
type CreateIdentity = foundationbinding.CreateIdentity

type recoveringCreateKey struct{}

type unrecordedResource struct{ name, id string }

func (resource *unrecordedResource) Error() string {
	return "resource " + resource.name + " has no authenticated foundation ownership checkpoint; refusing adoption without exact pending-create recovery"
}

func recoveringCreate(ctx context.Context) bool {
	recovering, _ := ctx.Value(recoveringCreateKey{}).(bool)
	return recovering
}

func (f *Foundation) bindAuxiliary(ctx context.Context, key string, resource Object) error {
	if resource == nil {
		return nil
	}
	id, err := command.ID(resource)
	if err != nil {
		return err
	}
	if old := f.AuxiliaryIDs[key]; old != "" && old != id {
		return errors.New("auxiliary foundation identity cannot be replaced")
	}
	if f.Apply {
		if f.CheckpointAuxiliary == nil {
			return errors.New("auxiliary foundation identity requires a durable checkpoint")
		}
		if err := f.CheckpointAuxiliary(ctx, key, id); err != nil {
			return err
		}
	}
	return nil
}
