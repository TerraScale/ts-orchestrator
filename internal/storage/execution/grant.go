package execution

import (
	"context"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ContainerAllocationResolver supplies the real read-only allocation store only
// after authenticating the root-signed migration and its OCI region.
type ContainerAllocationResolver func(context.Context, release.ContainerBundle, trust.Keyring, release.ContainerTarget) (release.SequenceLocation, error)

type WorkerGrantMaterial = executionwire.WorkerGrantMaterial

const StatefulContainerKind = "terrascale.stateful-container.v1"
const StatefulContainerTypeURL = "terrascale.tech/runtime/stateful-container/v1"
