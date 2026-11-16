package bootstrapstart

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// GenerationChainCopy is the durable copy of the adopted generation chain.
// The chain is root-signed public metadata (secret OCIDs, versions and
// digests), so it stays on disk; the credential directory itself is memory
// only and is rebuilt at every boot from Vault (TS-745).
const GenerationChainCopy = MarkerDirectory + "/" + MaterialGenerationsFile

// SecretReader reads one exact Vault version and returns its bytes once they
// match the reference's digest and size.
type SecretReader func(context.Context, bootstrap.SecretReference) ([]byte, error)
