package bootstrapstart

import (
	"context"

	"golang.org/x/sys/unix"

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

func clearContents(contents map[string][]byte) {
	for _, content := range contents {
		clear(content)
	}
}

// keepChain writes the durable copy of a staged chain before it commits.
func (store MaterialStore) keepChain(staging int) error {
	if store.chainCopy == "" {
		return nil
	}
	chain, err := readUnpinned(staging, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	if err != nil {
		return err
	}
	return writeSynced(store.chainCopy, chain)
}

func memoryFilesystem(fd int) bool {
	var fs unix.Statfs_t
	return unix.Fstatfs(fd, &fs) == nil && fs.Type == unix.TMPFS_MAGIC
}
