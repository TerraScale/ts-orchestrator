package rootfoundation

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/materialsource"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// EnsureOriginalSourceArchive archives original source without granting startup authority.
func EnsureOriginalSourceArchive(ctx context.Context) error {
	actor, err := region.OpenOriginalSourceActor(ctx)
	if err != nil {
		return fmt.Errorf("open original source actor: %w", err)
	}
	archive, err := materialsource.ResolveOriginalSourceArchive(ctx, actor, filepath.Join(sourceDirectory, "original"), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("resolve original source archive: %w", err)
	}
	if err := archive.VerifyCurrent(ctx); err != nil {
		return fmt.Errorf("verify current original source archive: %w", err)
	}
	return nil
}
