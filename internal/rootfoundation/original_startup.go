package rootfoundation

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/materialsource"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// OpenOriginalStartupArchive retains the genuine original actor and completed publication.
func OpenOriginalStartupArchive(ctx context.Context) (materialsource.VerifiedOriginalSourceArchive, error) {
	actor, err := region.OpenOriginalSourceActor(ctx)
	if err != nil {
		return materialsource.VerifiedOriginalSourceArchive{}, fmt.Errorf("open original source actor: %w", err)
	}
	archive, err := materialsource.ResolveOriginalSourceArchive(ctx, actor, filepath.Join(sourceDirectory, "original"), time.Now().UTC())
	if err != nil {
		return materialsource.VerifiedOriginalSourceArchive{}, fmt.Errorf("resolve original source archive: %w", err)
	}
	if err := archive.VerifyCurrent(ctx); err != nil {
		return materialsource.VerifiedOriginalSourceArchive{}, fmt.Errorf("verify current original source archive: %w", err)
	}
	if err := archive.PublishRegionalMaterial(ctx, time.Now().UTC()); err != nil {
		return materialsource.VerifiedOriginalSourceArchive{}, fmt.Errorf("publish original regional material: %w", err)
	}
	return archive, nil
}
