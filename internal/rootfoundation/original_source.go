package rootfoundation

import "context"

// EnsureOriginalSourceArchive archives and publishes original material without granting startup authority.
func EnsureOriginalSourceArchive(ctx context.Context) error {
	_, err := OpenOriginalStartupArchive(ctx)
	return err
}
