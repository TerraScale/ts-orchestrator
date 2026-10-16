// Package vaultsecret delivers regional OCI Vault CURRENT versions to a
// service's memory. IAM grants should name only that service's secret OCIDs.
package vaultsecret

import (
	"context"
	"time"

	internal "github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type Ref = internal.Ref
type Current = internal.Current
type Stored = internal.Stored
type VersionClient = internal.VersionClient

var ErrVersionConflict = internal.ErrVersionConflict

// PublishVersion uses the owner's OCI client and an ETag to add a version.
// The owner rereads CURRENT after success or uncertainty before retrying.
func PublishVersion(ctx context.Context, client VersionClient, ref Ref, id string, expected int64, value []byte) (Stored, error) {
	return internal.PublishVersion(ctx, client, ref, id, expected, value)
}

func Read(ctx context.Context, refs map[string]Ref) (map[string]Current, error) {
	return internal.ReadCurrentRefs(ctx, refs)
}

func Watch(ctx context.Context, refs map[string]Ref, interval time.Duration,
	apply func(map[string]Current) error, failed func(error),
) error {
	return internal.Watch(ctx, refs, interval, apply, failed)
}
