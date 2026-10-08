package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/machines"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/capacity"
)

// controlStoreHeadroomBytes keeps room for the configured intent stream,
// host state, placement KV, and authority log (1536 MiB), plus the host
// metric archive (1536 MiB): 3072 MiB beside the artifact store.
const controlStoreHeadroomBytes int64 = 1536<<20 + observability.HostMetricStreamBytes

// specStoreHeadroomBytes is what a cell spec's artifact store leaves beside
// it: the other streams that reserve their max_bytes on every controller,
// delivery intents (1 GiB), decisions, host state, placement, host
// enrollment, hold about 1.7 GiB together. Their 2048 MiB
// headroom plus the host metric archive's 1536 MiB reserves 3584 MiB. Embedded NATS
// refuses every stream update, even a shrink, once reservations pass
// store_max_bytes (TS-662).
const specStoreHeadroomBytes int64 = 2048<<20 + observability.HostMetricStreamBytes

// machinesAPIStoreBytes is what the Machines API's two buckets reserve
// beside them while the cell spec carries machines_api.
const machinesAPIStoreBytes int64 = 3 * machines.BucketMaxBytes

const (
	artifactStoreKeeperInterval = time.Minute
	artifactStoreKeeperTimeout  = 2 * time.Minute
)

// artifactStoreKeeper holds the delivery artifact store at the cell spec's
// quota and deletes the artifacts no host needs, from the authority leader,
// so releases never wait on a hand cleanup (TS-576).
type artifactStoreKeeper struct {
	control  authority.Fencer
	service  *delivery.Service
	hosts    *host.Controller
	quota    func() int64
	storeDir string
	netbird  *netbirdRollout
}

func (k artifactStoreKeeper) Run(ctx context.Context) error {
	ticker := time.NewTicker(artifactStoreKeeperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if k.control.Current().CanMutate() {
			k.pass(ctx)
		}
	}
}

func (k artifactStoreKeeper) pass(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, artifactStoreKeeperTimeout)
	defer cancel()
	epoch := k.control.Current().Epoch
	guard := func(ctx context.Context) error { return k.control.Guard(ctx, epoch) }
	if err := k.resize(ctx, guard); err != nil && ctx.Err() == nil {
		slog.Warn("artifact store quota not applied", observability.ComponentKey, "delivery", "error", err)
	}
	collection, err := k.service.CollectArtifacts(ctx, func(ctx context.Context) ([]delivery.ArtifactUse, error) {
		uses, err := artifactsInUse(ctx, k.hosts)
		if err != nil || k.netbird == nil {
			return uses, err
		}
		network, err := k.netbird.artifactsInUse(ctx)
		return append(uses, network...), err
	}, time.Now(), guard)
	if len(collection.Deleted)+len(collection.Purged) > 0 {
		slog.Info("artifact store collected", observability.ComponentKey, "delivery",
			"deleted", collection.Deleted, "purged", collection.Purged)
	}
	if err != nil && ctx.Err() == nil {
		slog.Warn("artifact store collection failed", observability.ComponentKey, "delivery", "error", err)
	}
}

// resize applies the quota. A raise needs room on this controller's disk
// for everything the store may still grow.
func (k artifactStoreKeeper) resize(ctx context.Context, guard func(context.Context) error) error {
	want := k.quota()
	current, used, err := k.service.ArtifactStoreSize(ctx)
	if err != nil || current == want {
		return err
	}
	if want > current {
		disk, err := capacity.Statfs(k.storeDir)
		if err != nil {
			return err
		}
		if err := quotaFits(want, used, disk.AvailBytes); err != nil {
			return err
		}
	}
	if err := guard(ctx); err != nil {
		return err
	}
	if err := k.service.ResizeArtifactStore(ctx, want); err != nil {
		return err
	}
	slog.Info("artifact store quota set", observability.ComponentKey, "delivery", "max_bytes", want, "previous", current)
	return nil
}

func quotaFits(want int64, used, available uint64) error {
	if growth := want - int64(used); growth > 0 && uint64(growth) > available {
		return fmt.Errorf("artifact store quota %d needs %d more bytes on disk; %d are available", want, growth, available)
	}
	return nil
}

// artifactsInUse are the digests every committed desired names, withdrawn
// targets included.
func artifactsInUse(ctx context.Context, hosts *host.Controller) ([]delivery.ArtifactUse, error) {
	desired, err := hosts.ListDesired(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list host desired state: %w", err)
	}
	uses := make([]delivery.ArtifactUse, 0, len(desired))
	for _, d := range desired {
		uses = append(uses, delivery.ArtifactUse{Digest: d.Digest, Role: d.Role, Environment: d.Environment})
	}
	return uses, nil
}
