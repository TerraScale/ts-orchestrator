package app

import (
	"github.com/TerraScale/ts-orchestrator/internal/machines"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

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
