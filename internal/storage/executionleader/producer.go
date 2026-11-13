// Package executionleader derives worker material from current manager records.
package executionleader

import (
	"context"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// EvidenceReader reads only evidence retained by the exact delivery operation.
type EvidenceReader func(context.Context, string, string) (io.ReadCloser, error)

// AllocationResolver reads the exact signed reservation retained by one operation.
type AllocationResolver func(context.Context, string, release.ContainerBundle, trust.Keyring, release.ContainerTarget) (release.SequenceLocation, error)

func qualifiedUser(ctx context.Context, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget, open func(context.Context, string) (io.ReadCloser, error), allocations release.SequenceLocation) (uint32, uint32, error) {
	verified, err := execution.VerifyStatefulDeclared(ctx, bundle, roots, target, time.Now().UTC(), time.Now().UTC().Add(time.Second), open, allocations)
	if err != nil {
		return 0, 0, err
	}
	user := verified.ImageConfig().User
	u, g, ok := strings.Cut(user, ":")
	uid, e1 := strconv.ParseUint(u, 10, 32)
	gid, e2 := strconv.ParseUint(g, 10, 32)
	if !ok || e1 != nil || e2 != nil || uid == 0 || gid == 0 {
		return 0, 0, execution.ErrUnsafe
	}
	return uint32(uid), uint32(gid), nil
}
