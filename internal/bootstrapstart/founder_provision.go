package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

var ErrFounderProvision = errors.New("fresh seed founder floor provisioning is invalid")

// NewServiceFounderSelectionFloorStore binds the durable floor to the service
// account even when the initial admission process runs as root.
func NewServiceFounderSelectionFloorStore(serviceUID uint32) (*FounderSelectionFloorStore, error) {
	if serviceUID == 0 {
		return nil, ErrFounderProvision
	}
	return &FounderSelectionFloorStore{directory: FounderSelectionFloorDirectory, ownerUID: serviceUID}, nil
}

// ProvisionInitialFounderFloor is only for a verified first external-seed
// installation. It validates the entire selected signed snapshot before the
// initial generation-one floor is made durable. Restart never calls it.
func ProvisionInitialFounderFloor(ctx context.Context, baked BakedInputs, accepted AcceptedInstall,
	floor *FounderSelectionFloorStore, serviceUID, serviceGID uint32, now time.Time, clockCheck func() error,
) error {
	if accepted.validate() != nil || accepted.Slot != accepted.SeedSlot ||
		accepted.HeadAttempt != 1 || accepted.HeadGeneration != 1 ||
		serviceUID == 0 || serviceGID == 0 || floor == nil || floor.ownerUID != serviceUID ||
		now.IsZero() || now.Location() != time.UTC || clockCheck == nil {
		return ErrFounderProvision
	}
	reader, err := NewOCICurrentFounderAuthorityReader(baked, accepted, floor)
	if err != nil {
		return fmt.Errorf("%w: create exact selected authority reader: %v", ErrFounderProvision, err)
	}
	return reader.provisionInitial(ctx, now, serviceUID, serviceGID, clockCheck)
}

func (reader *CurrentFounderAuthorityReader) provisionInitial(ctx context.Context, now time.Time,
	serviceUID, serviceGID uint32, clockCheck func() error,
) error {
	if reader == nil || reader.floor == nil || reader.objects == nil || now.IsZero() || now.Location() != time.UTC ||
		reader.accepted.HeadAttempt != 1 || reader.accepted.HeadGeneration != 1 ||
		reader.floor.ownerUID != serviceUID || clockCheck == nil {
		return ErrFounderProvision
	}
	selectorKey := FounderSelectionObjectName(reader.domain, reader.baked.Identity.DeploymentID,
		string(reader.baked.Identity.Cell), reader.baked.Identity.Environment)
	wire, etag, err := reader.getExact(ctx, reader.domain.HeadBucket, selectorKey, founderSelectionMaxBytes)
	if err != nil {
		return err
	}
	selection, digest, expires, err := reader.verifySelection(wire, now)
	if err != nil || selection.Generation != 1 || selection.AnchorSHA256 != reader.accepted.AnchorSHA256 ||
		!now.Before(expires) {
		return ErrFounderProvision
	}
	getImmutable := func(digest string) ([]byte, error) {
		name := FounderImmutableObjectName(reader.domain, selection.DeploymentID, selection.Cell, selection.Environment, digest)
		body, _, err := reader.getExact(ctx, reader.domain.LedgerBucket, name, founderObjectMaxBytes)
		if err != nil || digestWire(body) != digest {
			return nil, ErrFounderProvision
		}
		return body, nil
	}
	planWire, err := getImmutable(selection.PlanSHA256)
	if err != nil {
		return err
	}
	anchorWire, err := getImmutable(selection.AnchorSHA256)
	if err != nil {
		return err
	}
	manifests := make(map[string][]byte, len(selection.Manifests))
	for _, pin := range selection.Manifests {
		manifests[pin.Slot], err = getImmutable(pin.SHA256)
		if err != nil {
			return err
		}
	}
	if err := reader.confirmSelector(ctx, selectorKey, wire, etag); err != nil {
		return err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return ErrFounderProvision
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, reader.baked.Roots,
		reader.baked.Identity.AnchorExpectation(), now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != selection.AnchorSHA256 || anchor.StorageDomain() != reader.domain ||
		anchor.Anchor().ClusterID != reader.acceptedClusterID {
		return ErrFounderProvision
	}
	plan, err := bootstrap.VerifyFounderPlan(planWire, reader.baked.Roots, anchorWire, manifests, now,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	if err != nil || plan.Plan().SeedSlot != reader.accepted.Slot ||
		plan.Plan().SeedManifestSHA256 != reader.accepted.ManifestSHA256 ||
		plan.Digest() != selection.PlanSHA256 || !slices.Contains(anchor.Anchor().ControllerSlots, reader.accepted.Slot) {
		return ErrFounderProvision
	}
	if err := prepareFounderFloorOwner(reader.floor, serviceUID, serviceGID); err != nil {
		return fmt.Errorf("%w: prepare service-owned floor lock: %v", ErrFounderProvision, err)
	}
	present, err := founderFloorPresent(reader.floor)
	if err != nil {
		return fmt.Errorf("%w: inspect existing founder floor: %v", ErrFounderProvision, err)
	}
	if err := reader.confirmSelector(ctx, selectorKey, wire, etag); err != nil {
		return err
	}
	if err := clockCheck(); err != nil {
		return fmt.Errorf("%w: initial founder NTP clock health: %v", ErrFounderProvision, err)
	}
	freshAt := time.Now().UTC()
	confirmed, confirmedDigest, confirmedExpiry, err := reader.verifySelection(wire, freshAt)
	if err != nil || confirmedDigest != digest || confirmed.Generation != 1 ||
		!confirmedExpiry.Equal(expires) || !freshAt.Before(expires) {
		return ErrFounderProvision
	}
	anchor, err = bootstrap.VerifyBootstrapAnchor(anchorEnvelope, reader.baked.Roots,
		reader.baked.Identity.AnchorExpectation(), freshAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != selection.AnchorSHA256 || anchor.StorageDomain() != reader.domain ||
		anchor.Anchor().ClusterID != reader.acceptedClusterID {
		return ErrFounderProvision
	}
	plan, err = bootstrap.VerifyFounderPlan(planWire, reader.baked.Roots, anchorWire, manifests, freshAt,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	if err != nil || plan.Digest() != selection.PlanSHA256 || plan.Plan().SeedSlot != reader.accepted.Slot ||
		plan.Plan().SeedManifestSHA256 != reader.accepted.ManifestSHA256 || ctx.Err() != nil {
		return ErrFounderProvision
	}
	if present {
		// Only the exact owner-checked generation-one floor can replay an
		// interrupted first install. Observe also fsyncs its directory.
		if err := reader.floor.Observe(1, digest); err != nil {
			return fmt.Errorf("%w: conflicting existing founder floor: %v", ErrFounderProvision, err)
		}
	} else {
		if err := reader.floor.InitializeForService(1, digest, serviceGID); err != nil {
			return fmt.Errorf("%w: initialize durable selection floor: %v", ErrFounderProvision, err)
		}
	}
	current, err := reader.ReadCurrent(ctx, freshAt)
	if err != nil || current.SelectionSHA256 != digest || current.SelectionGeneration != 1 ||
		!bytes.Equal(current.PlanWire, planWire) {
		return ErrFounderProvision
	}
	return nil
}

func prepareFounderFloorOwner(floor *FounderSelectionFloorStore, uid, gid uint32) error {
	dir, err := floor.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, founderSelectionLockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	created := false
	if errors.Is(err, unix.ENOENT) {
		fd, err = unix.Openat(dir, founderSelectionLockName,
			unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		created = err == nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || !created &&
		(stat.Uid != uid || stat.Gid != gid) &&
		(os.Geteuid() != 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Size != 0) {
		return ErrFounderProvision
	}
	if stat.Uid == uid && stat.Gid == gid {
		if err := unix.Fsync(fd); err != nil {
			return err
		}
		return unix.Fsync(dir)
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

func founderFloorPresent(floor *FounderSelectionFloorStore) (bool, error) {
	dir, err := floor.openDirectory()
	if err != nil {
		return false, err
	}
	defer unix.Close(dir)
	var stat unix.Stat_t
	err = unix.Fstatat(dir, founderSelectionFloorName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}
