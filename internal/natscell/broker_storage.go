package natscell

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// BrokerStorageInfo measures retained local identity, never history completeness.
// StartedAt is the durable marker's original creation time; ServerID identifies
// the currently running process and can change on restart.
type BrokerStorageInfo struct {
	BrokerGenesisInfo
	ObservedAt time.Time
}

// VerifiedBrokerStorage is read-only identity continuity, not creation authority.
type VerifiedBrokerStorage struct {
	runtime     *Runtime
	observation *brokerGenesis
	observedAt  time.Time
}

func (p VerifiedBrokerStorage) Info() BrokerStorageInfo {
	if p.observation == nil {
		return BrokerStorageInfo{}
	}
	return BrokerStorageInfo{BrokerGenesisInfo: p.observation.info, ObservedAt: p.observedAt}
}

func (p VerifiedBrokerStorage) ExpiresAt() time.Time {
	if p.observation == nil {
		return time.Time{}
	}
	return p.observation.expires
}

func (p VerifiedBrokerStorage) Revalidate(ctx context.Context) error {
	if p.runtime == nil || p.observation == nil || p.runtime.storeLock == nil || p.runtime.server == nil || p.runtime.conn == nil {
		return errors.New("retained broker storage observation is unavailable")
	}
	return validateBrokerStorage(ctx, p.runtime, p.observation)
}

// ObserveBrokerStorage reads the original durable marker of this actual runtime.
// A protected parent must match the original incarnation independently; marker
// presence does not prove that streams or deleted role history were retained.
func (r *Runtime) ObserveBrokerStorage(ctx context.Context) (VerifiedBrokerStorage, error) {
	observedAt := time.Now().UTC()
	expires := observedAt.Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if err := ctx.Err(); err != nil {
		return VerifiedBrokerStorage{}, err
	}
	if r == nil || r.storeLock == nil || r.server == nil || r.conn == nil || r.storeConfig.Embedded == nil {
		return VerifiedBrokerStorage{}, errors.New("retained embedded broker is unavailable")
	}
	cfg := r.storeConfig
	dir := int(r.storeLock.Fd())
	var stat, markerStat unix.Stat_t
	if err := unix.Fstat(dir, &stat); err != nil {
		return VerifiedBrokerStorage{}, err
	}
	identity, err := observeInstalledIdentity(cfg, dir)
	if err != nil {
		return VerifiedBrokerStorage{}, err
	}
	claims, err := brokerGenesisClaims(cfg)
	if err != nil {
		return VerifiedBrokerStorage{}, err
	}
	marker, err := readInstallationFileAt(dir, brokerGenesisMarker, 4096)
	if err != nil {
		return VerifiedBrokerStorage{}, err
	}
	if err := unix.Fstatat(dir, brokerGenesisMarker, &markerStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return VerifiedBrokerStorage{}, err
	}
	createdAt, err := parseBrokerStorageMarker(marker, identity.NodeIdentitySHA256)
	if err != nil || createdAt.After(observedAt) || markerStat.Uid != 0 {
		return VerifiedBrokerStorage{}, errors.Join(ErrStoreIdentity, err)
	}
	g := &brokerGenesis{info: BrokerGenesisInfo{Installation: identity, Cell: cfg.Cell, Instance: cfg.Instance,
		ServerID: r.server.ID(), RaftNodeID: r.server.NodeName(), StartedAt: createdAt,
		Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, OperatorSHA256: claims[0], SystemJWTSHA256: claims[1], CellJWTSHA256: claims[2],
		MarkerInode: markerStat.Ino, MarkerSHA256: installationDigest(marker)},
		ctx: ctx, expires: expires, marker: marker, markerInode: markerStat.Ino, cfg: cfg}
	proof := VerifiedBrokerStorage{runtime: r, observation: g, observedAt: observedAt}
	if err := proof.Revalidate(ctx); err != nil {
		return VerifiedBrokerStorage{}, err
	}
	return proof, nil
}

func parseBrokerStorageMarker(marker []byte, nodeSHA256 string) (time.Time, error) {
	first, rest, ok := strings.Cut(string(marker), "\n")
	if !ok || rest != nodeSHA256+"\n" {
		return time.Time{}, ErrStoreIdentity
	}
	createdAt, err := time.Parse(time.RFC3339Nano, first)
	if err != nil || createdAt.IsZero() || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339Nano) != first {
		return time.Time{}, ErrStoreIdentity
	}
	return createdAt, nil
}

// RevalidateRuntime binds the observation to the exact live broker target.
func (p VerifiedBrokerStorage) RevalidateRuntime(ctx context.Context, runtime *Runtime) error {
	if runtime == nil || p.runtime != runtime {
		return errors.New("broker observation belongs to a different runtime")
	}
	return p.Revalidate(ctx)
}
