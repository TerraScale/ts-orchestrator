package natscell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const brokerGenesisMarker = ".broker-genesis"

// BrokerGenesisInfo describes one local store incarnation, not a regional
// history proof. Every original regional broker needs independent protection.
type BrokerGenesisInfo struct {
	Installation                                   InstallationIdentity
	Cell, Instance, ServerID, RaftNodeID           string
	StartedAt                                      time.Time
	Device, Inode                                  uint64
	UID                                            uint32
	OperatorSHA256, SystemJWTSHA256, CellJWTSHA256 string
	MarkerInode                                    uint64
	MarkerSHA256                                   string
}

type brokerGenesis struct {
	info        BrokerGenesisInfo
	ctx         context.Context
	expires     time.Time
	marker      []byte
	markerInode uint64
	cfg         Config
}

// VerifiedBrokerGenesis can only originate from the original broker start.
// It grants no permission to initialize a release floor or regional history.
type VerifiedBrokerGenesis struct{ runtime *Runtime }

// StartOriginalBroker records local provenance only. The combined root consumer
// must enforce its independent protected before-start reservation.
func StartOriginalBroker(ctx context.Context, cfg Config) (*Runtime, VerifiedBrokerGenesis, error) {
	if os.Geteuid() != 0 || cfg.Embedded == nil {
		return nil, VerifiedBrokerGenesis{}, errors.New("original broker requires root and an installed embedded broker")
	}
	r, err := startBroker(ctx, cfg, false, true)
	if err != nil {
		return nil, VerifiedBrokerGenesis{}, err
	}
	return r, VerifiedBrokerGenesis{r}, nil
}

func (p VerifiedBrokerGenesis) Info() BrokerGenesisInfo {
	if p.runtime == nil || p.runtime.genesis == nil {
		return BrokerGenesisInfo{}
	}
	return p.runtime.genesis.info
}

func (p VerifiedBrokerGenesis) ExpiresAt() time.Time {
	if p.runtime == nil || p.runtime.genesis == nil {
		return time.Time{}
	}
	return p.runtime.genesis.expires
}

// Revalidate retains the original operation deadline and concrete runtime.
func (p VerifiedBrokerGenesis) Revalidate(ctx context.Context) error {
	r := p.runtime
	if r == nil || r.genesis == nil || r.storeLock == nil || r.server == nil || r.conn == nil {
		return errors.New("original broker provenance is unavailable")
	}
	return validateBrokerStorage(ctx, r, r.genesis)
}

func validateBrokerStorage(ctx context.Context, r *Runtime, g *brokerGenesis) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(g.expires) || !r.server.Running() || !r.conn.IsConnected() ||
		r.server.ID() != g.info.ServerID || r.server.NodeName() != g.info.RaftNodeID {
		return errors.New("original broker lifetime ended")
	}
	var held, current unix.Stat_t
	if err := unix.Fstat(int(r.storeLock.Fd()), &held); err != nil {
		return err
	}
	dir, err := openInstallationDirectory(g.info.Installation.Directory, false)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := unix.Fstat(dir, &current); err != nil {
		return err
	}
	if held.Dev != current.Dev || held.Ino != current.Ino || held.Nlink == 0 ||
		uint64(current.Dev) != g.info.Device || current.Ino != g.info.Inode ||
		current.Uid != g.info.UID || current.Mode&0o022 != 0 {
		return ErrStoreIdentity
	}
	observed, err := observeInstalledIdentity(g.cfg, dir)
	if err != nil || observed != g.info.Installation || r.operator == nil || r.resolver == nil ||
		r.operator.Subject != observed.Operator || r.resolver.cell != observed.CellAccount ||
		r.server.NodeName() != observed.RaftNodeID || r.serverName != observed.ServerName {
		return errors.Join(ErrStoreIdentity, err)
	}
	claims, err := brokerGenesisClaims(g.cfg)
	if err != nil || claims != [3]string{g.info.OperatorSHA256, g.info.SystemJWTSHA256, g.info.CellJWTSHA256} {
		return errors.Join(ErrStoreIdentity, err)
	}
	cellJWT, cellErr := r.resolver.Fetch(observed.CellAccount)
	systemJWT, systemErr := r.resolver.Fetch(observed.SystemAccount)
	if cellErr != nil || systemErr != nil || installationDigest([]byte(strings.TrimSpace(cellJWT))) != claims[2] || installationDigest([]byte(strings.TrimSpace(systemJWT))) != claims[1] {
		return errors.Join(ErrStoreIdentity, cellErr, systemErr)
	}
	var markerStat unix.Stat_t
	if err := unix.Fstatat(dir, brokerGenesisMarker, &markerStat, unix.AT_SYMLINK_NOFOLLOW); err != nil || markerStat.Ino != g.markerInode || markerStat.Uid != 0 {
		return errors.Join(ErrStoreIdentity, err)
	}
	marker, err := readInstallationFileAt(dir, brokerGenesisMarker, 4096)
	if err != nil || string(marker) != string(g.marker) {
		return errors.Join(ErrStoreIdentity, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(g.expires) || !r.server.Running() || !r.conn.IsConnected() {
		return errors.New("original broker lifetime ended during observation")
	}
	return nil
}

func (r *Runtime) lockBrokerStore(ctx context.Context, cfg Config, original bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	started := time.Now().UTC()
	dir, err := openInstallationDirectory(cfg.Embedded.StoreDir, true)
	if err != nil {
		return err
	}
	r.storeLock = os.NewFile(uintptr(dir), cfg.Embedded.StoreDir)
	if err := unix.Flock(dir, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("lock embedded broker store: %w", err)
	}
	embedded := *cfg.Embedded
	if embedded.InterRegion != nil {
		interRegion := *embedded.InterRegion
		embedded.InterRegion = &interRegion
	}
	cfg.Embedded = &embedded
	r.storeConfig = cfg
	if !original {
		return nil
	}
	var stat unix.Stat_t
	if err := unix.Fstat(dir, &stat); err != nil {
		return err
	}
	if stat.Mode&0o022 != 0 {
		return ErrStoreIdentity
	}
	identity, err := observeInstalledIdentity(cfg, dir)
	if err != nil {
		return err
	}
	claims, err := brokerGenesisClaims(cfg)
	if err != nil {
		return err
	}
	scanFD, err := unix.Openat(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	scan := os.NewFile(uintptr(scanFD), cfg.Embedded.StoreDir)
	entries, readErr := scan.ReadDir(-1)
	closeErr := scan.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if entry.Name() != storeIdentityFile && entry.Name() != nodeIdentityFile {
			return errors.New("original broker store contains prior or unknown state")
		}
	}
	// O_EXCL and fsync make an interrupted start permanently ineligible locally.
	marker := []byte(started.Format(time.RFC3339Nano) + "\n" + identity.NodeIdentitySHA256 + "\n")
	fd, err := unix.Openat(dir, brokerGenesisMarker, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), brokerGenesisMarker)
	var markerStat unix.Stat_t
	statErr := unix.Fstat(fd, &markerStat)
	n, writeErr := file.Write(marker)
	if n != len(marker) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	syncErr := file.Sync()
	closeErr = file.Close()
	if err := errors.Join(statErr, writeErr, syncErr, closeErr, unix.Fsync(dir)); err != nil {
		return err
	}
	expires := started.Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	r.genesis = &brokerGenesis{info: BrokerGenesisInfo{Installation: identity, Cell: cfg.Cell, Instance: cfg.Instance,
		StartedAt: started, Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, OperatorSHA256: claims[0], SystemJWTSHA256: claims[1], CellJWTSHA256: claims[2], MarkerInode: markerStat.Ino, MarkerSHA256: installationDigest(marker)}, ctx: ctx, expires: expires, marker: marker, markerInode: markerStat.Ino, cfg: cfg}
	return nil
}

func brokerGenesisClaims(cfg Config) ([3]string, error) {
	var result [3]string
	for index, path := range []string{cfg.Embedded.OperatorJWTFile, cfg.Embedded.SystemJWTFile, cfg.Embedded.CellJWTFile} {
		wire, err := readInstallationFile(path, 64<<10)
		if err != nil {
			return result, err
		}
		result[index] = installationDigest([]byte(strings.TrimSpace(string(wire))))
	}
	return result, nil
}
