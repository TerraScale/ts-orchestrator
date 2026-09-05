package vmnet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	hostClaimVersion           = 1
	maxHostClaimBytes          = 16 << 10
	maxHostClaimStages         = 32
	defaultHostCoordinationDir = "/run/terrascale/vmnet"
)

type hostClaim struct {
	Version     int      `json:"version"`
	RunID       string   `json:"run_id"`
	Fingerprint string   `json:"fingerprint"`
	Resources   []string `json:"resources"`
}

type hostLease struct {
	root       *os.File
	locks      []*os.File
	claimNames []string
	present    []bool
	claim      hostClaim
	closed     bool
}

type hostLockSpec struct {
	name     string
	resource string
	run      bool
}

// acquireHostLease locks the RunID and every root-namespace resource before
// the journal or host networking can be changed. The returned recovered flag
// means a prior process left durable claims and only cleanup may continue.
func acquireHostLease(coordinationRoot, runID, fingerprint string, uplinks []RegionUplink) (_ *hostLease, recovered bool, err error) {
	resources, err := hostResourceKeys(uplinks)
	if err != nil {
		return nil, false, err
	}
	claim := hostClaim{Version: hostClaimVersion, RunID: runID, Fingerprint: fingerprint, Resources: resources}
	if err := claim.validate(); err != nil {
		return nil, false, err
	}
	root, err := openHostCoordinationDir(coordinationRoot)
	if err != nil {
		return nil, false, err
	}
	lease := &hostLease{root: root, claim: claim}
	defer func() {
		if err != nil {
			lease.unlock()
		}
	}()

	specs := []hostLockSpec{{name: "run-" + runID, resource: runID, run: true}}
	for _, resource := range resources {
		digest := sha256.Sum256([]byte(resource))
		specs = append(specs, hostLockSpec{name: "resource-" + hex.EncodeToString(digest[:]), resource: resource})
	}
	for _, spec := range specs {
		lock, lockErr := openAndLockHostFile(root, spec.name+".lock")
		if lockErr != nil {
			if errors.Is(lockErr, unix.EWOULDBLOCK) || errors.Is(lockErr, unix.EAGAIN) {
				if spec.run {
					return nil, false, fmt.Errorf("vmnet: run %s is active on this host", runID)
				}
				return nil, false, fmt.Errorf("vmnet: host resource %q is active", spec.resource)
			}
			return nil, false, lockErr
		}
		lease.locks = append(lease.locks, lock)
		lease.claimNames = append(lease.claimNames, spec.name+".claim")
	}

	lease.present = make([]bool, len(lease.claimNames))
	for index, name := range lease.claimNames {
		staged, recoverErr := recoverHostClaimStages(root, name, claim)
		if recoverErr != nil {
			return nil, false, recoverErr
		}
		recovered = recovered || staged
		observed, found, loadErr := loadHostClaim(root, name)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if !found {
			continue
		}
		lease.present[index] = true
		recovered = true
		if !observed.equal(claim) {
			if index == 0 {
				return nil, false, errors.New("vmnet: run identity is claimed by a different network plan")
			}
			return nil, false, fmt.Errorf("vmnet: host resource %q is claimed by run %s", specs[index].resource, observed.RunID)
		}
	}

	return lease, recovered, nil
}

func hostResourceKeys(uplinks []RegionUplink) ([]string, error) {
	if len(uplinks) == 0 || len(uplinks) > MaxRegions {
		return nil, errors.New("vmnet: host allocation has an invalid uplink count")
	}
	resources := make([]string, 0, 1+2*len(uplinks))
	serviceAddress := uplinks[0].HostServiceAddress
	if serviceAddress == "" {
		return nil, errors.New("vmnet: host allocation lacks a service address")
	}
	resources = append(resources, "service-address/"+serviceAddress)
	for _, uplink := range uplinks {
		if uplink.HostServiceAddress != serviceAddress || uplink.CIDR == "" || uplink.RootDevice == "" {
			return nil, errors.New("vmnet: host allocation contains an invalid uplink")
		}
		resources = append(resources, "uplink-cidr/"+uplink.CIDR, "root-device/"+uplink.RootDevice)
	}
	sort.Strings(resources)
	for index := 1; index < len(resources); index++ {
		if resources[index] == resources[index-1] {
			return nil, errors.New("vmnet: host allocation contains a duplicate resource")
		}
	}
	return resources, nil
}

func (c hostClaim) validate() error {
	if c.Version != hostClaimVersion || !runIDPattern.MatchString(c.RunID) || !validSHA256Hex(c.Fingerprint) || len(c.Resources) == 0 || len(c.Resources) > 1+2*MaxRegions {
		return errors.New("vmnet: invalid host allocation claim")
	}
	for index, resource := range c.Resources {
		if resource == "" || len(resource) > 128 || strings.ContainsAny(resource, "\x00\r\n") || (index > 0 && c.Resources[index-1] >= resource) {
			return errors.New("vmnet: invalid host allocation resources")
		}
	}
	return nil
}

func (c hostClaim) equal(other hostClaim) bool {
	if c.Version != other.Version || c.RunID != other.RunID || c.Fingerprint != other.Fingerprint || len(c.Resources) != len(other.Resources) {
		return false
	}
	for index := range c.Resources {
		if c.Resources[index] != other.Resources[index] {
			return false
		}
	}
	return true
}

func (l *hostLease) publish() error {
	if l == nil || l.closed || l.root == nil || len(l.present) != len(l.claimNames) {
		return errors.New("vmnet: invalid host allocation lease")
	}
	var created []string
	var createdIndexes []int
	for index, name := range l.claimNames {
		if l.present[index] {
			continue
		}
		if err := createHostClaim(l.root, name, l.claim); err != nil {
			rollbackErr := removeHostClaims(l.root, created, l.claim)
			if rollbackErr != nil {
				err = errors.Join(err, fmt.Errorf("rollback host claims: %w", rollbackErr))
			} else {
				for _, createdIndex := range createdIndexes {
					l.present[createdIndex] = false
				}
			}
			return err
		}
		l.present[index] = true
		created = append(created, name)
		createdIndexes = append(createdIndexes, index)
	}
	return nil
}

func (l *hostLease) complete() error {
	if l == nil || l.closed || l.root == nil {
		return errors.New("vmnet: invalid host allocation lease")
	}
	// Resource claims go first. If a process crashes partway through removal,
	// the RunID claim still prevents a conflicting plan from reusing names.
	names := append([]string(nil), l.claimNames[1:]...)
	names = append(names, l.claimNames[0])
	if err := removeHostClaims(l.root, names, l.claim); err != nil {
		return err
	}
	l.unlock()
	return nil
}

func (l *hostLease) unlock() {
	if l == nil || l.closed {
		return
	}
	for index := len(l.locks) - 1; index >= 0; index-- {
		_ = unix.Flock(int(l.locks[index].Fd()), unix.LOCK_UN)
		_ = l.locks[index].Close()
	}
	if l.root != nil {
		_ = l.root.Close()
	}
	l.closed = true
}

func openHostCoordinationDir(path string) (*os.File, error) {
	if err := validateHostCoordinationRoot(path); err != nil {
		return nil, err
	}
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("vmnet: open host coordination root: %w", err)
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(current)
			return nil, errors.New("vmnet: invalid host coordination directory component")
		}
		if mkdirErr := unix.Mkdirat(current, component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
			_ = unix.Close(current)
			return nil, fmt.Errorf("vmnet: create host coordination directory: %w", mkdirErr)
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return nil, fmt.Errorf("vmnet: open host coordination directory: %w", openErr)
		}
		var stat unix.Stat_t
		if statErr := unix.Fstat(next, &stat); statErr != nil {
			_ = unix.Close(next)
			return nil, fmt.Errorf("vmnet: inspect host coordination directory: %w", statErr)
		}
		if err := validateHostCoordinationDir(stat, index == len(components)-1); err != nil {
			_ = unix.Close(next)
			return nil, err
		}
		current = next
	}
	return os.NewFile(uintptr(current), path), nil
}

func validateHostCoordinationRoot(path string) error {
	if path == "" || len(path) > 1024 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return errors.New("vmnet: invalid host coordination directory")
	}
	return nil
}

func validateHostCoordinationDir(stat unix.Stat_t, final bool) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return errors.New("vmnet: host coordination path is not a trusted directory")
	}
	unsafeWritable := stat.Mode&0o022 != 0
	trustedSticky := stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0
	if unsafeWritable && !trustedSticky {
		return errors.New("vmnet: host coordination path is writable by another user")
	}
	if final && stat.Mode&0o077 != 0 {
		return errors.New("vmnet: host coordination directory must be private")
	}
	return nil
}

func openAndLockHostFile(root *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("vmnet: open host allocation lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if err := validatePrivateRegularFile(fd); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func loadHostClaim(root *os.File, name string) (hostClaim, bool, error) {
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return hostClaim{}, false, nil
	}
	if err != nil {
		return hostClaim{}, false, fmt.Errorf("vmnet: open host allocation claim: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := validatePrivateRegularFile(fd); err != nil {
		return hostClaim{}, false, err
	}
	info, err := file.Stat()
	if err != nil {
		return hostClaim{}, false, fmt.Errorf("vmnet: inspect host allocation claim: %w", err)
	}
	if info.Size() <= 0 || info.Size() > maxHostClaimBytes {
		return hostClaim{}, false, errors.New("vmnet: host allocation claim has an invalid size")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxHostClaimBytes+1))
	if err != nil {
		return hostClaim{}, false, fmt.Errorf("vmnet: read host allocation claim: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var claim hostClaim
	if err := decoder.Decode(&claim); err != nil {
		return hostClaim{}, false, fmt.Errorf("vmnet: decode host allocation claim: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return hostClaim{}, false, fmt.Errorf("vmnet: decode host allocation claim: %w", err)
	}
	if err := claim.validate(); err != nil {
		return hostClaim{}, false, err
	}
	return claim, true, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func recoverHostClaimStages(root *os.File, target string, expected hostClaim) (bool, error) {
	_, targetFound, err := loadHostClaim(root, target)
	if err != nil {
		return false, err
	}
	stages, err := hostClaimStageNames(root, ".claim-"+target+"-")
	if err != nil {
		return false, err
	}
	promoted := false
	changed := false
	for _, stage := range stages {
		if err := validateRecoverableHostStage(root, stage); err != nil {
			return false, err
		}
		claim, found, loadErr := loadHostClaim(root, stage)
		if loadErr == nil && found && !targetFound && claim.equal(expected) {
			renameErr := unix.Renameat2(int(root.Fd()), stage, int(root.Fd()), target, unix.RENAME_NOREPLACE)
			if renameErr == nil {
				targetFound = true
				promoted = true
				changed = true
				continue
			}
			if !errors.Is(renameErr, unix.EEXIST) {
				return false, fmt.Errorf("vmnet: recover host allocation claim: %w", renameErr)
			}
			targetFound = true
		}
		// A malformed stage cannot have preceded host networking because claim
		// publication completes before the runner is called. It is safe to drop.
		if err := unix.Unlinkat(int(root.Fd()), stage, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return false, fmt.Errorf("vmnet: remove stale host allocation stage: %w", err)
		}
		changed = true
	}
	if changed {
		if err := unix.Fsync(int(root.Fd())); err != nil {
			return false, fmt.Errorf("vmnet: sync recovered host allocation directory: %w", err)
		}
	}
	return promoted, nil
}

func hostClaimStageNames(root *os.File, prefix string) ([]string, error) {
	fd, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("vmnet: scan host allocation stages: %w", err)
	}
	directory := os.NewFile(uintptr(fd), "host-coordination-stages")
	defer directory.Close()
	var result []string
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			result = append(result, name)
			if len(result) > maxHostClaimStages {
				return nil, errors.New("vmnet: too many host allocation staging files")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("vmnet: scan host allocation stages: %w", readErr)
		}
	}
	sort.Strings(result)
	return result, nil
}

func validateRecoverableHostStage(root *os.File, name string) error {
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("vmnet: open host allocation stage: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := validatePrivateRegularFile(fd); err != nil {
		return err
	}
	return nil
}

func createHostClaim(root *os.File, name string, claim hostClaim) error {
	raw, err := json.Marshal(claim)
	if err != nil {
		return fmt.Errorf("vmnet: encode host allocation claim: %w", err)
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return fmt.Errorf("vmnet: create host allocation claim token: %w", err)
	}
	temporary := ".claim-" + name + "-" + hex.EncodeToString(token[:])
	fd, err := unix.Openat(int(root.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("vmnet: create host allocation claim: %w", err)
	}
	file := os.NewFile(uintptr(fd), temporary)
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = unix.Unlinkat(int(root.Fd()), temporary, 0)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return fmt.Errorf("vmnet: write host allocation claim: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("vmnet: sync host allocation claim: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("vmnet: close host allocation claim: %w", err)
	}
	if err := unix.Renameat2(int(root.Fd()), temporary, int(root.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("vmnet: publish host allocation claim: %w", err)
		}
		observed, found, loadErr := loadHostClaim(root, name)
		if loadErr != nil {
			return loadErr
		}
		if !found || !observed.equal(claim) {
			return errors.New("vmnet: host allocation claim changed while locked")
		}
		if err := unix.Unlinkat(int(root.Fd()), temporary, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("vmnet: remove redundant host allocation staging file: %w", err)
		}
	}
	removeTemporary = false
	if err := unix.Fsync(int(root.Fd())); err != nil {
		return fmt.Errorf("vmnet: sync host allocation directory: %w", err)
	}
	return nil
}

func removeHostClaims(root *os.File, names []string, expected hostClaim) error {
	for _, name := range names {
		claim, found, err := loadHostClaim(root, name)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if !claim.equal(expected) {
			return errors.New("vmnet: refusing to remove a foreign host allocation claim")
		}
		if err := unix.Unlinkat(int(root.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("vmnet: remove host allocation claim: %w", err)
		}
		if err := unix.Fsync(int(root.Fd())); err != nil {
			return fmt.Errorf("vmnet: sync host allocation directory: %w", err)
		}
	}
	return nil
}

func validatePrivateRegularFile(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("vmnet: inspect host coordination file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0o077 != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return errors.New("vmnet: host coordination file is not a private owned regular file")
	}
	return nil
}
