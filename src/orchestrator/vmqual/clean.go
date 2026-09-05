package vmqual

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmdisk"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const maxCleanupJournalBytes = 4 << 20

// CleanJournal replays only resources claimed by one v1 vmqual run. It never
// scans process tables, network interfaces, or a broad directory.
func CleanJournal(ctx context.Context, path string, runner vmnet.Runner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return errors.New("vmqual: cleanup journal path must be an absolute file path")
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	lock, err := acquireJournalLock(path)
	if err != nil {
		return err
	}
	defer releaseJournalLock(lock)

	journal, err := readJournal(path)
	if err != nil {
		return err
	}
	if err := validateOwnershipGraph(journal, path); err != nil {
		return err
	}
	cleanCtx := context.WithoutCancel(ctx)
	var diskIdentity vmdisk.StoreIdentity
	if journal.DiskStore != nil {
		diskIdentity, err = journalDiskStoreIdentity(journal)
		if err != nil {
			return err
		}
	}
	for index := len(journal.VMs) - 1; index >= 0; index-- {
		if journal.VMs[index].Cleaned || journal.VMs[index].Phase == vmPhaseCleaned {
			continue
		}
		journal.VMs[index].Phase = vmPhaseCleaning
		journal.Phase = journalPhaseCleaning
		if err := persistJournalUpdate(path, &journal); err != nil {
			return err
		}
		if err := cleanupJournalVMResource(cleanCtx, journal.VMs[index], journal.CreatedAt, diskIdentity); err != nil {
			return fmt.Errorf("vmqual: cleanup VM %s: %w", journal.VMs[index].ID, err)
		}
		journal.VMs[index].Phase = vmPhaseCleaned
		journal.VMs[index].Cleaned = true
		if err := persistJournalUpdate(path, &journal); err != nil {
			return err
		}
	}
	if journal.DiskStore != nil {
		if err := vmdisk.RemoveStore(cleanCtx, diskIdentity); err != nil {
			return fmt.Errorf("vmqual: remove disk store: %w", err)
		}
	}
	if !journal.NetworkCleaned && journal.NetworkPhase != networkPhaseCleaned {
		journal.NetworkPhase = networkPhaseCleaning
		journal.Phase = journalPhaseCleaning
		if err := persistJournalUpdate(path, &journal); err != nil {
			return err
		}
		if len(journal.Network.Cleanup.Commands) > 0 {
			if runner == nil {
				return errors.New("vmqual: cleanup network runner is required")
			}
			if err := journal.Network.Cleanup.Run(cleanCtx, runner); err != nil {
				return err
			}
		}
		journal.NetworkPhase = networkPhaseCleaned
		journal.NetworkCleaned = true
		if err := persistJournalUpdate(path, &journal); err != nil {
			return err
		}
	}
	journal.Phase = journalPhaseComplete
	if err := persistJournalUpdate(path, &journal); err != nil {
		return err
	}
	if err := removeJournalFile(path, journal.RunID); err != nil {
		return err
	}
	return removeRunMarker(journal.StateRoot, journal.RunID, path)
}

func (s *Stack) cleanupJournalVM(ctx context.Context, id string) error {
	if s == nil || s.config.JournalPath == "" {
		return nil
	}
	resource, err := s.journalVM(id)
	if err != nil {
		return err
	}
	if resource.Cleaned || resource.Phase == vmPhaseCleaned {
		return nil
	}
	diskIdentity, err := s.diskStoreIdentity()
	if err != nil && resource.DriveDir != "" {
		return err
	}
	if err := cleanupJournalVMResource(ctx, resource, s.journalCreatedAt(), diskIdentity); err != nil {
		return err
	}
	return s.setVMPhase(id, vmPhaseCleaned)
}

func (s *Stack) cleanupJournalVMsWithoutHandles() error {
	if s == nil || s.config.JournalPath == "" {
		return nil
	}
	s.journalMu.Lock()
	if s.journal == nil {
		s.journalMu.Unlock()
		return nil
	}
	resources := append([]JournalVM(nil), s.journal.VMs...)
	s.journalMu.Unlock()

	s.mu.Lock()
	handles := make(map[string]bool, len(s.vms))
	for id := range s.vms {
		handles[id] = true
	}
	s.mu.Unlock()
	var errs []error
	for index := len(resources) - 1; index >= 0; index-- {
		resource := resources[index]
		if handles[resource.ID] || resource.Cleaned || resource.Phase == vmPhaseCleaned {
			continue
		}
		if resource.Phase != vmPhasePlanned && resource.StateDir == "" && resource.DriveDir == "" && resource.SeedDir == "" {
			errs = append(errs, fmt.Errorf("vmqual: VM %s mutated without a resource plan", resource.ID))
			continue
		}
		if err := s.setVMPhase(resource.ID, vmPhaseCleaning); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := s.cleanupJournalVM(context.Background(), resource.ID); err != nil {
			errs = append(errs, fmt.Errorf("cleanup %s: %w", resource.ID, err))
		}
	}
	return errors.Join(errs...)
}

func initializeJournalFiles(path string, journal Journal, marker runOwnership) (Journal, error) {
	if existing, err := readJournal(path); err == nil {
		if existing.RunID != journal.RunID {
			return Journal{}, fmt.Errorf("vmqual: unfinished cleanup journal belongs to run %s", existing.RunID)
		}
		if !sameJournalPlan(existing, journal) {
			return Journal{}, errors.New("vmqual: existing cleanup journal does not match this run plan")
		}
		if err := validateOwnershipGraph(existing, path); err != nil {
			return Journal{}, err
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Journal{}, err
	}
	if err := mkdirAllNoSymlinks(journal.StateRoot, 0700); err != nil {
		return Journal{}, err
	}
	if err := mkdirAllNoSymlinks(filepath.Dir(path), 0700); err != nil {
		return Journal{}, err
	}
	if err := preflightResourcePaths(journal); err != nil {
		return Journal{}, err
	}
	if existingMarker, err := readRunMarker(journal.RunMarkerPath); err == nil {
		if existingMarker.RunID != marker.RunID || filepath.Clean(existingMarker.JournalPath) != marker.JournalPath || filepath.Clean(existingMarker.StateRoot) != marker.StateRoot {
			return Journal{}, errors.New("vmqual: run marker belongs to a different cleanup run")
		}
		journal.CreatedAt = existingMarker.CreatedAt
		journal.UpdatedAt = existingMarker.CreatedAt
		marker = existingMarker
	} else if !errors.Is(err, os.ErrNotExist) {
		return Journal{}, err
	} else if err := writeExclusiveJSON(journal.RunMarkerPath, marker); err != nil {
		return Journal{}, err
	}
	createdClaims := make([]string, 0, len(journal.VMs))
	cleanupInit := func() {
		for _, claim := range createdClaims {
			_ = RemoveFileAndSync(claim)
		}
		_ = RemoveFileAndSync(journal.RunMarkerPath)
	}
	for _, resource := range journal.VMs {
		claim := claimForResource(resource, journal.CreatedAt)
		if err := ensureExclusiveJSON(resource.ClaimPath, claim); err != nil {
			cleanupInit()
			return Journal{}, err
		}
		createdClaims = append(createdClaims, resource.ClaimPath)
	}
	if err := writeNewJournal(path, journal); err != nil {
		cleanupInit()
		return Journal{}, err
	}
	return journal, nil
}

func preflightResourcePaths(journal Journal) error {
	for _, resource := range journal.VMs {
		for _, path := range []string{resource.StateDir, resource.DriveDir, resource.SeedDir, resource.CgroupPath, resource.JailerCgroupPath} {
			if path == "" {
				continue
			}
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("vmqual: refusing pre-existing resource path %s", path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func validateJournal(journal Journal) error {
	if journal.Version != cleanupJournalVersion {
		if journal.Version == 1 {
			return errors.New("vmqual: cleanup journal v1 is not run-bound")
		}
		return fmt.Errorf("vmqual: unsupported cleanup journal version %d", journal.Version)
	}
	if journal.Marker != OwnershipMarker || !validRunID(journal.RunID) {
		return errors.New("vmqual: cleanup journal ownership identity is invalid")
	}
	if journal.Revision == 0 || journal.CreatedAt.IsZero() || journal.UpdatedAt.Before(journal.CreatedAt) {
		return errors.New("vmqual: cleanup journal timestamps or revision are invalid")
	}
	if !CanonicalAbsolute(journal.StateRoot) || filepath.Clean(journal.StateRoot) == string(filepath.Separator) {
		return errors.New("vmqual: cleanup state root is invalid")
	}
	if journal.ResourceRoot != "" && (!CanonicalAbsolute(journal.ResourceRoot) || filepath.Clean(journal.ResourceRoot) == string(filepath.Separator)) {
		return errors.New("vmqual: cleanup resource root is invalid")
	}
	if journal.DiskStore != nil {
		identity, err := journalDiskStoreIdentity(journal)
		if err != nil {
			return err
		}
		if journal.ResourceRoot == "" || identity.Root != filepath.Join(journal.ResourceRoot, "drives") {
			return errors.New("vmqual: disk store is outside the cleanup resource root")
		}
	}
	wantRunMarker := filepath.Join(journal.StateRoot, ".vmqual-runs", journal.RunID+".json")
	if journal.RunMarkerPath != wantRunMarker {
		return errors.New("vmqual: cleanup run marker path is invalid")
	}
	if !oneOf(journal.Phase, journalPhasePlanned, journalPhaseActive, journalPhaseCleaning, journalPhaseComplete) {
		return errors.New("vmqual: cleanup journal phase is invalid")
	}
	if !oneOf(journal.NetworkPhase, networkPhasePlanned, networkPhaseApplying, networkPhaseApplied, networkPhaseCleaning, networkPhaseCleaned) {
		return errors.New("vmqual: cleanup network phase is invalid")
	}
	if journal.NetworkCleaned != (journal.NetworkPhase == networkPhaseCleaned) {
		return errors.New("vmqual: cleanup network completion state is inconsistent")
	}
	if err := validateJournalNetwork(journal.Network); err != nil {
		return err
	}
	if len(journal.VMs) == 0 {
		return errors.New("vmqual: cleanup journal has no VMs")
	}
	seenIDs := make(map[string]struct{}, len(journal.VMs))
	seenPaths := make(map[string]string)
	drivePlanned := false
	admittedHosts := 0
	for _, resource := range journal.VMs {
		if resource.Region == string(FourthRegion) {
			admittedHosts++
		}
		if resource.RunID != journal.RunID || !validGuestID(resource.ID) || !journalOwnsGuestRegion(journal, resource) {
			return fmt.Errorf("vmqual: cleanup resource %q has invalid identity", resource.ID)
		}
		if _, exists := seenIDs[resource.ID]; exists {
			return fmt.Errorf("vmqual: duplicate cleanup resource %q", resource.ID)
		}
		seenIDs[resource.ID] = struct{}{}
		if !oneOf(resource.Phase, vmPhasePlanned, vmPhaseCreating, vmPhaseCreated, vmPhaseStarting, vmPhaseRunning, vmPhaseCleaning, vmPhaseCleaned) || resource.Cleaned != (resource.Phase == vmPhaseCleaned) {
			return fmt.Errorf("vmqual: cleanup resource %q has invalid phase", resource.ID)
		}
		wantClaim := filepath.Join(journal.StateRoot, ".vmqual-runs", journal.RunID+".claims", resource.ID+".json")
		if resource.ClaimPath != wantClaim {
			return fmt.Errorf("vmqual: cleanup resource %q has invalid claim path", resource.ID)
		}
		if err := validateResourcePaths(journal, resource); err != nil {
			return err
		}
		drivePlanned = drivePlanned || resource.DriveDir != ""
		for _, path := range resourcePaths(resource) {
			if path == "" {
				continue
			}
			if owner, exists := seenPaths[path]; exists {
				return fmt.Errorf("vmqual: cleanup path %s is shared by %s and %s", path, owner, resource.ID)
			}
			seenPaths[path] = resource.ID
		}
		if resource.Process != nil {
			if err := validateProcessIdentity(*resource.Process); err != nil {
				return fmt.Errorf("vmqual: cleanup resource %q: %w", resource.ID, err)
			}
		}
	}
	if admittedHosts != 0 && admittedHosts != 2 {
		return errors.New("vmqual: fourth-region cleanup must retain both admitted host obligations")
	}
	if drivePlanned != (journal.DiskStore != nil) {
		return errors.New("vmqual: disk resources and disk store identity are inconsistent")
	}
	return nil
}

func journalDiskStoreIdentity(journal Journal) (vmdisk.StoreIdentity, error) {
	if journal.DiskStore == nil {
		return vmdisk.StoreIdentity{}, errors.New("vmqual: cleanup journal has no disk store identity")
	}
	stored := journal.DiskStore
	planned, err := vmdisk.PlanStoreIdentity(stored.Root, stored.RunID, vmdisk.Ownership{UID: stored.JailerUID, GID: stored.JailerGID})
	if err != nil {
		return vmdisk.StoreIdentity{}, fmt.Errorf("vmqual: invalid disk store identity: %w", err)
	}
	if stored.RunID != journal.RunID || planned.Root != stored.Root || planned.RunID != stored.RunID || planned.Ownership.UID != stored.JailerUID || planned.Ownership.GID != stored.JailerGID || planned.Tombstone != stored.Tombstone {
		return vmdisk.StoreIdentity{}, errors.New("vmqual: disk store identity differs from its deterministic plan")
	}
	return planned, nil
}

func validateResourcePaths(journal Journal, resource JournalVM) error {
	stateFields := []string{resource.StateDir, resource.SandboxOwnershipPath, resource.RunMarkerPath, resource.RuntimePath, resource.JailRoot, resource.SocketPath, resource.LogPath, resource.MetricsPath, resource.CgroupRoot, resource.CgroupPath, resource.JailerCgroupPath, resource.FirecrackerPath}
	stateEmpty := resource.StateDir == ""
	for _, path := range stateFields {
		if (path == "") != stateEmpty || path != "" && !CanonicalAbsolute(path) {
			return fmt.Errorf("vmqual: cleanup resource %q has an incomplete state plan", resource.ID)
		}
	}
	if !stateEmpty {
		firecrackerName := filepath.Base(filepath.Dir(resource.StateDir))
		if !PathWithin(journal.StateRoot, resource.StateDir) || filepath.Base(resource.StateDir) != resource.ID ||
			resource.SandboxOwnershipPath != filepath.Join(resource.StateDir, "ownership.json") ||
			resource.RunMarkerPath != filepath.Join(resource.StateDir, RunMarkerName) ||
			resource.RuntimePath != filepath.Join(resource.StateDir, "runtime.json") ||
			resource.JailRoot != filepath.Join(resource.StateDir, "root") ||
			resource.SocketPath != filepath.Join(resource.JailRoot, "api.sock") ||
			resource.LogPath != filepath.Join(resource.StateDir, "firecracker.log") ||
			resource.MetricsPath != filepath.Join(resource.StateDir, "firecracker.metrics") ||
			!CanonicalAbsolute(resource.CgroupRoot) || filepath.Clean(resource.CgroupRoot) == string(filepath.Separator) ||
			resource.CgroupPath != filepath.Join(resource.CgroupRoot, "terrascale-sandboxvm", resource.ID) ||
			resource.JailerCgroupPath != filepath.Join(resource.CgroupRoot, firecrackerName, resource.ID) ||
			resource.FirecrackerPath != filepath.Join(resource.JailRoot, firecrackerName) {
			return fmt.Errorf("vmqual: cleanup resource %q has invalid sandbox paths", resource.ID)
		}
	}
	driveFields := []string{resource.DriveDir, resource.DrivePath, resource.DriveMetadataPath, resource.DriveOwnershipPath}
	driveEmpty := resource.DriveDir == ""
	for _, path := range driveFields {
		if (path == "") != driveEmpty || path != "" && !CanonicalAbsolute(path) {
			return fmt.Errorf("vmqual: cleanup resource %q has an incomplete drive plan", resource.ID)
		}
	}
	if !driveEmpty {
		wantDir := filepath.Join(journal.ResourceRoot, "drives", "drives", resource.ID)
		if journal.ResourceRoot == "" || resource.DriveDir != wantDir || resource.DrivePath != filepath.Join(resource.DriveDir, "artifact-00000000000000000001.img") || resource.DriveMetadataPath != filepath.Join(resource.DriveDir, "metadata.json") || resource.DriveOwnershipPath != filepath.Join(resource.DriveDir, ".owner.json") {
			return fmt.Errorf("vmqual: cleanup resource %q has invalid drive paths", resource.ID)
		}
	}
	seedEmpty := resource.SeedDir == ""
	if !seedEmpty && resource.SeedDir != filepath.Join(journal.StateRoot, resource.ID) {
		return fmt.Errorf("vmqual: cleanup resource %q has invalid seed paths", resource.ID)
	}
	return nil
}

func validateJournalNetwork(journal vmnet.Journal) error {
	if journal.Version == 0 && journal.Cleanup.Version == 0 && len(journal.Cleanup.Commands) == 0 {
		return nil
	}
	if err := ValidateNetworkJournal(journal); err != nil {
		return err
	}
	if !validNetworkRunID(journal.RunID) || journal.Cleanup.RunID != journal.RunID {
		return errors.New("vmqual: network journal run identity is invalid")
	}
	return nil
}

func validateOwnershipGraph(journal Journal, journalPath string) error {
	if err := validateJournal(journal); err != nil {
		return err
	}
	if journal.Phase != journalPhaseComplete {
		marker, err := readRunMarker(journal.RunMarkerPath)
		if err != nil {
			return fmt.Errorf("vmqual: read run marker: %w", err)
		}
		if marker.Version != runMarkerVersion || marker.Marker != runOwnershipMarker || marker.RunID != journal.RunID || marker.JournalPath != filepath.Clean(journalPath) || marker.StateRoot != journal.StateRoot || !marker.CreatedAt.Equal(journal.CreatedAt) {
			return errors.New("vmqual: run marker does not match cleanup journal")
		}
	}
	for _, resource := range journal.VMs {
		claim, err := readResourceClaim(resource.ClaimPath)
		if err != nil {
			return fmt.Errorf("vmqual: read resource claim %s: %w", resource.ID, err)
		}
		if !reflect.DeepEqual(claim, claimForResource(resource, journal.CreatedAt)) {
			return fmt.Errorf("vmqual: resource claim %s does not match cleanup journal", resource.ID)
		}
		if err := validateExistingResource(journal, resource); err != nil {
			return err
		}
	}
	return nil
}

func validateExistingResource(journal Journal, resource JournalVM) error {
	if resource.StateDir != "" {
		exists, err := existingOwnedDirectory(resource.StateDir)
		if err != nil {
			return fmt.Errorf("vmqual: state resource %s: %w", resource.ID, err)
		}
		if exists {
			if resource.Phase == vmPhasePlanned || resource.Phase == vmPhaseCleaned {
				return fmt.Errorf("vmqual: unexpected state resource for %s in phase %s", resource.ID, resource.Phase)
			}
			if err := validateSandboxOwnership(resource, journal.CreatedAt); err != nil {
				return err
			}
			marker, markerErr := readVMRunMarker(resource.RunMarkerPath)
			if markerErr == nil {
				if marker.Version != runMarkerVersion || marker.Marker != runOwnershipMarker || marker.RunID != journal.RunID || marker.ID != resource.ID || marker.Region != resource.Region || marker.StateDir != resource.StateDir || marker.CreatedAt.Before(journal.CreatedAt) {
					return fmt.Errorf("vmqual: VM run marker %s does not match journal", resource.ID)
				}
			} else if !errors.Is(markerErr, os.ErrNotExist) || resource.Phase != vmPhaseCreating {
				return fmt.Errorf("vmqual: read VM run marker %s: %w", resource.ID, markerErr)
			}
			runtime, runtimeErr := readRuntimeRecord(resource.RuntimePath)
			if runtimeErr == nil {
				if err := validateRuntimeRecord(runtime, resource, journal.CreatedAt); err != nil {
					return err
				}
			} else if !errors.Is(runtimeErr, os.ErrNotExist) {
				return fmt.Errorf("vmqual: read runtime record %s: %w", resource.ID, runtimeErr)
			} else if resource.Phase == vmPhaseRunning {
				return fmt.Errorf("vmqual: running VM %s has no runtime record", resource.ID)
			} else if resource.Phase == vmPhaseStarting && socketActive(resource.SocketPath) {
				return fmt.Errorf("vmqual: starting VM %s has an active socket without a runtime record", resource.ID)
			}
			if resource.Process == nil && socketActive(resource.SocketPath) {
				return fmt.Errorf("vmqual: VM %s has an active socket without process identity", resource.ID)
			}
		}
	}
	if resource.SeedDir != "" {
		exists, err := existingOwnedDirectory(resource.SeedDir)
		if err != nil {
			return fmt.Errorf("vmqual: seed resource %s: %w", resource.ID, err)
		}
		if exists {
			info, err := os.Lstat(resource.SeedDir)
			if err != nil {
				return err
			}
			if info.ModTime().Before(journal.CreatedAt) {
				return fmt.Errorf("vmqual: seed resource %s predates its run", resource.ID)
			}
		}
	}
	return nil
}

func validateSandboxOwnership(resource JournalVM, createdAt time.Time) error {
	exists, err := existingOwnedDirectory(resource.StateDir)
	if err != nil || !exists {
		if err != nil {
			return err
		}
		return os.ErrNotExist
	}
	var marker sandboxOwnership
	if err := readStrictJSONFile(resource.SandboxOwnershipPath, &marker); err != nil {
		return fmt.Errorf("vmqual: read sandbox ownership %s: %w", resource.ID, err)
	}
	if marker.Marker != "terrascale-sandboxvm-v1" || marker.ID != resource.ID || marker.Region != resource.Region || marker.JailRoot != resource.JailRoot || marker.SocketPath != resource.SocketPath || marker.LogPath != resource.LogPath || marker.MetricsPath != resource.MetricsPath || marker.RuntimeState != resource.RuntimePath || marker.CgroupRoot != resource.CgroupRoot || marker.CgroupPath != resource.CgroupPath || marker.JailerCgroupPath != resource.JailerCgroupPath || marker.CreatedAt.IsZero() || marker.CreatedAt.Before(createdAt) {
		return fmt.Errorf("vmqual: refusing unowned sandbox resource %s", resource.ID)
	}
	return nil
}

func validateDriveOwnership(resource JournalVM, createdAt time.Time, identity vmdisk.StoreIdentity) error {
	exists, err := existingOwnedDirectory(resource.DriveDir)
	if err != nil || !exists {
		return err
	}
	_ = createdAt
	paths, err := vmdisk.VerifyDriveOwned(identity, resource.ID)
	if err != nil {
		return fmt.Errorf("vmqual: verify drive ownership %s: %w", resource.ID, err)
	}
	if paths.DriveDir != resource.DriveDir || paths.Metadata != resource.DriveMetadataPath || paths.Ownership != resource.DriveOwnershipPath || !PathWithin(resource.DriveDir, paths.Artifact) {
		return fmt.Errorf("vmqual: refusing unowned drive resource %s", resource.ID)
	}
	return nil
}

func cleanupJournalVMResource(ctx context.Context, resource JournalVM, createdAt time.Time, diskIdentity vmdisk.StoreIdentity) error {
	if resource.StateDir == "" && resource.DriveDir == "" && resource.SeedDir == "" {
		return nil
	}
	if resource.StateDir != "" {
		exists, err := existingOwnedDirectory(resource.StateDir)
		if err != nil {
			return err
		}
		if exists {
			if err := validateSandboxOwnership(resource, createdAt); err != nil {
				return err
			}
			if err := stopJournaledProcess(resource); err != nil {
				return err
			}
			if err := RemoveTreeAndSync(resource.StateDir); err != nil {
				return err
			}
		}
	}
	for _, cgroup := range []string{resource.CgroupPath, resource.JailerCgroupPath} {
		if err := removeEmptyOwnedCgroup(cgroup); err != nil {
			return err
		}
	}
	if resource.DriveDir != "" {
		exists, err := existingOwnedDirectory(resource.DriveDir)
		if err != nil {
			return err
		}
		if exists {
			if err := validateDriveOwnership(resource, createdAt, diskIdentity); err != nil {
				return err
			}
			if err := vmdisk.RemoveDriveOwned(ctx, diskIdentity, resource.ID); err != nil {
				return err
			}
		}
	}
	if resource.SeedDir != "" {
		exists, err := existingOwnedDirectory(resource.SeedDir)
		if err != nil {
			return err
		}
		if exists {
			info, err := os.Lstat(resource.SeedDir)
			if err != nil {
				return err
			}
			if info.ModTime().Before(createdAt) {
				return fmt.Errorf("vmqual: seed resource %s predates its run", resource.ID)
			}
			if err := RemoveTreeAndSync(resource.SeedDir); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Stack) diskStoreIdentity() (vmdisk.StoreIdentity, error) {
	if s == nil || s.config.JournalPath == "" {
		return vmdisk.StoreIdentity{}, nil
	}
	s.journalMu.Lock()
	if s.journal == nil {
		s.journalMu.Unlock()
		return vmdisk.StoreIdentity{}, nil
	}
	journal := *s.journal
	if s.journal.DiskStore != nil {
		stored := *s.journal.DiskStore
		journal.DiskStore = &stored
	}
	s.journalMu.Unlock()
	if journal.DiskStore == nil {
		return vmdisk.StoreIdentity{}, nil
	}
	return journalDiskStoreIdentity(journal)
}

func (s *Stack) cleanupJournalDiskStore(ctx context.Context) error {
	identity, err := s.diskStoreIdentity()
	if err != nil || identity.Root == "" {
		return err
	}
	if finalizer, ok := s.config.VMFactory.(diskStoreFinalizer); ok {
		return finalizer.FinalizeDiskStore(ctx, identity)
	}
	return vmdisk.RemoveStore(ctx, identity)
}

func removeEmptyOwnedCgroup(path string) error {
	if path == "" {
		return nil
	}
	if !CanonicalAbsolute(path) || filepath.Clean(path) == string(filepath.Separator) {
		return errors.New("vmqual: cgroup cleanup path is invalid")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmqual: owned cgroup path is not a directory")
	}
	processes, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(processes)) != "" {
		return errors.New("vmqual: refusing to remove a cgroup with live processes")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func stopJournaledProcess(resource JournalVM) error {
	runtime, runtimeErr := readRuntimeRecord(resource.RuntimePath)
	if runtimeErr != nil && !errors.Is(runtimeErr, os.ErrNotExist) {
		return runtimeErr
	}
	var process *VMProcessIdentity
	if resource.Process != nil {
		identity := *resource.Process
		process = &identity
	}
	if runtimeErr == nil {
		if runtime.ID != resource.ID || runtime.SocketPath != resource.SocketPath || runtime.PID <= 0 || runtime.ProcessStartTime == 0 {
			return errors.New("vmqual: runtime process identity does not match cleanup journal")
		}
		if process != nil && (runtime.PID != process.PID || runtime.ProcessStartTime != process.StartTimeTicks) && runtime.State == "running" {
			return errors.New("vmqual: running process differs from the cleanup journal")
		}
		if process == nil && runtime.State == "running" {
			identity := VMProcessIdentity{PID: runtime.PID, StartTimeTicks: runtime.ProcessStartTime, Executable: resource.FirecrackerPath}
			if err := validateProcessIdentity(identity); err != nil {
				return errors.New("vmqual: running process cannot be recovered from the runtime record")
			}
			process = &identity
		}
	}
	if process == nil {
		if socketActive(resource.SocketPath) || runtimeErr == nil && runtime.State == "running" {
			return errors.New("vmqual: active VM has no process identity")
		}
		return nil
	}
	matched, err := ProcessIdentityMatches(*process)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if socketActive(resource.SocketPath) {
				return errors.New("vmqual: active VM socket remains after its process disappeared")
			}
			return nil
		}
		return err
	}
	if !matched {
		return errors.New("vmqual: process identity mismatch; refusing to signal reused PID")
	}
	if err := verifyProcessCgroupOwnership(resource, process.PID); err != nil {
		return err
	}
	if err := syscall.Kill(process.PID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if WaitForProcessExit(*process, time.Second) {
		return nil
	}
	matched, err = ProcessIdentityMatches(*process)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !matched {
		return errors.New("vmqual: process identity changed before forced stop")
	}
	if err := verifyProcessCgroupOwnership(resource, process.PID); err != nil {
		return err
	}
	if err := syscall.Kill(process.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if !WaitForProcessExit(*process, time.Second) {
		return errors.New("vmqual: VM process did not stop")
	}
	return nil
}

func verifyProcessCgroupOwnership(resource JournalVM, pid int) error {
	for _, path := range []string{resource.CgroupPath, resource.JailerCgroupPath} {
		file, err := os.Open(filepath.Join(path, "cgroup.procs"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return err
		}
		if len(data) > 4096 {
			return errors.New("vmqual: owned cgroup process list exceeds its bound")
		}
		fields := strings.Fields(string(data))
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 1 || fields[0] != strconv.Itoa(pid) {
			return errors.New("vmqual: owned cgroup contains an unexpected process")
		}
		return nil
	}
	return errors.New("vmqual: running process is absent from its owned cgroups")
}

func ProcessIdentityMatches(identity VMProcessIdentity) (bool, error) {
	start, err := ProcStartTime(identity.PID)
	if err != nil {
		return false, err
	}
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(identity.PID), "exe"))
	if err != nil {
		return false, err
	}
	return start == identity.StartTimeTicks && filepath.Clean(executable) == identity.Executable, nil
}

func ProcStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	closeParen := bytes.LastIndexByte(data, ')')
	if closeParen < 0 || closeParen+2 >= len(data) {
		return 0, errors.New("vmqual: malformed process stat")
	}
	fields := strings.Fields(string(data[closeParen+2:]))
	if len(fields) <= 19 {
		return 0, errors.New("vmqual: incomplete process stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("vmqual: parse process start time: %w", err)
	}
	return start, nil
}

func WaitForProcessExit(identity VMProcessIdentity, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		matched, err := ProcessIdentityMatches(identity)
		if errors.Is(err, os.ErrNotExist) || err == nil && !matched {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func socketActive(path string) bool {
	if path == "" {
		return false
	}
	connection, err := net.DialTimeout("unix", path, 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func validateProcessIdentity(process VMProcessIdentity) error {
	if process.PID <= 0 || process.StartTimeTicks == 0 || !CanonicalAbsolute(process.Executable) || filepath.Clean(process.Executable) == string(filepath.Separator) {
		return errors.New("VM process identity is incomplete")
	}
	return nil
}

func ZeroProcessIdentity(process VMProcessIdentity) bool {
	return process.PID == 0 && process.StartTimeTicks == 0 && process.Executable == ""
}

func sameResourcePaths(expected JournalVM, observed VMResourceIdentity, runID string) bool {
	return observed.RunID == runID && expected.StateDir == observed.StateDir && expected.SandboxOwnershipPath == observed.SandboxOwnershipPath && expected.RunMarkerPath == observed.RunMarkerPath && expected.RuntimePath == observed.RuntimePath && expected.JailRoot == observed.JailRoot && expected.SocketPath == observed.SocketPath && expected.LogPath == observed.LogPath && expected.MetricsPath == observed.MetricsPath && expected.CgroupRoot == observed.CgroupRoot && expected.CgroupPath == observed.CgroupPath && expected.JailerCgroupPath == observed.JailerCgroupPath && expected.FirecrackerPath == observed.FirecrackerPath && expected.DriveDir == observed.DriveDir && expected.DrivePath == observed.DrivePath && expected.DriveMetadataPath == observed.DriveMetadataPath && expected.DriveOwnershipPath == observed.DriveOwnershipPath && expected.SeedDir == observed.SeedDir
}

func claimForResource(resource JournalVM, createdAt time.Time) vmResourceClaim {
	return vmResourceClaim{Version: runMarkerVersion, Marker: runClaimMarker, RunID: resource.RunID, ID: resource.ID, Region: resource.Region, StateDir: resource.StateDir, SandboxOwnershipPath: resource.SandboxOwnershipPath, RuntimePath: resource.RuntimePath, CgroupRoot: resource.CgroupRoot, CgroupPath: resource.CgroupPath, JailerCgroupPath: resource.JailerCgroupPath, FirecrackerPath: resource.FirecrackerPath, DriveDir: resource.DriveDir, DriveMetadataPath: resource.DriveMetadataPath, DriveOwnershipPath: resource.DriveOwnershipPath, SeedDir: resource.SeedDir, CreatedAt: createdAt}
}

func readJournal(path string) (Journal, error) {
	var journal Journal
	if err := readStrictJSONFileLimit(path, &journal, maxCleanupJournalBytes); err != nil {
		return Journal{}, err
	}
	if err := validateJournal(journal); err != nil {
		return Journal{}, err
	}
	return journal, nil
}

func readRunMarker(path string) (runOwnership, error) {
	var marker runOwnership
	err := readStrictJSONFile(path, &marker)
	return marker, err
}

func readVMRunMarker(path string) (vmRunOwnership, error) {
	var marker vmRunOwnership
	err := readStrictJSONFile(path, &marker)
	return marker, err
}

func readResourceClaim(path string) (vmResourceClaim, error) {
	var claim vmResourceClaim
	err := readStrictJSONFile(path, &claim)
	return claim, err
}

type sandboxOwnership struct {
	Marker           string    `json:"marker"`
	ID               string    `json:"id"`
	Region           string    `json:"region"`
	JailRoot         string    `json:"jailRoot"`
	SocketPath       string    `json:"socketPath"`
	LogPath          string    `json:"logPath"`
	MetricsPath      string    `json:"metricsPath"`
	RuntimeState     string    `json:"runtimeState"`
	CgroupRoot       string    `json:"cgroupRoot"`
	CgroupPath       string    `json:"cgroupPath"`
	JailerCgroupPath string    `json:"jailerCgroupPath"`
	CreatedAt        time.Time `json:"createdAt"`
}

type runtimeRecord struct {
	Version          int        `json:"version"`
	Marker           string     `json:"marker"`
	ID               string     `json:"id"`
	State            string     `json:"state"`
	PID              int        `json:"pid"`
	ProcessStartTime uint64     `json:"processStartTimeTicks"`
	Firecracker      string     `json:"firecrackerVersion"`
	SocketPath       string     `json:"socketPath"`
	LogPath          string     `json:"logPath"`
	MetricsPath      string     `json:"metricsPath"`
	ObservedAt       time.Time  `json:"observedAt"`
	StoppedAt        *time.Time `json:"stoppedAt,omitempty"`
}

func readRuntimeRecord(path string) (runtimeRecord, error) {
	var record runtimeRecord
	err := readStrictJSONFile(path, &record)
	return record, err
}

func validateRuntimeRecord(record runtimeRecord, resource JournalVM, createdAt time.Time) error {
	if record.Version != 1 || record.Marker != "terrascale-sandboxvm-v1" || record.ID != resource.ID || !oneOf(record.State, "running", "stopped") || record.PID <= 0 || record.ProcessStartTime == 0 || record.SocketPath != resource.SocketPath || record.LogPath != resource.LogPath || record.MetricsPath != resource.MetricsPath || record.ObservedAt.IsZero() || record.ObservedAt.Before(createdAt) {
		return fmt.Errorf("vmqual: runtime record %s does not match cleanup journal", resource.ID)
	}
	if resource.Process != nil && (record.PID != resource.Process.PID || record.ProcessStartTime != resource.Process.StartTimeTicks) {
		return fmt.Errorf("vmqual: runtime process %s does not match cleanup journal", resource.ID)
	}
	return nil
}

func readStrictJSONFile(path string, value any) error {
	return readStrictJSONFileLimit(path, value, 1<<20)
}

func readStrictJSONFileLimit(path string, value any, limit int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return errors.New("vmqual: owned JSON path is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, limit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("vmqual: JSON contains trailing data")
		}
		return err
	}
	return nil
}

func writeNewJournal(path string, journal Journal) error {
	return writeExclusiveJSON(path, journal)
}

func replaceJournal(path string, journal Journal) error {
	current, err := readJournal(path)
	if err != nil {
		return err
	}
	if current.RunID != journal.RunID {
		return errors.New("vmqual: refusing to replace another run's cleanup journal")
	}
	return writeAtomicJSON(path, journal)
}

func persistJournalUpdate(path string, journal *Journal) error {
	journal.Revision++
	journal.UpdatedAt = time.Now().UTC()
	return replaceJournal(path, *journal)
}

func writeExclusiveJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := mkdirAllNoSymlinks(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vmqual-new-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	return SyncDirectory(filepath.Dir(path))
}

func ensureExclusiveJSON(path string, value any) error {
	if err := writeExclusiveJSON(path, value); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	existing := reflect.New(reflect.TypeOf(value)).Interface()
	if err := readStrictJSONFile(path, existing); err != nil {
		return err
	}
	if !reflect.DeepEqual(reflect.ValueOf(existing).Elem().Interface(), value) {
		return errors.New("vmqual: existing ownership file does not match this run")
	}
	return nil
}

func writeAtomicJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vmqual-replace-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return SyncDirectory(filepath.Dir(path))
}

func acquireJournalLock(path string) (*os.File, error) {
	if err := mkdirAllNoSymlinks(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lockPath := path + ".lock"
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("vmqual: cleanup journal is in use by an active run")
		}
		return nil, err
	}
	return file, nil
}

func releaseJournalLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func removeJournalFile(path, runID string) error {
	journal, err := readJournal(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if journal.RunID != runID {
		return errors.New("vmqual: refusing to remove another run's cleanup journal")
	}
	return RemoveFileAndSync(path)
}

func removeRunMarker(stateRoot, runID, journalPath string) error {
	markerPath := filepath.Join(stateRoot, ".vmqual-runs", runID+".json")
	marker, err := readRunMarker(markerPath)
	if !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		if marker.Version != runMarkerVersion || marker.Marker != runOwnershipMarker || marker.RunID != runID || marker.JournalPath != filepath.Clean(journalPath) || marker.StateRoot != filepath.Clean(stateRoot) {
			return errors.New("vmqual: refusing to remove mismatched run marker")
		}
		if err := RemoveFileAndSync(markerPath); err != nil {
			return err
		}
	}
	claims := filepath.Join(stateRoot, ".vmqual-runs", runID+".claims")
	if exists, err := existingOwnedDirectory(claims); err != nil {
		return err
	} else if exists {
		entries, err := os.ReadDir(claims)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				return errors.New("vmqual: refusing unexpected run claim entry")
			}
			claim, err := readResourceClaim(filepath.Join(claims, entry.Name()))
			if err != nil || claim.RunID != runID || claim.Marker != runClaimMarker {
				return errors.New("vmqual: refusing mismatched run claim")
			}
		}
		if err := RemoveTreeAndSync(claims); err != nil {
			return err
		}
	}
	return nil
}

func RemoveFileAndSync(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmqual: refusing to remove non-regular ownership file")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return SyncDirectory(filepath.Dir(path))
}

func RemoveTreeAndSync(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmqual: refusing to remove non-directory owned path")
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return SyncDirectory(filepath.Dir(path))
}

func SyncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func mkdirAllNoSymlinks(path string, mode os.FileMode) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return errors.New("vmqual: directory path must be absolute")
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, mode); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("vmqual: path component %s is not a directory", current)
		}
	}
	return nil
}

func existingOwnedDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("path is not an owned directory")
	}
	return true, nil
}

func PathWithin(root, candidate string) bool {
	if !CanonicalAbsolute(root) || !CanonicalAbsolute(candidate) {
		return false
	}
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func CanonicalAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validGuestID(id string) bool {
	if id == "" || len(id) > 64 || id[0] == '-' || id[len(id)-1] == '-' {
		return false
	}
	for _, character := range id {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validRegion(region string) bool {
	return region == string(vmnet.GRU) || region == string(vmnet.SFO) || region == string(vmnet.FRA)
}

func validNetworkRunID(runID string) bool {
	if len(runID) != 32 {
		return false
	}
	for _, character := range runID {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func oneOf(value string, admitted ...string) bool {
	for _, candidate := range admitted {
		if value == candidate {
			return true
		}
	}
	return false
}

func resourcePaths(resource JournalVM) []string {
	return []string{resource.ClaimPath, resource.StateDir, resource.SandboxOwnershipPath, resource.RunMarkerPath, resource.RuntimePath, resource.JailRoot, resource.SocketPath, resource.LogPath, resource.MetricsPath, resource.CgroupPath, resource.JailerCgroupPath, resource.DriveDir, resource.DrivePath, resource.DriveMetadataPath, resource.DriveOwnershipPath, resource.SeedDir}
}

func sameJournalPlan(existing, proposed Journal) bool {
	if existing.Version != proposed.Version || existing.Marker != proposed.Marker || existing.RunID != proposed.RunID || existing.StateRoot != proposed.StateRoot || existing.ResourceRoot != proposed.ResourceRoot || existing.RunMarkerPath != proposed.RunMarkerPath || !reflect.DeepEqual(existing.Network, proposed.Network) || len(existing.VMs) != len(proposed.VMs) {
		return false
	}
	for index := range existing.VMs {
		a, b := existing.VMs[index], proposed.VMs[index]
		a.Phase, b.Phase = "", ""
		a.Process, b.Process = nil, nil
		a.Cleaned, b.Cleaned = false, false
		if !reflect.DeepEqual(a, b) {
			return false
		}
	}
	return true
}

func cloneJournal(journal Journal) Journal {
	if journal.DiskStore != nil {
		identity := *journal.DiskStore
		journal.DiskStore = &identity
	}
	journal.VMs = append([]JournalVM(nil), journal.VMs...)
	for index := range journal.VMs {
		if journal.VMs[index].Process != nil {
			identity := *journal.VMs[index].Process
			journal.VMs[index].Process = &identity
		}
	}
	journal.Network.Cleanup.Commands = append([]vmnet.Command(nil), journal.Network.Cleanup.Commands...)
	return journal
}
