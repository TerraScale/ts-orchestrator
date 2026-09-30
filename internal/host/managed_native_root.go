//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nativerootoci"
)

type managedNativeRoot struct {
	role        string
	fingerprint string
	target      nativerootoci.Target
	path        string
	file        os.FileInfo
	listener    *net.UnixListener
	cancel      context.CancelFunc
	done        chan struct{}
}

type nativeRootDesired struct {
	fingerprint string
	until       time.Time
}

// A successful, validated desired refresh may advance this bound. Session
// renewal alone cannot extend authority to an old desired generation.
func (a *Agent) pinManagedNativeRootDesired(role, fingerprint string) error {
	_, deadline, err := a.executionLease()
	if err != nil {
		return err
	}
	a.nativeRootMu.Lock()
	if a.nativeDesired == nil {
		a.nativeDesired = make(map[string]nativeRootDesired)
	}
	a.nativeDesired[role] = nativeRootDesired{fingerprint: fingerprint, until: deadline}
	a.nativeRootMu.Unlock()
	return nil
}

// refreshNativeRootPin re-validates the signed desired right before the native
// OCI root starts and pins it again. The pin taken at reconcile start lasts one
// session lease, which a first member start (artifact, material, volume
// format) outlasts on a small host.
func (a *Agent) refreshNativeRootPin(ctx context.Context, target desiredReply, fingerprint string) error {
	if target.Desired == nil {
		return errors.New("native OCI root requires a signed desired")
	}
	role := target.Desired.Role
	latest := desiredReply{}
	if err := a.request(ctx, "desired", struct {
		Role string `json:"role"`
	}{role}, &latest); err != nil {
		return err
	}
	if err := a.validateDesiredReply(latest); err != nil || !sameDesiredReplyBinding(target, latest) {
		return errors.New("managed desired changed before native OCI root start")
	}
	return a.pinManagedNativeRootDesired(role, fingerprint)
}

// extendManagedNativeRootPin advances an existing pin for the same
// fingerprint to the current session deadline. It never recreates a revoked
// pin or adopts a changed desired.
func (a *Agent) extendManagedNativeRootPin(role, fingerprint string) error {
	_, deadline, err := a.executionLease()
	if err != nil {
		return err
	}
	a.nativeRootMu.Lock()
	defer a.nativeRootMu.Unlock()
	if pin, pinned := a.nativeDesired[role]; pinned && pin.fingerprint == fingerprint && deadline.After(pin.until) {
		a.nativeDesired[role] = nativeRootDesired{fingerprint: fingerprint, until: deadline}
	}
	return nil
}

// refreshNativeRootPins re-validates every pinned desired once per poll. A
// pin lasts one session lease, while a reconcile on a single-OCPU host can
// take as long; a lapsed pin makes the native OCI root reject the member's
// root publication, which the member must treat as an uncertain commit.
func (a *Agent) refreshNativeRootPins(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		for _, role := range a.cfg.Roles {
			a.nativeRootMu.Lock()
			pin, pinned := a.nativeDesired[role]
			a.nativeRootMu.Unlock()
			if !pinned {
				continue
			}
			var latest desiredReply
			if err := a.request(ctx, "desired", struct {
				Role string `json:"role"`
			}{role}, &latest); err != nil || a.validateDesiredReply(latest) != nil || latest.Desired == nil {
				continue
			}
			if fingerprint, err := desiredFingerprint(*latest.Desired); err == nil && fingerprint == pin.fingerprint {
				_ = a.extendManagedNativeRootPin(role, fingerprint)
			}
		}
	}
}

func (a *Agent) revokeManagedNativeRoot(role string) error {
	a.nativeRootMu.Lock()
	delete(a.nativeDesired, role)
	a.nativeRootMu.Unlock()
	return a.stopManagedNativeRoot(role)
}

func (a *Agent) nativeRootDesiredDeadline(role, fingerprint string) (time.Time, error) {
	a.nativeRootMu.Lock()
	pin, found := a.nativeDesired[role]
	a.nativeRootMu.Unlock()
	if !found || pin.fingerprint != fingerprint || !time.Now().Before(pin.until) {
		return time.Time{}, errors.New("managed native OCI root desired pin expired or changed")
	}
	return pin.until, nil
}

func nativeRootTarget(launch ManagedMemberLaunch, config []byte) (nativerootoci.Target, bool, error) {
	scope := launch.Member.Scope
	publication, err := nativerootoci.PublicationDigest(scope.ClusterID, scope.TenantID,
		scope.DatabaseID, scope.MemberID, scope.Incarnation, scope.ShardID)
	if err != nil {
		return nativerootoci.Target{}, false, err
	}
	return nativerootoci.TargetFromSignedConfig(config, launch.Runtime.LiveS3TargetSHA256, publication)
}

func (a *Agent) managedNativeRootTarget(launch ManagedMemberLaunch) (nativerootoci.Target, bool,
	managedRuntimePaths, error,
) {
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, launch)
	if err != nil || launch.Runtime == nil {
		return nativerootoci.Target{}, false, managedRuntimePaths{}, errors.New("managed native root has no signed runtime")
	}
	config, err := verifyManagedMaterial(filepath.Join(paths.material, "signed-v2-s3-config.json"),
		launch.Runtime.LiveS3ConfigSHA256, a.cfg.WorkloadIdentity, 16<<10)
	if err != nil {
		return nativerootoci.Target{}, false, managedRuntimePaths{}, err
	}
	target, selected, err := nativeRootTarget(launch, config)
	return target, selected, paths, err
}

// ensureManagedNativeRoot starts the host-only native OCI socket before a
// managed member is launched. Generic S3 members never start this capability.
func (a *Agent) ensureManagedNativeRoot(ctx context.Context, desired Desired, fingerprint string) error {
	launch := desired.ManagedMember
	if launch == nil {
		return errors.New("native OCI root requires a signed managed member")
	}
	target, selected, paths, err := a.managedNativeRootTarget(*launch)
	if err != nil {
		return err
	}
	if !selected {
		return a.stopManagedNativeRoot(desired.Role)
	}
	if _, err := a.nativeRootDesiredDeadline(desired.Role, fingerprint); err != nil {
		return err
	}
	a.nativeRootMu.Lock()
	current := a.nativeRoots[desired.Role]
	a.nativeRootMu.Unlock()
	if current != nil {
		select {
		case <-current.done:
		default:
			if current.fingerprint == fingerprint && current.target == target && current.path == paths.nativeRoot {
				return nil
			}
		}
		if err := a.stopManagedNativeRoot(desired.Role); err != nil {
			return err
		}
	}
	if err := verifyManagedDirectory(paths.memberDir, a.cfg.WorkloadIdentity, 0750); err != nil {
		return err
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	client, err := nativerootoci.NewInstancePrincipalClient(ctx, target.Region)
	if err != nil {
		return err
	}
	if _, err := a.nativeRootDesiredDeadline(desired.Role, fingerprint); err != nil {
		return err
	}
	service, err := nativerootoci.NewService(target, client)
	if err != nil {
		return err
	}
	listener, file, err := listenManagedNativeRoot(paths.nativeRoot, a.cfg.WorkloadIdentity)
	if err != nil {
		return err
	}
	work, cancel := context.WithCancel(ctx)
	root := &managedNativeRoot{role: desired.Role, fingerprint: fingerprint, target: target,
		path: paths.nativeRoot, file: file, listener: listener, cancel: cancel, done: make(chan struct{})}
	a.nativeRootMu.Lock()
	if ctx.Err() != nil || a.sessionLost.Load() {
		a.nativeRootMu.Unlock()
		cancel()
		_ = listener.Close()
		_ = removeManagedNativeRootSocket(root)
		return errors.New("managed native OCI root session was lost")
	}
	if a.nativeRoots == nil {
		a.nativeRoots = make(map[string]*managedNativeRoot)
	}
	a.nativeRoots[desired.Role] = root
	a.nativeRootMu.Unlock()
	go func() {
		defer close(root.done)
		_ = nativerootoci.Serve(work, listener, service, func(ctx context.Context, peer nativerootoci.Peer) (time.Time, error) {
			return a.authorizeManagedNativeRoot(ctx, peer, desired, root)
		})
	}()
	return nil
}

func listenManagedNativeRoot(path string, identity WorkloadIdentity) (*net.UnixListener, os.FileInfo, error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("native OCI root helper requires the root host process")
	}
	if old, err := os.Lstat(path); err == nil {
		owner, ok := old.Sys().(*syscall.Stat_t)
		if !ok || old.Mode()&os.ModeSocket == 0 || owner.Uid != 0 || owner.Gid != identity.GID || old.Mode().Perm() != 0660 {
			return nil, nil, errors.New("stale native OCI root socket is unsafe")
		}
		active, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = active.Close()
			return nil, nil, errors.New("another native OCI root listener is active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, nil, errors.New("native OCI root socket liveness is uncertain")
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(old, current) {
			return nil, nil, errors.New("stale native OCI root socket changed before removal")
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, errors.New("stale native OCI root socket could not be removed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chown(path, 0, int(identity.GID)); err == nil {
		err = os.Chmod(path, 0660)
	}
	file, inspectErr := os.Lstat(path)
	if err != nil || inspectErr != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, nil, errors.New("native OCI root socket ownership could not be set")
	}
	return listener, file, nil
}

func (a *Agent) authorizeManagedNativeRoot(ctx context.Context, peer nativerootoci.Peer,
	desired Desired, root *managedNativeRoot,
) (time.Time, error) {
	if ctx.Err() != nil || a.sessionLost.Load() {
		return time.Time{}, nativerootoci.AuthorizationError{Cause: "session_revoked",
			Err: errors.New("managed native OCI root peer is unauthorized")}
	}
	if peer.UID != a.cfg.WorkloadIdentity.UID || peer.GID != a.cfg.WorkloadIdentity.GID || peer.PID <= 0 {
		return time.Time{}, nativerootoci.AuthorizationError{Cause: "peer_credentials",
			Err: errors.New("managed native OCI root peer is unauthorized")}
	}
	a.nativeRootMu.Lock()
	active := a.nativeRoots[desired.Role] == root
	pin, pinned := a.nativeDesired[desired.Role]
	a.nativeRootMu.Unlock()
	if !active || !pinned || pin.fingerprint != root.fingerprint || !time.Now().Before(pin.until) {
		return time.Time{}, nativerootoci.AuthorizationError{Cause: "listener_or_pin_revoked",
			Err: errors.New("managed native OCI root listener is no longer active")}
	}
	_, deadline, err := a.executionLease()
	if err != nil {
		return time.Time{}, nativerootoci.AuthorizationError{Cause: "execution_lease", Err: err}
	}
	if pin.until.Before(deadline) {
		deadline = pin.until
	}
	observed, err := a.runner.Observe(ctx, desired.Role)
	if err != nil || !observed.Running {
		return time.Time{}, nativerootoci.AuthorizationError{Cause: "process_unavailable",
			Err: errors.New("managed native OCI root peer differs from active member")}
	}
	if observed.PID != peer.PID ||
		observed.Digest != desired.Digest || observed.Fingerprint != root.fingerprint ||
		observed.CgroupMemoryMaxBytes != desired.ManagedMember.CgroupMemoryMaxBytes {
		return time.Time{}, nativerootoci.AuthorizationError{Cause: "process_witness",
			Err: errors.New("managed native OCI root peer differs from active member")}
	}
	runner, ok := a.runner.(*processRunner)
	if !ok || runner.cgroups == "" {
		return time.Time{}, nativerootoci.AuthorizationError{Cause: "cgroup_witness",
			Err: errors.New("managed native OCI root has no native cgroup witness")}
	}
	contained, err := nativeCgroupContainsPID(filepath.Join(runner.cgroups, desired.Role), peer.PID)
	if err != nil || !contained {
		return time.Time{}, nativerootoci.AuthorizationError{Cause: "cgroup_membership",
			Err: errors.New("managed native OCI root peer left its role cgroup")}
	}
	return deadline, nil
}

func (a *Agent) stopManagedNativeRoot(role string) error {
	a.nativeRootMu.Lock()
	root := a.nativeRoots[role]
	delete(a.nativeRoots, role)
	a.nativeRootMu.Unlock()
	if root == nil {
		return nil
	}
	root.cancel()
	_ = root.listener.Close()
	<-root.done
	return removeManagedNativeRootSocket(root)
}

func (a *Agent) stopManagedNativeRootIfChanged(role, fingerprint string) error {
	a.nativeRootMu.Lock()
	current := a.nativeRoots[role]
	a.nativeRootMu.Unlock()
	if current != nil && current.fingerprint != fingerprint {
		return a.stopManagedNativeRoot(role)
	}
	return nil
}

func (a *Agent) stopAllManagedNativeRoots() error {
	a.nativeRootMu.Lock()
	roles := make([]string, 0, len(a.nativeRoots))
	for role := range a.nativeRoots {
		roles = append(roles, role)
	}
	a.nativeRootMu.Unlock()
	var failures []error
	for _, role := range roles {
		if err := a.stopManagedNativeRoot(role); err != nil {
			failures = append(failures, fmt.Errorf("stop native OCI root helper for %s: %w", role, err))
		}
	}
	return errors.Join(failures...)
}

func removeManagedNativeRootSocket(root *managedNativeRoot) error {
	current, err := os.Lstat(root.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !os.SameFile(root.file, current) {
		return errors.New("managed native OCI root socket changed before cleanup")
	}
	return os.Remove(root.path)
}
