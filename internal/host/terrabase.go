package host

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"golang.org/x/sys/unix"
)

// C# TerraBase members are generic native workloads of role "terrabase" on a
// host configured with a TerraBase root. Unlike the generic runner contract,
// the host prepares the member's data directory and its CA-signed TLS
// certificate, reports the member running only once its health endpoint
// answers, and stops it with SIGTERM before the cgroup is killed.

// terraBaseDrain bounds a member's graceful shutdown; the host unit's
// TimeoutStopSec leaves room for it.
const terraBaseDrain = 45 * time.Second

// terraBaseMember is what the agent remembers about a launched member.
type terraBaseMember struct {
	certificateExpiry time.Time // of the certificate the process loaded
	exited            bool      // its exit was reported; relaunch on the next poll
}

type terraBasePeerQuery struct {
	CSR []byte `json:"csr"`
}

type terraBasePeerReply struct {
	Certificate []byte `json:"certificate"`
	CA          []byte `json:"ca"`
}

// serveTerraBasePeer signs the member certificate of a host whose current
// desired runs a TerraBase member that its signed profile lists as a peer.
// The certificate names exactly that listed name and address.
func (c *Controller) serveTerraBasePeer(ctx context.Context, req request, r Registration) (any, error) {
	if c.terraBaseCA == nil {
		return nil, errors.New("terrabase member CA is not configured")
	}
	var query terraBasePeerQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if !slices.Contains(r.Roles, terrabase.Role) || r.ManagedOCI != nil {
		return nil, errors.New("host does not run C# TerraBase members")
	}
	d, _, exists, err := c.readDesired(ctx, req.Node, terrabase.Role)
	if err != nil {
		return nil, err
	}
	if !exists || d.Withdrawn || d.ManagedMember != nil {
		return nil, errors.New("host has no active TerraBase member")
	}
	if err := validateDesired(d, c.cell, r); err != nil {
		return nil, err
	}
	profile, err := terrabase.ParseProfile(d.Env)
	if err != nil {
		return nil, err
	}
	peer, listed := profile.Peer(req.Node)
	if !listed {
		return nil, fmt.Errorf("node %s is not in %s", req.Node, terrabase.EnvPeers)
	}
	certificate, err := c.terraBaseCA.Issue(query.CSR, peer, time.Now())
	if err != nil {
		return nil, err
	}
	return terraBasePeerReply{Certificate: certificate, CA: c.terraBaseCA.CertificatePEM()}, nil
}

// validateTerraBaseRoot keeps the member's files apart from the agent's. The
// agent chowns the root and creates the member's directories below it, so
// neither the root nor any ancestor may be a symlink or replaceable by the
// workload identity, and the workload must be able to traverse to its data.
func validateTerraBaseRoot(root, installRoot, stateRoot string, identity WorkloadIdentity) error {
	separator := string(filepath.Separator)
	for _, other := range []string{installRoot, stateRoot} {
		if other != "" && (root == other || strings.HasPrefix(root, other+separator) || strings.HasPrefix(other, root+separator)) {
			return errors.New("terrabase root must be separate from the install and state roots")
		}
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == separator {
		return errors.New("terrabase root must be a clean absolute path other than /")
	}
	// Only the member root may be absent; every parent must already be safe.
	if err := inspectWorkloadPath(filepath.Dir(root), identity, true, false, false); err != nil {
		return fmt.Errorf("terrabase root parent: %w", err)
	}
	// Every existing component is a real, non-replaceable directory...
	if err := inspectWorkloadPath(root, identity, true, true, false); err != nil {
		return fmt.Errorf("terrabase root: %w", err)
	}
	// ...and the workload cannot create the root before the agent does, not
	// even in a sticky parent such as /tmp.
	if info, err := os.Lstat(filepath.Dir(root)); err == nil && identity.UID != uint32(os.Geteuid()) {
		owner, _ := info.Sys().(*syscall.Stat_t)
		write := info.Mode().Perm() & 0o002
		if owner != nil && owner.Gid == identity.GID {
			write = info.Mode().Perm() & 0o020
		}
		if owner != nil && owner.Uid == identity.UID {
			write = info.Mode().Perm() & 0o200
		}
		if write != 0 {
			return errors.New("the workload identity can create entries next to the terrabase root")
		}
	}
	// ...so the path resolves to itself.
	existing := root
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		existing = filepath.Dir(existing)
	}
	if resolved, err := filepath.EvalSymlinks(existing); err != nil || resolved != existing {
		return fmt.Errorf("terrabase root %s does not resolve to itself", existing)
	}
	return nil
}

// terraBaseMember reports whether this host launches d as a C# TerraBase member.
func (a *Agent) terraBaseMember(d Desired) bool {
	return a.cfg.TerraBaseRoot != "" && d.Role == terrabase.Role && d.ManagedMember == nil && !d.Withdrawn
}

// terraBaseExited reports, once per exit, that the member of this exact
// desired stopped running, so the host reports it failed before relaunching
// it on the next poll; a crash-looping release then fails its gate at once.
func (a *Agent) terraBaseExited(observed Observation, d Desired, fingerprint string) bool {
	member := a.terraBase[d.Role]
	exited := !observed.Running && observed.Digest == d.Digest && observed.Fingerprint == fingerprint && !member.exited
	member.exited = exited
	a.terraBase[d.Role] = member
	return exited
}

// terraBaseRunningReport renews the member certificate files when they are
// due and reports the member's health. A member that reloads renewed files
// (TerraBase TS-464) serves the new certificate at its next handshake; one
// that does not keeps the certificate it started with. Shortly before the
// certificate the member actually serves expires, the host restarts it, with
// a drain, so it loads the renewed one.
func (a *Agent) terraBaseRunningReport(ctx context.Context, d Desired) Report {
	_, _, renewErr := a.prepareTerraBase(ctx, d)
	// ponytail: a per-node offset of one to seven days keeps the members of
	// a cell that cannot reload from restarting together.
	restartBefore := time.Duration(24+crc32.ChecksumIEEE([]byte(a.cfg.Node))%144) * time.Hour
	member := a.terraBase[d.Role]
	if renewErr == nil && !member.certificateExpiry.IsZero() && time.Until(member.certificateExpiry) < restartBefore {
		served, err := a.terraBaseServedExpiry(ctx, d)
		if err != nil || time.Until(served) < restartBefore {
			stopErr := a.runner.Stop(ctx, d.Role)
			if stopErr == nil {
				delete(a.terraBase, d.Role)
			}
			return a.reportFor(d, "starting", errors.Join(errors.New("restarting to load the renewed member certificate"),
				err, stopErr))
		}
		member.certificateExpiry = served
		a.terraBase[d.Role] = member
	}
	state, healthErr := a.terraBaseState(ctx, d)
	return a.reportFor(d, state, errors.Join(healthErr, renewErr))
}

// terraBaseServedExpiry is the earliest expiry of the certificates the
// member's peer and client listeners serve.
func (a *Agent) terraBaseServedExpiry(ctx context.Context, d Desired) (time.Time, error) {
	profile, err := terrabase.ParseProfile(d.Env)
	if err != nil {
		return time.Time{}, err
	}
	peer, _ := profile.Peer(a.cfg.Node)
	layout := terrabase.Layout(a.cfg.TerraBaseRoot)
	ca, err := os.ReadFile(layout.CA())
	if err != nil {
		return time.Time{}, err
	}
	earliest := time.Time{}
	for _, port := range []int{profile.PeerPort, profile.ClientPort} {
		if port == 0 {
			continue
		}
		served, err := terrabase.ServedCertificateExpiry(ctx, port, peer, layout.Certificate(), layout.Key(), ca)
		if err != nil {
			return time.Time{}, err
		}
		if earliest.IsZero() || served.Before(earliest) {
			earliest = served
		}
	}
	return earliest, nil
}

// prepareTerraBase creates the member directories, makes sure its
// certificate is current, and returns the member's launch environment and
// the certificate's expiry.
func (a *Agent) prepareTerraBase(ctx context.Context, d Desired) (map[string]string, time.Time, error) {
	if len(d.Args) != 0 {
		// The binary lets an argument override the host-owned settings.
		return nil, time.Time{}, errors.New("terrabase members take no arguments")
	}
	profile, err := terrabase.ParseProfile(d.Env)
	if err != nil {
		return nil, time.Time{}, err
	}
	peer, listed := profile.Peer(a.cfg.Node)
	if !listed {
		return nil, time.Time{}, fmt.Errorf("node %s is not in %s", a.cfg.Node, terrabase.EnvPeers)
	}
	// Recheck the ancestors right before the privileged effects below.
	if err := validateTerraBaseRoot(a.cfg.TerraBaseRoot, a.cfg.InstallRoot, a.cfg.StateRoot, a.cfg.WorkloadIdentity); err != nil {
		return nil, time.Time{}, err
	}
	layout := terrabase.Layout(a.cfg.TerraBaseRoot)
	supervisor, uid, gid := os.Geteuid(), int(a.cfg.WorkloadIdentity.UID), int(a.cfg.WorkloadIdentity.GID)
	// The binary writes its databases and extracted libraries; it only
	// reads its TLS material, which stays supervisor-owned.
	for _, dir := range []struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}{
		{string(layout), supervisor, gid, 0o750}, {layout.TLS(), supervisor, gid, 0o750},
		{layout.Data(), uid, gid, 0o700}, {layout.Bundle(), uid, gid, 0o700},
	} {
		if err := ensureOwnedDir(dir.path, dir.uid, dir.gid, dir.mode); err != nil {
			return nil, time.Time{}, err
		}
	}
	key, err := os.ReadFile(layout.Key())
	if errors.Is(err, os.ErrNotExist) {
		if key, _, err = terrabase.NewMemberKey(); err == nil {
			err = writeOwnedFile(layout.Key(), key, gid)
		}
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	certificate, _ := os.ReadFile(layout.Certificate())
	ca, _ := os.ReadFile(layout.CA())
	if !terrabase.CurrentCertificate(certificate, key, ca, peer, time.Now()) {
		csr, err := terrabase.CertificateRequest(key)
		if err != nil {
			return nil, time.Time{}, err
		}
		var reply terraBasePeerReply
		if err := a.request(ctx, "terrabase-peer", terraBasePeerQuery{CSR: csr}, &reply); err != nil {
			return nil, time.Time{}, err
		}
		if !terrabase.CurrentCertificate(reply.Certificate, key, reply.CA, peer, time.Now()) {
			return nil, time.Time{}, errors.New("controller returned an unusable TerraBase member certificate")
		}
		if err := writeOwnedFile(layout.CA(), reply.CA, gid); err != nil {
			return nil, time.Time{}, err
		}
		if err := writeOwnedFile(layout.Certificate(), reply.Certificate, gid); err != nil {
			return nil, time.Time{}, err
		}
		certificate = reply.Certificate
	}
	return layout.Env(d.Env, profile), terrabase.CertificateExpiry(certificate), nil
}

// terraBaseState is "running" once the member answers its health endpoint,
// and "starting" until then.
func (a *Agent) terraBaseState(ctx context.Context, d Desired) (string, error) {
	profile, err := terrabase.ParseProfile(d.Env)
	if err != nil {
		return "", err
	}
	if err := terrabase.Healthy(ctx, profile.AdminPort); err != nil {
		return "starting", err
	}
	return "running", nil
}

// ensureOwnedDir creates path and sets its owner and mode through a
// descriptor opened without following a symlink at path.
func ensureOwnedDir(path string, uid, gid int, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s must be a directory, not a symlink: %w", path, err)
	}
	defer unix.Close(fd)
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, uint32(mode.Perm()))
}

// writeOwnedFile atomically replaces a supervisor-owned file the workload group may read.
func writeOwnedFile(path string, data []byte, gid int) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	_, err = temporary.Write(data)
	if err == nil {
		err = temporary.Chown(os.Geteuid(), gid)
	}
	if err == nil {
		err = temporary.Chmod(0o440)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
