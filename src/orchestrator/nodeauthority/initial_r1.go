package nodeauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

// InitialR1AdmissionDirectory is separate from the private ts-node journal.
const InitialR1AdmissionDirectory = "/var/lib/terrascale/host-admission/initial-gru-r1"

const initialR1MaximumBytes = 8192
const initialR1LockTimeout = 2 * time.Second

var ErrInitialR1Retired = errors.New("nodeauthority: initial R1 is permanently retired")

// InitialR1Identity binds an existing owner-verified launch to one durable store
// scope. Digests are supplied by the verified host manifest path, not desired
// epochs. StoreScopeSHA256 covers the account/server/storage identity and profile.
type InitialR1Identity struct {
	Role             string    `json:"role"`
	NodeID           string    `json:"nodeId"`
	GrantSHA256      string    `json:"grantSha256"`
	ManifestSHA256   string    `json:"manifestSha256"`
	LaunchSHA256     string    `json:"launchSha256"`
	CandidateID      string    `json:"candidateId"`
	StoreScopeSHA256 string    `json:"storeScopeSha256"`
	IssuedAt         time.Time `json:"issuedAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

// InitialR1Retirement records an already admitted host command. It does not
// certify global quorum or mint a new authority. The existing host receiver is
// the sole writer; runtime callers only receive InitialR1Guard.
type InitialR1Retirement struct {
	CommandID                 string `json:"commandId"`
	PreviousManifestSHA256    string `json:"previousManifestSha256"`
	ReplacementManifestSHA256 string `json:"replacementManifestSha256"`
	AuthorityID               string `json:"authorityId"`
	Epoch                     int64  `json:"epoch"`
	CandidateID               string `json:"candidateId"`
	LeaseID                   string `json:"leaseId"`
}

type initialR1Record struct {
	Version    int                  `json:"version"`
	Ready      bool                 `json:"ready"`
	Identity   InitialR1Identity    `json:"identity"`
	Retirement *InitialR1Retirement `json:"retirement"`
}

// InitialR1Guard reads root-owned admission state. It cannot initialize or
// retire it. Call WithinMutation around each bounded provisioning/election
// mutation, not around the runtime lifetime. Missing state always refuses.
type InitialR1Guard struct {
	directory string
	identity  InitialR1Identity
	uid       uint32
}

func NewInitialR1Guard(directory string, identity InitialR1Identity) (*InitialR1Guard, error) {
	return newInitialR1Guard(directory, identity, 0)
}

func (g *InitialR1Guard) Check(ctx context.Context) error {
	return g.WithinMutation(ctx, func(context.Context) error { return nil })
}

func newInitialR1Guard(directory string, identity InitialR1Identity, uid uint32) (*InitialR1Guard, error) {
	if !validInitialR1Identity(identity) {
		return nil, errors.New("nodeauthority: invalid initial R1 identity")
	}
	g := &InitialR1Guard{directory: directory, identity: identity, uid: uid}
	dir, err := g.openDirectory()
	if err != nil {
		return nil, err
	}
	dir.Close()
	return g, nil
}

func validInitialR1Token(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func validInitialR1Identity(i InitialR1Identity) bool {
	prefix := "global-controller-gru-"
	if i.Role == "participant" {
		prefix = "gru-controller-"
	} else if i.Role != "seed" {
		return false
	}
	return validInitialR1Token(i.NodeID) && strings.HasPrefix(i.NodeID, "gru-") && validInitialR1Token(i.CandidateID) && strings.HasPrefix(i.CandidateID, prefix) && len(i.CandidateID) > len(prefix) && authorityDigest(i.GrantSHA256) && authorityDigest(i.ManifestSHA256) && authorityDigest(i.LaunchSHA256) && authorityDigest(i.StoreScopeSHA256) && !i.IssuedAt.IsZero() && i.ExpiresAt.After(i.IssuedAt) && i.ExpiresAt.Sub(i.IssuedAt) <= 24*time.Hour
}
func sameInitialR1Identity(a, b InitialR1Identity) bool {
	return a.Role == b.Role && a.NodeID == b.NodeID && a.GrantSHA256 == b.GrantSHA256 && a.ManifestSHA256 == b.ManifestSHA256 && a.LaunchSHA256 == b.LaunchSHA256 && a.CandidateID == b.CandidateID && a.StoreScopeSHA256 == b.StoreScopeSHA256 && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}
func validInitialR1Retirement(r *InitialR1Retirement) bool {
	return r != nil && validInitialR1Token(r.CommandID) && authorityDigest(r.PreviousManifestSHA256) && authorityDigest(r.ReplacementManifestSHA256) && r.PreviousManifestSHA256 != r.ReplacementManifestSHA256 && r.AuthorityID == "gru-regional" && r.Epoch > 0 && validInitialR1Token(r.CandidateID) && strings.HasPrefix(r.CandidateID, "gru-controller-") && validInitialR1Token(r.LeaseID)
}

// WithinMutation also caps the callback context at the original grant expiry.
// Callbacks must respect that context. A callback ignoring cancellation retains
// its shared lock: retirement times out rather than falsely claiming success.
func (g *InitialR1Guard) WithinMutation(ctx context.Context, mutate func(context.Context) error) error {
	if g == nil || ctx == nil || mutate == nil {
		return errors.New("nodeauthority: invalid initial R1 mutation")
	}
	dir, lock, _, err := g.lock(ctx, false, false)
	if err != nil {
		return err
	}
	defer dir.Close()
	defer lock.Close()
	record, err := g.read(dir)
	if err != nil {
		return err
	}
	if record.Retirement != nil {
		return ErrInitialR1Retired
	}
	if !record.Ready {
		return errors.New("nodeauthority: initial R1 publication is pending")
	}
	// A writer may have renamed Ready=true before a failed directory sync.
	// Make that visible admission durable before allowing any callback effect.
	if err = dir.Sync(); err != nil {
		return err
	}
	now := time.Now()
	if now.Before(g.identity.IssuedAt) || !now.Before(g.identity.ExpiresAt) {
		return errors.New("nodeauthority: initial R1 grant is outside its lifetime")
	}
	bounded, cancel := context.WithDeadline(ctx, g.identity.ExpiresAt)
	defer cancel()
	if err = bounded.Err(); err != nil {
		return err
	}
	if err = mutate(bounded); err != nil {
		return err
	}
	return bounded.Err()
}

// AdmitInitialR1 is called only by the existing verified initial host launch
// path after AdmitBootstrap. The caller holds the host command mutex. The
// admission directory must already have been provisioned root-owned, mode0755.
func (s *EpochStore) AdmitInitialR1(ctx context.Context, directory string, identity InitialR1Identity) error {
	return s.admitInitialR1(ctx, directory, identity, 0, nil)
}

// AdmitInitialR1WithPublication runs the host's original signed-proof publication
// only after checking the existing pinned grant under receiver ownership. The
// callback must durably publish that immutable public proof before returning.
func (s *EpochStore) AdmitInitialR1WithPublication(ctx context.Context, directory string, identity InitialR1Identity, publish func() error) error {
	if publish == nil {
		return errors.New("nodeauthority: original proof publication is required")
	}
	return s.admitInitialR1Publication(ctx, directory, identity, 0, nil, publish)
}
func (s *EpochStore) admitInitialR1(ctx context.Context, directory string, identity InitialR1Identity, uid uint32, afterRename func() error) error {
	return s.admitInitialR1Publication(ctx, directory, identity, uid, afterRename, nil)
}
func (s *EpochStore) admitInitialR1Publication(ctx context.Context, directory string, identity InitialR1Identity, uid uint32, afterRename, publish func() error) error {
	if s == nil || ctx == nil || uint32(os.Geteuid()) != uid {
		return errors.New("nodeauthority: initial R1 admission requires trusted host writer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil || identity.NodeID != s.node {
		return errors.New("nodeauthority: host admission ownership differs")
	}
	floor, err := s.load()
	if err != nil {
		return err
	}
	if floor.Epoch != 0 {
		return ErrInitialR1Retired
	}
	admitted, found, err := s.loadManifestAdmission()
	if err != nil {
		return err
	}
	if !found || admitted.GrantSHA256 != identity.GrantSHA256 || admitted.ManifestSHA256 != identity.ManifestSHA256 {
		return errors.New("nodeauthority: initial R1 launch lacks pinned bootstrap admission")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if publish != nil {
		if err = publish(); err != nil {
			return err
		}
	}
	return s.publishInitialR1(ctx, directory, identity, uid, afterRename)

}

// RetireInitialR1 consumes the exact CommandAuthorization already persisted by
// EpochStore.Admit, plus its current admitted manifest predecessor. It must be
// called inside the existing verified ApplyManifest handler, before replacement
// effects. An arbitrary desired epoch does not satisfy these checks.
func (s *EpochStore) RetireInitialR1(ctx context.Context, directory string, identity InitialR1Identity, command CommandAuthorization, commandID, currentManifest, replacementManifest string) error {
	return s.retireInitialR1(ctx, directory, identity, command, commandID, currentManifest, replacementManifest, 0, nil)
}
func (s *EpochStore) retireInitialR1(ctx context.Context, directory string, identity InitialR1Identity, command CommandAuthorization, commandID, currentManifest, replacementManifest string, uid uint32, afterRename func() error) error {
	if s == nil || ctx == nil || uint32(os.Geteuid()) != uid {
		return errors.New("nodeauthority: initial R1 retirement requires trusted host writer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownerLock == nil || identity.NodeID != s.node || command.NodeID != s.node || command.BootstrapGrantSHA256 != "" || !command.ExpiresAt.After(time.Now()) {
		return errors.New("nodeauthority: retirement requires live admitted runtime command")
	}
	handoff, err := hostmanifest.ParseApplyManifestCommand(command.Command)
	if err != nil {
		return err
	}
	digest, err := hostmanifest.HostManifestSha256(handoff.Manifest)
	if err != nil {
		return err
	}
	if handoff.CommandId != commandID || handoff.ExpectedManifestSha256 != currentManifest || digest != replacementManifest {
		return errors.New("nodeauthority: retirement differs from authenticated manifest command")
	}
	floor, err := s.load()
	if err != nil {
		return err
	}
	if floor.Epoch <= 0 || floor.AuthorityID != command.AuthorityID || floor.Epoch != command.Epoch || floor.CandidateID != command.CandidateID || floor.LeaseID != command.LeaseID {
		return errors.New("nodeauthority: retirement authority differs from durable floor")
	}
	admission, found, err := s.loadManifestAdmission()
	if err != nil {
		return err
	}
	if !found || admission.GrantSHA256 != identity.GrantSHA256 {
		return errors.New("nodeauthority: retirement predecessor was not admitted")
	}
	publication, published, err := s.readInitialR1Publication()
	if err != nil {
		return err
	}
	if !published || !publication.Committed || publication.Directory != directory || !sameInitialR1Identity(publication.Identity, identity) {
		return errors.New("nodeauthority: initial R1 publication was not committed")
	}
	r := InitialR1Retirement{CommandID: commandID, PreviousManifestSHA256: currentManifest, ReplacementManifestSHA256: replacementManifest, AuthorityID: command.AuthorityID, Epoch: command.Epoch, CandidateID: command.CandidateID, LeaseID: command.LeaseID}
	if !validInitialR1Retirement(&r) {
		return errors.New("nodeauthority: invalid initial R1 retirement")
	}
	g, err := newInitialR1Guard(directory, identity, uid)
	if err != nil {
		return err
	}
	dir, lock, _, err := g.lock(ctx, true, false)
	if err != nil {
		return err
	}
	defer dir.Close()
	defer lock.Close()
	record, err := g.read(dir)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if !command.ExpiresAt.After(time.Now()) {
		return errors.New("nodeauthority: retirement command expired waiting for mutation")
	}
	if record.Retirement != nil {
		prior := record.Retirement
		// A successor can finish the same authenticated logical transition after
		// the prior lease expired. Keep the original retirement evidence immutable.
		if prior.CommandID != r.CommandID || prior.PreviousManifestSHA256 != r.PreviousManifestSHA256 || prior.ReplacementManifestSHA256 != r.ReplacementManifestSHA256 || prior.AuthorityID != r.AuthorityID || r.Epoch < prior.Epoch || r.Epoch == prior.Epoch && (r.CandidateID != prior.CandidateID || r.LeaseID != prior.LeaseID) {
			return errors.New("nodeauthority: conflicting initial R1 retirement")
		}
		return dir.Sync()
	}
	if !record.Ready {
		return errors.New("nodeauthority: initial R1 publication is pending")
	}
	if currentManifest != admission.ManifestSHA256 && currentManifest != admission.PreviousSHA256 {
		return errors.New("nodeauthority: retirement predecessor was not admitted")
	}
	record.Retirement = &r
	return writeInitialR1(dir, record, afterRename)
}

// All traversal uses directory descriptors; writable or symlink ancestors
// cannot redirect a privileged writer or a service reader. Sticky root-owned
// public ancestors (such as /tmp in isolated tests) are safe to traverse.
func (g *InitialR1Guard) openDirectory() (*os.File, error) {
	if !filepath.IsAbs(g.directory) || filepath.Clean(g.directory) != g.directory {
		return nil, errors.New("nodeauthority: invalid initial R1 state path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(g.directory, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 && st.Uid != g.uid || st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
			unix.Close(fd)
			return nil, errors.New("nodeauthority: unsafe initial R1 directory ancestry")
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != g.uid || st.Mode&0777 != 0755 {
		unix.Close(fd)
		return nil, errors.New("nodeauthority: initial R1 directory must be host-owned mode0755")
	}
	return os.NewFile(uintptr(fd), g.directory), nil
}
func (g *InitialR1Guard) lock(ctx context.Context, exclusive, create bool) (*os.File, *os.File, bool, error) {
	dir, err := g.openDirectory()
	if err != nil {
		return nil, nil, false, err
	}
	fail := func(err error) (*os.File, *os.File, bool, error) { dir.Close(); return nil, nil, false, err }
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if exclusive {
		flags = unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	}
	created := false
	fd, err := unix.Openat(int(dir.Fd()), "initial-r1.lock", flags, 0)
	if errors.Is(err, unix.ENOENT) && create {
		fd, err = unix.Openat(int(dir.Fd()), "initial-r1.lock", flags|unix.O_CREAT|unix.O_EXCL, 0644)
		if errors.Is(err, unix.EEXIST) {
			fd, err = unix.Openat(int(dir.Fd()), "initial-r1.lock", flags, 0)
		} else if err == nil {
			created = true
		}
	}
	if err != nil {
		return fail(err)
	}
	lock := os.NewFile(uintptr(fd), "initial-r1.lock")
	if created {
		if err = lock.Chmod(0644); err == nil {
			err = lock.Sync()
		}
		if err == nil {
			err = dir.Sync()
		}
	}
	if err == nil {
		err = initialR1File(lock, g.uid, 0)
	}
	if err != nil {
		lock.Close()
		return fail(err)
	}
	bounded, cancel := context.WithTimeout(ctx, initialR1LockTimeout)
	defer cancel()
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	for {
		if err = bounded.Err(); err != nil {
			lock.Close()
			return fail(err)
		}
		err = unix.Flock(fd, mode|unix.LOCK_NB)
		if err == nil {
			return dir, lock, created, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			lock.Close()
			return fail(err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
func initialR1File(file *os.File, uid uint32, max int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || st.Uid != uid || st.Nlink != 1 || info.Size() > max {
		return errors.New("nodeauthority: unsafe initial R1 admission file")
	}
	return nil
}
func (g *InitialR1Guard) read(dir *os.File) (initialR1Record, error) {
	var record initialR1Record
	fd, err := unix.Openat(int(dir.Fd()), "initial-r1.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return record, err
	}
	f := os.NewFile(uintptr(fd), "initial-r1.json")
	defer f.Close()
	if err = initialR1File(f, g.uid, initialR1MaximumBytes); err != nil {
		return record, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, initialR1MaximumBytes+1))
	if err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return record, errors.New("nodeauthority: corrupt initial R1 admission")
	}
	canonical, e := json.Marshal(record)
	if e != nil || !bytes.Equal(raw, canonical) || record.Version != 1 || !validInitialR1Identity(record.Identity) || !sameInitialR1Identity(record.Identity, g.identity) || record.Retirement != nil && (!record.Ready || !validInitialR1Retirement(record.Retirement)) {
		return record, errors.New("nodeauthority: initial R1 admission binding differs")
	}
	return record, nil
}
func writeInitialR1(dir *os.File, record initialR1Record, afterRename func() error) error {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > initialR1MaximumBytes {
		return errors.New("nodeauthority: invalid initial R1 document")
	}
	// CreateTemp needs a path; /proc/self/fd pins the already validated directory.
	file, err := os.CreateTemp("/proc/self/fd/"+strconv.FormatUint(uint64(dir.Fd()), 10), ".initial-r1-")
	if err != nil {
		return err
	}
	name := filepath.Base(file.Name())
	defer unix.Unlinkat(int(dir.Fd()), name, 0)
	if err = file.Chmod(0644); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = unix.Renameat(int(dir.Fd()), name, int(dir.Fd()), "initial-r1.json"); err != nil {
		return err
	}
	if afterRename != nil {
		if err = afterRename(); err != nil {
			return err
		}
	}
	return dir.Sync()
}
