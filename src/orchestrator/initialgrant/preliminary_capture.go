package initialgrant

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
)

// VerifyPreliminaryRequest uses the original, already verified owner key. A
// request cannot nominate its own verifier or introduce another initial launch.
func (a *Admission) VerifyPreliminaryRequest(ctx context.Context, raw []byte) (preliminarycapture.VerifiedRequest, error) {
	if err := a.Check(ctx); err != nil {
		return preliminarycapture.VerifiedRequest{}, err
	}
	if a.proof == nil || a.proof.config.Role != "seed" || a.proof.config.PreliminaryCapture == nil {
		return preliminarycapture.VerifiedRequest{}, errors.New("initialgrant: source capture is not admitted")
	}
	verified, err := preliminarycapture.VerifyRequest(a.proof.public, raw)
	if err != nil {
		return preliminarycapture.VerifiedRequest{}, err
	}
	r := verified.Request
	i, c := a.proof.identity, a.proof.config
	if err := verified.Check(time.Now().UTC()); err != nil {
		return preliminarycapture.VerifiedRequest{}, err
	}
	if r.SourceNodeID != i.NodeID || r.InitialGrantSHA256 != i.GrantSHA256 || r.StoreScopeSHA256 != i.StoreScopeSHA256 || r.ProfileSHA256 != c.ProfileSHA256 || r.IssuedAt.Before(i.IssuedAt) || r.ExpiresAt.After(i.ExpiresAt) || len(r.Accounts) != 2 || r.Accounts[0].Account != c.Regional.Account || r.Accounts[1].Account != c.Global.Account {
		return preliminarycapture.VerifiedRequest{}, errors.New("initialgrant: preliminary request differs from admitted source")
	}
	return verified, nil
}

// ReadPreliminaryRequest reads only the configured root-owned request, through
// directory descriptors. A missing file is idle; service-writable ancestry or
// files, symlinks, special files and multiple hard links are refused.
func ReadPreliminaryRequest(path string) ([]byte, error) {
	return readRootRequest(path, 64<<10)
}

func readRootRequest(path string, maximumBytes int64) ([]byte, error) {
	if !cleanPath(path) {
		return nil, errors.New("initialgrant: unsafe preliminary request path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, errors.New("initialgrant: preliminary request ancestry must be protected and root-owned")
		}
	}
	requestFD, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(requestFD), path)
	defer f.Close()
	var before unix.Stat_t
	if unix.Fstat(requestFD, &before) != nil || before.Uid != 0 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 || before.Nlink != 1 || before.Size <= 0 || before.Size > maximumBytes {
		return nil, errors.New("initialgrant: unsafe preliminary request ownership or bounds")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximumBytes+1))
	var after unix.Stat_t
	if err != nil || unix.Fstat(requestFD, &after) != nil || int64(len(raw)) != before.Size || after.Size != before.Size || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return nil, errors.New("initialgrant: preliminary request changed while reading")
	}
	return raw, nil
}
